// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {AxisBVerifierCore} from "./AxisBVerifierCore.sol";
import {Nb2ReceiptVerifier} from "../verifier/Nb2ReceiptVerifier.sol";
import {Nb2Cbor as C} from "../verifier/Nb2Cbor.sol";
import {Nb2Crypto as X} from "../verifier/Nb2Crypto.sol";
// All offsets and counts are read from bounded uint64 evidence.
// forge-lint: disable-start(unsafe-typecast,uninitialized-local,encode-packed-collision)
import {Nb2Rules as R} from "../verifier/Nb2Rules.sol";
import {AxisBCommitment as W, AXIS_B_PAGE_BYTES, AXIS_B_MAX_WINDOW_BYTES} from "./AxisBCommitment.sol";
import {AxisBDeposit} from "./AxisBDeposit.sol";
import {AxisBSha256} from "./AxisBSha256.sol";

/// @notice Experimental receipt-chained lineage verifier with no vault entry point.
contract AxisBRecovery is AxisBVerifierCore {
    event AxisBProgress(bytes32 indexed session, bytes32 state);
    event AxisBComplete(
        bytes32 domain,
        bytes32 eta,
        uint64 minSegment,
        bytes32 asset,
        address recipient,
        uint256 amount
    );
    bytes32 private constant SHA_IV =
        0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;
    AxisBSha256 public immutable HASHER;
    AxisBDeposit public immutable DEPOSIT;
    bytes32 public immutable DEPOSIT_CODEHASH;
    W public immutable COMMITMENTS;
    bytes32 public immutable HASHER_CODEHASH;
    bytes32 public immutable COMMITMENTS_CODEHASH;
    error InvalidState();

    enum Phase {
        Invalid,
        Discover,
        Prepare,
        HashMint,
        Mint,
        Transfer,
        Unwind,
        Complete
    }

    struct Frame {
        uint64 start;
        uint64 end;
        uint64 mint;
        uint64 just;
        uint64 justEnd;
    }

    struct State {
        Phase phase;
        Frame frame;
        bytes32 stack;
        bytes32 seen;
        uint64 pos;
        uint64 mintEnd;
        uint64 left;
        uint64 splitProof;
        bytes32 hash;
        bytes32 owner;
        bytes1 ownerTail;
        bytes32 state;
        bytes32 id;
        uint256 amount;
        bytes32 parentID;
        uint256 parentAmount;
        bytes32 parentManifest;
    }

    struct Input {
        W.Window[] windows;
        Frame frame;
        bytes32 tail;
        uint256 seenBitmap;
        bytes32[] siblings;
    }

    constructor(
        bool testSet,
        Nb2ReceiptVerifier receipts,
        AxisBSha256 hasher,
        W commitments,
        AxisBDeposit deposit
    ) AxisBVerifierCore(testSet, receipts) {
        if (
            address(hasher).code.length == 0 || address(commitments).code.length == 0
                || address(deposit).code.length == 0
        ) revert HelperCodeMismatch();
        HASHER = hasher;
        DEPOSIT = deposit;
        DEPOSIT_CODEHASH = address(deposit).codehash;
        COMMITMENTS = commitments;
        HASHER_CODEHASH = address(hasher).codehash;
        COMMITMENTS_CODEHASH = address(commitments).codehash;
    }

    function _session(bytes32 domain, bytes32 root, uint64 length) private view returns (bytes32) {
        return keccak256(
            abi.encodePacked("UNICITY_NB2_AXIS_B_PROTOTYPE_V1", domain, address(this), root, length)
        );
    }

    function _frame(Frame memory f) private pure returns (bytes memory) {
        return abi.encodePacked(f.start, f.end, f.mint, f.just, f.justEnd);
    }

    function _push(Frame memory f, bytes32 tail) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x03), _frame(f), tail));
    }

    function stateDigest(bytes32 session, State memory s) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes1(0x04),
                session,
                uint8(s.phase),
                _frame(s.frame),
                s.stack,
                s.seen,
                s.pos,
                s.mintEnd,
                s.left,
                s.splitProof,
                s.hash,
                s.owner,
                s.ownerTail,
                s.state,
                s.id,
                s.amount,
                s.parentID,
                s.parentAmount,
                s.parentManifest
            )
        );
    }

    function _context(bytes calldata gamma) private view returns (Ctx memory ctx) {
        ctx = _newCtx();
        ctx.cfg = _config(gamma);
        ctx.claims = new Claim[](3);
        ctx.claimIds = new bytes32[](16);
    }

    function start(bytes calldata gamma, bytes32 root, uint64 length, Input calldata input)
        external
        returns (State memory s)
    {
        Ctx memory ctx = _context(gamma);
        _witness(input, root, length);
        bytes calldata begin = _read(input, 0, length);
        if (begin.length < 2 || begin[0] != 0x82 || begin[1] != 0x01) C.fail(R.EVIDENCE_SHAPE);
        s.phase = Phase.Discover;
        s.frame.start = 2;
        s.frame.end = length;
        s.seen = COMMITMENTS.emptyRoot();
        _advance(ctx, gamma, _session(ctx.cfg.d, root, length), s, input);
    }

    function resume(
        bytes calldata gamma,
        bytes32 root,
        uint64 length,
        State calldata prior,
        bytes calldata receipt,
        Input calldata input
    ) external returns (State memory s) {
        Ctx memory ctx = _context(gamma);
        bytes32 session = _session(ctx.cfg.d, root, length);
        if (prior.phase == Phase.Invalid || prior.phase == Phase.Complete) revert InvalidState();
        _witness(input, root, length);
        DEPOSIT.verifyProgress(gamma, address(this), session, stateDigest(session, prior), receipt);
        s = prior;
        _advance(ctx, gamma, session, s, input);
    }

    function _witness(Input calldata input, bytes32 root, uint64 length) private view {
        if (
            address(HASHER).codehash != HASHER_CODEHASH
                || address(COMMITMENTS).codehash != COMMITMENTS_CODEHASH
                || address(DEPOSIT).codehash != DEPOSIT_CODEHASH
        ) {
            revert HelperCodeMismatch();
        }
        if (root == 0 || length < 3 || input.windows.length == 0 || input.windows.length > 3) {
            revert W.InvalidWitness();
        }
        uint256 pages;
        for (uint256 i; i < input.windows.length; ++i) {
            uint256 size = input.windows[i].data.length;
            pages += (size + AXIS_B_PAGE_BYTES - 1) / AXIS_B_PAGE_BYTES;
        }
        if (pages > AXIS_B_MAX_WINDOW_BYTES / AXIS_B_PAGE_BYTES) revert W.InvalidWitness();
        for (uint256 i; i < input.windows.length; ++i) {
            // At most three independent windows and 32 total pages.
            // forge-lint: disable-next-line(calls-loop)
            COMMITMENTS.verify(input.windows[i], root, length);
        }
    }

    function _read(Input calldata input, uint256 position, uint256 limit)
        private
        pure
        returns (bytes calldata data)
    {
        if (position >= limit) revert W.InvalidWitness();
        for (uint256 i; i < input.windows.length; ++i) {
            W.Window calldata w = input.windows[i];
            if (position >= w.start && position - w.start < w.data.length) {
                uint256 end = limit - w.start;
                if (end > w.data.length) end = w.data.length;
                return w.data[position - w.start:end];
            }
        }
        revert W.InvalidWitness();
    }

    function _advance(
        Ctx memory ctx,
        bytes calldata gamma,
        bytes32 session,
        State memory s,
        Input calldata input
    ) private {
        if (s.phase == Phase.Discover) {
            _discover(ctx, s, input);
        } else if (s.phase == Phase.Prepare) {
            (, s.mintEnd) = _parseMint(ctx, s.frame, input);
            s.pos = s.frame.mint;
            s.hash = SHA_IV;
            s.phase = Phase.HashMint;
        } else if (s.phase == Phase.HashMint) {
            _hashMint(s, input);
        } else if (s.phase == Phase.Mint) {
            _verifyMint(ctx, gamma, s, input);
        } else if (s.phase == Phase.Transfer) {
            _verifyTransfer(ctx, s, input);
        } else if (s.phase == Phase.Unwind) {
            _unwind(s, input);
        } else {
            revert InvalidState();
        }
        if (s.phase != Phase.Complete) emit AxisBProgress(session, stateDigest(session, s));
    }

    function _head(uint256 p, uint256 end) private pure returns (uint256 m, uint256 a, uint256 q) {
        if (p >= end) C.fail(R.TRUNCATED);
        uint256 b = C.u8(p);
        uint256 ai = b & 31;
        if (ai > 27) C.fail(R.NON_CANONICAL);
        (m, a, q) = C.hd(p);
        if (q > end) C.fail(R.TRUNCATED);
        if (
            (ai == 24 && a < 24) || (ai == 25 && a <= 0xff) || (ai == 26 && a <= 0xffff)
                || (ai == 27 && a <= 0xffffffff)
        ) C.fail(R.NON_CANONICAL);
    }

    function _expect(uint256 p, uint256 end, uint256 maj, uint256 arg)
        private
        pure
        returns (uint256 q)
    {
        (uint256 m, uint256 a, uint256 next) = _head(p, end);
        if (m != maj || a != arg) C.fail(R.SHAPE);
        return next;
    }

    function _mintHead(Ctx memory ctx, Tok memory t, uint256 p, uint256 limit)
        private
        view
        returns (uint256 just, uint256 size)
    {
        uint256 q = _expect(p, limit, 6, TAG_MINT);
        q = _expect(q, limit, 4, 8);
        q = _expect(q, limit, 0, 2);
        (uint256 m, uint256 nw, uint256 afterNetwork) = _head(q, limit);
        if (m != 0 || nw == 0 || nw > type(uint16).max) C.fail(R.INT_RANGE);
        t.network = nw;
        bytes calldata pred;
        assembly ("memory-safe") {
            pred.offset := afterNetwork
            pred.length := sub(limit, afterNetwork)
        }
        uint256 afterPred = afterNetwork + COMMITMENTS.itemLength(pred, false, 6);
        if (_pred(ctx, t.mint.recipient, afterNetwork) != afterPred) revert InvalidState();
        uint256 afterSalt = _expect(afterPred, limit, 2, 32);
        if (limit - afterSalt < 32) C.fail(R.TRUNCATED);
        t.mint.mask = C.word(afterSalt);
        uint256 afterType = _expect(afterSalt + 32, limit, 2, 32);
        if (limit - afterType < 32) C.fail(R.TRUNCATED);
        t.ty = C.word(afterType);
        (m, size, just) = _head(afterType + 32, limit);
        if (m != 2 || size == 0) C.fail(R.MINT_REASON);
    }

    function _discover(Ctx memory ctx, State memory s, Input calldata input) private view {
        Frame memory f = s.frame;
        bytes calldata body = _read(input, f.start, f.end);
        uint256 p = _cdPos(body);
        uint256 limit = p + body.length;
        uint256 q = _expect(p, limit, 6, TAG_TOKEN);
        q = _expect(q, limit, 4, 3);
        q = _expect(q, limit, 0, 2);
        q = _expect(q, limit, 4, 2);
        f.mint = f.start + uint64(q - p);
        Tok memory header;
        (uint256 j, uint256 size) = _mintHead(ctx, header, q, limit);
        f.just = f.start + uint64(j - p);
        if (size > f.end - f.just) C.fail(R.MINT_REASON);
        f.justEnd = f.just + uint64(size);
        bytes calldata reason = _read(input, f.just, f.justEnd);
        p = _cdPos(reason);
        limit = p + reason.length;
        (uint256 m, uint256 tag, uint256 next) = _head(p, limit);
        if (m != 6) C.fail(R.MINT_REASON);
        if (tag == TAG_RECEIPT_BACKING) {
            s.frame = f;
            s.phase = Phase.Prepare;
        } else if (tag == TAG_SPLIT_JUSTIFICATION) {
            (uint256 array, uint256 count, uint256 afterArray) = _head(next, limit);
            if (array != 4 || count != 2) C.fail(R.SPLIT_JUSTIF);
            next = afterArray;
            s.stack = _push(f, s.stack);
            s.frame = Frame(f.just + uint64(next - p), f.justEnd, 0, 0, 0);
        } else {
            C.fail(R.MINT_REASON);
        }
    }

    function _parseMint(Ctx memory ctx, Frame memory f, Input calldata input)
        private
        view
        returns (Tok memory t, uint64 end)
    {
        bytes calldata prefix = _read(input, f.mint, f.end);
        uint256 p = _cdPos(prefix);
        (uint256 j, uint256 size) = _mintHead(ctx, t, p, p + prefix.length);
        if (f.mint + j - p != f.just || size != f.justEnd - f.just) revert InvalidState();
        bytes calldata tail = _read(input, f.justEnd, f.end);
        p = _cdPos(tail);
        uint256 depth = f.start == 2 ? 5 : 6;
        uint256 dataSize = COMMITMENTS.itemLength(tail, false, depth);
        uint256 dataEnd = p + dataSize;
        uint256 dlEnd = dataEnd + COMMITMENTS.itemLength(tail[dataSize:], false, depth);
        uint256 q;
        (t.mint.dataNull, t.mint.dataPos, t.mint.dataLen, q) = C.nullable(p);
        if (q != dataEnd) revert InvalidState();
        (t.mint.dlSet, t.mint.dl, q) = C.deadline(q);
        if (q != dlEnd) revert InvalidState();
        end = f.justEnd + uint64(q - p);
    }

    function _hashMint(State memory s, Input calldata input) private view {
        uint64 end = s.mintEnd;
        if (end - s.pos > 4096) end = s.pos + 4096;
        bytes calldata chunk = _read(input, s.pos, end);
        if (chunk.length != end - s.pos) revert W.InvalidWitness();
        s.hash = HASHER.advance(s.hash, s.pos - s.frame.mint, chunk, end == s.mintEnd);
        s.pos = end;
        if (end == s.mintEnd) s.phase = Phase.Mint;
    }

    function _allocation(Input calldata input, uint64 pos, uint64 end, Tok memory kid)
        private
        view
    {
        bytes calldata raw = _read(input, pos, end);
        if (raw.length != end - pos) revert W.InvalidWitness();
        uint256 p = _cdPos(raw);
        uint256 limit = p + raw.length;
        if (COMMITMENTS.itemLength(raw, false, 2) != raw.length) C.fail(R.SPLIT_PROOF_SHAPE);
        uint256 q = _expect(p, limit, 4, 1);
        (uint256 m, uint256 steps, uint256 first) = _head(q, limit);
        if (m != 4 || steps > 256) C.fail(R.SPLIT_PROOF_SHAPE);
        kid.proofPos = first;
        kid.proofSteps = steps;
        q = first;
        uint256 prev = 256;
        for (uint256 i; i < steps; ++i) {
            q = _expect(q, limit, 4, 3);
            (uint256 dm, uint256 depth, uint256 sibling) = _head(q, limit);
            if (dm != 0 || depth >= prev) C.fail(R.SPLIT_PROOF_SHAPE);
            prev = depth;
            uint256 value = _expect(sibling, limit, 2, 32);
            if (limit - value < 32) C.fail(R.TRUNCATED);
            (bool ok,, uint256 next) = C.amountOk(value + 32);
            if (!ok || next > limit) C.fail(R.SPLIT_PROOF_SHAPE);
            q = next;
        }
        if (q != limit) C.fail(R.SPLIT_PROOF_SHAPE);
    }

    function _unwind(State memory s, Input calldata input) private view {
        Frame memory f = input.frame;
        if (_push(f, input.tail) != s.stack || f.justEnd != s.frame.end || s.pos >= f.justEnd) {
            revert W.InvalidWitness();
        }
        Tok memory unused;
        _allocation(input, s.pos, f.justEnd, unused);
        s.splitProof = s.pos;
        s.frame = f;
        s.stack = input.tail;
        s.phase = Phase.Prepare;
    }

    function _check(
        Ctx memory ctx,
        State memory s,
        Step memory step,
        bytes32 sourceHash,
        bytes32 txHash,
        bool sourceMatches,
        address sourceKey,
        Input calldata input
    ) private view returns (bytes32 sid) {
        _require(
            ctx, sourceMatches && sourceHash == step.srcHash && txHash == step.txHash, R.CDMISMATCH
        );
        _require(ctx, step.cdDlSet == step.dlSet && step.cdDl == step.dl, R.DEADLINE_MISMATCH);
        _require(ctx, step.src.typ == 1, R.BURN_NOT_FINAL);
        _unlock(ctx, sourceKey, sourceHash, txHash, step.unlockPos, step.unlockLen);
        _require(ctx, !step.dlSet || step.t < step.dl, R.DEADLINE_EXPIRED);
        sid = _stateId(step.src, sourceHash);
        (bytes32 next, bool absent) =
            COMMITMENTS.insert(s.seen, sid, input.seenBitmap, input.siblings);
        _require(ctx, absent, R.REPEATED_SID);
        bytes32 leaf = sha256(abi.encodePacked(hex"825820", txHash, _cuint(step.t)));
        _inclusion(ctx, sid, leaf, step);
        _flush(ctx);
        s.seen = next;
    }

    function _verifyMint(Ctx memory ctx, bytes calldata gamma, State memory s, Input calldata input)
        private
        view
    {
        bool root = s.splitProof == 0;
        (Tok memory t, uint64 mintEnd) = _parseMint(ctx, s.frame, input);
        if (mintEnd != s.mintEnd) revert InvalidState();
        if (root) {
            bytes calldata signed = _read(input, s.frame.mint, mintEnd);
            if (signed.length != mintEnd - s.frame.mint) revert W.InvalidWitness();
            DEPOSIT.verify(gamma, signed);
        }
        Step memory m = t.mint;
        _require(ctx, t.network == ctx.cfg.network && m.recipient.typ == 1, R.MINT_SHAPE);
        _require(ctx, t.ty == ctx.cfg.ty, R.MINT_TYPE);
        (bool ok, uint256 amount) = _mintAmount(ctx.cfg.aid, m);
        _require(ctx, ok, R.MINT_DATA);
        t.amount = amount;
        bytes calldata tail = _read(input, mintEnd, s.frame.end);
        uint256 p = _cdPos(tail);
        uint256 end = p + COMMITMENTS.itemLength(tail, true, s.frame.start == 2 ? 4 : 5);
        if (_proof(ctx, m, p) != end) revert InvalidState();
        (uint256 major, uint256 count, uint256 afterHeader) = _head(end, p + tail.length);
        if (major != 4) C.fail(R.SHAPE);
        _require(ctx, count != 0, R.NO_TRANSFERS);
        t.id = sha256(abi.encodePacked(hex"825820", m.mask, _cuint(t.network)));
        uint256 k = uint256(
            sha256(abi.encodePacked(hex"82581a", "I_AM_UNIVERSAL_MINTER_FOR_", hex"5820", t.id))
        );
        if (k == 0 || k >= X.N) revert InvalidMinterScalar();
        bytes32 h0 = sha256(abi.encodePacked(hex"825820", t.id, hex"5820", TOKENID_SUFFIX));
        address minter = X.scalarAddress(k);
        _check(ctx, s, m, h0, s.hash, m.src.typ == 1 && m.src.key == minter, minter, input);
        if (!root) {
            _allocation(input, s.splitProof, s.frame.justEnd, t);
            Tok memory parent;
            parent.id = s.parentID;
            parent.amount = s.parentAmount;
            parent.manifestRoot = s.parentManifest;
            _splitEdge(ctx, parent, t);
        }
        _owner(s, m.recipient);
        s.state = _resultState(h0, t.id);
        s.id = t.id;
        s.amount = amount;
        s.pos = mintEnd + uint64(afterHeader - p);
        s.left = uint64(count);
        s.phase = Phase.Transfer;
        s.splitProof = 0;
        s.parentID = 0;
        s.parentAmount = 0;
        s.parentManifest = 0;
    }

    function _owner(State memory s, Pred memory p) private pure {
        s.owner = C.word(p.pos + 9);
        s.ownerTail = bytes1(C.word(p.pos + 41));
    }

    function _verifyTransfer(Ctx memory ctx, State memory s, Input calldata input) private {
        bytes calldata tail = _read(input, s.pos, s.frame.end);
        uint256 p = _cdPos(tail);
        uint256 end = p + COMMITMENTS.itemLength(tail, true, s.frame.start == 2 ? 4 : 5);
        Step memory tr;
        uint256 q = _expect(p, end, 4, 2);
        q = _transfer(ctx, tr, q);
        if (_proof(ctx, tr, q) != end || s.left == 0) revert InvalidState();
        bytes32 txHash = X.sha256Cd(tr.rawPos, tr.rawLen);
        bool same = tr.src.typ == 1 && C.word(tr.src.pos + 9) == s.owner
            && bytes1(C.word(tr.src.pos + 41)) == s.ownerTail;
        bytes32 sid = _check(ctx, s, tr, s.state, txHash, same, tr.src.key, input);
        s.pos += uint64(end - p);
        --s.left;
        if (s.left != 0) {
            _require(ctx, tr.recipient.typ == 1, R.BURN_NOT_FINAL);
            _require(ctx, tr.dataNull, R.TRANSFER_DATA);
            _owner(s, tr.recipient);
            s.state = _resultState(s.state, tr.mask);
            return;
        }
        Tok memory t;
        t.transfers = new Step[](1);
        t.transfers[0] = tr;
        t.amount = s.amount;
        if (s.stack != 0) {
            _splitBurn(ctx, t);
            s.parentID = s.id;
            s.parentAmount = s.amount;
            s.parentManifest = t.manifestRoot;
            s.phase = Phase.Unwind;
            return;
        }
        if (s.pos != s.frame.end) C.fail(R.TRAILING);
        (uint256 index, bytes32 asset, address recipient) = _return(ctx, t);
        s.phase = Phase.Complete;
        emit AxisBComplete(
            ctx.cfg.d, _eta(ctx.cfg.d, sid, txHash), uint64(index), asset, recipient, s.amount
        );
    }
}
// forge-lint: disable-end(unsafe-typecast,uninitialized-local,encode-packed-collision)
