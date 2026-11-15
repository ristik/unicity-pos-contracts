// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The linter's boolean-cst and uninitialized-local flag every `return (false, ...)` and zero-initialised accumulator; the
// precompile calls in loops are bounded by the input; typecasts are range-checked before narrowing; CBOR encodings are
// self-delimiting, so packed concatenation does not collide.
// forge-lint: disable-start(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)

import {INativeBridgeVerifierV2} from "../INativeBridgeVerifierV2.sol";
import {Nb2Rules as R} from "./Nb2Rules.sol";
import {Nb2Cbor as C} from "./Nb2Cbor.sol";
import {Nb2Crypto as X} from "./Nb2Crypto.sol";
import {Nb2ReceiptVerifier} from "./Nb2ReceiptVerifier.sol";

/// @notice The native bridge v2 token and receipt verifier (NB2-05, ristik/bft-core#1101; docs/design/native-bridge-v2.md
///         sections 6, 7, 8 and 11.2). Given Γ and a returned token part, it returns the authenticated verdict
///         (D, eta, a, asset, recipient, amount) or reverts with the section 14 rule that refuses it, in the frozen check
///         order. Every bridge rule is EVM bytecode here; native code is used only through the generic primitives: the
///         CERT_BATCH_V2 certificate batch at 0x0100 (each certificate's seal under the historical authority of its epoch) and
///         the RSMT membership at 0x0102, plus the standard precompiles.
///
///         Certificates are judged locally up to the seal root (encoding, network, structure, folds). Their authority verdict
///         (epoch entry, round interval, weighted quorum) is batched: claims are collected in check order and flushed in the
///         fewest calls before the first later refusal and before acceptance. A false call is re-checked one claim at a time
///         and the earliest failing claim refuses: QuorumNotMet for an aggregator certificate, DepositUC for the EVM one.
///
///         Stateless and without an owner. `admitsTestSet` selects the admitted (K, B) set: production admits only (64, 16), a
///         test build only K in {4, 8} x B in {2, 4}. It is an immutable, so the two builds have different code hashes.
contract NativeBridgeVerifierV2 is INativeBridgeVerifierV2 {
    /// @dev The 0x0100 batch halted or answered outside its ABI: never a rule, the call reverts.
    error CertBatchFailed();
    /// @dev The 0x0102 membership halted or answered outside its ABI.
    error MembershipFailed();
    /// @dev The universal minter scalar of a token ID is outside [1, n): no such ID is known (not a rule).
    error InvalidMinterScalar();

    address internal constant CERT_BATCH = address(0x0100);
    address internal constant MEMBERSHIP = address(0x0102);

    uint256 internal constant MAX_CONFIG_BYTES = 1024;
    uint256 internal constant MAX_JUSTIFICATION = 65536;
    uint256 internal constant MAX_DEPOSIT_UC = 16384;
    uint256 internal constant MAX_HEADER = 2048;
    uint256 internal constant MAX_RECEIPT_NODES = 65;
    uint256 internal constant MAX_BRANCH_NODE = 1024;
    uint256 internal constant MAX_LEAF_NODE = 49152;
    uint256 internal constant MAX_PROOF_UC = 24576;
    uint256 internal constant MAX_DEPOSIT = (1 << 56) - 1;
    uint256 internal constant MAX_SEGMENT = (1 << 48) - 1;
    uint256 internal constant MAX_INDEX = (1 << 32) - 1;
    uint256 internal constant QMAX_LIMIT = (1 << 144) - 1;
    /// @dev Claims per 0x0100 call and the request byte cap (ureth crates/unicity/b1 batch.rs).
    uint256 internal constant BATCH_CLAIMS = 16;
    uint256 internal constant BATCH_BYTES = 262144;

    uint256 internal constant TAG_PREDICATE = 39032;
    uint256 internal constant TAG_MINT = 39041;
    uint256 internal constant TAG_TRANSFER = 39045;
    uint256 internal constant TAG_CERTIFICATION = 39031;
    uint256 internal constant TAG_TOKEN = 39040;
    uint256 internal constant TAG_INCLUSION = 39033;
    uint256 internal constant TAG_SPLIT_JUSTIFICATION = 39044;
    uint256 internal constant TAG_RECEIPT_BACKING = 39051;

    bytes32 internal constant DEPOSIT_SECRET = keccak256("UNICITY_NB2_DEPOSIT_SECRET");
    bytes32 internal constant TOPIC_DEPOSITED =
        keccak256("Deposited(uint64,bytes32,uint256,bytes32,bytes)");
    bytes32 internal constant TOPIC_SEGMENT_SEALED =
        keccak256("SegmentSealed(uint64,bytes32,bytes32,bytes)");
    /// @dev a_UCT = H_U("unicity-nb2-asset:native-uct").
    bytes32 internal constant ASSET_UCT = sha256("unicity-nb2-asset:native-uct");
    /// @dev H_U("TOKENID"), the mint source hash suffix.
    bytes32 internal constant TOKENID_SUFFIX = sha256("TOKENID");

    bool public immutable admitsTestSet;
    /// @notice The receipt verifier this verifier created.
    Nb2ReceiptVerifier public immutable RECEIPTS;
    /// @notice The runtime code hash `RECEIPTS` must have. Both immutables are bytes of this contract's runtime, so its code
    ///         hash pins the helper's code, not only its address: every call checks EXTCODEHASH(RECEIPTS) against it first, and
    ///         a verifier whose runtime was installed by other initialization code cannot be paired with another helper.
    bytes32 public immutable RECEIPTS_CODEHASH;

    /// @dev The helper at RECEIPTS does not have the pinned code (not a rule).
    error HelperCodeMismatch();

    constructor(bool testSet_) {
        admitsTestSet = testSet_;
        RECEIPTS = new Nb2ReceiptVerifier();
        RECEIPTS_CODEHASH = keccak256(type(Nb2ReceiptVerifier).runtimeCode);
        if (address(RECEIPTS).codehash != RECEIPTS_CODEHASH) revert HelperCodeMismatch();
    }

    // ---- state of one call ----------------------------------------------------------------------------------------------

    struct Cfg {
        bytes32 d;
        uint256 network;
        uint256 evmPartition;
        uint256 evmShardPos;
        uint256 evmShardLen;
        uint256 aggPartition;
        address vault;
        bytes32 ty;
        bytes32 aid;
        uint256 k;
    }

    struct Claim {
        bytes data;
        bool evm;
    }

    struct Ctx {
        Cfg cfg;
        Claim[] claims;
        uint256 nClaims;
        uint256 flushed;
        bytes32[] claimIds; // open-addressing set of claim digests already flushed
        bytes32[] sids; // open-addressing set of the lineage's state IDs
        bytes32[] keyH; // compressed key cache: keccak(key33) -> address
        address[] keyA;
        uint256[4] meter; // instrumentation of test harnesses (gas metering); unused here
    }

    /// @dev A predicate: its exact tagged bytes, its type and, for a signature predicate, the key's address; for a burn, its
    ///      32-byte reason hash.
    struct Pred {
        uint256 pos;
        uint256 len;
        uint256 typ;
        address key;
        bytes32 burn;
    }

    /// @dev One certified transaction (the mint or a transfer) with its inclusion proof.
    struct Step {
        uint256 rawPos;
        uint256 rawLen;
        Pred recipient;
        bytes32 mask; // a transfer's mask; the mint's salt
        bool dataNull;
        uint256 dataPos;
        uint256 dataLen;
        bool dlSet;
        uint256 dl;
        Pred src;
        bytes32 srcHash;
        bytes32 txHash;
        bool cdDlSet;
        uint256 cdDl;
        uint256 unlockPos;
        uint256 unlockLen;
        uint256 t;
        uint256 pathPos;
        uint256 pathLen;
        uint256 ucPos;
        uint256 ucLen;
    }

    struct Tok {
        uint256 network;
        bytes32 ty;
        bool justNull;
        uint256 justPos;
        uint256 justLen;
        Step mint;
        Step[] transfers;
        // split reason of this token (when its mint reason is a SplitJ): the allocation proof
        uint256 proofPos;
        uint256 proofSteps;
        // verified
        bytes32 id;
        uint256 amount;
        bytes32 manifestRoot;
        bytes32 lastSid;
        bytes32 lastTx;
    }

    // ---- entry point -----------------------------------------------------------------------------------------------------

    /// @inheritdoc INativeBridgeVerifierV2
    function verifyReturn(bytes calldata gamma, bytes calldata evidence)
        external
        view
        returns (
            bytes32 domain,
            bytes32 eta,
            uint64 minSegment,
            bytes32 asset,
            address recipient,
            uint256 amount
        )
    {
        Ctx memory ctx = _newCtx();
        return _verify(ctx, gamma, evidence);
    }

    function _newCtx() internal view returns (Ctx memory ctx) {
        if (address(RECEIPTS).codehash != RECEIPTS_CODEHASH) revert HelperCodeMismatch();
        ctx.keyH = new bytes32[](128);
        ctx.keyA = new address[](128);
    }

    /// @dev The relation in its frozen order (section 11.2).
    function _verify(Ctx memory ctx, bytes calldata gamma, bytes calldata evidence)
        internal
        view
        returns (
            bytes32 domain,
            bytes32 eta,
            uint64 minSegment,
            bytes32 asset,
            address recipient,
            uint256 amount
        )
    {
        // 1. Γ, then D.
        ctx.cfg = _config(gamma);
        // 2. evidence = C(1, Token).
        Tok memory part = _evidence(ctx, evidence);
        // 3. The walk from the part to the root.
        Tok[] memory chain = _walk(ctx, part);
        uint256 depth = chain.length - 1;
        _initCtx(ctx, chain);
        // 4. The root's J.
        _rootMint(ctx, chain[depth]);
        // 5. Root first, every token of the walk.
        for (uint256 i = depth + 1; i != 0;) {
            --i;
            _level(ctx, chain[i]);
            if (i < depth) _splitEdge(ctx, chain[i + 1], chain[i]);
            if (i > 0) _splitBurn(ctx, chain[i]);
        }
        // 6. The part's terminal burn.
        uint256 a;
        (a, asset, recipient) = _return(ctx, part);
        // Every certificate's authority before acceptance.
        _flush(ctx);
        // 7. btid and eta.
        domain = ctx.cfg.d;
        eta = _eta(domain, part.lastSid, part.lastTx);
        // forge-lint: disable-next-line(unsafe-typecast)
        minSegment = uint64(a);
        amount = part.amount;
    }

    // ---- refusals ---------------------------------------------------------------------------------------------------------

    /// @dev A refusal raised after the first certificate claim: the pending claims are judged first, so an earlier
    ///      certificate's authority failure classifies before it.
    function _fail(Ctx memory ctx, bytes4 rule) internal view {
        _flush(ctx);
        C.fail(rule);
    }

    function _require(Ctx memory ctx, bool ok, bytes4 rule) internal view {
        if (!ok) _fail(ctx, rule);
    }

    // ---- 1. Γ ---------------------------------------------------------------------------------------------------------

    function _config(bytes calldata gamma) internal view returns (Cfg memory c) {
        uint256 p = _cdPos(gamma);
        uint256 end = p + gamma.length;
        if (gamma.length > MAX_CONFIG_BYTES || C.scan(p, end, false) != 0) C.fail(R.CONFIG_SHAPE);
        (uint256 mj, uint256 n, uint256 q) = C.hd(p);
        if (mj != 4 || n != 19) C.fail(R.CONFIG_SHAPE);
        bool ok = _literal(q, "UNICITY_NB2_CFG");
        q = C.skip(q);
        (ok,, q) = _cfgUint(ok, q, 1, 1);
        (ok, c.network, q) = _cfgUint(ok, q, 1, type(uint16).max);
        (ok,, q) = _cfgFixed(ok, q, 32); // rootGenesis32: the chain's own seal registry is this history
        (ok,, q) = _cfgFixed(ok, q, 32); // executionGenesis32
        (ok,, q) = _cfgUint(ok, q, 1, type(uint64).max); // chainId
        (ok, c.evmPartition, q) = _cfgUint(ok, q, 1, type(uint32).max);
        if (ok) {
            (uint256 smj, uint256 sl, uint256 sp) = C.hd(q);
            ok = smj == 2 && _canonicalShard(sp, sl);
            c.evmShardPos = sp;
            c.evmShardLen = sl;
            q = sp + sl;
        }
        (ok, c.aggPartition, q) = _cfgUint(ok, q, 1, type(uint32).max);
        ok = ok && c.aggPartition != c.evmPartition;
        uint256 dp;
        (ok, dp, q) = _cfgFixed(ok, q, 20);
        if (ok) c.vault = address(bytes20(C.word(dp)));
        (ok,, q) = _cfgFixed(ok, q, 32); // asset32: the vault constructor checks the derivations
        (ok, dp, q) = _cfgFixed(ok, q, 32);
        if (ok) c.ty = C.word(dp);
        (ok, dp, q) = _cfgFixed(ok, q, 32);
        if (ok) c.aid = C.word(dp);
        (ok,, q) = _cfgFixed(ok, q, 32); // semanticProfileHash32
        (ok,, q) = _cfgFixed(ok, q, 20); // verifier20
        (ok,, q) = _cfgFixed(ok, q, 32); // verifierCodeHash32
        uint256 k;
        uint256 b;
        (ok, k, q) = _cfgUint(ok, q, 2, 64);
        (ok, b, q) = _cfgUint(ok, q, 2, 64);
        ok = ok && _admits(k, b);
        if (ok) {
            uint256 qmax;
            (ok, qmax,) = C.amountOk(q);
            ok = ok && qmax <= QMAX_LIMIT;
        }
        if (!ok) C.fail(R.CONFIG_SHAPE);
        c.k = k;
        c.d = X.sha256Cd(p, gamma.length);
    }

    function _cdPos(bytes calldata b) internal pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := b.offset
        }
    }

    function _literal(uint256 q, string memory s) internal pure returns (bool) {
        (uint256 mj, uint256 len, uint256 dp) = C.hd(q);
        bytes memory lit = bytes(s);
        if (mj != 2 || len != lit.length) return false;
        bytes32 a;
        bytes32 w;
        assembly ("memory-safe") {
            a := mload(add(lit, 32))
            w := calldataload(dp)
        }
        uint256 mask = type(uint256).max << (8 * (32 - len));
        return (a & bytes32(mask)) == (w & bytes32(mask));
    }

    function _cfgUint(bool ok, uint256 q, uint256 lo, uint256 hi)
        internal
        pure
        returns (bool, uint256 v, uint256)
    {
        if (!ok) return (false, 0, q);
        (uint256 mj, uint256 arg, uint256 next) = C.hd(q);
        return (mj == 0 && arg >= lo && arg <= hi, arg, next);
    }

    function _cfgFixed(bool ok, uint256 q, uint256 n)
        internal
        pure
        returns (bool, uint256 dp, uint256)
    {
        if (!ok) return (false, 0, q);
        (uint256 mj, uint256 len, uint256 d) = C.hd(q);
        return (mj == 2 && len == n, d, d + len);
    }

    function _canonicalShard(uint256 p, uint256 len) internal pure returns (bool) {
        if (len == 0 || len > 33) return false;
        uint256 last = C.u8(p + len - 1);
        if (last == 0) return false;
        uint256 tz;
        while ((last >> tz) & 1 == 0) ++tz;
        return 8 * len - tz - 1 <= 256;
    }

    function _admits(uint256 k, uint256 b) internal view returns (bool) {
        if (k & (k - 1) != 0 || b & (b - 1) != 0 || b > k) return false;
        if (admitsTestSet) return (k == 4 || k == 8) && (b == 2 || b == 4);
        return k == 64 && b == 16;
    }

    // ---- 2. evidence and the SDK token wire ---------------------------------------------------------------------------

    function _evidence(Ctx memory ctx, bytes calldata evidence) internal view returns (Tok memory) {
        uint256 p = _cdPos(evidence);
        bytes4 e = C.scan(p, p + evidence.length, true);
        if (e != 0) C.fail(e);
        (uint256 mj, uint256 n, uint256 q) = C.hd(p);
        if (mj != 4 || n != 2) C.fail(R.EVIDENCE_SHAPE);
        (uint256 vmj, uint256 v,) = C.hd(q);
        uint256 tp = C.skip(q);
        (uint256 tmj,,) = C.hd(tp);
        if (tmj != 6) C.fail(R.EVIDENCE_SHAPE);
        if (vmj != 0 || v != 1) C.fail(R.EVIDENCE_SHAPE);
        return _token(ctx, tp);
    }

    function _token(Ctx memory ctx, uint256 p) internal view returns (Tok memory t) {
        uint256 q = C.tagged(p, TAG_TOKEN);
        q = C.array(q, 3);
        uint256 g = C.version(q, 2);
        uint256 gq = C.array(g, 2);
        (uint256 tmj, uint256 n, uint256 tq) = C.hd(C.skip(g));
        if (tmj != 4) C.fail(R.SHAPE);
        q = _mint(ctx, t, gq);
        _proof(ctx, t.mint, q);
        t.transfers = new Step[](n);
        for (uint256 i; i < n; ++i) {
            uint256 pq = C.array(tq, 2);
            Step memory s = t.transfers[i];
            q = _transfer(ctx, s, pq);
            tq = _proof(ctx, s, q);
        }
    }

    function _pred(Ctx memory ctx, Pred memory pr, uint256 p) internal view returns (uint256) {
        uint256 c = C.tagged(p, TAG_PREDICATE);
        c = C.array(c, 3);
        (uint256 mj0, uint256 a0,) = C.hd(c);
        uint256 q1 = C.skip(c);
        (uint256 mj1, uint256 l1, uint256 d1) = C.hd(q1);
        uint256 q2 = C.skip(q1);
        (uint256 mj2, uint256 l2, uint256 d2) = C.hd(q2);
        uint256 end = C.skip(q2);
        if (mj0 != 0 || mj1 != 2 || mj2 != 2) C.fail(R.SHAPE);
        if (a0 != 1) C.fail(R.PREDICATE);
        uint256 code = l1 == 1 ? C.u8(d1) : 0;
        if (code != 1 && code != 2) C.fail(R.PREDICATE);
        pr.pos = p;
        pr.len = end - p;
        pr.typ = code;
        if (code == 1) {
            if (l2 != 33) C.fail(R.PREDICATE);
            pr.key = _key(ctx, d2);
            if (pr.key == address(0)) C.fail(R.PREDICATE);
        } else {
            if (l2 != 32) C.fail(R.PREDICATE);
            pr.burn = C.word(d2);
        }
        return end;
    }

    /// @dev The address of a compressed key, through the call's cache (zero for a key off the curve).
    function _key(Ctx memory ctx, uint256 kp) internal view returns (address a) {
        bytes32 h = X.keccakCd(kp, 33);
        uint256 mask = ctx.keyH.length - 1;
        uint256 i = uint256(h) & mask;
        for (uint256 probe; probe <= mask; ++probe) {
            bytes32 slot = ctx.keyH[i];
            if (slot == h) return ctx.keyA[i];
            if (slot == 0) {
                a = X.keyAddress(kp);
                ctx.keyH[i] = h;
                ctx.keyA[i] = a;
                return a;
            }
            i = (i + 1) & mask;
        }
        return X.keyAddress(kp);
    }

    function _mint(Ctx memory ctx, Tok memory t, uint256 p) internal view returns (uint256 q) {
        Step memory s = t.mint;
        q = C.tagged(p, TAG_MINT);
        q = C.array(q, 8);
        q = C.version(q, 2);
        (t.network, q) = C.uintIn(q, 1, type(uint16).max);
        q = _pred(ctx, s.recipient, q);
        (s.mask, q) = C.bytes32At(q);
        (t.ty, q) = C.bytes32At(q);
        (t.justNull, t.justPos, t.justLen, q) = C.nullable(q);
        (s.dataNull, s.dataPos, s.dataLen, q) = C.nullable(q);
        (s.dlSet, s.dl, q) = C.deadline(q);
        s.rawPos = p;
        s.rawLen = q - p;
    }

    function _transfer(Ctx memory ctx, Step memory s, uint256 p) internal view returns (uint256 q) {
        q = C.tagged(p, TAG_TRANSFER);
        q = C.array(q, 5);
        q = C.version(q, 2);
        q = _pred(ctx, s.recipient, q);
        (s.mask, q) = C.bytes32At(q);
        (s.dataNull, s.dataPos, s.dataLen, q) = C.nullable(q);
        (s.dlSet, s.dl, q) = C.deadline(q);
        s.rawPos = p;
        s.rawLen = q - p;
    }

    function _proof(Ctx memory ctx, Step memory s, uint256 p) internal view returns (uint256 q) {
        q = C.tagged(p, TAG_INCLUSION);
        q = C.array(q, 5);
        q = C.version(q, 1);
        q = C.tagged(q, TAG_CERTIFICATION);
        q = C.array(q, 6);
        q = C.version(q, 2);
        q = _pred(ctx, s.src, q);
        (s.srcHash, q) = C.bytes32At(q);
        (s.txHash, q) = C.bytes32At(q);
        (s.cdDlSet, s.cdDl, q) = C.deadline(q);
        (s.unlockPos, s.unlockLen, q) = C.bstr(q);
        (s.t, q) = C.uintIn(q, 0, type(uint64).max);
        (s.pathPos, s.pathLen, q) = C.bstr(q);
        if (s.pathLen < 32 || s.pathLen % 32 != 0) C.fail(R.LENGTH);
        if (s.pathLen != 32 + 32 * _popcount(uint256(C.word(s.pathPos)))) C.fail(R.LENGTH);
        (uint256 mj,,) = C.hd(q);
        if (mj != 6) C.fail(R.SHAPE);
        uint256 end = C.skip(q);
        if (end - q > MAX_PROOF_UC) C.fail(R.INPUT_TOO_LARGE);
        s.ucPos = q;
        s.ucLen = end - q;
        q = end;
    }

    function _popcount(uint256 x) internal pure returns (uint256) {
        x = x - ((x >> 1) & 0x5555555555555555555555555555555555555555555555555555555555555555);
        x = (x & 0x3333333333333333333333333333333333333333333333333333333333333333)
            + ((x >> 2) & 0x3333333333333333333333333333333333333333333333333333333333333333);
        x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
        x = (x & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
            + ((x >> 8) & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff);
        unchecked {
            return (x * 0x0001000100010001000100010001000100010001000100010001000100010001) >> 240;
        }
    }

    // ---- 3. the walk --------------------------------------------------------------------------------------------------

    function _walk(Ctx memory ctx, Tok memory part) internal view returns (Tok[] memory chain) {
        chain = new Tok[](8);
        chain[0] = part;
        uint256 n = 1;
        Tok memory cur = part;
        while (true) {
            (bool ok, uint256 tag) = _reasonTag(cur);
            if (ok && tag == TAG_RECEIPT_BACKING) break;
            if (!ok || tag != TAG_SPLIT_JUSTIFICATION) C.fail(R.MINT_REASON);
            Tok memory parent = _splitJustification(ctx, cur);
            if (n == chain.length) {
                Tok[] memory grown = new Tok[](2 * n);
                for (uint256 i; i < n; ++i) {
                    grown[i] = chain[i];
                }
                chain = grown;
            }
            chain[n++] = parent;
            cur = parent;
        }
        assembly ("memory-safe") {
            mstore(chain, n)
        }
    }

    /// @dev The tag number at the head of a mint reason, without scanning it.
    function _reasonTag(Tok memory t) internal pure returns (bool, uint256) {
        if (t.justNull || t.justLen == 0) return (false, 0);
        uint256 p = t.justPos;
        uint256 end = p + t.justLen;
        uint256 b = C.u8(p);
        uint256 ai = b & 31;
        uint256 arg = ai;
        if (ai >= 24) {
            if (ai > 27) return (false, 0);
            uint256 n = 1 << (ai - 24);
            if (end - p - 1 < n) return (false, 0);
            assembly ("memory-safe") {
                arg := shr(sub(256, shl(3, n)), calldataload(add(p, 1)))
            }
            if (
                (ai == 24 && arg < 24) || (ai == 25 && arg <= 0xff) || (ai == 26 && arg <= 0xffff)
                    || (ai == 27 && arg <= 0xffffffff)
            ) return (false, 0);
        }
        if (b >> 5 != 6) return (false, 0);
        return (true, arg);
    }

    /// @dev SplitJ = tag(39044, [ParentToken, [Proof]]): SplitJustif, SplitProofCount, SplitProofShape, then the parent's
    ///      wire rules.
    function _splitJustification(Ctx memory ctx, Tok memory child)
        internal
        view
        returns (Tok memory parent)
    {
        uint256 p = child.justPos;
        if (C.scan(p, p + child.justLen, true) != 0) C.fail(R.SPLIT_JUSTIF);
        (,, uint256 c) = C.hd(p); // the tag 39044 (checked by the caller)
        (uint256 mj, uint256 n, uint256 k0) = C.hd(c);
        if (mj != 4 || n != 2) C.fail(R.SPLIT_JUSTIF);
        (uint256 pmj,,) = C.hd(k0);
        uint256 k1 = C.skip(k0);
        (uint256 amj, uint256 an, uint256 a0) = C.hd(k1);
        if (pmj != 6 || amj != 4) C.fail(R.SPLIT_JUSTIF);
        if (an != 1) C.fail(R.SPLIT_PROOF_COUNT);
        // decodeSumProof
        (uint256 smj, uint256 steps, uint256 sq) = C.hd(a0);
        if (smj != 4 || steps > 256) C.fail(R.SPLIT_PROOF_SHAPE);
        child.proofPos = sq;
        child.proofSteps = steps;
        uint256 prev = 256;
        for (uint256 i; i < steps; ++i) {
            (uint256 emj, uint256 en, uint256 eq) = C.hd(sq);
            if (emj != 4 || en != 3) C.fail(R.SPLIT_PROOF_SHAPE);
            (uint256 dmj, uint256 d, uint256 hq) = C.hd(eq);
            if (dmj != 0 || d > 255 || d >= prev) C.fail(R.SPLIT_PROOF_SHAPE);
            prev = d;
            (uint256 hmj, uint256 hl, uint256 hd) = C.hd(hq);
            if (hmj != 2 || hl != 32) C.fail(R.SPLIT_PROOF_SHAPE);
            (bool ok,, uint256 next) = C.amountOk(hd + 32);
            if (!ok) C.fail(R.SPLIT_PROOF_SHAPE);
            sq = next;
        }
        parent = _token(ctx, k0);
    }

    // ---- claims and the certificate batch ---------------------------------------------------------------------------

    function _initCtx(Ctx memory ctx, Tok[] memory chain) internal pure {
        uint256 steps;
        for (uint256 i; i < chain.length; ++i) {
            steps += 1 + chain[i].transfers.length;
        }
        ctx.claims = new Claim[](steps + 1);
        ctx.claimIds = new bytes32[](_pow2(2 * (steps + 1)));
        ctx.sids = new bytes32[](_pow2(2 * steps));
    }

    function _pow2(uint256 n) internal pure returns (uint256 p) {
        p = 16;
        while (p < n) p <<= 1;
    }

    /// @dev Judges every pending claim's authority: the distinct new claims in check order, in the fewest calls of at most
    ///      16 claims and 256 KiB, balanced. A false call is re-checked one claim at a time; the earliest failing claim refuses.
    function _flush(Ctx memory ctx) internal view {
        uint256 from = ctx.flushed;
        uint256 to = ctx.nClaims;
        if (from == to) return;
        ctx.flushed = to;
        uint256[] memory idx = new uint256[](to - from);
        uint256 m;
        for (uint256 i = from; i < to; ++i) {
            if (_newClaim(ctx, keccak256(ctx.claims[i].data))) idx[m++] = i;
        }
        if (m == 0) return;
        uint256 calls = (m + BATCH_CLAIMS - 1) / BATCH_CLAIMS;
        uint256 per = (m + calls - 1) / calls;
        uint256 s;
        while (s < m) {
            uint256 e = s;
            uint256 bytes_ = 4;
            while (e < m && e - s < per && bytes_ + ctx.claims[idx[e]].data.length <= BATCH_BYTES) {
                bytes_ += ctx.claims[idx[e]].data.length;
                ++e;
            }
            if (e == s) ++e; // a single claim always fits the cap (a UC is at most 24 KiB)
            if (!_batch(ctx, idx, s, e)) {
                for (uint256 i = s; i < e; ++i) {
                    if (!_batch(ctx, idx, i, i + 1)) {
                        C.fail(ctx.claims[idx[i]].evm ? R.DEPOSIT_UC : R.QUORUM_NOT_MET);
                    }
                }
                C.fail(R.QUORUM_NOT_MET); // only a combination failed: two claims for one shard under one seal
            }
            s = e;
        }
    }

    function _newClaim(Ctx memory ctx, bytes32 h) internal pure returns (bool) {
        if (h == 0) h = bytes32(uint256(1));
        uint256 mask = ctx.claimIds.length - 1;
        uint256 i = uint256(h) & mask;
        while (true) {
            bytes32 slot = ctx.claimIds[i];
            if (slot == h) return false;
            if (slot == 0) {
                ctx.claimIds[i] = h;
                return true;
            }
            i = (i + 1) & mask;
        }
        return false;
    }

    /// @dev One CERT_BATCH_V2 call over claims idx[s..e): version 2, flags 0, count, the packed claims.
    function _batch(Ctx memory ctx, uint256[] memory idx, uint256 s, uint256 e)
        internal
        view
        returns (bool valid)
    {
        uint256 total = 4;
        for (uint256 i = s; i < e; ++i) {
            total += ctx.claims[idx[i]].data.length;
        }
        bytes memory req = new bytes(total);
        uint256 w;
        uint256 count = e - s;
        assembly ("memory-safe") {
            w := add(req, 32)
            mstore(w, or(shl(248, 2), shl(224, count)))
        }
        w += 4;
        for (uint256 i = s; i < e; ++i) {
            bytes memory c = ctx.claims[idx[i]].data;
            uint256 l = c.length;
            assembly ("memory-safe") {
                mcopy(w, add(c, 32), l)
            }
            w += l;
        }
        return _certBatch(ctx, req);
    }

    /// @dev The CERT_BATCH_V2 call: exactly abi.encode(uint256(2), bool).
    function _certBatch(Ctx memory, bytes memory req) internal view virtual returns (bool) {
        (bool ok, uint256 version, uint256 v) = _native(CERT_BATCH, req);
        if (!ok || version != 2 || v > 1) revert CertBatchFailed();
        return v == 1;
    }

    /// @dev A STATICCALL forwarding all gas whose answer must be exactly two words.
    function _native(address target, bytes memory req)
        internal
        view
        returns (bool ok, uint256 w0, uint256 w1)
    {
        assembly ("memory-safe") {
            ok := staticcall(gas(), target, add(req, 32), mload(req), 0, 64)
            switch eq(returndatasize(), 64)
            case 1 {
                w0 := mload(0)
                w1 := mload(32)
            }
            default { ok := 0 }
        }
    }

    /// @dev RSMT membership of (key, value) under root through 0x0102: version 1, flags 0, count 1, root, key, u32 length,
    ///      value, bitmap and siblings.
    function _member(
        Ctx memory ctx,
        bytes32 root,
        bytes32 key,
        bytes32 value,
        uint256 pathPos,
        uint256 pathLen
    ) internal view returns (bool) {
        uint256 total = 4 + 32 + 32 + 4 + 32 + pathLen;
        bytes memory req = new bytes(total);
        assembly ("memory-safe") {
            let w := add(req, 32)
            mstore(w, shl(224, 0x01000001))
            mstore(add(w, 4), root)
            mstore(add(w, 36), key)
            mstore(add(w, 68), shl(224, 32))
            mstore(add(w, 72), value)
            calldatacopy(add(w, 104), pathPos, pathLen)
        }
        return _membership(ctx, req);
    }

    /// @dev The 0x0102 call: exactly abi.encode(uint256(1), bool).
    function _membership(Ctx memory, bytes memory req) internal view virtual returns (bool) {
        (bool ok, uint256 version, uint256 v) = _native(MEMBERSHIP, req);
        if (!ok || version != 1 || v > 1) revert MembershipFailed();
        return v == 1;
    }

    // ---- 4. the root's J and the receipt -----------------------------------------------------------------------------

    struct Receipt {
        uint256 ucPos;
        uint256 ucLen;
        uint256 headerPos;
        uint256 headerLen;
        uint256 txIndex;
        uint256 logIndex;
        uint256[] nodePos;
        uint256[] nodeLen;
    }

    /// @dev DepositProof = [1, b(evmUC), b(headerRLP), txIndex, logIndex, [b(receiptNodeRLP), ...]].
    function _depositProof(uint256 p) internal pure returns (Receipt memory r, uint256 q) {
        q = C.array(p, 6);
        q = C.version(q, 1);
        (r.ucPos, r.ucLen, q) = C.bstr(q);
        if (r.ucLen > MAX_DEPOSIT_UC) C.fail(R.INPUT_TOO_LARGE);
        (r.headerPos, r.headerLen, q) = C.bstr(q);
        if (r.headerLen > MAX_HEADER) C.fail(R.INPUT_TOO_LARGE);
        (r.txIndex, q) = C.uintIn(q, 0, MAX_INDEX);
        (r.logIndex, q) = C.uintIn(q, 0, MAX_INDEX);
        uint256 n;
        (n, q) = C.anyArray(q);
        if (n > MAX_RECEIPT_NODES) C.fail(R.INPUT_TOO_LARGE);
        r.nodePos = new uint256[](n);
        r.nodeLen = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            (r.nodePos[i], r.nodeLen[i], q) = C.bstr(q);
            if (r.nodeLen[i] > (i == n - 1 ? MAX_LEAF_NODE : MAX_BRANCH_NODE)) {
                C.fail(R.INPUT_TOO_LARGE);
            }
        }
    }

    /// @dev Section 6.2 steps 2 to 5 up to the emitter (VerifyReceiptLog), in the receipt verifier; the EVM UC's claim is
    ///      registered before any later rule is raised. Returns the selected log's topics and data.
    function _receiptLog(Ctx memory ctx, Receipt memory r)
        internal
        view
        returns (bytes32[] memory topics, bytes memory data)
    {
        Cfg memory c = ctx.cfg;
        bytes[] memory nodes = new bytes[](r.nodePos.length);
        for (uint256 i; i < nodes.length; ++i) {
            nodes[i] = _cdSlice(r.nodePos[i], r.nodeLen[i]);
        }
        Nb2ReceiptVerifier.Env memory env = Nb2ReceiptVerifier.Env(
            c.network, c.evmPartition, _cdSlice(c.evmShardPos, c.evmShardLen), c.vault
        );
        bytes4 rule;
        bytes memory claim;
        (rule, claim, topics, data) = RECEIPTS.receiptLog(
            env,
            _cdSlice(r.ucPos, r.ucLen),
            _cdSlice(r.headerPos, r.headerLen),
            r.txIndex,
            r.logIndex,
            nodes
        );
        if (claim.length != 0) ctx.claims[ctx.nClaims++] = Claim(claim, true);
        if (rule != 0) _fail(ctx, rule);
    }

    function _rootMint(Ctx memory ctx, Tok memory root) internal view {
        uint256 jp = root.justPos;
        uint256 jl = root.justLen;
        if (jl > MAX_JUSTIFICATION) C.fail(R.INPUT_TOO_LARGE);
        bytes4 e = C.scan(jp, jp + jl, false);
        if (e != 0) C.fail(e);
        uint256 q = C.tagged(jp, TAG_RECEIPT_BACKING);
        q = C.array(q, 5);
        q = C.version(q, 1);
        bytes32 jd;
        (jd, q) = C.bytes32At(q);
        uint256 n;
        (n, q) = C.uintIn(q, 1, MAX_DEPOSIT);
        bytes32 rr;
        (rr, q) = C.bytes32At(q);
        (Receipt memory r,) = _depositProof(q);
        bytes32 d = ctx.cfg.d;
        if (jd != d) C.fail(R.MINT_DOMAIN);
        (bytes32[] memory topics, bytes memory data) = _receiptLog(ctx, r);
        _require(
            ctx,
            topics.length == 2 && topics[0] == TOPIC_DEPOSITED && uint256(topics[1]) == n,
            R.LOG_TOPICS
        );
        _require(ctx, data.length == 224, R.LOG_DATA);
        uint256 v = uint256(_mword(data, 32));
        bool shape = _mword(data, 0) == jd && v != 0 && uint256(_mword(data, 96)) == 0x80
            && uint256(_mword(data, 128)) == 42
            && uint256(_mword(data, 192)) & ((1 << 176) - 1) == 0;
        _require(ctx, shape, R.LOG_DATA);
        _require(
            ctx,
            keccak256(abi.encodePacked(DEPOSIT_SECRET, jd, rr)) == _mword(data, 64),
            R.SECRET_OPENING
        );
        Step memory m = root.mint;
        _require(ctx, m.mask == _depositSalt(d, n, rr), R.MINT_SALT);
        _require(ctx, root.ty == ctx.cfg.ty, R.MINT_TYPE);
        bool owner = m.recipient.len == 42;
        if (owner) {
            bytes32 h;
            assembly ("memory-safe") {
                h := keccak256(add(data, 192), 42)
            }
            owner = h == X.keccakCd(m.recipient.pos, 42);
        }
        _require(ctx, owner, R.MINT_OWNER);
        _require(ctx, _isValueData(ctx.cfg.aid, m, v), R.MINT_DATA);
    }

    function _mword(bytes memory b, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), off))
        }
    }

    function _eqCd(uint256 a, uint256 b, uint256 len) internal pure returns (bool) {
        return X.keccakCd(a, len) == X.keccakCd(b, len);
    }

    /// @dev salt_n = H_U(C(b("UNICITY_NB2_DEPOSIT_SALT"), b(D), n, b(r))).
    function _depositSalt(bytes32 d, uint256 n, bytes32 rr) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                hex"845818", "UNICITY_NB2_DEPOSIT_SALT", hex"5820", d, _cuint(n), hex"5820", rr
            )
        );
    }

    /// @dev The mint data is exactly tag(39050, [1, [[b(aid), b(v)]], null]).
    function _isValueData(bytes32 aid, Step memory m, uint256 v) internal pure returns (bool) {
        if (m.dataNull) return false;
        bytes memory want = abi.encodePacked(hex"d9988a830181825820", aid, _amountItem(v), hex"f6");
        return m.dataLen == want.length && keccak256(want) == X.keccakCd(m.dataPos, m.dataLen);
    }

    // ---- CBOR encoders of the hashed structures ----------------------------------------------------------------------

    function _cuint(uint256 n) internal pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(uint8(n));
        if (n <= 0xff) return abi.encodePacked(uint8(24), uint8(n));
        if (n <= 0xffff) return abi.encodePacked(uint8(25), uint16(n));
        if (n <= 0xffffffff) return abi.encodePacked(uint8(26), uint32(n));
        return abi.encodePacked(uint8(27), uint64(n));
    }

    function _bhead(uint256 n) internal pure returns (bytes memory b) {
        b = _cuint(n);
        b[0] = bytes1(uint8(b[0]) | 0x40);
    }

    function _amountItem(uint256 v) internal pure returns (bytes memory) {
        uint256 n;
        for (uint256 t = v; t != 0; t >>= 8) {
            ++n;
        }
        bytes memory out = new bytes(n + 1);
        out[0] = bytes1(uint8(0x40 + n));
        for (uint256 i; i < n; ++i) {
            out[n - i] = bytes1(uint8(v >> (8 * i)));
        }
        return out;
    }

    // ---- 5. every token of the walk ----------------------------------------------------------------------------------

    function _level(Ctx memory ctx, Tok memory t) internal view {
        Cfg memory c = ctx.cfg;
        Step memory m = t.mint;
        _require(ctx, t.network == c.network && m.recipient.typ == 1, R.MINT_SHAPE);
        _require(ctx, t.ty == c.ty, R.MINT_TYPE);
        (bool ok, uint256 amount) = _mintAmount(c.aid, m);
        _require(ctx, ok, R.MINT_DATA);
        t.amount = amount;
        _require(ctx, t.transfers.length != 0, R.NO_TRANSFERS);
        t.id = sha256(abi.encodePacked(hex"825820", m.mask, _cuint(t.network)));
        uint256 k = uint256(
            sha256(abi.encodePacked(hex"82581a", "I_AM_UNIVERSAL_MINTER_FOR_", hex"5820", t.id))
        );
        if (k == 0 || k >= X.N) revert InvalidMinterScalar();
        bytes32 h0 = sha256(abi.encodePacked(hex"825820", t.id, hex"5820", TOKENID_SUFFIX));
        // The mint: its source is the universal minter's signature predicate.
        address minter = X.scalarAddress(k);
        _step(ctx, m, h0, m.src.typ == 1 && m.src.key == minter, minter, m.src);
        bytes32 state = _resultState(h0, t.id);
        Pred memory owner = m.recipient;
        uint256 n = t.transfers.length;
        for (uint256 i; i < n; ++i) {
            Step memory s = t.transfers[i];
            bool same = s.src.len == owner.len && _eqCd(s.src.pos, owner.pos, owner.len);
            (bytes32 sid, bytes32 txh) =
                _step(ctx, s, state, same, owner.typ == 1 ? owner.key : address(0), owner);
            t.lastSid = sid;
            t.lastTx = txh;
            if (i < n - 1) {
                _require(ctx, s.recipient.typ == 1, R.BURN_NOT_FINAL);
                _require(ctx, s.dataNull, R.TRANSFER_DATA);
            }
            state = _resultState(state, s.mask);
            owner = s.recipient;
        }
    }

    function _resultState(bytes32 sourceHash, bytes32 mask) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(hex"8258220000", sourceHash, hex"5820", mask));
    }

    /// @dev The mint data's amount: exactly tag(39050, [1, [[b(aid), Amount]], null]) (MintData).
    function _mintAmount(bytes32 aid, Step memory m) internal pure returns (bool, uint256) {
        if (m.dataNull) return (false, 0);
        uint256 p = m.dataPos;
        uint256 end = p + m.dataLen;
        if (C.scan(p, end, false) != 0 || m.dataLen < 44) return (false, 0);
        // d9988a 83 01 81 82 5820 <aid>
        if (bytes9(C.word(p)) != bytes9(hex"d9988a830181825820") || C.word(p + 9) != aid) {
            return (false, 0);
        }
        (bool ok, uint256 v, uint256 q) = C.amountOk(p + 41);
        if (!ok || q + 1 != end || C.u8(q) != 0xf6) return (false, 0);
        return (true, v);
    }

    /// @dev checkStep: CD against the reconstructed source and hash, the deadline, the unlock, the reference time against an
    ///      explicit deadline, the state ID's uniqueness, the inclusion proof. Returns (sid, txHash).
    function _step(
        Ctx memory ctx,
        Step memory s,
        bytes32 sourceHash,
        bool sourceMatches,
        address sourceKey,
        Pred memory source
    ) internal view returns (bytes32 sid, bytes32 txh) {
        txh = X.sha256Cd(s.rawPos, s.rawLen);
        _require(ctx, sourceMatches && s.srcHash == sourceHash && s.txHash == txh, R.CDMISMATCH);
        _require(ctx, s.cdDlSet == s.dlSet && s.cdDl == s.dl, R.DEADLINE_MISMATCH);
        _require(ctx, source.typ == 1, R.BURN_NOT_FINAL);
        _unlock(ctx, sourceKey, sourceHash, txh, s.unlockPos, s.unlockLen);
        _require(ctx, !s.dlSet || s.t < s.dl, R.DEADLINE_EXPIRED);
        sid = _stateId(source, sourceHash);
        _require(ctx, _newSid(ctx, sid), R.REPEATED_SID);
        bytes32 leafValue = sha256(abi.encodePacked(hex"825820", txh, _cuint(s.t)));
        _inclusion(ctx, sid, leafValue, s);
    }

    /// @dev sid = H_U(C(Psource, b(sourceHash))); the source's exact bytes are its encoding.
    function _stateId(Pred memory source, bytes32 sourceHash) internal view returns (bytes32) {
        uint256 m;
        assembly ("memory-safe") {
            m := mload(0x40)
        }
        uint256 sp = source.pos;
        uint256 sl = source.len;
        assembly ("memory-safe") {
            mstore8(m, 0x82)
            calldatacopy(add(m, 1), sp, sl)
            let w := add(add(m, 1), sl)
            mstore8(w, 0x58)
            mstore8(add(w, 1), 0x20)
            mstore(add(w, 2), sourceHash)
        }
        return X.sha256Mem(m, sl + 35);
    }

    function _newSid(Ctx memory ctx, bytes32 h) internal pure returns (bool) {
        bytes32 key = h == 0 ? bytes32(uint256(1)) : h; // a zero state ID (no preimage known) shares the sentinel's slot
        uint256 mask = ctx.sids.length - 1;
        uint256 i = uint256(key) & mask;
        while (true) {
            bytes32 slot = ctx.sids[i];
            if (slot == key) return false;
            if (slot == 0) {
                ctx.sids[i] = key;
                return true;
            }
            i = (i + 1) & mask;
        }
        return false;
    }

    /// @dev VerifyUnlock: exactly 65 bytes r || s || id (UnlockLength), 1 <= r < n and 1 <= s <= n/2 (UnlockScalars), id 0
    ///      or 1 (UnlockRecovery: NB2 admits no recovery IDs 2 and 3), the key recovered with the supplied id equal to the
    ///      source key (UnlockKey).
    function _unlock(
        Ctx memory ctx,
        address key,
        bytes32 sourceHash,
        bytes32 txh,
        uint256 up,
        uint256 ul
    ) internal view {
        _unlockDigest(
            ctx, key, sha256(abi.encodePacked(hex"825820", sourceHash, hex"5820", txh)), up, ul
        );
    }

    /// @dev The unlock rule over its message digest H(C(b(sourceHash), b(txHash))).
    function _unlockDigest(Ctx memory ctx, address key, bytes32 digest, uint256 up, uint256 ul)
        internal
        view
    {
        _require(ctx, ul == 65, R.UNLOCK_LENGTH);
        uint256 r = uint256(C.word(up));
        uint256 s = uint256(C.word(up + 32));
        _require(ctx, r != 0 && r < X.N && s != 0 && s <= X.HALF_N, R.UNLOCK_SCALARS);
        uint256 id = C.u8(up + 64);
        _require(ctx, id <= 1, R.UNLOCK_RECOVERY);
        address got = X.recover(digest, id, bytes32(r), bytes32(s));
        _require(ctx, got != address(0) && got == key, R.UNLOCK_KEY);
    }

    /// @dev One aggregator inclusion proof: the UC (encoding, network, structure for aggregatorPartition and its own shard,
    ///      folds; its authority is a pending claim), the state ID inside the UC's shard and its RSMT membership under the
    ///      certified state root (InclusionProof), and t <= IR.timestamp (ReferenceTime).
    function _inclusion(Ctx memory ctx, bytes32 sid, bytes32 leafValue, Step memory s)
        internal
        view
    {
        Cfg memory c = ctx.cfg;
        (
            bytes4 rule,
            bytes memory claim,
            bytes32 stateHash,
            uint256 timestamp,
            bytes memory shard
        ) = RECEIPTS.certificate(_cdSlice(s.ucPos, s.ucLen), c.network, c.aggPartition);
        if (rule != 0) _fail(ctx, rule);
        ctx.claims[ctx.nClaims++] = Claim(claim, false);
        _require(ctx, _inShard(shard, sid), R.INCLUSION_PROOF);
        _require(
            ctx, _member(ctx, stateHash, sid, leafValue, s.pathPos, s.pathLen), R.INCLUSION_PROOF
        );
        _require(ctx, s.t <= timestamp, R.REFERENCE_TIME);
    }

    /// @dev Whether the state ID lies in the shard: its first `depth` bits are the shard's prefix bits (the canonical
    ///      shard encoding ends in one terminator bit and zero padding).
    function _inShard(bytes memory shard, bytes32 sid) internal pure returns (bool) {
        uint256 len = shard.length;
        uint256 last = uint8(shard[len - 1]);
        uint256 tz;
        while ((last >> tz) & 1 == 0) ++tz;
        uint256 depth = 8 * len - tz - 1;
        for (uint256 i; i < depth; ++i) {
            uint256 sb = (uint8(shard[i / 8]) >> (7 - (i % 8))) & 1;
            if (sb != (uint256(sid) >> (255 - i)) & 1) return false;
        }
        return true;
    }

    /// @dev A child's allocation edge: its output commitment proved against the parent's manifest root (SplitProof), and the
    ///      root sum equal to the parent's amount (SplitSum).
    function _splitEdge(Ctx memory ctx, Tok memory parent, Tok memory child) internal view {
        Step memory m = child.mint;
        bytes memory dataItem;
        if (m.dataNull) {
            dataItem = hex"40";
        } else {
            dataItem = abi.encodePacked(_bhead(m.dataLen), _cdSlice(m.dataPos, m.dataLen));
        }
        bytes32 d = sha256(
            abi.encodePacked(
                hex"8854",
                "UNICITY_SPLIT_OUTPUT",
                hex"5820",
                parent.id,
                _cuint(child.network),
                _bhead(m.recipient.len),
                _cdSlice(m.recipient.pos, m.recipient.len),
                hex"5820",
                m.mask,
                hex"5820",
                child.id,
                hex"5820",
                child.ty,
                dataItem
            )
        );
        (bool ok, uint256 sum) = _sumVerify(child, d, parent.manifestRoot);
        _require(ctx, ok, R.SPLIT_PROOF);
        _require(ctx, sum == parent.amount, R.SPLIT_SUM);
    }

    function _cdSlice(uint256 p, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        assembly ("memory-safe") {
            calldatacopy(add(out, 32), p, len)
        }
    }

    /// @dev The leaf-first allocation proof folded from H(0x10 || childId || d || u256(v)) to the parent's manifest root,
    ///      with checked 256-bit sums: (proves, root sum).
    function _sumVerify(Tok memory child, bytes32 d, bytes32 root)
        internal
        pure
        returns (bool, uint256)
    {
        bytes32 key = child.id;
        uint256 sum = child.amount;
        bytes32 h = sha256(abi.encodePacked(uint8(0x10), key, d, sum));
        uint256 q = child.proofPos;
        for (uint256 i; i < child.proofSteps; ++i) {
            (,, uint256 eq) = C.hd(q); // [depth, b(hash), Amount]
            (, uint256 depth, uint256 hq) = C.hd(eq);
            bytes32 sh = C.word(hq + 2);
            (, uint256 ssum, uint256 next) = C.amountOk(hq + 34);
            q = next;
            uint256 total;
            unchecked {
                total = sum + ssum;
            }
            if (total < sum) return (false, 0);
            if ((uint256(key) >> (255 - depth)) & 1 == 1) {
                h = sha256(abi.encodePacked(uint8(0x11), uint8(depth), sh, ssum, h, sum));
            } else {
                h = sha256(abi.encodePacked(uint8(0x11), uint8(depth), h, sum, sh, ssum));
            }
            sum = total;
        }
        return (h == root, sum);
    }

    /// @dev A parent's terminal transfer burns exactly its manifest tag(39046, [b(root)]) (SplitBurn, SplitManifest).
    function _splitBurn(Ctx memory ctx, Tok memory t) internal view {
        Step memory last = t.transfers[t.transfers.length - 1];
        _require(ctx, last.recipient.typ == 2 && !last.dataNull, R.SPLIT_BURN);
        uint256 p = last.dataPos;
        bool ok = last.dataLen == 38 && C.scan(p, p + 38, false) == 0
            && bytes6(C.word(p)) == bytes6(hex"d99886815820");
        _require(ctx, ok, R.SPLIT_MANIFEST);
        _require(ctx, X.sha256Cd(p, 38) == last.recipient.burn, R.SPLIT_BURN);
        t.manifestRoot = C.word(p + 6);
    }

    // ---- 6. the return burn ------------------------------------------------------------------------------------------

    function _return(Ctx memory ctx, Tok memory part)
        internal
        view
        returns (uint256 a, bytes32 asset, address recipient)
    {
        Step memory last = part.transfers[part.transfers.length - 1];
        _require(ctx, last.recipient.typ == 2, R.NOT_BURN);
        bool ok;
        bytes32 rd;
        uint256 v;
        (ok, rd, asset, recipient, v, a) = _returnData(last);
        _require(ctx, ok, R.RETURN_DATA);
        _require(ctx, a <= MAX_SEGMENT, R.RETURN_INDEX);
        _require(ctx, rd == ctx.cfg.d, R.RETURN_DOMAIN);
        _require(ctx, asset == ASSET_UCT, R.RETURN_ASSET);
        _require(ctx, v == part.amount, R.RETURN_AMOUNT);
        _require(ctx, recipient != address(0) && recipient != ctx.cfg.vault, R.RETURN_RECIPIENT);
        _require(ctx, X.sha256Cd(last.dataPos, last.dataLen) == last.recipient.burn, R.BURN_REASON);
    }

    /// @dev R = tag(39052, [1, b(D), b(asset32), b(recipient20), b(v), a]), strictly (ReturnData).
    function _returnData(Step memory last)
        internal
        pure
        returns (bool ok, bytes32 d, bytes32 asset, address recipient, uint256 v, uint256 a)
    {
        if (last.dataNull) return (false, 0, 0, address(0), 0, 0);
        uint256 p = last.dataPos;
        uint256 end = p + last.dataLen;
        if (last.dataLen < 97 || C.scan(p, end, false) != 0) {
            return (false, 0, 0, address(0), 0, 0);
        }
        // d9988c 86 01 5820 D 5820 asset 54 recipient
        if (
            bytes7(C.word(p)) != bytes7(hex"d9988c86015820")
                || bytes2(C.word(p + 39)) != bytes2(hex"5820") || C.u8(p + 73) != 0x54
        ) return (false, 0, 0, address(0), 0, 0);
        d = C.word(p + 7);
        asset = C.word(p + 41);
        recipient = address(bytes20(C.word(p + 74)));
        uint256 q;
        (ok, v, q) = C.amountOk(p + 94);
        if (!ok) return (false, 0, 0, address(0), 0, 0);
        (uint256 mj, uint256 arg, uint256 q2) = C.hd(q);
        if (mj != 0 || q2 != end) return (false, 0, 0, address(0), 0, 0);
        a = arg;
    }

    // ---- 7. identifiers --------------------------------------------------------------------------------------------

    /// @dev eta = H_U(C(b("UNICITY_NB2_REDEMPTION"), b(D), b(btid))), btid = H_U(C(b("UNICITY_NB2_BURN"), b(sid), b(txHash))).
    function _eta(bytes32 d, bytes32 sid, bytes32 txh) internal pure returns (bytes32) {
        bytes32 btid =
            sha256(abi.encodePacked(hex"8350", "UNICITY_NB2_BURN", hex"5820", sid, hex"5820", txh));
        return sha256(
            abi.encodePacked(hex"8356", "UNICITY_NB2_REDEMPTION", hex"5820", d, hex"5820", btid)
        );
    }
}
// forge-lint: disable-end(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)
