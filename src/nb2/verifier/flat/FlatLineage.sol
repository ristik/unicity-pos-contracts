// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// CBOR conversion widths are checked before narrowing. Memory return structs are zero-initialized.
// forge-lint: disable-start(unsafe-typecast,uninitialized-local)

import {Nb2Cbor as C} from "../Nb2Cbor.sol";
import {Nb2Crypto as X} from "../Nb2Crypto.sol";
import {
    FlatConfig,
    FlatPart,
    FlatOwner,
    FlatVerdict,
    FlatClaim,
    FlatHash,
    FlatWire as W,
    BadStep,
    BadBinding
} from "./FlatTypes.sol";
import {FlatNative} from "./FlatNative.sol";
import {FlatReceipts} from "./FlatReceipts.sol";

/// @notice Shared verification of one signed operation and all its local obligations.
/// @dev The caller must verify the returned claims with B1 and enforce the SID and claim maps.
contract FlatLineage {
    bytes32 private constant DEPOSITED =
        keccak256("Deposited(uint64,bytes32,uint256,bytes32,bytes)");
    bytes32 private constant SECRET = keccak256("UNICITY_NB2_DEPOSIT_SECRET");
    bytes32 private constant TOKENID = sha256("TOKENID");

    FlatReceipts public immutable RECEIPTS;
    bytes32 public immutable RECEIPTS_HASH;

    struct Predicate {
        FlatOwner owner;
        address key;
        bytes32 burn;
        bool signature;
    }

    struct Mint {
        Predicate owner;
        bytes32 salt;
        bytes32 tokenID;
        uint256 reasonPos;
        uint256 reasonLen;
        uint256 predPos;
        uint256 dataPos;
        uint256 dataLen;
        uint256 deadlinePos;
        uint256 amount;
        bytes32 output;
        uint64 deadline;
    }

    constructor(FlatReceipts receipts) {
        bytes32 hash = keccak256(type(FlatReceipts).runtimeCode);
        if (address(receipts).codehash != hash) revert BadBinding();
        RECEIPTS = receipts;
        RECEIPTS_HASH = hash;
    }

    function mint(
        FlatConfig calldata cfg,
        FlatPart calldata parent,
        bool root,
        bytes calldata allocation,
        bytes calldata rawMint,
        bytes calldata proof
    )
        external
        view
        returns (
            FlatPart memory part,
            bytes32 sid,
            FlatClaim memory claim,
            FlatClaim memory deposit
        )
    {
        _checkReceipts();
        Mint memory m = _mint(cfg, rawMint);
        if (root) {
            if (allocation.length != 0) revert BadStep();
            deposit = _deposit(cfg, m);
        } else {
            _childReason(m, parent.parentLink);
            m.output = _output(cfg, m, parent.tokenID, W.offset(rawMint) + rawMint.length);
            _allocation(allocation, m, parent);
        }

        uint256 scalar = uint256(
            sha256(
                abi.encodePacked(hex"82581a", "I_AM_UNIVERSAL_MINTER_FOR_", hex"5820", m.tokenID)
            )
        );
        if (scalar == 0 || scalar >= X.N) revert BadStep();
        bytes32 source = sha256(abi.encodePacked(hex"825820", m.tokenID, hex"5820", TOKENID));
        (sid,, claim) = _source(
            cfg, proof, rawMint, m.deadline, source, FlatOwner(0, 0), X.scalarAddress(scalar)
        );
        part = FlatPart(m.owner.owner, _resultState(source, m.tokenID), m.tokenID, m.amount, 0, 0);
    }

    /// @param ending 0 continues this level, 1 splits to its child, 2 completes a return.
    function transfer(
        FlatConfig calldata cfg,
        FlatPart calldata before_,
        uint8 ending,
        bytes calldata pair
    )
        external
        view
        returns (
            FlatPart memory part,
            bytes32 sid,
            FlatClaim memory claim,
            FlatVerdict memory verdict
        )
    {
        _checkReceipts();
        _scan(pair, true);
        uint256 p = C.array(W.offset(pair), 2);
        uint256 start = p;
        p = C.version(C.array(C.tagged(p, 39045), 5), 2);
        Predicate memory next;
        (next, p) = _predicate(p);
        bytes32 mask;
        (mask, p) = C.bytes32At(p);
        (bool noData, uint256 dp, uint256 dl, uint256 q) = C.nullable(p);
        uint64 deadline;
        (deadline, p) = _deadline(q);
        bytes32 txHash;
        (sid, txHash, claim) = _source(
            cfg,
            W.slice(p, W.offset(pair) + pair.length - p),
            W.slice(start, p - start),
            deadline,
            before_.state,
            before_.owner,
            address(0)
        );

        part = before_;
        if (ending == 0) {
            if (!next.signature || !noData) revert BadStep();
            part.owner = next.owner;
            part.state = _resultState(before_.state, mask);
        } else {
            if (next.signature || noData || X.sha256Cd(dp, dl) != next.burn) revert BadStep();
            if (ending == 1) {
                if (dl != 38 || bytes6(C.word(dp)) != hex"d99886815820") revert BadStep();
                part.parentManifest = C.word(dp + 6);
                part.parentLink = sha256(
                    abi.encodePacked(
                        "UNICITY/NB2/1.1/PARENT",
                        cfg.domain,
                        before_.tokenID,
                        sid,
                        txHash,
                        part.parentManifest,
                        before_.amount
                    )
                );
                part.owner = FlatOwner(0, 0);
                part.state = 0;
            } else {
                verdict = _verdict(cfg, W.slice(dp, dl), before_.amount, sid, txHash);
            }
        }
    }

    function _checkReceipts() private view {
        if (address(RECEIPTS).codehash != RECEIPTS_HASH) revert BadBinding();
    }

    function _scan(bytes calldata raw, bool native) private pure {
        uint256 p = W.offset(raw);
        if (C.scan(p, p + raw.length, native) != 0) revert BadStep();
    }

    function _predicate(uint256 p) private view returns (Predicate memory pred, uint256 next) {
        p = C.version(C.array(C.tagged(p, 39032), 3), 1);
        (uint256 code, uint256 q) = C.fixedBytes(p, 1);
        uint256 kind = C.u8(code);
        if (kind == 1) {
            uint256 key;
            (key, next) = C.fixedBytes(q, 33);
            pred.owner = FlatOwner(C.word(key), bytes1(C.word(key + 32)));
            pred.key = X.keyAddress(key);
            if (pred.key == address(0)) revert BadStep();
            pred.signature = true;
        } else {
            if (kind != 2) revert BadStep();
            (pred.burn, next) = C.bytes32At(q);
        }
    }

    function _deadline(uint256 p) private pure returns (uint64 deadline, uint256 next) {
        (, uint256 when, uint256 q) = C.deadline(p);
        return (uint64(when), q);
    }

    function _mint(FlatConfig calldata cfg, bytes calldata raw)
        private
        view
        returns (Mint memory m)
    {
        _scan(raw, false);
        uint256 p = C.version(C.array(C.tagged(W.offset(raw), 39041), 8), 2);
        (uint256 network, uint256 q) = C.uintIn(p, 1, type(uint16).max);
        if (network != cfg.network) revert BadStep();
        m.predPos = q;
        (m.owner, p) = _predicate(q);
        if (!m.owner.signature) revert BadStep();
        (m.salt, p) = C.bytes32At(p);
        bytes32 ty;
        (ty, p) = C.bytes32At(p);
        if (ty != cfg.tokenType) revert BadStep();
        (m.reasonPos, m.reasonLen, p) = C.bstr(p);
        (m.dataPos, m.dataLen, m.deadlinePos) = C.bstr(p);
        (m.deadline, p) = _deadline(m.deadlinePos);
        if (p != W.offset(raw) + raw.length) revert BadStep();
        uint256 dp = m.dataPos;
        uint256 dl = m.dataLen;
        bytes calldata data = W.slice(dp, dl);
        _scan(data, false);
        q = C.version(C.array(C.tagged(dp, 39050), 3), 1);
        bytes32 coin;
        (coin, q) = C.bytes32At(C.array(C.array(q, 1), 2));
        (m.amount, q) = C.amount(q);
        if (coin != cfg.coin || q + 1 != dp + dl || !C.isNull(q)) revert BadStep();
        m.tokenID = sha256(abi.encodePacked(hex"825820", m.salt, _uint(network)));
    }

    function _output(FlatConfig calldata cfg, Mint memory m, bytes32 parentID, uint256 end)
        private
        pure
        returns (bytes32)
    {
        // The concatenated fields are canonical CBOR items with explicit lengths.
        // forge-lint: disable-start(encode-packed-collision)
        return sha256(
            abi.encodePacked(
                hex"8955",
                "UNICITY_NB2_11_OUTPUT",
                hex"5820",
                parentID,
                _uint(cfg.network),
                hex"582a",
                W.slice(m.predPos, 42),
                hex"5820",
                m.salt,
                hex"5820",
                m.tokenID,
                hex"5820",
                cfg.tokenType,
                _byteStringHead(m.dataLen),
                W.slice(m.dataPos, m.dataLen),
                W.slice(m.deadlinePos, end - m.deadlinePos)
            )
        );
        // forge-lint: disable-end(encode-packed-collision)
    }

    function _deposit(FlatConfig calldata cfg, Mint memory m)
        private
        view
        returns (FlatClaim memory claim)
    {
        bytes calldata reason = W.slice(m.reasonPos, m.reasonLen);
        if (reason.length > W.MAX_RECEIPT) revert BadStep();
        W.boundDeposit(reason);
        _scan(reason, false);
        uint256 p = C.version(C.array(C.tagged(W.offset(reason), 39051), 5), 1);
        (bytes32 domain, uint256 q) = C.bytes32At(p);
        uint256 nonce;
        (nonce, q) = C.uintIn(q, 1, (1 << 56) - 1);
        (bytes32 secret, uint256 proofPos) = C.bytes32At(q);
        if (
            domain != cfg.domain
                || m.salt
                    != sha256(
                        abi.encodePacked(
                            hex"845818",
                            "UNICITY_NB2_DEPOSIT_SALT",
                            hex"5820",
                            domain,
                            _uint(nonce),
                            hex"5820",
                            secret
                        )
                    )
        ) revert BadStep();
        bytes32[] memory topics;
        bytes memory data;
        (claim, topics, data) = RECEIPTS.receipt(
            FlatReceipts.ReceiptEnv(cfg.network, cfg.evmPartition, cfg.evmShard, cfg.vault),
            W.slice(proofPos, W.offset(reason) + reason.length - proofPos)
        );
        if (
            topics.length != 2 || topics[0] != DEPOSITED || uint256(topics[1]) != nonce
                || data.length != 224 || W.mword(data, 0) != domain
                || uint256(W.mword(data, 32)) != m.amount
                || W.mword(data, 64) != keccak256(abi.encodePacked(SECRET, domain, secret))
                || uint256(W.mword(data, 96)) != 128 || uint256(W.mword(data, 128)) != 42
                || uint176(uint256(W.mword(data, 192))) != 0
        ) revert BadStep();
        bytes32 loggedOwner;
        assembly ("memory-safe") { loggedOwner := keccak256(add(data, 192), 42) }
        if (loggedOwner != X.keccakCd(m.predPos, 42)) revert BadStep();
    }

    function _childReason(Mint memory m, bytes32 link) private pure {
        bytes calldata reason = W.slice(m.reasonPos, m.reasonLen);
        if (
            reason.length != 39 || bytes7(W.word(reason, 0)) != hex"d9988482025820"
                || W.word(reason, 7) != link
        ) revert BadStep();
    }

    function _allocation(bytes calldata proof, Mint memory m, FlatPart calldata parent)
        private
        pure
    {
        W.boundAllocation(proof);
        _scan(proof, false);
        (uint256 n, uint256 p) = C.anyArray(W.offset(proof));
        if (n > 256) revert BadStep();
        uint256 prev = 256;
        uint256 sum = m.amount;
        bytes32 h = sha256(abi.encodePacked(uint8(0x10), m.tokenID, m.output, sum));
        for (uint256 i; i < n; ++i) {
            (uint256 depth, uint256 q) = C.uintIn(C.array(p, 3), 0, prev - 1);
            (bytes32 sibling, uint256 r) = C.bytes32At(q);
            uint256 siblingSum;
            (siblingSum, p) = C.amount(r);
            if (siblingSum > type(uint256).max - sum || (depth == 0 && i + 1 != n)) {
                revert BadStep();
            }
            if ((uint256(m.tokenID) >> (255 - depth)) & 1 == 0) {
                h = sha256(abi.encodePacked(uint8(0x11), uint8(depth), h, sum, sibling, siblingSum));
            } else {
                h = sha256(abi.encodePacked(uint8(0x11), uint8(depth), sibling, siblingSum, h, sum));
            }
            sum += siblingSum;
            prev = depth;
        }
        if (sum != parent.amount || h != parent.parentManifest) revert BadStep();
    }

    function _source(
        FlatConfig calldata cfg,
        bytes calldata proof,
        bytes calldata txBytes,
        uint64 deadline,
        bytes32 source,
        FlatOwner memory owner,
        address minter
    ) private view returns (bytes32 sid, bytes32 txHash, FlatClaim memory claim) {
        _scan(proof, true);
        uint256 p = C.version(C.array(C.tagged(W.offset(proof), 39033), 5), 1);
        p = C.version(C.array(C.tagged(p, 39031), 6), 2);
        uint256 predStart = p;
        (Predicate memory origin, uint256 q) = _predicate(p);
        if (!origin.signature) revert BadStep();
        if (minter != address(0)) {
            if (origin.key != minter) revert BadStep();
        } else if (origin.owner.prefix != owner.prefix || origin.owner.tail != owner.tail) {
            revert BadStep();
        }
        sid =
            sha256(abi.encodePacked(hex"82", W.slice(predStart, q - predStart), hex"5820", source));
        (bytes32 sourceHash, uint256 r) = C.bytes32At(q);
        (bytes32 signedHash, uint256 afterHash) = C.bytes32At(r);
        txHash = X.sha256Cd(W.offset(txBytes), txBytes.length);
        (uint64 cdDeadline, uint256 afterDeadline) = _deadline(afterHash);
        if (sourceHash != source || signedHash != txHash || cdDeadline != deadline) {
            revert BadStep();
        }
        (uint256 unlock, uint256 afterUnlock) = C.fixedBytes(afterDeadline, 65);
        _unlock(origin.key, source, txHash, unlock);
        (uint256 time, uint256 afterTime) = C.uintIn(afterUnlock, 0, type(uint64).max);
        if (deadline != 0 && time >= deadline) revert BadStep();
        (uint256 path, uint256 len, uint256 uc) = C.bstr(afterTime);
        if (len < 32 || len > 8224 || len != 32 + 32 * W.popcount(uint256(C.word(path)))) {
            revert BadStep();
        }
        bytes32 root;
        (claim, root) = RECEIPTS.certificate(
            W.slice(uc, W.offset(proof) + proof.length - uc),
            cfg.network,
            cfg.aggPartition,
            sid,
            uint64(time)
        );
        bytes32 leaf = sha256(abi.encodePacked(hex"825820", txHash, _uint(time)));
        if (!FlatNative.member(root, sid, leaf, W.slice(path, len))) revert BadStep();
    }

    function _unlock(address key, bytes32 source, bytes32 txHash, uint256 p) private view {
        bytes32 r = C.word(p);
        bytes32 s = C.word(p + 32);
        uint256 id = C.u8(p + 64);
        if (
            r == 0 || uint256(r) >= X.N || s == 0 || uint256(s) > X.HALF_N || id > 1
                || X.recover(
                        sha256(abi.encodePacked(hex"825820", source, hex"5820", txHash)), id, r, s
                    ) != key
        ) {
            revert BadStep();
        }
    }

    function _resultState(bytes32 source, bytes32 mask) private pure returns (bytes32) {
        return sha256(abi.encodePacked(hex"8258220000", source, hex"5820", mask));
    }

    function _verdict(
        FlatConfig calldata cfg,
        bytes calldata raw,
        uint256 amount,
        bytes32 sid,
        bytes32 txHash
    ) private pure returns (FlatVerdict memory v) {
        _scan(raw, false);
        uint256 p = C.version(C.array(C.tagged(W.offset(raw), 39052), 6), 1);
        (v.domain, p) = C.bytes32At(p);
        (v.asset, p) = C.bytes32At(p);
        (uint256 addr, uint256 q) = C.fixedBytes(p, 20);
        v.recipient = address(bytes20(C.word(addr)));
        (v.amount, p) = C.amount(q);
        (uint256 index, uint256 end) = C.uintIn(p, 0, (1 << 48) - 1);
        if (
            end != W.offset(raw) + raw.length || v.domain != cfg.domain || v.asset != FlatHash.ASSET
                || v.amount != amount || v.recipient == address(0) || v.recipient == cfg.vault
        ) revert BadStep();
        v.minSegment = uint64(index);
        bytes32 burn = sha256(
            abi.encodePacked(hex"8350", "UNICITY_NB2_BURN", hex"5820", sid, hex"5820", txHash)
        );
        v.eta = sha256(
            abi.encodePacked(
                hex"8356", "UNICITY_NB2_REDEMPTION", hex"5820", v.domain, hex"5820", burn
            )
        );
    }

    function _byteStringHead(uint256 n) private pure returns (bytes memory head) {
        head = _uint(n);
        head[0] |= 0x40;
    }

    function _uint(uint256 n) private pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(uint8(n));
        if (n <= 0xff) return abi.encodePacked(uint8(24), uint8(n));
        if (n <= 0xffff) return abi.encodePacked(uint8(25), uint16(n));
        if (n <= 0xffffffff) return abi.encodePacked(uint8(26), uint32(n));
        return abi.encodePacked(uint8(27), uint64(n));
    }
}
