// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {B1Calls} from "./B1Calls.sol";
import {BridgeBounds} from "./BridgeBounds.sol";
import {InputRecord} from "./InputRecord.sol";
import {UcScan} from "./UcScan.sol";
import {BridgeProfile} from "./BridgeProfile.sol";
import {Anchor, Cfg, KernelResult, Leaf, LeafProof, Policy} from "./BridgeTypes.sol";
import {
    BudgetExceeded,
    ChainIdMismatch,
    EnvelopeFraming,
    KernelBadOutput,
    KernelCfgMismatch,
    KernelRejected,
    KernelResultShape,
    LeafNotIncluded,
    PathBitmapMismatch,
    PolicyAnchorCount,
    PolicyAnchorDuplicate,
    PolicyAnchorUnused,
    PolicyHashMismatch,
    PolicyLeafCount,
    PolicyLeafIndex,
    PolicyPartitionIsEvm,
    PolicyTupleMismatch,
    IRTimeAfterAnchor,
    UCRejected,
    WrongVerifier
} from "./BridgeErrors.sol";

// Every refusal inside the bounded loops below must revert the whole call.
// forge-lint: disable-start(require-revert-in-loop)

/// @notice Stateless composing verifier of the whole-token native bridge (design
///         `bridge-b2b4-design-v2.md`, "Verification relation"). It composes the proposed 0x0104
///         semantics kernel with B1 A' certificate and RSMT calls. It stores nothing, takes `Cfg` as
///         input and authorizes nothing: a caller receives a relation result, and only a vault whose
///         immutable cfg equals the result's cfg may act on it.
///
///         Order of checks: Cfg and environment, envelope framing and bounds, policy opening, kernel,
///         result shape, anchor table (one anchor per distinct complete UC in first-use leaf order),
///         the shared gas gate over bounded scans, one UC call per anchor, per-leaf time against the
///         leaf's own anchor, one RSMT path per leaf. Everything is a STATICCALL or pure; every native
///         call is forwarded exactly its computed charge; failure reverts with a named error and no
///         state effect. The bounds and the gate formula live in `BridgeBounds`.
contract TokenVerifier {
    uint8 internal constant OP_PREPARE_LOCK = 0;
    uint8 internal constant OP_MINT = 1;
    uint8 internal constant OP_RETURN = 2;

    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 internal constant KERNEL_MARKER = bytes32("UNICITY_TOKEN_SEMANTICS");

    /// @dev Result head (3 words), Result static part (10 words) and the array length.
    uint256 internal constant KERNEL_FIXED_BYTES = 448;
    /// @dev Four words per leaf since SDK 3.0.1: sid, txHash, uint64 referenceTime, leafValue.
    uint256 internal constant KERNEL_LEAF_BYTES = 128;
    uint256 internal constant KERNEL_MAX_BYTES =
        KERNEL_FIXED_BYTES + KERNEL_LEAF_BYTES * BridgeBounds.KERNEL_MAX_LEAVES;

    /// @dev What `_verify` carries between its stages: each leaf's own anchor and the computed charge
    ///      of every native call (the gate terms, also the gas forwarded to each call).
    struct Plan {
        uint256[] leafAnchor;
        uint256[] ucGas;
        uint256[] leafGas;
    }

    /// @notice Validates a lock request against the kernel and returns the values the vault compares
    ///         with its own: salt, token ID, first predicate hash and lock digest.
    function prepareLock(bytes calldata cfgBytes, uint256 nonce, uint256 amount, bytes calldata p0)
        external
        view
        returns (KernelResult memory r)
    {
        if (p0.length > BridgeBounds.MAX_SEMANTIC_BYTES) revert BudgetExceeded();
        (Cfg memory c, bytes32 ch) = _openCfg(cfgBytes);
        r = _kernel(OP_PREPARE_LOCK, cfgBytes, BridgeProfile.preparePayload(nonce, amount, p0));
        _checkShape(OP_PREPARE_LOCK, r, c, ch);
    }

    /// @notice Mint relation: kernel mint result plus B1 inclusion of the one mint leaf. The caller (a
    ///         vault view) separately checks that the lock exists and is unspent.
    function verifyMint(bytes calldata cfgBytes, bytes calldata proof)
        external
        view
        returns (KernelResult memory)
    {
        return _verify(OP_MINT, cfgBytes, proof);
    }

    /// @notice Return relation: kernel return result plus B1 inclusion of every exported leaf.
    function verifyReturn(bytes calldata cfgBytes, bytes calldata proof)
        external
        view
        returns (KernelResult memory)
    {
        return _verify(OP_RETURN, cfgBytes, proof);
    }

    // -------------------------------------------------------------------------------------------
    // Relation
    // -------------------------------------------------------------------------------------------

    function _verify(uint8 op, bytes calldata cfgBytes, bytes calldata proof)
        private
        view
        returns (KernelResult memory r)
    {
        (Cfg memory c, bytes32 ch) = _openCfg(cfgBytes);
        (
            bytes memory policyBody,
            bytes memory history,
            Anchor[] memory anchors,
            LeafProof[] memory paths
        ) = _openEnvelope(proof);
        // The policy body is opened before the kernel and before any B1 call; a submitted anchor table
        // never chooses its own admission.
        Policy memory pol = _checkPolicyBody(c, policyBody, anchors.length);
        if (history.length > BridgeBounds.MAX_SEMANTIC_BYTES) revert BudgetExceeded();
        r = _kernel(op, cfgBytes, history);
        _checkShape(op, r, c, ch);
        Plan memory plan = _planAnchors(pol, anchors, r, paths);
        // The gate is computed from complete bounded scans before any native call.
        uint256 total = BridgeBounds.intrinsicGas(proof.length)
            + BridgeBounds.b2Gas(
                BridgeBounds.kernelRequestBytes(cfgBytes.length, history.length), r.leaves.length
            ) + BridgeBounds.GAS_RESERVE;
        total += _gate(pol, anchors, paths, plan);
        if (total > BridgeBounds.TX_GAS_BUDGET) revert BudgetExceeded();

        // One UC call per anchor. B1 0x0100 authenticates the claim's expected state root and expected
        // IR hash together; only then does the opening carry weight: it must hash to the authenticated
        // IR hash and open to the authenticated state root, and its timestamp bounds the time of every
        // leaf that anchor serves.
        uint64[] memory times = new uint64[](anchors.length);
        for (uint256 j = 0; j < anchors.length; ++j) {
            Anchor memory a = anchors[j];
            if (!B1Calls.verdict(B1Calls.UC_VERIFIER, B1Calls.ucRequest(a), plan.ucGas[j])) {
                revert UCRejected();
            }
            times[j] = InputRecord.open(a.inputRecord, a.expectedIRHash, a.expectedStateRoot);
        }
        uint256 n = r.leaves.length;
        for (uint256 i = 0; i < n; ++i) {
            uint64 anchorTime = times[plan.leafAnchor[i]];
            if (r.leaves[i].referenceTime > anchorTime) {
                revert IRTimeAfterAnchor(i, r.leaves[i].referenceTime, anchorTime);
            }
        }
        for (uint256 i = 0; i < n; ++i) {
            // The leaf's own anchor's authenticated shard state root; sid is the key and the raw
            // 32-byte leaf value H(C(b(txHash),t)) the value. Neither txHash nor an imprint.
            bytes memory req = B1Calls.memberRequest(
                anchors[plan.leafAnchor[i]].expectedStateRoot,
                r.leaves[i].sid,
                abi.encodePacked(r.leaves[i].leafValue),
                paths[i].bitmap,
                paths[i].siblings
            );
            if (!B1Calls.verdict(B1Calls.RSMT_VERIFIER, req, plan.leafGas[i])) {
                revert LeafNotIncluded(i);
            }
        }
    }

    function _openCfg(bytes calldata cfgBytes) private view returns (Cfg memory c, bytes32 ch) {
        if (cfgBytes.length > BridgeProfile.MAX_CFG_BYTES) revert BudgetExceeded();
        bytes memory raw = cfgBytes;
        c = BridgeProfile.decodeCfg(raw);
        // Runtime checks: this deployment is the pinned verifier and the chain is the configured one.
        // The vault equality that authorizes anything is the vault's own comparison of the cfg hash.
        if (c.tokenVerifier != address(this)) revert WrongVerifier(c.tokenVerifier, address(this));
        if (c.chainId != block.chainid) revert ChainIdMismatch(c.chainId, block.chainid);
        ch = BridgeProfile.cfgHash(raw);
    }

    function _openEnvelope(bytes calldata proof)
        private
        pure
        returns (
            bytes memory policyBody,
            bytes memory history,
            Anchor[] memory anchors,
            LeafProof[] memory paths
        )
    {
        if (proof.length > BridgeBounds.MAX_ENVELOPE_BYTES) {
            revert BudgetExceeded();
        }
        _boundCounts(proof);
        // The one canonical `abi.encode` of the four fields, checked by walking the offsets and the
        // padding in place (no decode, no copy), so the decoder below sees only canonical input.
        _checkFraming(proof);
        (policyBody, history, anchors, paths) =
            abi.decode(proof, (bytes, bytes, Anchor[], LeafProof[]));
    }

    /// @dev `proof` is exactly `abi.encode(bytes, bytes, Anchor[], LeafProof[])`: every offset is the
    ///      position the canonical encoder gives it (no gaps, aliases or reordering), every length fits
    ///      the data, every padding byte is zero and nothing follows the last element. The ABI decoder
    ///      tolerates all of these deviations; the profile does not.
    function _checkFraming(bytes calldata b) private pure {
        uint256 n = b.length;
        if (n < 128 || n % 32 != 0) revert EnvelopeFraming();
        if (_word(b, 0) != 128) revert EnvelopeFraming();
        uint256 pos = _framedBytes(b, 128);
        if (_word(b, 32) != pos) revert EnvelopeFraming();
        pos = _framedBytes(b, pos);
        if (_word(b, 64) != pos) revert EnvelopeFraming();
        pos = _framedAnchors(b, pos);
        if (_word(b, 96) != pos) revert EnvelopeFraming();
        pos = _framedLeaves(b, pos);
        if (pos != n) revert EnvelopeFraming();
    }

    /// @dev `bytes` at `off`: length word, data, zero padding to a word. Returns the end.
    function _framedBytes(bytes calldata b, uint256 off) private pure returns (uint256 end) {
        uint256 len = _word(b, off);
        uint256 tail = len % 32;
        end = off + 32 + len + (tail == 0 ? 0 : 32 - tail);
        if (end > b.length) revert EnvelopeFraming();
        if (tail != 0) {
            // the padding of the last word is the low bytes after the data
            if (uint256(bytes32(b[end - 32:end])) & ((uint256(1) << (8 * (32 - tail))) - 1) != 0) {
                revert EnvelopeFraming();
            }
        }
    }

    function _framedAnchors(bytes calldata b, uint256 off) private pure returns (uint256 pos) {
        uint256 n = _word(b, off);
        uint256 base = off + 32;
        pos = base + 32 * n;
        if (pos > b.length) revert EnvelopeFraming();
        for (uint256 i = 0; i < n; ++i) {
            if (_word(b, base + 32 * i) != pos - base) revert EnvelopeFraming();
            uint256 t = pos;
            // (uint32 partition, bytes shard, bytes32, bytes32, bytes32, bytes uc, bytes inputRecord)
            if (_word(b, t) > type(uint32).max || _word(b, t + 32) != 224) {
                revert EnvelopeFraming();
            }
            pos = _framedBytes(b, t + 224);
            if (_word(b, t + 160) != pos - t) revert EnvelopeFraming();
            pos = _framedBytes(b, pos);
            if (_word(b, t + 192) != pos - t) revert EnvelopeFraming();
            pos = _framedBytes(b, pos);
        }
    }

    function _framedLeaves(bytes calldata b, uint256 off) private pure returns (uint256 pos) {
        uint256 n = _word(b, off);
        uint256 base = off + 32;
        pos = base + 32 * n;
        if (pos > b.length) revert EnvelopeFraming();
        for (uint256 i = 0; i < n; ++i) {
            if (_word(b, base + 32 * i) != pos - base) revert EnvelopeFraming();
            uint256 t = pos;
            // (uint16 anchorIndex, bytes32 bitmap, bytes32[] siblings)
            if (_word(b, t) > type(uint16).max || _word(b, t + 64) != 96) revert EnvelopeFraming();
            pos = t + 96 + 32 + 32 * _word(b, t + 96);
            if (pos > b.length) revert EnvelopeFraming();
        }
    }

    /// @dev Reads the declared counts straight from the head words, so an over-budget count is
    ///      rejected before any allocation. Walks the leaf proofs in order; a layout it cannot follow
    ///      is a framing error, an over-budget count a budget error. Words above 2^64-1 are framing
    ///      errors, so every sum below stays far from overflow.
    function _boundCounts(bytes calldata b) private pure {
        uint256 n = b.length;
        // `_word` refuses any read past the end, which covers a short envelope and an offset beyond
        // it; alignment and trailing data are covered by the re-encode comparison in `_openEnvelope`.
        uint256 offAnchors = _word(b, 64);
        uint256 offLeaves = _word(b, 96);
        uint256 na = _word(b, offAnchors);
        if (na > n) revert EnvelopeFraming();
        if (na > BridgeBounds.MAX_ANCHORS) revert BudgetExceeded();
        // Every anchor's UC and InputRecord opening are bounded before anything is allocated: their
        // length words sit at the offsets of the tuple's sixth and seventh head words.
        for (uint256 i = 0; i < na; ++i) {
            uint256 t = offAnchors + 32 + _word(b, offAnchors + 32 + 32 * i);
            if (_word(b, t + _word(b, t + 160)) > BridgeBounds.MAX_ANCHOR_UC_BYTES) {
                revert BudgetExceeded();
            }
            if (_word(b, t + _word(b, t + 192)) > InputRecord.MAX_BYTES) revert BudgetExceeded();
        }
        uint256 nl = _word(b, offLeaves);
        if (nl > n) revert EnvelopeFraming();
        if (nl > BridgeBounds.MAX_LEAVES) revert BudgetExceeded();
        // The cumulative step bound (`MAX_PATH_STEPS`) is implied by the per-leaf bound and the leaf
        // and anchor bounds; `BridgeBounds` pins that inequality.
        for (uint256 i = 0; i < nl; ++i) {
            uint256 rel = _word(b, offLeaves + 32 + 32 * i);
            uint256 t = offLeaves + 32 + rel;
            uint256 sRel = _word(b, t + 64);
            if (_word(b, t + sRel) > BridgeBounds.MAX_RSMT_SIBLINGS) revert BudgetExceeded();
        }
    }

    function _word(bytes calldata b, uint256 off) private pure returns (uint256 v) {
        if (off + 32 > b.length) revert EnvelopeFraming();
        v = uint256(bytes32(b[off:off + 32]));
        if (v > type(uint64).max) revert EnvelopeFraming();
    }

    /// @dev Hash first, interpretation second: the supplied body is compared with the immutable
    ///      `aggregatorPolicyHash` before it is decoded.
    function _checkPolicyBody(Cfg memory c, bytes memory body, uint256 anchorCount)
        private
        pure
        returns (Policy memory p)
    {
        if (body.length > BridgeProfile.MAX_POLICY_BYTES) revert BudgetExceeded();
        bytes32 h = sha256(body);
        if (h != c.aggregatorPolicyHash) revert PolicyHashMismatch(c.aggregatorPolicyHash, h);
        p = BridgeProfile.decodePolicy(body);
        if (p.partition == c.evmPartition) revert PolicyPartitionIsEvm();
        // The upper bound was refused from the declared count, before anything was allocated.
        if (anchorCount == 0) revert PolicyAnchorCount(anchorCount);
    }

    /// @dev The anchor table is exactly the function of the exported leaves the profile defines: one
    ///      path per leaf in kernel order; every anchor's partition, shard and configuration equal to a
    ///      policy row; anchors pairwise distinct by complete UC bytes; numbered by first use in leaf
    ///      order with none unused; every leaf's `anchorIndex` an already-used index or the next unused
    ///      one, naming an anchor of the leaf's own shard (the top `depth` bits of its state ID).
    function _planAnchors(
        Policy memory pol,
        Anchor[] memory anchors,
        KernelResult memory r,
        LeafProof[] memory paths
    ) private pure returns (Plan memory plan) {
        uint256 nl = r.leaves.length;
        if (paths.length != nl) revert PolicyLeafCount(nl, paths.length);
        if (anchors.length > nl) revert PolicyAnchorCount(anchors.length);
        uint256 na = anchors.length;
        uint256[] memory rowOf = new uint256[](na);
        bytes32[] memory ucHash = new bytes32[](na);
        for (uint256 j = 0; j < na; ++j) {
            Anchor memory a = anchors[j];
            uint256 row = 0;
            bool found;
            for (uint256 k = 0; k < pol.shardConfHashes.length; ++k) {
                if (a.shard.length == 1 && a.shard[0] == BridgeProfile.shardId(pol.depth, k)) {
                    row = k;
                    found = true;
                }
            }
            if (
                !found || a.partition != pol.partition
                    || a.shardConfHash != pol.shardConfHashes[row]
            ) {
                revert PolicyTupleMismatch();
            }
            rowOf[j] = row;
            ucHash[j] = sha256(a.uc);
            for (uint256 k = 0; k < j; ++k) {
                if (ucHash[k] == ucHash[j]) revert PolicyAnchorDuplicate(j);
            }
        }
        plan.leafAnchor = new uint256[](nl);
        uint256 next = 0;
        for (uint256 i = 0; i < nl; ++i) {
            uint256 idx = paths[i].anchorIndex;
            uint256 want = pol.depth == 0 ? 0 : uint256(uint8(r.leaves[i].sid[0]) >> 7);
            if (idx >= na || idx > next || rowOf[idx] != want) revert PolicyLeafIndex(i, idx);
            if (idx == next) ++next;
            plan.leafAnchor[i] = idx;
        }
        if (next != na) revert PolicyAnchorUnused(next);
    }

    /// @dev Prices every native call from complete bounded scans and returns `sum G_UC + sum G_RSMT`.
    ///      A UC whose shard certificate does not name the claim's shard, or does not carry exactly
    ///      `depth` shard siblings, is refused here; a bitmap whose popcount differs from the sibling
    ///      count is refused here; both before any native call.
    function _gate(
        Policy memory pol,
        Anchor[] memory anchors,
        LeafProof[] memory paths,
        Plan memory plan
    ) private pure returns (uint256 total) {
        plan.ucGas = new uint256[](anchors.length);
        for (uint256 j = 0; j < anchors.length; ++j) {
            Anchor memory a = anchors[j];
            (uint256 sigs, uint256 steps) = UcScan.scan(a.uc, a.shard, pol.depth);
            plan.ucGas[j] = BridgeBounds.ucGas(a.shard.length, a.uc.length, sigs, steps);
            total += plan.ucGas[j];
        }
        plan.leafGas = new uint256[](paths.length);
        for (uint256 i = 0; i < paths.length; ++i) {
            uint256 pop = BridgeBounds.popcount(uint256(paths[i].bitmap));
            if (pop != paths[i].siblings.length) revert PathBitmapMismatch(i);
            plan.leafGas[i] = BridgeBounds.rsmtGas(pop);
            total += plan.leafGas[i];
        }
    }

    // -------------------------------------------------------------------------------------------
    // Kernel
    // -------------------------------------------------------------------------------------------

    function _kernel(uint8 op, bytes memory cfgBytes, bytes memory payload)
        private
        view
        returns (KernelResult memory)
    {
        // The charge depends on the result's leaf count, known only afterwards: the forwarded gas is
        // the charge at the kernel's own output bound, the gate below prices the actual count.
        bytes memory out = B1Calls.staticCall(
            B1Calls.KERNEL,
            abi.encode(op, cfgBytes, payload),
            KERNEL_MAX_BYTES,
            BridgeBounds.b2Gas(
                BridgeBounds.kernelRequestBytes(cfgBytes.length, payload.length),
                BridgeBounds.KERNEL_MAX_LEAVES
            )
        );
        return _parseKernel(out);
    }

    /// @dev Strict parse of `abi.encode(bytes32 marker, bool valid, Result)`. The canonical layout is
    ///      fully determined by the leaf count, so every offset and the total length are checked
    ///      exactly rather than re-encoded. A short, extra, misaligned or empty (inactive address)
    ///      output is `KernelBadOutput`; a well-formed `valid=false` is `KernelRejected`.
    function _parseKernel(bytes memory out) private pure returns (KernelResult memory r) {
        // Whatever a read past a short output sees, no length below 448 bytes can satisfy the
        // exact-length test, so a short, extra or misaligned output is refused there.
        uint256 len = out.length;
        if (_mw(out, 0) != uint256(KERNEL_MARKER)) revert KernelBadOutput();
        uint256 valid = _mw(out, 32);
        if (valid > 1 || _mw(out, 64) != 0x60 || _mw(out, 384) != 0x140) revert KernelBadOutput();
        uint256 k = _mw(out, 416);
        if (k > BridgeBounds.KERNEL_MAX_LEAVES || len != KERNEL_FIXED_BYTES + KERNEL_LEAF_BYTES * k)
        {
            revert KernelBadOutput();
        }
        uint256 releaseTo = _mw(out, 320);
        if (releaseTo > type(uint160).max) revert KernelBadOutput();
        if (valid == 0) revert KernelRejected();
        // A valid result above the profile's leaf bound is a budget refusal, never a truncation.
        if (k > BridgeBounds.MAX_LEAVES) revert BudgetExceeded();
        r.cfg = bytes32(_mw(out, 96));
        r.nonce = _mw(out, 128);
        r.amount = _mw(out, 160);
        r.tokenId = bytes32(_mw(out, 192));
        r.salt = bytes32(_mw(out, 224));
        r.firstPredicateHash = bytes32(_mw(out, 256));
        r.lockDigest = bytes32(_mw(out, 288));
        // forge-lint: disable-next-line(unsafe-typecast)
        r.releaseTo = address(uint160(releaseTo));
        r.nullifier = bytes32(_mw(out, 352));
        r.leaves = new Leaf[](k);
        for (uint256 i = 0; i < k; ++i) {
            uint256 o = KERNEL_FIXED_BYTES + KERNEL_LEAF_BYTES * i;
            // The time word is a uint64: any set high bit is a noncanonical output.
            uint256 t = _mw(out, o + 64);
            if (t > type(uint64).max) revert KernelBadOutput();
            r.leaves[i] = Leaf({
                sid: bytes32(_mw(out, o)),
                txHash: bytes32(_mw(out, o + 32)),
                // forge-lint: disable-next-line(unsafe-typecast)
                referenceTime: uint64(t),
                leafValue: bytes32(_mw(out, o + 96))
            });
        }
    }

    function _mw(bytes memory b, uint256 off) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := mload(add(add(b, 32), off))
        }
    }

    /// @dev Operation-specific result shape. The kernel result alone never authorizes anything; these
    ///      are the fixed-profile facts the vault relies on.
    function _checkShape(uint8 op, KernelResult memory r, Cfg memory c, bytes32 ch) private pure {
        if (r.cfg != ch) revert KernelCfgMismatch(ch, r.cfg);
        if (
            r.nonce == 0 || r.nonce > type(uint64).max || r.amount == 0
                || r.lockDigest == bytes32(0)
        ) {
            revert KernelResultShape();
        }
        uint256 n = r.leaves.length;
        if (op == OP_PREPARE_LOCK) {
            if (n != 0 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {
                revert KernelResultShape();
            }
        } else if (op == OP_MINT) {
            if (n != 1 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {
                revert KernelResultShape();
            }
        } else {
            // One leaf per transaction: the mint and at least the final burn (the leaf bound is checked
            // in `_parseKernel`).
            if (
                n < 2 || r.releaseTo == address(0) || r.releaseTo == c.vault
                    || r.nullifier == bytes32(0)
            ) revert KernelResultShape();
        }
    }
}
// forge-lint: disable-end(require-revert-in-loop)
