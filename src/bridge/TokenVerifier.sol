// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {B1Calls} from "./B1Calls.sol";
import {InputRecord} from "./InputRecord.sol";
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
    PolicyAnchorCount,
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
///         Order of checks: Cfg and environment, envelope framing and bounds, policy opening and
///         tuple, kernel, result shape, leaf obligations, one UC, one RSMT path per leaf. Everything
///         is a STATICCALL or pure; failure reverts with a named error and no state effect.
contract TokenVerifier {
    uint8 internal constant OP_PREPARE_LOCK = 0;
    uint8 internal constant OP_MINT = 1;
    uint8 internal constant OP_RETURN = 2;

    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 internal constant KERNEL_MARKER = bytes32("UNICITY_TOKEN_SEMANTICS");

    // DEV-DEFAULT ceilings (design "Gas and finite development limits"): test ceilings, not a claim
    // that maximum cases fit a block.
    uint256 internal constant MAX_ENVELOPE_BYTES = 256 * 1024;
    uint256 internal constant MAX_SEMANTIC_BYTES = 128 * 1024;
    uint256 internal constant MAX_LEAVES = 65;
    uint256 internal constant MAX_ANCHORS = 8;
    uint256 internal constant MAX_PATH_STEPS = 2048;

    /// @dev Result head (3 words), Result static part (10 words) and the array length.
    uint256 internal constant KERNEL_FIXED_BYTES = 448;
    /// @dev Four words per leaf since SDK 3.0.1: sid, txHash, uint64 referenceTime, leafValue.
    uint256 internal constant KERNEL_LEAF_BYTES = 128;
    uint256 internal constant KERNEL_MAX_BYTES = KERNEL_FIXED_BYTES + KERNEL_LEAF_BYTES
        * MAX_LEAVES;

    /// @notice Validates a lock request against the kernel and returns the values the vault compares
    ///         with its own: salt, token ID, first predicate hash and lock digest.
    function prepareLock(bytes calldata cfgBytes, uint256 nonce, uint256 amount, bytes calldata p0)
        external
        view
        returns (KernelResult memory r)
    {
        if (p0.length > MAX_SEMANTIC_BYTES) revert BudgetExceeded();
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

    /// @dev Public only so `_openEnvelope` can turn every ABI decoder failure into `EnvelopeFraming`
    ///      through try/catch; it has no other use and no state.
    function decodeEnvelope(bytes calldata proof)
        external
        pure
        returns (bytes memory, bytes memory, Anchor[] memory, LeafProof[] memory)
    {
        return abi.decode(proof, (bytes, bytes, Anchor[], LeafProof[]));
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
        // The policy body is opened and the one anchor tuple checked before the kernel and before
        // any B1 call; a submitted anchor table never chooses its own admission.
        _checkPolicy(c, policyBody, anchors);
        if (history.length > MAX_SEMANTIC_BYTES) revert BudgetExceeded();
        r = _kernel(op, cfgBytes, history);
        _checkShape(op, r, c, ch);
        _checkLeafProofs(r, paths);

        Anchor memory a = anchors[0];
        // B1 0x0100 authenticates the claim's expected state root and expected IR hash together.
        if (!B1Calls.verdict(B1Calls.UC_VERIFIER, B1Calls.ucRequest(a))) revert UCRejected();
        // Only now does the opening carry weight: it must hash to the authenticated IR hash and open
        // to the authenticated state root, and its timestamp is the bound of every leaf's time.
        uint64 anchorTime = InputRecord.open(a.inputRecord, a.expectedIRHash, a.expectedStateRoot);
        uint256 n = r.leaves.length;
        for (uint256 i = 0; i < n; ++i) {
            if (r.leaves[i].referenceTime > anchorTime) {
                revert IRTimeAfterAnchor(i, r.leaves[i].referenceTime, anchorTime);
            }
        }
        for (uint256 i = 0; i < n; ++i) {
            // Same authenticated shard state root as the UC just verified; sid is the key and the
            // raw 32-byte leaf value H(C(b(txHash),t)) the value. Neither txHash nor an imprint.
            bytes memory req = B1Calls.memberRequest(
                a.expectedStateRoot,
                r.leaves[i].sid,
                abi.encodePacked(r.leaves[i].leafValue),
                paths[i].bitmap,
                paths[i].siblings
            );
            if (!B1Calls.verdict(B1Calls.RSMT_VERIFIER, req)) revert LeafNotIncluded(i);
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
        view
        returns (
            bytes memory policyBody,
            bytes memory history,
            Anchor[] memory anchors,
            LeafProof[] memory paths
        )
    {
        if (proof.length > MAX_ENVELOPE_BYTES) revert BudgetExceeded();
        _boundCounts(proof);
        try this.decodeEnvelope(proof) returns (
            bytes memory p, bytes memory h, Anchor[] memory a, LeafProof[] memory l
        ) {
            (policyBody, history, anchors, paths) = (p, h, a, l);
        } catch {
            // A decoder failure leaves every output empty, and empty outputs cannot re-encode to
            // the input, so the single comparison below refuses it.
        }
        // Re-encoding must reproduce the input: rejects a decoder failure, noncanonical offsets,
        // padding, aliases and trailing data that the ABI decoder tolerates.
        if (keccak256(abi.encode(policyBody, history, anchors, paths)) != keccak256(proof)) {
            revert EnvelopeFraming();
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
        if (na > MAX_ANCHORS) revert BudgetExceeded();
        // Every anchor's InputRecord opening is bounded before anything is allocated: its length word
        // sits at the offset of the tuple's seventh head word.
        for (uint256 i = 0; i < na; ++i) {
            uint256 t = offAnchors + 32 + _word(b, offAnchors + 32 + 32 * i);
            if (_word(b, t + _word(b, t + 192)) > InputRecord.MAX_BYTES) revert BudgetExceeded();
        }
        uint256 nl = _word(b, offLeaves);
        if (nl > n) revert EnvelopeFraming();
        if (nl > MAX_LEAVES) revert BudgetExceeded();
        uint256 steps = 0;
        for (uint256 i = 0; i < nl; ++i) {
            uint256 rel = _word(b, offLeaves + 32 + 32 * i);
            uint256 t = offLeaves + 32 + rel;
            uint256 sRel = _word(b, t + 64);
            uint256 ns = _word(b, t + sRel);
            if (ns > MAX_PATH_STEPS - steps) revert BudgetExceeded();
            steps += ns;
        }
    }

    function _word(bytes calldata b, uint256 off) private pure returns (uint256 v) {
        if (off + 32 > b.length) revert EnvelopeFraming();
        v = uint256(bytes32(b[off:off + 32]));
        if (v > type(uint64).max) revert EnvelopeFraming();
    }

    /// @dev Hash first, interpretation second: the supplied body is compared with the immutable
    ///      `aggregatorPolicyHash` before it is decoded.
    function _checkPolicy(Cfg memory c, bytes memory body, Anchor[] memory anchors) private pure {
        if (body.length > BridgeProfile.MAX_POLICY_BYTES) revert BudgetExceeded();
        bytes32 h = sha256(body);
        if (h != c.aggregatorPolicyHash) revert PolicyHashMismatch(c.aggregatorPolicyHash, h);
        Policy memory p = BridgeProfile.decodePolicy(body);
        if (p.partition == c.evmPartition) revert PolicyPartitionIsEvm();
        if (anchors.length != 1) revert PolicyAnchorCount(anchors.length);
        Anchor memory a = anchors[0];
        if (
            a.partition != p.partition || a.shard.length != 1
                || a.shard[0] != BridgeProfile.EMPTY_PREFIX || a.shardConfHash != p.shardConfHash
        ) revert PolicyTupleMismatch();
    }

    /// @dev Exactly one path per exported leaf, every one against the single anchor.
    function _checkLeafProofs(KernelResult memory r, LeafProof[] memory paths) private pure {
        if (paths.length != r.leaves.length) revert PolicyLeafCount(r.leaves.length, paths.length);
        for (uint256 i = 0; i < paths.length; ++i) {
            if (paths[i].anchorIndex != 0) revert PolicyLeafIndex(i, paths[i].anchorIndex);
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
        bytes memory out = B1Calls.staticCall(
            B1Calls.KERNEL, abi.encode(op, cfgBytes, payload), KERNEL_MAX_BYTES
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
        if (k > MAX_LEAVES || len != KERNEL_FIXED_BYTES + KERNEL_LEAF_BYTES * k) {
            revert KernelBadOutput();
        }
        uint256 releaseTo = _mw(out, 320);
        if (releaseTo > type(uint160).max) revert KernelBadOutput();
        if (valid == 0) revert KernelRejected();
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
            // One leaf per transaction: the mint and at least the final burn (the 65-leaf cap is the
            // kernel output bound in `_parseKernel`).
            if (
                n < 2 || r.releaseTo == address(0) || r.releaseTo == c.vault
                    || r.nullifier == bytes32(0)
            ) revert KernelResultShape();
        }
    }
}
// forge-lint: disable-end(require-revert-in-loop)
