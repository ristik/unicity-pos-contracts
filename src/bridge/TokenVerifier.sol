// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {B1Calls} from "./B1Calls.sol";
import {BridgeBounds} from "./BridgeBounds.sol";
import {BridgeProfile} from "./BridgeProfile.sol";
import {Cfg, KernelResult} from "./BridgeTypes.sol";
import {
    BridgeRejected,
    BudgetExceeded,
    ChainIdMismatch,
    KernelBadOutput,
    KernelCfgMismatch,
    KernelRejected,
    KernelResultShape,
    PrecompileBadReturn,
    WrongVerifier
} from "./BridgeErrors.sol";

/// @notice Stateless verifier of the native bridge (B7 direct path, owner §36; protocol 6: a redeemed token may be a part of a split
///         lock). The composed relation of a mint or a return (framing and the resource policy, the policy body, the lineage from
///         the lock-backed root to the redeemed part, the anchor table, ONE registry-backed certificate batch, the IR openings and
///         leaf times, one RSMT membership per leaf) runs natively in `BRIDGE_COMPOSE_V2` at 0x0105 (bft-core
///         `bridgeprofile.NativeComposeV2`, docs/design/bridge-split-lineage-spec.md section 5); this contract binds the configuration (the
///         pinned verifier, the chain, the Cfg hash), forwards the call, and checks the fixed-size result. `prepareLock` calls
///         the kernel directly. It stores nothing and authorizes nothing: only a vault whose immutable cfg equals the result's
///         cfg may act on it. There is no gas ceiling: a call given too little gas runs out of gas and reverts.
contract TokenVerifier {
    uint8 internal constant OP_PREPARE_LOCK = 0;
    uint8 internal constant OP_MINT = 1;
    uint8 internal constant OP_RETURN = 2;

    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 internal constant KERNEL_MARKER = bytes32("UNICITY_TOKEN_SEMANTICS");
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 internal constant COMPOSE_MARKER = bytes32("UNICITY_BRIDGE_COMPOSE_V2");

    /// @dev The kernel's prepare result: head (3 words), Result static part (10 words) and the empty leaf array's length.
    uint256 internal constant KERNEL_FIXED_BYTES = 448;
    /// @dev The composition's result, fifteen words: marker, status, the ROOT lock's cfg, nonce, amount, tokenId, salt, firstPredicateHash,
    ///      lockDigest, the part's releaseTo and nullifier, the leaf count, then partTokenId, partAmount, splitDepth.
    uint256 internal constant COMPOSE_BYTES = 480;

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

    /// @dev One native call forwarded all the gas left (the composition meters itself and halts when it runs out). A nonzero
    ///      status is the native refusal, named by its code (bft-core `ComposeStatus`).
    function _verify(uint8 op, bytes calldata cfgBytes, bytes calldata proof)
        private
        view
        returns (KernelResult memory r)
    {
        (Cfg memory c, bytes32 ch) = _openCfg(cfgBytes);
        bytes memory out = B1Calls.staticCall(
            B1Calls.COMPOSE, abi.encode(op, cfgBytes, proof), COMPOSE_BYTES, gasleft()
        );
        if (out.length != COMPOSE_BYTES || _mw(out, 0) != uint256(COMPOSE_MARKER)) {
            revert PrecompileBadReturn(B1Calls.COMPOSE);
        }
        uint256 status = _mw(out, 32);
        if (status != 0) revert BridgeRejected(status);
        uint256 releaseTo = _mw(out, 288);
        if (releaseTo > type(uint160).max) revert PrecompileBadReturn(B1Calls.COMPOSE);
        r.cfg = bytes32(_mw(out, 64));
        r.nonce = _mw(out, 96);
        r.amount = _mw(out, 128);
        r.tokenId = bytes32(_mw(out, 160));
        r.salt = bytes32(_mw(out, 192));
        r.firstPredicateHash = bytes32(_mw(out, 224));
        r.lockDigest = bytes32(_mw(out, 256));
        // forge-lint: disable-next-line(unsafe-typecast)
        r.releaseTo = address(uint160(releaseTo));
        r.nullifier = bytes32(_mw(out, 320));
        r.leafCount = _mw(out, 352);
        r.partTokenId = bytes32(_mw(out, 384));
        r.partAmount = _mw(out, 416);
        r.splitDepth = _mw(out, 448);
        if (r.splitDepth > type(uint64).max) revert PrecompileBadReturn(B1Calls.COMPOSE);
        _checkShape(op, r, c, ch);
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

    function _kernel(uint8 op, bytes memory cfgBytes, bytes memory payload)
        private
        view
        returns (KernelResult memory)
    {
        // A prepare result has no leaves: the forwarded gas is the kernel's charge of the request alone.
        bytes memory out = B1Calls.staticCall(
            B1Calls.KERNEL,
            abi.encode(op, cfgBytes, payload),
            KERNEL_FIXED_BYTES,
            BridgeBounds.b2Gas(BridgeBounds.kernelRequestBytes(cfgBytes.length, payload.length))
        );
        return _parseKernel(out);
    }

    /// @dev Strict parse of the prepare result `abi.encode(bytes32 marker, bool valid, Result)` with no leaves: exactly 448
    ///      bytes with the canonical offsets. Anything else is `KernelBadOutput`; a well-formed `valid=false` is
    ///      `KernelRejected`.
    function _parseKernel(bytes memory out) private pure returns (KernelResult memory r) {
        if (out.length != KERNEL_FIXED_BYTES || _mw(out, 0) != uint256(KERNEL_MARKER)) {
            revert KernelBadOutput();
        }
        uint256 valid = _mw(out, 32);
        if (valid > 1 || _mw(out, 64) != 0x60 || _mw(out, 384) != 0x140 || _mw(out, 416) != 0) {
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
        // A prepared lock is whole: its part is the root.
        r.partTokenId = r.tokenId;
        r.partAmount = r.amount;
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
        uint256 n = r.leafCount;
        if (op == OP_PREPARE_LOCK) {
            // `_parseKernel` admits no leaves in a prepare result.
            if (r.releaseTo != address(0) || r.nullifier != bytes32(0)) {
                revert KernelResultShape();
            }
        } else if (op == OP_MINT) {
            // A mint is the root's: depth 0, the part is the root.
            if (
                n != 1 || r.releaseTo != address(0) || r.nullifier != bytes32(0)
                    || r.splitDepth != 0 || r.partTokenId != r.tokenId || r.partAmount != r.amount
            ) revert KernelResultShape();
        } else {
            // Every token of the lineage has its mint and at least its terminal burn: 2 * (depth + 1) leaves at least.
            if (
                n < 2 || r.splitDepth > (n - 2) / 2 || r.releaseTo == address(0)
                    || r.releaseTo == c.vault || r.nullifier == bytes32(0)
            ) revert KernelResultShape();
            // The redeemed part: a whole positive part of the lock, the root itself at depth 0 and another token otherwise.
            if (r.partTokenId == bytes32(0) || r.partAmount == 0 || r.partAmount > r.amount) {
                revert KernelResultShape();
            }
            if (r.splitDepth == 0) {
                if (r.partTokenId != r.tokenId || r.partAmount != r.amount) {
                    revert KernelResultShape();
                }
            } else if (r.partTokenId == r.tokenId) {
                revert KernelResultShape();
            }
        }
    }
}
