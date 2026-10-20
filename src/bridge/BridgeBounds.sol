// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice The one resource policy and the published gas estimate of the any-age composing verifier (owner §36,
///         bft-core briefs/b7-direct-uncapped-design.md section 1). This file is the one place the contract names them: the oracle
///         (bft-core `bridgeprofile`) and `native-bridge-plugins` carry the same numbers. There is no gas ceiling and no bridge-specific
///         history cap: the aggregate bounds are the native kernels' own (B2 transfers and history, B1 claims) and the envelope bound is
///         an ingress bound; the rest are per-object shape bounds. The estimate below is what a wallet sets its gas limit from; the
///         contract never compares it with a budget, and a call given too little gas runs out of gas and reverts. The native batch's
///         price is `CertGroups.batchGas` (one formula for the estimate and the precompile).
library BridgeBounds {
    // ---- resource policy ------------------------------------------------------------------------
    /// @dev Distinct UC anchors of one redemption (one per distinct complete UC), and at most the leaves: B1's claim ceiling (K <= 16).
    uint256 internal constant MAX_ANCHORS = 16;
    /// @dev The kernel's own leaf output bound (ureth b2 `MAX_TRANSFERS` 64 plus the mint): visited transaction/leaf occurrences L
    ///      across the whole recursive verification (mint, transfers, burn and embedded dependencies). It also sizes the returndata
    ///      buffer. A history whose leaves each carry their own certificate can need more than MAX_ANCHORS anchors (refused).
    uint256 internal constant KERNEL_MAX_LEAVES = 65;
    uint256 internal constant MAX_LEAVES = KERNEL_MAX_LEAVES;
    uint256 internal constant MAX_ANCHOR_UC_BYTES = 8 * 1024;
    uint256 internal constant MAX_RSMT_SIBLINGS = 32;
    /// @dev ureth b2 `MAX_HISTORY`.
    uint256 internal constant MAX_SEMANTIC_BYTES = 128 * 1024;
    /// @dev The ingress bound: above every envelope the native bounds admit; the pool and RPC are configured to carry it.
    uint256 internal constant MAX_ENVELOPE_BYTES = 512 * 1024;
    /// @dev Items of the fixed-shape objects the verifier opens itself: Cfg (array head and 16 fields), the policy (array head and 3
    ///      fields) and each anchor's InputRecord opening (tag, array head and 10 fields). They are part of the estimate's J.
    uint256 internal constant CFG_ITEMS = 17;
    uint256 internal constant POLICY_ITEMS = 4;
    uint256 internal constant IR_ITEMS = 12;

    // ---- gas estimate ---------------------------------------------------------------------------
    uint256 internal constant GAS_RESERVE = 1_000_000;
    /// @dev `G_items = 1000*J`: the executed EVM overhead per CBOR item occurrence Solidity traverses (arch's ruling of 2026-10-14). It is
    ///      composition work, never forwarded to a precompile.
    uint256 internal constant ITEM_GAS = 1_000;

    uint256 internal constant INTRINSIC_BASE = 21_000;
    uint256 internal constant PER_BYTE = 16;
    /// @dev The composing verifier's own execution per envelope byte (decode, scans, hashing, memory), priced at 80 and conditional on the
    ///      full-composition measurement before the profile is pinned.
    uint256 internal constant EXEC_PER_BYTE = 80;
    uint256 internal constant B2_BASE = 26_000;
    uint256 internal constant B2_PER_BYTE = 20;
    uint256 internal constant B2_PER_LEAF = 14_000;
    uint256 internal constant PER_STEP = 250;
    uint256 internal constant RSMT_BASE = 2_000;
    /// @dev RSMT_MEMBER_V1 request without siblings.
    uint256 internal constant RSMT_REQUEST_FIXED = 136;
    /// @dev The canonical two-bytes-argument call: selector 4, two offsets and two lengths 128.
    uint256 internal constant CALL_FIXED = 4 + 128;

    /// @dev `D_max = 4 + 128 + pad32(B_cfg) + pad32(B_env)`: the calldata of the canonical `TokenVerifier` call, an allowance larger than
    ///      the one-bytes-argument vault redeem call.
    function maxCalldata(uint256 cfgBytes, uint256 envelopeBytes) internal pure returns (uint256) {
        return CALL_FIXED + _pad32(cfgBytes) + _pad32(envelopeBytes);
    }

    /// @dev `21000 + 16*D_max + 80*B_env`.
    function intrinsicGas(uint256 cfgBytes, uint256 envelopeBytes) internal pure returns (uint256) {
        return INTRINSIC_BASE + PER_BYTE * maxCalldata(cfgBytes, envelopeBytes) + EXEC_PER_BYTE
            * envelopeBytes;
    }

    /// @dev `B_kernel = 160 + pad32(B_cfg) + pad32(B_history)`, i.e. `len(abi.encode(uint8 op, bytes cfg, bytes payload))`.
    function kernelRequestBytes(uint256 cfgBytes, uint256 payloadBytes)
        internal
        pure
        returns (uint256)
    {
        return 96 + 32 + _pad32(cfgBytes) + 32 + _pad32(payloadBytes);
    }

    /// @dev `G_kernel = 26000 + 20*B_kernel + 14000*L`.
    function b2Gas(uint256 requestBytes, uint256 leaves) internal pure returns (uint256) {
        return B2_BASE + B2_PER_BYTE * requestBytes + B2_PER_LEAF * leaves;
    }

    /// @dev `G_leaf(i) = 2000 + 16*(136 + 32*p_i) + 250*(1 + p_i)`.
    function rsmtGas(uint256 siblings) internal pure returns (uint256) {
        return
            RSMT_BASE + PER_BYTE * (RSMT_REQUEST_FIXED + 32 * siblings) + PER_STEP * (1 + siblings);
    }

    function _pad32(uint256 n) private pure returns (uint256) {
        return (n + 31) & ~uint256(31);
    }

    /// @dev Number of set bits of a 256-bit word, branch-free (eight halving steps).
    function popcount(uint256 x) internal pure returns (uint256) {
        unchecked {
            x = (x & M1) + ((x >> 1) & M1);
            x = (x & M2) + ((x >> 2) & M2);
            x = (x & M4) + ((x >> 4) & M4);
            x = (x & M8) + ((x >> 8) & M8);
            x = (x & M16) + ((x >> 16) & M16);
            x = (x & M32) + ((x >> 32) & M32);
            x = (x & M64) + ((x >> 64) & M64);
            return (x & M128) + (x >> 128);
        }
    }

    uint256 private constant M1 =
        0x5555555555555555555555555555555555555555555555555555555555555555;
    uint256 private constant M2 =
        0x3333333333333333333333333333333333333333333333333333333333333333;
    uint256 private constant M4 =
        0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
    uint256 private constant M8 =
        0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;
    uint256 private constant M16 =
        0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;
    uint256 private constant M32 =
        0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;
    uint256 private constant M64 =
        0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
    uint256 private constant M128 =
        0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff;
}
