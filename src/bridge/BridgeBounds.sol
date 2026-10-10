// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice The named bounds and the shared gas gate of the profile-v3 composing verifier. This file is
///         the one place the contract names them: the oracle (bft-core `bridgeprofile` `limits.go`,
///         `gas.go`), the plug-ins and `native-bridge-plugins` `protocol/profile-v3.json` `limits` carry
///         the same numbers. They bound the parsers; the gate below decides each bundle against the
///         7,000,000 ordinary transaction capacity; a later profile version raises them together
///         with the budget. Nothing else in this repository states them as literals.
library BridgeBounds {
    // ---- profile parameters (profile-v3.json `limits`) ----------------------------------------
    /// @dev Distinct UC anchors of one redemption (one per distinct complete UC): a parser ceiling; the
    ///      gate below admits or refuses each bundle (two anchors at every cap fit, five never can).
    uint256 internal constant MAX_ANCHORS = 4;
    /// @dev Exported kernel leaves of one redemption (mint plus transfers plus the final burn).
    uint256 internal constant MAX_LEAVES = 16;
    uint256 internal constant MAX_ANCHOR_UC_BYTES = 8 * 1024;
    uint256 internal constant MAX_RSMT_SIBLINGS = 32;
    uint256 internal constant MAX_SEMANTIC_BYTES = 16 * 1024;
    uint256 internal constant MAX_ENVELOPE_BYTES = 64 * 1024;
    /// @dev Cumulative path steps over all anchors and leaf paths (oracle `MaxPathSteps`). It cannot
    ///      bind: `MAX_ANCHORS * (1 + MAX_UNICITY_STEPS) + MAX_LEAVES * MAX_RSMT_SIBLINGS <= MAX_PATH_STEPS`.
    uint256 internal constant MAX_PATH_STEPS = 2048;
    /// @dev B1's own sublimits that the gate prices: unicity path steps and seal signatures.
    uint256 internal constant MAX_UNICITY_STEPS = 32;
    uint256 internal constant MAX_SIGNATURES = 64;
    /// @dev The kernel's own leaf output bound (ureth `MaxTransfers` 64 plus the mint); it sizes the
    ///      returndata buffer only. A result above `MAX_LEAVES` is `BudgetExceeded`.
    uint256 internal constant KERNEL_MAX_LEAVES = 65;

    // ---- gate ---------------------------------------------------------------------------------
    /// @dev DN-B ordinary transaction capacity (`maxGas` minus system gas).
    uint256 internal constant TX_GAS_BUDGET = 7_000_000;
    uint256 internal constant GAS_RESERVE = 1_000_000;

    uint256 internal constant INTRINSIC_BASE = 21_000;
    uint256 internal constant PER_BYTE = 16;
    uint256 internal constant B2_BASE = 26_000;
    uint256 internal constant B2_PER_BYTE = 20;
    uint256 internal constant B2_PER_LEAF = 14_000;
    uint256 internal constant UC_BASE = 1_243_700;
    uint256 internal constant UC_PER_SIGNATURE = 6_000;
    uint256 internal constant PER_STEP = 250;
    uint256 internal constant RSMT_BASE = 2_000;
    /// @dev UC_V1 request without shard and UC: header 4, partition 4, shard length 2, three words, UC length 4.
    uint256 internal constant UC_REQUEST_FIXED = 110;
    /// @dev RSMT_MEMBER_V1 request without siblings.
    uint256 internal constant RSMT_REQUEST_FIXED = 136;

    /// @dev `G_intrinsic = 21000 + 16*len(envelope)`.
    function intrinsicGas(uint256 envelopeBytes) internal pure returns (uint256) {
        return INTRINSIC_BASE + PER_BYTE * envelopeBytes;
    }

    /// @dev `len(abi.encode(uint8 op, bytes cfg, bytes payload))`.
    function kernelRequestBytes(uint256 cfgBytes, uint256 payloadBytes)
        internal
        pure
        returns (uint256)
    {
        return 96 + 32 + _pad32(cfgBytes) + 32 + _pad32(payloadBytes);
    }

    /// @dev `G_B2 = 26000 + 20*B_sem + 14000*L`.
    function b2Gas(uint256 requestBytes, uint256 leaves) internal pure returns (uint256) {
        return B2_BASE + B2_PER_BYTE * requestBytes + B2_PER_LEAF * leaves;
    }

    /// @dev `G_UC = 1243700 + 16*B_a + 6000*S_a + 250*P_a` with `B_a = 110 + len(shard) + len(uc)`.
    function ucGas(uint256 shardBytes, uint256 ucBytes, uint256 signatures, uint256 steps)
        internal
        pure
        returns (uint256)
    {
        return UC_BASE + PER_BYTE * (UC_REQUEST_FIXED + shardBytes + ucBytes) + UC_PER_SIGNATURE
            * signatures + PER_STEP * steps;
    }

    /// @dev `G_RSMT = 2000 + 16*(136 + 32*s) + 250*(1 + s)`.
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
