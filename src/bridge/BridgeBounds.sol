// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice The bounds and the kernel charge the verifier still applies itself (`prepareLock` calls the kernel directly). The
///         resource policy and the gas of a mint or return are the native composition's (0x0105, bft-core `bridgeprofile`
///         `limits.go` and `ComposeGas`); there is no gas ceiling (owner §36).
library BridgeBounds {
    /// @dev ureth b2 `MAX_HISTORY`: the kernel's payload bound.
    uint256 internal constant MAX_SEMANTIC_BYTES = 128 * 1024;

    uint256 internal constant B2_BASE = 26_000;
    uint256 internal constant B2_PER_BYTE = 20;

    /// @dev `B_kernel = 160 + pad32(B_cfg) + pad32(B_payload)`, i.e. `len(abi.encode(uint8 op, bytes cfg, bytes payload))`.
    function kernelRequestBytes(uint256 cfgBytes, uint256 payloadBytes)
        internal
        pure
        returns (uint256)
    {
        return 96 + 32 + _pad32(cfgBytes) + 32 + _pad32(payloadBytes);
    }

    /// @dev `G_kernel = 26000 + 20*B_kernel` for a prepare request (no leaves; the kernel adds 14000 per leaf otherwise).
    function b2Gas(uint256 requestBytes) internal pure returns (uint256) {
        return B2_BASE + B2_PER_BYTE * requestBytes;
    }

    function _pad32(uint256 n) private pure returns (uint256) {
        return (n + 31) & ~uint256(31);
    }
}
