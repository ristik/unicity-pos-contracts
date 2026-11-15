// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice Native bridge v2 token and receipt verifier (bft-core docs/design/native-bridge-v2.md section 11.2, protocol 9).
///         Stateless, no owner and no configuration of its own: it receives the exact Γ bytes on every call. It reverts with the
///         custom error `<RuleName>()` of section 14 on every refusal and, on acceptance, returns the authenticated
///         `(D, eta, a, asset, recipient, v)` of the returned part. Selector 0xdf447dca.
interface INativeBridgeVerifierV2 {
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
        );
}
