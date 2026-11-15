// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// NB2-02 mock token verifier: evidence is the ABI encoding of the verdict, returned as is. It
/// stands in for NB2-05 (#1101) so the bake-off measures replay and settlement only.
contract MockVerifier {
    function verifyReturn(bytes calldata, bytes calldata evidence)
        external
        pure
        returns (bytes32, bytes32, uint64, bytes32, address, uint256)
    {
        return abi.decode(evidence, (bytes32, bytes32, uint64, bytes32, address, uint256));
    }
}
