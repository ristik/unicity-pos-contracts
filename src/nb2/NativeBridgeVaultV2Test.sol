// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {NB2VaultBase} from "./NB2VaultBase.sol";

/// @notice The test build of the native bridge v2 vault (bft-core docs/design/native-bridge-v2.md section 4.1): it admits the
///         separate test set K in {4, 8} x B in {2, 4} and never the production pair, so a Γ is valid for exactly one build.
///         It runs the production code unchanged (NB2VaultBase); the NB2-03 vectors' k4 and k8 deployments use it. Never
///         deploy it for real value.
contract NativeBridgeVaultV2Test is NB2VaultBase {
    constructor(bytes memory gamma)
        NB2VaultBase(gamma, (1 << 4) | (1 << 8), (1 << 2) | (1 << 4), 1)
    {}
}
