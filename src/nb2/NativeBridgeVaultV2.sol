// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {NB2VaultBase} from "./NB2VaultBase.sol";

/// @notice The production build of the native bridge v2 vault (bft-core docs/design/native-bridge-v2.md section 4.1): it admits
///         only (K, B) = (64, 16), fixed by the NB2-02 gas bake-off (bft-core#1098). Every rule is in NB2VaultBase.
contract NativeBridgeVaultV2 is NB2VaultBase {
    constructor(bytes memory gamma) NB2VaultBase(gamma, 1 << 64, 1 << 16) {}
}
