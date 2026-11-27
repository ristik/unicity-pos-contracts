// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {FlatBindings} from "../verifier/flat/FlatBindings.sol";

library ERC20Context {
    struct Recovery {
        bytes gamma;
        address ordinary;
        bytes32 generation;
        FlatBindings.ReleaseInputs release;
        bytes32 pins;
    }

    struct Vault {
        bytes gamma;
        address recovery;
        bytes32 recoveryHash;
        bytes32 profile;
    }
}

interface IERC20ActivationContext {
    function recoveryContext() external view returns (ERC20Context.Recovery memory);
    function vaultContext() external view returns (ERC20Context.Vault memory);
}
