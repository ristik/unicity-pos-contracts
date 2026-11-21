// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {NB2Config} from "./NB2Config.sol";
import {NB2VaultBase} from "./NB2VaultBase.sol";
import {NB2VaultRecovered} from "./NB2VaultRecovered.sol";
import {FlatReceipts} from "./verifier/flat/FlatReceipts.sol";

/// @notice Ordinary-only NB2 v1.1 vault (fresh generation): the A side of the dispatch comparison. It runs exactly the code the
///         full vault runs for `deposit`, `redeem` and the views, without the cold route and without a recovery verifier.
contract NativeBridgeVault11Ordinary is NB2VaultBase {
    constructor(bytes memory gamma, bytes32 expectedProfile)
        NB2VaultBase(gamma, 1 << 64, 1 << 16, 2)
    {
        if (
            NB2Config.decode(gamma, 1 << 64, 1 << 16, 2).profile != expectedProfile
                || expectedProfile == 0
        ) {
            revert NB2Config.BadConfig(13);
        }
    }
}

/// @notice NB2 v1.1 native vault, production build (K, B) = (64, 16): ordinary `redeem` and cold `redeemRecovered`, one payment
///         routine. The verifier graph is pinned at construction: the ordinary verifier and its runtime hash through Γ, the
///         profile digest through `expectedProfile`, and the recovery verifier by address and runtime hash with every binding it
///         publishes (this vault, this domain, this ordinary verifier, its receipt helper and that helper's runtime hash).
contract NativeBridgeVault11 is NB2VaultRecovered {
    constructor(
        bytes memory gamma,
        address recovery,
        bytes32 recoveryRuntime,
        bytes32 expectedProfile
    ) NB2VaultRecovered(gamma, 1 << 64, 1 << 16, recovery, recoveryRuntime, expectedProfile) {}
}

/// @notice The same vault for the NB2 test configuration (K in {4, 8}, B in {2, 4}). Never deploy it for real value.
contract NativeBridgeVault11Test is NB2VaultRecovered {
    constructor(
        bytes memory gamma,
        address recovery,
        bytes32 recoveryRuntime,
        bytes32 expectedProfile
    )
        NB2VaultRecovered(
            gamma,
            (1 << 4) | (1 << 8),
            (1 << 2) | (1 << 4),
            recovery,
            recoveryRuntime,
            expectedProfile
        )
    {}
}
