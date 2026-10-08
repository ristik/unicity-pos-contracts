// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {B1Layout} from "../src/B1Layout.sol";
import {Deployment} from "../src/bridge/BridgeTypes.sol";

/// @notice The identities of one registry genesis, as the genesis tool emits them: the root genesis
///         ID, the hash of the EVM partition's genesis block (the vault's `executionGenesis`) and the
///         B1 profile hash. `registryProfileWord` is the profile-hash word of the registry's genesis
///         allocation (`b1.profileHash`), which the registry itself holds on chain.
struct GenesisIdentity {
    bytes32 rootGenesisId;
    bytes32 evmGenesisHash;
    bytes32 profileHash;
    bytes32 registryProfileWord;
    uint64 chainId;
}

/// @dev A vault identity differs from the registry genesis. `field` names it.
error GenesisIdentityMismatch(string field, bytes32 vault, bytes32 genesis);
/// @dev The deployment target is not the genesis' execution chain: the vault derives its type and
///      asset from `block.chainid`, so deploying elsewhere would bind it to another identity.
error ChainIdMismatch(uint64 genesis, uint256 target);
/// @dev The registry on the target chain holds another profile hash than the genesis allocation.
error RegistryProfileMismatch(bytes32 onChain, bytes32 genesis);

/// @notice Deployment-time binding of the vault to the registry genesis. The vault itself takes
///         `rootGenesis`, `executionGenesis` and `b1ProfileHash` as constructor inputs and cannot
///         compare them with the registry (the root genesis and the EVM genesis hash are not
///         readable on chain), so the deployment tooling does: a vault configured with any other
///         value would pass the same contract tests and every B1 proof of it would fail or, worse,
///         bind a different type and asset identity. Pure and callable from tests.
library BridgeGenesisBinding {
    /// @notice Reverts unless the three vault identities and the chain equal the genesis'.
    function check(Deployment memory d, GenesisIdentity memory g, uint256 targetChainId)
        internal
        pure
    {
        if (g.profileHash != g.registryProfileWord) {
            revert RegistryProfileMismatch(g.registryProfileWord, g.profileHash);
        }
        if (d.rootGenesis != g.rootGenesisId) {
            revert GenesisIdentityMismatch("rootGenesis", d.rootGenesis, g.rootGenesisId);
        }
        if (d.executionGenesis != g.evmGenesisHash) {
            revert GenesisIdentityMismatch("executionGenesis", d.executionGenesis, g.evmGenesisHash);
        }
        if (d.b1ProfileHash != g.profileHash) {
            revert GenesisIdentityMismatch("b1ProfileHash", d.b1ProfileHash, g.profileHash);
        }
        if (uint256(g.chainId) != targetChainId) revert ChainIdMismatch(g.chainId, targetChainId);
    }

    /// @notice The registry's own profile hash word, from its storage on the target chain.
    function profileSlot() internal pure returns (bytes32) {
        return B1Layout.F_PROFILE_HASH;
    }
}
