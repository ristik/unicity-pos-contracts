// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {BridgeVault} from "../src/bridge/BridgeVault.sol";
import {TokenVerifier} from "../src/bridge/TokenVerifier.sol";
import {B1Calls} from "../src/bridge/B1Calls.sol";
import {Deployment} from "../src/bridge/BridgeTypes.sol";
import {
    BridgeGenesisBinding,
    GenesisIdentity,
    RegistryProfileMismatch
} from "./BridgeGenesisBinding.sol";

/// @notice Deploys the TokenVerifier and the BridgeVault for one registry genesis, after asserting that
///         the vault's `rootGenesis`, `executionGenesis` and `b1ProfileHash` are the genesis' own and
///         that the registry on the target chain carries the same profile hash.
///
///         Inputs (both read from `script/bridge-deploy/`, the only readable directory):
///         - `BRIDGE_GENESIS`: the genesis tool's identity document, with `rootGenesisId`,
///           `evmGenesisHash`, `profileHash`, `executionChainId` and `registryWords` (a map keyed by
///           storage slot; the `b1.profileHash` word is required).
///         - `BRIDGE_DEPLOYMENT`: `network`, `rootGenesis`, `executionGenesis`, `evmPartition`,
///           `evmShard`, `semanticProfileHash`, `b1ProfileHash`, `policyBody`.
///         The vault is configured from the deployment document; the genesis document only judges it.
contract BridgeDeploy is Script {
    using stdJson for string;

    function run() external returns (BridgeVault vault, TokenVerifier verifier) {
        string memory g = vm.readFile(vm.envString("BRIDGE_GENESIS"));
        string memory dep = vm.readFile(vm.envString("BRIDGE_DEPLOYMENT"));
        GenesisIdentity memory id = readGenesis(g);
        Deployment memory d = readDeployment(dep);

        assertBound(d, id);

        vm.startBroadcast();
        verifier = new TokenVerifier();
        d.tokenVerifier = address(verifier);
        d.tokenVerifierCodeHash = address(verifier).codehash;
        vault = new BridgeVault(d);
        vm.stopBroadcast();
    }

    /// @notice The deployment equals the genesis, and the registry on the target chain holds the
    ///         genesis' profile hash (the node serves the registry the genesis allocated).
    function assertBound(Deployment memory d, GenesisIdentity memory id) public view {
        BridgeGenesisBinding.check(d, id, block.chainid);
        bytes32 live = vm.load(B1Calls.REGISTRY, BridgeGenesisBinding.profileSlot());
        if (live != id.profileHash) revert RegistryProfileMismatch(live, id.profileHash);
    }

    function readGenesis(string memory g) public pure returns (GenesisIdentity memory id) {
        id.rootGenesisId = g.readBytes32(".rootGenesisId");
        id.evmGenesisHash = g.readBytes32(".evmGenesisHash");
        id.profileHash = g.readBytes32(".profileHash");
        id.chainId = SafeCast.toUint64(g.readUint(".executionChainId"));
        id.registryProfileWord = g.readBytes32(
            string.concat(".registryWords.", vm.toString(BridgeGenesisBinding.profileSlot()))
        );
    }

    function readDeployment(string memory dep) public pure returns (Deployment memory d) {
        d.network = SafeCast.toUint16(dep.readUint(".network"));
        d.rootGenesis = dep.readBytes32(".rootGenesis");
        d.executionGenesis = dep.readBytes32(".executionGenesis");
        d.evmPartition = SafeCast.toUint32(dep.readUint(".evmPartition"));
        d.evmShard = dep.readBytes(".evmShard");
        d.semanticProfileHash = dep.readBytes32(".semanticProfileHash");
        d.b1ProfileHash = dep.readBytes32(".b1ProfileHash");
        d.policyBody = dep.readBytes(".policyBody");
    }
}
