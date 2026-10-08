// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {Deployment} from "../../src/bridge/BridgeTypes.sol";
import {
    BridgeGenesisBinding,
    GenesisIdentity,
    GenesisIdentityMismatch,
    ChainIdMismatch,
    RegistryProfileMismatch
} from "../../script/BridgeGenesisBinding.sol";
import {BridgeDeploy} from "../../script/BridgeDeploy.s.sol";

/// @dev Calls the pure library through an external frame so `vm.expectRevert` sees the revert.
contract Binder {
    function check(Deployment memory d, GenesisIdentity memory g, uint256 chain) external pure {
        BridgeGenesisBinding.check(d, g, chain);
    }
}

contract GenesisBindingTest is Test {
    Binder internal binder = new Binder();
    BridgeDeploy internal script = new BridgeDeploy();
    GenesisIdentity internal id;
    Deployment internal dep;

    function setUp() public {
        id = script.readGenesis(vm.readFile("test/bridge/deploy/genesis.json"));
        dep = script.readDeployment(vm.readFile("test/bridge/deploy/deployment.json"));
    }

    function _check(Deployment memory d, GenesisIdentity memory g, uint256 chain) internal view {
        binder.check(d, g, chain);
    }

    function test_fixturesParseAndAgree() public view {
        assertEq(id.chainId, 31337);
        assertEq(id.profileHash, id.registryProfileWord);
        assertEq(dep.rootGenesis, id.rootGenesisId);
        _check(dep, id, 31337);
    }

    function test_rootGenesisMismatchIsNamed() public {
        Deployment memory d = dep;
        d.rootGenesis = bytes32(uint256(d.rootGenesis) ^ 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                GenesisIdentityMismatch.selector, "rootGenesis", d.rootGenesis, id.rootGenesisId
            )
        );
        _check(d, id, 31337);
    }

    function test_executionGenesisMismatchIsNamed() public {
        Deployment memory d = dep;
        d.executionGenesis = bytes32(uint256(d.executionGenesis) ^ 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                GenesisIdentityMismatch.selector,
                "executionGenesis",
                d.executionGenesis,
                id.evmGenesisHash
            )
        );
        _check(d, id, 31337);
    }

    function test_profileHashMismatchIsNamed() public {
        Deployment memory d = dep;
        d.b1ProfileHash = bytes32(uint256(d.b1ProfileHash) ^ 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                GenesisIdentityMismatch.selector, "b1ProfileHash", d.b1ProfileHash, id.profileHash
            )
        );
        _check(d, id, 31337);
    }

    function test_wrongChainIsRefused() public {
        vm.expectRevert(abi.encodeWithSelector(ChainIdMismatch.selector, uint64(31337), 1));
        _check(dep, id, 1);
    }

    function test_genesisWordDisagreeingWithItsProfileHashIsRefused() public {
        GenesisIdentity memory g = id;
        g.registryProfileWord = bytes32(uint256(g.registryProfileWord) ^ 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                RegistryProfileMismatch.selector, g.registryProfileWord, g.profileHash
            )
        );
        _check(dep, g, 31337);
    }

    // ---- the registry on the target chain -------------------------------------------------------

    function test_liveRegistryWithTheGenesisProfileIsAccepted() public {
        vm.chainId(31337);
        vm.store(B1Calls.REGISTRY, BridgeGenesisBinding.profileSlot(), id.profileHash);
        script.assertBound(dep, id);
    }

    function test_liveRegistryWithAnotherProfileIsRefused() public {
        vm.chainId(31337);
        bytes32 other = bytes32(uint256(id.profileHash) ^ 1);
        vm.store(B1Calls.REGISTRY, BridgeGenesisBinding.profileSlot(), other);
        vm.expectRevert(
            abi.encodeWithSelector(RegistryProfileMismatch.selector, other, id.profileHash)
        );
        script.assertBound(dep, id);
    }

    function test_absentRegistryIsRefused() public {
        vm.chainId(31337);
        vm.expectRevert(
            abi.encodeWithSelector(RegistryProfileMismatch.selector, bytes32(0), id.profileHash)
        );
        script.assertBound(dep, id);
    }
}
