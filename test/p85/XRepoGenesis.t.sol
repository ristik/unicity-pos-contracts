// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {P85Genesis} from "../../script/P85Genesis.s.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";

/// @notice The cross-repository genesis vector, contracts half. `fixtures/xrepo-genesis-input.json` is the file bft-core's
/// `ubft pos-relayer genesis --out-contracts` writes for a committed plan over the FULL shard configuration (bft-core
/// xrepo/testdata/genesis; its test also holds that the id in the file is the one the root names in the first CloseLiability).
/// Here the genesis script itself deploys from that file, exactly as script/p85-genesis.sh runs it, and custody must hold the
/// genesis assignment under the file's id with the file's identities: a renamed, re-typed or missing field on either side, or a
/// script that takes the id from somewhere else, fails here.
contract XRepoGenesisTest is Test {
    string internal constant INPUT = "/test/p85/fixtures/xrepo-genesis-input.json";

    function _f(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".identities[", vm.toString(i), "].", field);
    }

    function test_theGenesisScriptDeploysTheRootsGenesisInput() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), INPUT));
        string memory out = string.concat(vm.projectRoot(), "/script/genesis-out/xrepo-test");
        vm.createDir(out, true);
        // the script's inputs, as script/p85-genesis.sh passes them (these names are read by nothing else in the test suite)
        vm.setEnv("P85_GENESIS_JSON", json);
        vm.setEnv("P85_OUT", out);
        vm.setEnv("P85_CHAIN_ID", "31337");
        vm.setEnv("P85_NETWORK_WORD", vm.toString(keccak256("xrepo-genesis-network")));
        vm.setEnv("P85_ROOT_NETWORK", "5");
        vm.setEnv("P85_ROOT_GENESIS", vm.toString(keccak256("xrepo-root-genesis")));
        vm.setEnv("P85_ROOTS", "0xff00000000000000000000000000000000000002");
        vm.setEnv("P85_TREASURY", "0x00000000000000000000000000000000000000fe");
        vm.setEnv("P85_V_MAX", "16");
        vm.setEnv("P85_L_MAX", "2");
        vm.setEnv("P85_N_MAX", "8");
        vm.setEnv("P85_CADENCE_ROUNDS", "100000");
        vm.setEnv("P85_CADENCE_SECONDS", "604800");

        new P85Genesis().run();

        string memory dep = vm.readFile(string.concat(out, "/deployment.json"));
        StakeCustody custody = StakeCustody(vm.parseJsonAddress(dep, ".custody"));
        bytes32 assignment = vm.parseJsonBytes32(json, ".assignmentId");
        assertTrue(assignment != bytes32(0), "the file names an assignment");
        assertEq(
            custody.lastAckedAssignment(),
            assignment,
            "custody's genesis assignment is the id in the root's file"
        );
        bytes32[] memory exposures = custody.assignmentExposures(assignment);
        uint256 n;
        while (vm.keyExistsJson(json, _f(n, "owner"))) ++n;
        assertGt(n, 0, "the file names identities");
        assertEq(exposures.length, n, "one exposure per identity of the file");
        for (uint256 i; i < n; ++i) {
            (
                ,
                uint64 id,
                uint64 generation,,,
                bytes32 rootKeyHash,
                bytes32 evmKeyHash,
                address operatorPayee,,
            ) = custody.exposures(exposures[i]);
            assertEq(id, i + 1, "custody numbers the identities 1..N in the file's order");
            assertEq(generation, 1, "first generation");
            assertEq(rootKeyHash, keccak256(vm.parseJsonBytes(json, _f(i, "rootKey"))), "root key");
            assertEq(evmKeyHash, keccak256(vm.parseJsonBytes(json, _f(i, "evmKey"))), "EVM key");
            assertEq(operatorPayee, vm.parseJsonAddress(json, _f(i, "payee")), "operator payee");
            (address owner, address withdrawal,,,,,,,) = custody.positions(uint64(i + 1));
            assertEq(owner, vm.parseJsonAddress(json, _f(i, "owner")), "owner");
            assertEq(withdrawal, vm.parseJsonAddress(json, _f(i, "withdrawal")), "withdrawal");
            uint256[] memory lots = custody.exposureLots(exposures[i]);
            assertEq(lots.length, 1, "one genesis lot");
            assertEq(lots[0], i + 1, "the lot ids the root's plan assumes (1..N)");
        }
    }
}
