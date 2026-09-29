// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Script} from "forge-std/Script.sol";
import {ImmutableVestingVault} from "../src/ImmutableVestingVault.sol";

/// @notice Captures one canonical test deployment, including its constructor immutables.
contract VestingVaultArtifacts is Script {
    address payable internal constant TEST_RECIPIENT =
        payable(0x000000000000000000000000000000000000bEEF);
    uint256 internal constant TEST_PRINCIPAL = 1 ether;
    uint64 internal constant TEST_START = 1_700_000_000;
    uint64 internal constant TEST_CLIFF = 31_536_000;
    uint64 internal constant TEST_DURATION = 126_144_000;

    function run() external {
        ImmutableVestingVault vault = new ImmutableVestingVault(
            TEST_RECIPIENT, TEST_PRINCIPAL, TEST_START, TEST_CLIFF, TEST_DURATION
        );
        string memory json =
            vm.serializeString("vestingVault", "profile", "t2/vesting-vault/test-v1");
        json = vm.serializeBytes("vestingVault", "runtimeBytecode", address(vault).code);
        json = vm.serializeBytes32("vestingVault", "codeHash", keccak256(address(vault).code));
        json = vm.serializeAddress("vestingVault", "testRecipient", TEST_RECIPIENT);
        json = vm.serializeUint("vestingVault", "testPrincipal", TEST_PRINCIPAL);
        json = vm.serializeUint("vestingVault", "testStart", TEST_START);
        json = vm.serializeUint("vestingVault", "testCliff", TEST_CLIFF);
        json = vm.serializeUint("vestingVault", "testDuration", TEST_DURATION);
        vm.writeJson(json, string.concat(vm.projectRoot(), "/out/vesting-vault-runtimes.json"));
    }
}
