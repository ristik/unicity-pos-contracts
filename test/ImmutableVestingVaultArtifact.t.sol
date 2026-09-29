// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {ImmutableVestingVault} from "../src/ImmutableVestingVault.sol";

contract ImmutableVestingVaultArtifactTest is Test {
    string internal constant ARTIFACT = "artifacts/vesting-vault-test-v1.json";
    address payable internal constant TEST_RECIPIENT =
        payable(0x000000000000000000000000000000000000bEEF);
    uint256 internal constant TEST_PRINCIPAL = 1 ether;
    uint64 internal constant TEST_START = 1_700_000_000;
    uint64 internal constant TEST_CLIFF = 31_536_000;
    uint64 internal constant TEST_DURATION = 126_144_000;

    function testArtifactRuntimeAndCodeHashMatchCanonicalDeployment() public {
        string memory json = vm.readFile(ARTIFACT);
        ImmutableVestingVault vault = new ImmutableVestingVault(
            TEST_RECIPIENT, TEST_PRINCIPAL, TEST_START, TEST_CLIFF, TEST_DURATION
        );

        assertEq(vm.parseJsonBytes(json, ".runtimeBytecode"), address(vault).code);
        assertEq(vm.parseJsonBytes32(json, ".codeHash"), keccak256(address(vault).code));
    }

    function testArtifactRecordsPinnedCompilerAndConstructorValues() public view {
        string memory json = vm.readFile(ARTIFACT);
        assertEq(vm.parseJsonString(json, ".profile"), "t2/vesting-vault/test-v1");
        assertEq(vm.parseJsonString(json, ".compiler.solc"), "0.8.37");
        assertEq(vm.parseJsonString(json, ".compiler.evm_version"), "cancun");
        assertTrue(vm.parseJsonBool(json, ".compiler.via_ir"));
        assertTrue(vm.parseJsonBool(json, ".compiler.optimizer"));
        assertEq(vm.parseJsonUint(json, ".compiler.optimizer_runs"), 200);
        assertEq(vm.parseJsonString(json, ".compiler.bytecode_hash"), "none");
        assertFalse(vm.parseJsonBool(json, ".compiler.cbor_metadata"));
        assertEq(vm.parseJsonAddress(json, ".constructorTestValues.recipient"), TEST_RECIPIENT);
        assertEq(vm.parseJsonUint(json, ".constructorTestValues.principal"), TEST_PRINCIPAL);
        assertEq(vm.parseJsonUint(json, ".constructorTestValues.start"), TEST_START);
        assertEq(vm.parseJsonUint(json, ".constructorTestValues.cliff"), TEST_CLIFF);
        assertEq(vm.parseJsonUint(json, ".constructorTestValues.duration"), TEST_DURATION);
    }
}
