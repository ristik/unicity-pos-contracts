// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {FeeCollector} from "../src/FeeCollector.sol";
import {WUCT} from "../src/WUCT.sol";

contract T2T3ArtifactTest is Test {
    string internal constant ARTIFACT = "artifacts/t2t3-test-v1.json";
    address payable internal constant TEST_TREASURY =
        payable(0x000000000000000000000000000000000000bEEF);
    uint16 internal constant TEST_TREASURY_SHARE_BPS = 6000;

    function testArtifactRuntimeCodeAndHashesMatchCanonicalTestInstances() public {
        string memory json = vm.readFile(ARTIFACT);
        WUCT wrapped = new WUCT();
        FeeCollector collector = new FeeCollector(TEST_TREASURY, TEST_TREASURY_SHARE_BPS);

        assertEq(vm.parseJsonBytes(json, ".wuct.runtimeBytecode"), address(wrapped).code);
        assertEq(vm.parseJsonBytes32(json, ".wuct.codeHash"), keccak256(address(wrapped).code));
        assertEq(vm.parseJsonBytes(json, ".feeCollector.runtimeBytecode"), address(collector).code);
        assertEq(
            vm.parseJsonBytes32(json, ".feeCollector.codeHash"), keccak256(address(collector).code)
        );
    }

    function testArtifactRecordsPinnedToolchainAndConstructorValues() public view {
        string memory json = vm.readFile(ARTIFACT);
        assertEq(vm.parseJsonString(json, ".profile"), "t2t3/test-v1");
        assertEq(vm.parseJsonString(json, ".compiler.solc"), "0.8.37");
        assertEq(vm.parseJsonString(json, ".compiler.evm_version"), "cancun");
        assertTrue(vm.parseJsonBool(json, ".compiler.via_ir"));
        assertTrue(vm.parseJsonBool(json, ".compiler.optimizer"));
        assertEq(vm.parseJsonUint(json, ".compiler.optimizer_runs"), 200);
        assertEq(vm.parseJsonString(json, ".compiler.bytecode_hash"), "none");
        assertFalse(vm.parseJsonBool(json, ".compiler.cbor_metadata"));
        assertEq(
            vm.parseJsonAddress(json, ".feeCollector.constructorTestValues.treasury"), TEST_TREASURY
        );
        assertEq(
            vm.parseJsonUint(json, ".feeCollector.constructorTestValues.treasuryShareBps"),
            TEST_TREASURY_SHARE_BPS
        );
    }
}
