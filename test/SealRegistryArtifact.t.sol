// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {SealRegistry} from "../src/SealRegistry.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";

/// @notice The committed artifact is the compiled contract: same runtime bytecode, same code hash, the
/// same 22 slot keys in §4.2 order, and the §5.4 genesis word names. CI also regenerates the artifact
/// with script/seal-registry-artifact.sh and fails on any difference.
contract SealRegistryArtifactTest is SealRegistryBase {
    string internal constant ARTIFACT = "artifacts/seal-registry-v1.json";

    function test_artifactRuntimeBytecodeAndCodeHashAreTheCompiledContract() public view {
        string memory json = vm.readFile(ARTIFACT);
        bytes memory runtime = type(SealRegistry).runtimeCode;
        assertEq(vm.parseJsonBytes(json, ".runtimeBytecode"), runtime, "runtime bytecode");
        assertEq(vm.parseJsonBytes32(json, ".codeHash"), keccak256(runtime), "code hash");
        // The code placed at a_sr by genesis is the same bytes.
        assertEq(keccak256(A_SR.code), keccak256(runtime));
    }

    function test_artifactSlotKeysAreTheSpecifiedFields() public view {
        string memory json = vm.readFile(ARTIFACT);
        string[FIELD_COUNT] memory names = fieldNames();
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            string memory path = string.concat(".slotKeys[", vm.toString(i), "]");
            assertEq(vm.parseJsonString(json, string.concat(path, ".name")), names[i]);
            assertEq(
                vm.parseJsonBytes32(json, string.concat(path, ".key")), slotKey(names[i]), names[i]
            );
        }
    }

    function test_artifactNamesExactlyTheSixGenesisWords() public view {
        string memory json = vm.readFile(ARTIFACT);
        string[6] memory genesis = [
            "layoutVersion",
            "genesisCommitment",
            "config.shardConfHash",
            "assignment.epoch",
            "assignment.rootEpoch",
            "phase"
        ];
        for (uint256 i = 0; i < genesis.length; i++) {
            string memory path = string.concat(".genesisStorage[", vm.toString(i), "].name");
            assertEq(vm.parseJsonString(json, path), genesis[i]);
        }
        assertEq(
            vm.parseJsonAddress(json, ".systemCaller"),
            A_SYS,
            "the artifact records the caller the code checks"
        );
    }

    function test_artifactRecordsThePinnedCompilerSettings() public view {
        string memory json = vm.readFile(ARTIFACT);
        assertTrue(vm.parseJsonBool(json, ".compiler.via_ir"), "via_ir");
        assertTrue(vm.parseJsonBool(json, ".compiler.optimizer"), "optimizer");
        assertEq(vm.parseJsonUint(json, ".compiler.optimizer_runs"), 200);
        assertEq(vm.parseJsonString(json, ".compiler.evm_version"), "cancun");
        assertEq(vm.parseJsonString(json, ".compiler.bytecode_hash"), "none");
        assertFalse(vm.parseJsonBool(json, ".compiler.cbor_metadata"), "cbor_metadata");
    }
}
