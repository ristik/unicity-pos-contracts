// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {SealRegistry} from "../src/SealRegistry.sol";
import {B1GenesisBuilder} from "../src/B1GenesisBuilder.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";

/// @notice The committed artifact is the compiled contract: same runtime bytecode, same code hash,
/// the fixed slot keys, the B1 layout description and the genesis words. CI regenerates the artifact
/// with script/seal-registry-artifact.sh and fails on any difference.
contract SealRegistryArtifactTest is SealRegistryBase {
    string internal constant ARTIFACT = "artifacts/seal-registry.json";

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
        string[6] memory fixedNames =
            ["b1.network", "b1.wCert", "b1.profileHash", "b1.initialized", "b1.head", "b1.count"];
        for (uint256 i = 0; i < fixedNames.length; i++) {
            string memory path = string.concat(".slotKeys[", vm.toString(FIELD_COUNT + i), "]");
            assertEq(vm.parseJsonString(json, string.concat(path, ".name")), fixedNames[i]);
            assertEq(
                vm.parseJsonBytes32(json, string.concat(path, ".key")),
                fixedSlot(fixedNames[i]),
                fixedNames[i]
            );
        }
        // No layoutVersion word survives in the single fresh layout.
        string memory last = string.concat(".slotKeys[", vm.toString(FIELD_COUNT + 5), "]");
        string memory beyond = string.concat(".slotKeys[", vm.toString(FIELD_COUNT + 6), "]");
        assertTrue(vm.keyExists(json, last), "last slot key");
        assertFalse(vm.keyExists(json, beyond), "no extra slot key");
    }

    function test_artifactDescribesTheB1LayoutAndBounds() public view {
        string memory json = vm.readFile(ARTIFACT);
        assertEq(vm.parseJsonBytes32(json, ".b1Layout.queue.prefix.key"), fixedSlot("b1.queue"));
        assertEq(vm.parseJsonBytes32(json, ".b1Layout.entry.prefix.key"), fixedSlot("b1.entry"));
        assertEq(vm.parseJsonBytes32(json, ".b1Layout.member.prefix.key"), fixedSlot("b1.member"));
        assertEq(vm.parseJsonStringArray(json, ".b1Layout.entry.fields").length, 11);
        assertEq(vm.parseJsonStringArray(json, ".b1Layout.member.fields").length, 8);
        assertEq(vm.parseJsonUint(json, ".b1Layout.bounds.maxMembers"), 64);
        assertEq(vm.parseJsonUint(json, ".b1Layout.bounds.maxNodeIDBytes"), 128);
        assertEq(vm.parseJsonUint(json, ".b1Layout.bounds.maxEntryWords"), 11 + 8 * 64);
        assertEq(vm.parseJsonUint(json, ".gasProfile.gRestBound.base"), builder.G_REST_BASE());
        assertEq(
            vm.parseJsonUint(json, ".gasProfile.gRestBound.perInsert"), builder.G_REST_PER_INSERT()
        );
        assertEq(
            vm.parseJsonUint(json, ".gasProfile.gRestBound.perDelete"), builder.G_REST_PER_DELETE()
        );
        assertEq(
            vm.parseJsonUint(json, ".gasProfile.gRestBound.perEntry"), builder.G_REST_PER_ENTRY()
        );
        assertEq(vm.parseJsonUint(json, ".gasProfile.gRestBound.operationalWrites.count"), 28);
        assertEq(
            vm.parseJsonUint(json, ".gasProfile.gRestBound.operationalWrites.pricePerWrite"), 22_100
        );
    }

    function test_artifactNamesTheGenesisWordsAndCaller() public view {
        string memory json = vm.readFile(ARTIFACT);
        string[14] memory genesis = [
            "genesisCommitment",
            "config.shardConfHash",
            "assignment.epoch",
            "assignment.rootEpoch",
            "assignment.activeConfHash",
            "phase",
            "b1.network",
            "b1.wCert",
            "b1.profileHash",
            "b1.initialized",
            "b1.count",
            "b1.queue[0]",
            "b1.entry(genesis epoch)",
            "b1.member(genesis epoch, j)"
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
        assertEq(vm.parseJsonAddress(json, ".registryAddress"), A_SR);
        assertEq(vm.parseJsonString(json, ".profile"), "sealRegistry");
        assertEq(
            vm.parseJsonBytes(json, ".openSelector"), abi.encodePacked(SealRegistry.open.selector)
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
