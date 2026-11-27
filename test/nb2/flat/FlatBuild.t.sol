// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {FlatLineage} from "../../../src/nb2/verifier/flat/FlatLineage.sol";
import {FlatReceipts} from "../../../src/nb2/verifier/flat/FlatReceipts.sol";
import {NativeBridgeVerifier11} from "../../../src/nb2/verifier/flat/NativeBridgeVerifier11.sol";
import {NativeBridgeRecovery11} from "../../../src/nb2/verifier/flat/NativeBridgeRecovery11.sol";
import {BadBinding} from "../../../src/nb2/verifier/flat/FlatTypes.sol";

/// @notice Deployment limits and constructor binding refusals of the v1.1 verifier graph.
contract FlatBuildTest is Test {
    address private constant REGISTRY = 0xff00000000000000000000000000000000000002;
    uint256 private constant EIP170 = 24576;
    uint256 private constant EIP3860 = 49152;

    FlatReceipts private receipts;
    FlatLineage private lineage;

    function setUp() public {
        vm.etch(REGISTRY, hex"600200");
        receipts = new FlatReceipts();
        lineage = new FlatLineage(receipts);
    }

    function testRuntimeAndInitcodeSizes() external view {
        assertLe(vm.getDeployedCode("FlatReceipts.sol:FlatReceipts").length, EIP170);
        assertLe(vm.getDeployedCode("FlatLineage.sol:FlatLineage").length, EIP170);
        assertLe(
            vm.getDeployedCode("NativeBridgeVerifier11.sol:NativeBridgeVerifier11").length, EIP170
        );
        assertLe(
            vm.getDeployedCode("NativeBridgeRecovery11.sol:NativeBridgeRecovery11").length, EIP170
        );
        // Constructor arguments add at most a few hundred bytes (gamma <= 1024 bytes).
        assertLe(type(FlatReceipts).creationCode.length, EIP3860);
        assertLe(type(FlatLineage).creationCode.length + 32, EIP3860);
        assertLe(type(NativeBridgeVerifier11).creationCode.length + 128, EIP3860);
        assertLe(type(NativeBridgeRecovery11).creationCode.length + 1536, EIP3860);
    }

    function testOrdinaryConstructorRefusesMismatchedDependencies() external {
        bytes32 lineageHash = address(lineage).codehash;
        bytes32 registryHash = REGISTRY.codehash;
        new NativeBridgeVerifier11(lineage, lineageHash, bytes32(uint256(1)), registryHash);
        vm.expectRevert(BadBinding.selector);
        new NativeBridgeVerifier11(
            lineage, lineageHash ^ bytes32(uint256(1)), bytes32(uint256(1)), registryHash
        );
        vm.expectRevert(BadBinding.selector);
        new NativeBridgeVerifier11(lineage, bytes32(0), bytes32(uint256(1)), registryHash);
        vm.expectRevert(BadBinding.selector);
        new NativeBridgeVerifier11(lineage, lineageHash, bytes32(0), registryHash);
        vm.expectRevert(BadBinding.selector);
        new NativeBridgeVerifier11(
            lineage, lineageHash, bytes32(uint256(1)), registryHash ^ bytes32(uint256(1))
        );
        vm.etch(REGISTRY, "");
        vm.expectRevert(BadBinding.selector);
        new NativeBridgeVerifier11(lineage, lineageHash, bytes32(uint256(1)), keccak256(""));
    }

    function testLineageConstructorRefusesForeignReceiptHelper() external {
        vm.expectRevert(BadBinding.selector);
        new FlatLineage(FlatReceipts(address(0xf201)));
        vm.etch(address(0xf201), hex"600100");
        vm.expectRevert(BadBinding.selector);
        new FlatLineage(FlatReceipts(address(0xf201)));
    }
}
