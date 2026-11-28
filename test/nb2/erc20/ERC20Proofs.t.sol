// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC20FlatOrdinary} from "../../../src/nb2/erc20/generated/ERC20BridgeVerifier.sol";
import {ERC20FlatRecovery} from "../../../src/nb2/erc20/generated/ERC20BridgeRecovery.sol";
import {ERC20FlatConfig} from "../../../src/nb2/erc20/ERC20FlatConfig.sol";
import {ERC20FlatBindings} from "../../../src/nb2/erc20/generated/ERC20FlatBindings.sol";
import {ERC20FlatLineage} from "../../../src/nb2/erc20/generated/ERC20FlatLineage.sol";
import {FlatBindings} from "../../../src/nb2/verifier/flat/FlatBindings.sol";
import {FlatReceipts} from "../../../src/nb2/verifier/flat/FlatReceipts.sol";
import {FlatVerdict, BadStep} from "../../../src/nb2/verifier/flat/FlatTypes.sol";

/// @dev The vector uses a synthetic graph. The production graph binding is tested by ERC20BridgeTest.
contract ERC20VectorOrdinary is ERC20FlatOrdinary {
    constructor(ERC20FlatLineage lineage) ERC20FlatOrdinary(lineage, address(lineage).codehash) {}

    function vectorConfig(bytes calldata gamma) external view returns (ERC20FlatConfig memory) {
        return _config(gamma);
    }

    function _bind(ERC20FlatBindings.ConfigBinding memory) internal pure override {}
}

contract ERC20VectorRecovery is ERC20FlatRecovery {
    bytes32 private immutable _generation;

    constructor(
        ERC20FlatConfig memory cfg,
        uint64 chainId,
        ERC20FlatLineage lineage,
        FlatReceipts receipts
    ) ERC20FlatRecovery(cfg, chainId, lineage, receipts) {
        _generation = FlatBindings.generation(sha256("erc20-generation"), cfg.domain);
    }

    function _identity() internal view override returns (bytes32, bytes32, bytes32) {
        return (_generation, keccak256("erc20-recovery-runtime"), sha256("erc20-pins"));
    }
}

contract ERC20ProofsTest is Test {
    string private constant DIR = "test/nb2/erc20/";
    FlatReceipts private receipts;
    ERC20FlatLineage private lineage;
    ERC20VectorOrdinary private ordinary;

    function setUp() public {
        receipts = FlatReceipts(deployCode("FlatReceipts.sol:FlatReceipts"));
        lineage = ERC20FlatLineage(
            deployCode("ERC20FlatLineage.sol:ERC20FlatLineage", abi.encode(receipts))
        );
        ordinary = ERC20VectorOrdinary(
            deployCode("ERC20Proofs.t.sol:ERC20VectorOrdinary", abi.encode(lineage))
        );
        // The previous NB2 oracle verifies the B1 and RSMT witnesses. This test
        // exercises Solidity's receipts, lineage, packets and verdicts.
        vm.mockCall(address(0x0100), bytes(""), abi.encode(uint256(2), uint256(1)));
        vm.mockCall(address(0x0102), bytes(""), abi.encode(uint256(1), uint256(1)));
    }

    function testERC20SplitAndContinuationMatchGo() public {
        vm.chainId(31_337);
        bytes memory gamma = vm.readFileBinary(string.concat(DIR, "gamma.bin"));
        bytes memory evidence = vm.readFileBinary(string.concat(DIR, "evidence.bin"));
        FlatVerdict memory verdict = ordinary.verifyReturn(gamma, evidence);
        assertEq(abi.encode(verdict), vm.readFileBinary(string.concat(DIR, "verdict.bin")));

        address target = address(bytes20(vm.readFileBinary(string.concat(DIR, "recovery.bin"))));
        deployCodeTo(
            "ERC20Proofs.t.sol:ERC20VectorRecovery",
            abi.encode(ordinary.vectorConfig(gamma), uint64(31_337), lineage, receipts),
            target
        );
        vm.recordLogs();
        (bool ok, bytes memory reason) =
            target.call(vm.readFileBinary(string.concat(DIR, "packet.bin")));
        if (!ok) {
            assembly ("memory-safe") { revert(add(reason, 32), mload(reason)) }
        }
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].emitter, target);
        assertEq(logs[0].data, vm.readFileBinary(string.concat(DIR, "complete.bin")));

        gamma = vm.readFileBinary(string.concat(DIR, "foreign-gamma.bin"));
        vm.expectRevert(BadStep.selector);
        ordinary.verifyReturn(gamma, evidence);
    }
}
