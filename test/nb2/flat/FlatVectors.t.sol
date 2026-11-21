// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";
import {FlatBindings} from "../../../src/nb2/verifier/flat/FlatBindings.sol";
import {FlatReceipts} from "../../../src/nb2/verifier/flat/FlatReceipts.sol";
import {NativeBridgeVerifier11} from "../../../src/nb2/verifier/flat/NativeBridgeVerifier11.sol";
import {NativeBridgeRecovery11} from "../../../src/nb2/verifier/flat/NativeBridgeRecovery11.sol";
import {
    FlatConfig,
    FlatVerdict,
    FlatWire,
    BadPacket,
    BadPage,
    BadPredecessor,
    BadStep,
    BadBinding
} from "../../../src/nb2/verifier/flat/FlatTypes.sol";
import {CertBatchDouble, MembershipDouble} from "../verifier/Nb2Doubles.sol";
import {FlatHarness} from "./FlatHarness.sol";

contract FlatVectorsTest is FlatHarness {
    function testRoot() external {
        _scenario("root");
    }

    function testTransfers() external {
        _scenario("transfers");
    }

    function testSplit() external {
        _scenario("one-split");
    }

    function testDepth20() external {
        _scenario("depth-20");
    }

    function testParentOver32Pages() external {
        _scenario("parent-over-32-pages");
    }

    function testCappedRoot() external {
        _scenario("capped-root");
    }

    function testCombinedLargeReceiptAndPaths() external {
        _scenario("combined-large-receipt-and-paths");
    }

    function testSharedClaim() external {
        _scenario("shared-claim");
    }

    function testAlternateCertificate() external {
        _scenario("alternate-certificate");
    }

    function testTransfers600() external {
        _scenario("transfers-600");
    }

    function testHeldLineageHasNoReturnVerdict() external {
        for (uint256 i; i < 3; ++i) {
            string memory path = _path(string.concat("held-sibling-", vm.toString(i)));
            _loadTrust(path);
            bytes memory held = vm.readFileBinary(string.concat(path, "evidence.bin"));
            vm.expectRevert();
            ordinary.verifyReturn(gamma, held);
        }
    }

    function testPublishedRefusals() external {
        string memory root = _path("refusals");
        _loadTrust(_path("root"));
        Vm.DirEntry[] memory cases = vm.readDir(root);
        uint256 count;
        for (uint256 i; i < cases.length; ++i) {
            if (!cases[i].isDir) continue;
            string memory base = string.concat(cases[i].path, "/");
            string memory stage = vm.readLine(string.concat(base, "stage.txt"));
            bytes4 expected = bytes4(keccak256(bytes(string.concat(stage, "()"))));
            bytes memory input = vm.readFileBinary(string.concat(base, "calldata.bin"));
            // Settlement is T4. Replay the run and advanceGaps refusals in this suite.
            bytes4 selector = bytes4(_word(input, 0));
            if (
                selector != bytes4(keccak256("run(bytes)"))
                    && selector != bytes4(keccak256("advanceGaps(bytes)"))
            ) continue;
            _failsNamed(input, expected, base);
            string memory retry = string.concat(base, "retry-calldata.bin");
            if (vm.exists(retry)) {
                (bool ok, bytes memory why) = RECOVERY.call(vm.readFileBinary(retry));
                assertTrue(ok, string.concat(base, vm.toString(why)));
            }
            ++count;
        }
        assertEq(count, 36);
    }

    function testRetryAfterLateFailureAndOtherGenerationRefused() external {
        _loadTrust(_path("root"));
        string memory path = _path("refusals/last-sparse-opening-atomic");
        bytes memory input = vm.readFileBinary(string.concat(path, "retry-calldata.bin"));
        _fails(vm.readFileBinary(string.concat(path, "calldata.bin")), BadStep.selector);
        _installRecovery(bytes32(uint256(1)));
        _fails(input, BadPredecessor.selector);
        _installRecovery(_gold("generation.bin"));
        (bool first,) = RECOVERY.call(input);
        (bool again,) = RECOVERY.call(input);
        assertTrue(first && again);
    }

    function testGapEventsAndCountBoundaries() external {
        _loadTrust(_path("root"));
        for (uint256 kind = 1; kind <= 2; ++kind) {
            for (uint256 i; i < 2; ++i) {
                uint256 count = i == 0 ? 1 : 1024;
                string memory path = _path(
                    string.concat(
                        "cold/advance-kind", vm.toString(kind), "-count", vm.toString(count)
                    )
                );
                bytes memory input = vm.readFileBinary(string.concat(path, "calldata.bin"));
                bytes memory eventBytes = vm.readFileBinary(string.concat(path, "event.bin"));
                _event(input, eventBytes);
                uint256 countAt = 68 + 47 + uint32(bytes4(_word(input, 68 + 43)));
                input[countAt] = i == 0 ? bytes1(0) : bytes1(0x04);
                input[countAt + 1] = i == 0 ? bytes1(0) : bytes1(0x01);
                _fails(input, BadPacket.selector);
            }
        }
    }

    function testStrictNativeResultShape() external {
        _loadTrust(_path("root"));
        bytes memory trace = vm.readFileBinary(string.concat(_path("root"), "trace.bin"));
        (bytes memory start,) = _field(trace, 0);
        // STATICCALL succeeds but returns one word, then version 1 and a dirty bool.
        vm.etch(address(0x0102), hex"600160005260206000f3");
        _fails(start, BadStep.selector);
        vm.etch(address(0x0102), hex"6001600052600260205260406000f3");
        _fails(start, BadStep.selector);
        vm.etch(address(0x0102), type(MembershipDouble).runtimeCode);
        vm.etch(address(0x0100), hex"6001600052600160205260406000f3");
        _fails(start, BadStep.selector);
    }

    function testProductionBindings() external {
        vm.etch(REGISTRY, hex"600200");
        bytes32 profile = sha256(vm.readFileBinary(string.concat(DIR, "semantic-profile.bin")));
        NativeBridgeVerifier11 actual = NativeBridgeVerifier11(
            deployCode(
                "NativeBridgeVerifier11.sol:NativeBridgeVerifier11",
                abi.encode(lineage, address(lineage).codehash, profile, REGISTRY.codehash)
            )
        );
        bytes memory g = gamma;
        // Replace the ordinary verifier address/hash fields in the pinned Γ fixture.
        bytes20 installed = bytes20(address(actual));
        bytes32 runtime = address(actual).codehash;
        for (uint256 i; i < 20; ++i) {
            g[252 + i] = installed[i];
        }
        for (uint256 i; i < 32; ++i) {
            g[274 + i] = runtime[i];
        }
        FlatConfig memory cfg = actual.readConfig(g);
        assertEq(cfg.domain, sha256(g));
        assertEq(cfg.vault, address(0xf200));
        FlatBindings.ReleaseInputs memory desc = FlatBindings.ReleaseInputs(
            _descriptor("cert-batch-v2"),
            _descriptor("rsmt-member-v1"),
            _descriptor("seal-registry-layout"),
            _descriptor("cancun-b1"),
            _descriptor("build-index"),
            _descriptor("primitive-vectors")
        );
        bytes32 pins = FlatBindings.pins(
            desc,
            address(actual),
            runtime,
            address(receipts),
            address(receipts).codehash,
            REGISTRY.codehash,
            address(lineage),
            address(lineage).codehash
        );
        bytes32 salt = _gold("generation-salt.bin");
        NativeBridgeRecovery11 recovery = NativeBridgeRecovery11(
            payable(deployCode(
                    "NativeBridgeRecovery11.sol:NativeBridgeRecovery11",
                    abi.encode(g, actual, salt, desc, pins)
                ))
        );
        assertEq(recovery.GENERATION(), FlatBindings.generation(salt, cfg.domain));
        assertEq(recovery.PINS(), pins);
        _chainIdIsRechecked(actual, recovery, g);
        _creationMustFail(abi.encode(g, actual, salt, desc, bytes32(uint256(pins) ^ 1)));
        g[274] ^= 0x01;
        _creationMustFail(abi.encode(g, actual, salt, desc, pins));
        vm.expectRevert(BadBinding.selector);
        actual.readConfig(g);
    }

    // Both production routes refuse after a chain-ID change. With the right chain the same
    // calldata proceeds past the session check (the evidence is for the reference domain: BadStep).
    function _chainIdIsRechecked(
        NativeBridgeVerifier11 actual,
        NativeBridgeRecovery11 recovery,
        bytes memory g
    ) private {
        (bytes memory start,) = _field(
            vm.readFileBinary(string.concat(_path("root"), "trace.bin")), 0
        );
        bytes memory advance =
            vm.readFileBinary(string.concat(_path("cold/advance-kind1-count1"), "calldata.bin"));
        vm.chainId(1);
        vm.expectRevert(BadBinding.selector);
        actual.readConfig(g);
        (bool ok, bytes memory why) = address(recovery).call(start);
        assertFalse(ok);
        assertEq(why, abi.encodeWithSelector(BadPredecessor.selector));
        (ok, why) = address(recovery).call(advance);
        assertFalse(ok);
        assertEq(why, abi.encodeWithSelector(BadPredecessor.selector));
        vm.chainId(31337);
        (ok, why) = address(recovery).call(start);
        assertFalse(ok);
        assertEq(why, abi.encodeWithSelector(BadStep.selector));
    }
}
