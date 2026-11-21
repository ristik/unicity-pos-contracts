// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {AxisBDeposit} from "../../../src/nb2/prototype/AxisBDeposit.sol";
import {AxisBRecovery} from "../../../src/nb2/prototype/AxisBRecovery.sol";
import {AxisBSha256} from "../../../src/nb2/prototype/AxisBSha256.sol";
import {NativeBridgeVerifierV2} from "../../../src/nb2/verifier/NativeBridgeVerifierV2.sol";
import {CertBatchDouble, MembershipDouble} from "../verifier/Nb2Doubles.sol";
import {AxisBCommitment} from "../../../src/nb2/prototype/AxisBCommitment.sol";
import {Nb2ReceiptVerifier} from "../../../src/nb2/verifier/Nb2ReceiptVerifier.sol";

contract AxisBRecoveryTest is Test {
    address private constant EMITTER =
        address(bytes20(hex"a108000000000000000000000000000000000000"));
    bytes32 private constant PROGRESS = keccak256("AxisBProgress(bytes32,bytes32)");
    bytes32 private constant COMPLETE =
        keccak256("AxisBComplete(bytes32,bytes32,uint64,bytes32,address,uint256)");
    string private constant DIR = "test/nb2/prototype/generated/";
    AxisBRecovery private verifier;
    NativeBridgeVerifierV2 private ordinary;

    function setUp() public {
        vm.etch(address(0x0100), type(CertBatchDouble).runtimeCode);
        vm.etch(address(0x0102), type(MembershipDouble).runtimeCode);
        ordinary = NativeBridgeVerifierV2(
            deployCode("NativeBridgeVerifierV2.sol:NativeBridgeVerifierV2", abi.encode(true))
        );
        Nb2ReceiptVerifier receipts = ordinary.RECEIPTS();
        verifier = AxisBRecovery(
            deployCode(
                "AxisBRecovery.sol:AxisBRecovery",
                abi.encode(
                    true,
                    receipts,
                    new AxisBSha256(),
                    new AxisBCommitment(),
                    new AxisBDeposit(true, receipts)
                )
            )
        );
        vm.etch(EMITTER, address(verifier).code);
    }

    function _loadTrust(string memory trust) private {
        CertBatchDouble batch = CertBatchDouble(payable(address(0x0100)));
        batch.nb2Reset(vm.parseJsonUint(trust, ".network"));
        uint256[] memory epochs = vm.parseJsonUintArray(trust, ".epochs");
        uint256[] memory starts = vm.parseJsonUintArray(trust, ".starts");
        uint256[] memory ends = vm.parseJsonUintArray(trust, ".ends");
        uint256[] memory totals = vm.parseJsonUintArray(trust, ".totals");
        for (uint256 i = 0; i < epochs.length; ++i) {
            batch.nb2Epoch(epochs[i], starts[i], ends[i], totals[i]);
        }
        uint256[] memory me = vm.parseJsonUintArray(trust, ".memberEpochs");
        bytes[] memory ids = vm.parseJsonBytesArray(trust, ".memberIds");
        bytes[] memory keys = vm.parseJsonBytesArray(trust, ".memberKeys");
        for (uint256 i = 0; i < me.length; ++i) {
            batch.nb2Member(me[i], ids[i], keys[i]);
        }
    }

    function testAxisBShort() external {
        _run("short", true);
    }

    function testAxisBEpochRotation() external {
        _run("epoch-rotation", true);
    }

    function testAxisBDeepSplit() external {
        _run("deep-split", true);
    }

    function testAxisBTransferHeavy() external {
        _run("ordinary-envelope-exceeded", true);
    }

    function testAxisBOversizedChildMint() external {
        _run("oversized-child-mint", true);
    }

    function testAxisBQuorumFull() external {
        _run("quorum-4", true);
    }

    function testAxisBQuorumTrimmed() external {
        _run("quorum-3", true);
    }

    function testAxisBRepeatedSource() external {
        _run("repeated-source", false);
    }

    function testAxisBMalformedNestedLength() external {
        _run("malformed-nested-length", false);
    }

    function testAxisBIncomplete() external {
        _run("incomplete", false);
    }

    function testAxisBSha256AtPaddingAndChunkBoundaries() external view {
        AxisBSha256 hash = verifier.HASHER();
        for (uint256 i = 1; i <= 130; ++i) {
            bytes memory data = new bytes(i);
            for (uint256 j = 0; j < i; ++j) {
                data[j] = bytes1(uint8(j));
            }
            assertEq(hash.advance(hash.IV(), 0, data, true), sha256(data));
        }
        bytes memory prefix = new bytes(4096);
        for (uint256 i = 0; i < prefix.length; ++i) {
            prefix[i] = bytes1(uint8(i));
        }
        bytes32 h = hash.advance(hash.IV(), 0, prefix, false);
        bytes memory tail = hex"015768f9022859";
        assertEq(hash.advance(h, 4096, tail, true), sha256(bytes.concat(prefix, tail)));
    }

    function testAxisBWitnessLimits() external {
        AxisBCommitment commitments = verifier.COMMITMENTS();
        AxisBCommitment.Window memory window;
        window.data = new bytes(32 * 4096);
        window.paths = new bytes32[][](32);
        bytes32[] memory layer = new bytes32[](32);
        uint64 total = type(uint64).max;
        bytes memory page = new bytes(4096);
        for (uint256 i = 0; i < 32; ++i) {
            layer[i] = keccak256(abi.encodePacked(bytes1(0), uint64(i * 4096), total, page));
            window.paths[i] = new bytes32[](52);
        }
        for (uint256 level = 0; level < 5; ++level) {
            for (uint256 i = 0; i < 32; ++i) {
                window.paths[i][level] = layer[(i >> level) ^ 1];
            }
            for (uint256 i = 0; i < 32 >> (level + 1); ++i) {
                layer[i] = _node(layer[2 * i], layer[2 * i + 1]);
            }
        }
        bytes32 root = layer[0];
        for (uint256 level = 5; level < 52; ++level) {
            root = _node(root, 0);
        }
        vm.cool(address(commitments));
        uint256 before = gasleft();
        commitments.verify(window, root, total);
        emit log_named_uint("maximum positional witness wrapper gas", before - gasleft());
        emit log_named_uint("maximum positional witness ABI bytes", abi.encode(window).length);

        bytes32[] memory siblings = new bytes32[](256);
        root = 0;
        for (uint256 i = 0; i < siblings.length; ++i) {
            siblings[i] = keccak256(abi.encode(i));
            root = _node(root, siblings[i]);
        }
        vm.cool(address(commitments));
        before = gasleft();
        (bytes32 used, bool absent) = commitments.insert(root, 0, type(uint256).max, siblings);
        emit log_named_uint("maximum source-set witness wrapper gas", before - gasleft());
        assertTrue(absent);
        assertNotEq(used, root);
    }

    function _node(bytes32 left, bytes32 right) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), left, right));
    }

    function testAxisBItemDepthIncludesOuterContext() external {
        AxisBCommitment commitments = verifier.COMMITMENTS();
        assertEq(commitments.itemLength(hex"81810000", true, 14), 3);
        vm.expectRevert();
        commitments.itemLength(hex"818100", true, 15);
    }

    function _read(bytes memory file, uint256 pos)
        private
        pure
        returns (bytes memory value, uint256 next)
    {
        require(file.length - pos >= 4, "fixture header");
        uint256 size;
        assembly ("memory-safe") {
            size := shr(224, mload(add(add(file, 32), pos)))
        }
        require(size <= file.length - pos - 4, "fixture length");
        value = new bytes(size);
        assembly ("memory-safe") {
            mcopy(add(value, 32), add(add(file, 36), pos), size)
        }
        next = pos + 4 + size;
    }

    function _run(string memory name, bool valid) private {
        vm.skip(!vm.envOr("NB2_RECOVERY_RUN_FIXTURES", false));
        bytes memory file = vm.readFileBinary(string.concat(DIR, name, ".bin"));
        (bytes memory trust, uint256 pos) = _read(file, 0);
        _loadTrust(string(trust));
        bytes memory gamma;
        (gamma, pos) = _read(file, pos);
        bytes memory evidence;
        bytes memory want;
        (evidence, pos) = _read(file, pos);
        (want, pos) = _read(file, pos);
        vm.cool(address(ordinary));
        vm.cool(address(ordinary.RECEIPTS()));
        vm.cool(address(0x0100));
        vm.cool(address(0x0102));
        uint256 gasBefore = gasleft();
        (bool ordinaryOK, bytes memory result) = address(ordinary)
            .staticcall(abi.encodeCall(NativeBridgeVerifierV2.verifyReturn, (gamma, evidence)));
        uint256 ordinaryGas = gasBefore - gasleft();
        assertEq(ordinaryOK, valid, "ordinary verdict");
        if (valid) assertEq(result, want, "ordinary verdict differs from Go");
        uint256 calls;
        uint256 totalGas;
        uint256 totalBytes;
        uint256 largestCallGas;
        uint256 largestCallBytes;
        bool complete;
        uint256[7] memory phaseGas;
        uint256[7] memory phaseBytes;
        while (pos < file.length) {
            bytes memory callData;
            bytes memory expected;
            (callData, pos) = _read(file, pos);
            (expected, pos) = _read(file, pos);
            vm.recordLogs();
            vm.cool(EMITTER);
            vm.cool(address(verifier.RECEIPTS()));
            vm.cool(address(verifier.HASHER()));
            vm.cool(address(verifier.COMMITMENTS()));
            vm.cool(address(verifier.DEPOSIT()));
            vm.cool(address(0x0100));
            vm.cool(address(0x0102));
            gasBefore = gasleft();
            // forge-lint: disable-next-line(low-level-calls)
            (bool ok, bytes memory returnData) = EMITTER.call(callData);
            uint256 gasUsed = gasBefore - gasleft();
            if (expected.length != 0 && !ok) {
                emit log_named_uint("failing call index", calls);
                emit log_named_bytes("revert reason", returnData);
            }
            assertEq(ok, expected.length != 0, "chunk verdict");
            Vm.Log[] memory logs = vm.getRecordedLogs();
            if (!ok) {
                assertEq(logs.length, 0, "rejected no event");
                assertEq(pos, file.length, "rejection must be last");
                assertFalse(valid);
                break;
            }
            assertEq(logs.length, 1, "one chunk event");
            assertEq(logs[0].emitter, EMITTER);
            assertEq(logs[0].data, expected, "Go/Solidity progress or verdict mismatch");
            if (expected.length == 192) {
                assertEq(logs[0].topics[0], COMPLETE);
                assertEq(expected, want, "completion differs");
                assertEq(pos, file.length, "completion must be last");
                complete = true;
            } else {
                assertEq(logs[0].topics[0], PROGRESS);
            }
            uint256 phase = 1;
            if (calls != 0) {
                assembly ("memory-safe") { phase := mload(add(callData, 132)) }
            }
            ++calls;
            uint256 intrinsic = 21_000;
            for (uint256 i = 0; i < callData.length; ++i) {
                intrinsic += callData[i] == 0 ? 4 : 16;
            }
            gasUsed += intrinsic;
            if (gasUsed > phaseGas[phase]) phaseGas[phase] = gasUsed;
            if (callData.length > phaseBytes[phase]) phaseBytes[phase] = callData.length;
            totalGas += gasUsed;
            totalBytes += callData.length;
            if (gasUsed > largestCallGas) largestCallGas = gasUsed;
            if (callData.length > largestCallBytes) largestCallBytes = callData.length;
        }
        assertEq(complete, valid);
        emit log_named_uint("ordinary verifier call gas", ordinaryGas);
        emit log_named_uint("calls", calls);
        emit log_named_uint("total gas including intrinsic", totalGas);
        emit log_named_uint("largest call gas including intrinsic", largestCallGas);
        emit log_named_uint("total calldata bytes", totalBytes);
        emit log_named_uint("largest calldata bytes", largestCallBytes);
        for (uint256 i = 1; i < 7; ++i) {
            emit log_named_uint(string.concat("phase ", vm.toString(i), " max gas"), phaseGas[i]);
            emit log_named_uint(
                string.concat("phase ", vm.toString(i), " max calldata"), phaseBytes[i]
            );
        }
    }
}
