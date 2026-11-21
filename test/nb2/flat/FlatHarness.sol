// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {FlatBindings} from "../../../src/nb2/verifier/flat/FlatBindings.sol";
import {FlatLineage} from "../../../src/nb2/verifier/flat/FlatLineage.sol";
import {FlatPacket} from "../../../src/nb2/verifier/flat/FlatPacket.sol";
import {FlatReceipts} from "../../../src/nb2/verifier/flat/FlatReceipts.sol";
import {
    FlatOrdinary,
    NativeBridgeVerifier11
} from "../../../src/nb2/verifier/flat/NativeBridgeVerifier11.sol";
import {
    FlatRecovery,
    NativeBridgeRecovery11
} from "../../../src/nb2/verifier/flat/NativeBridgeRecovery11.sol";
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

/// @dev The reference session uses placeholder runtime digests. These two test
/// adapters inject that fixture binding while leaving wire/receipt/lineage code intact.
contract CorpusOrdinary11 is FlatOrdinary {
    constructor(FlatLineage lineage) FlatOrdinary(lineage, address(lineage).codehash) {}

    function _config(bytes calldata gamma) internal pure override returns (FlatConfig memory) {
        return FlatBindings.decode(gamma).cfg;
    }
}

contract CorpusRecovery11 is FlatRecovery {
    bytes32 public immutable PINS;
    bytes32 public immutable GENERATION;
    bytes32 public immutable FIXTURE_RUNTIME;

    constructor(
        FlatConfig memory cfg,
        FlatLineage lineage,
        FlatReceipts receipts,
        bytes32 pins,
        bytes32 generation,
        bytes32 runtime
    ) FlatRecovery(cfg, lineage, receipts) {
        PINS = pins;
        GENERATION = generation;
        FIXTURE_RUNTIME = runtime;
    }

    function _session(FlatPacket.Header memory h) internal view override returns (bytes32) {
        return FlatBindings.session(
            GENERATION, DOMAIN, VAULT, address(this), FIXTURE_RUNTIME, PINS, h.size, h.root
        );
    }
}

abstract contract FlatHarness is Test {
    string internal constant DIR = "test/nb2/flat/generated/";
    address internal constant RECOVERY = address(0xf202);
    address internal constant REGISTRY = 0xff00000000000000000000000000000000000002;

    FlatReceipts internal receipts;
    FlatLineage internal lineage;
    CorpusOrdinary11 internal ordinary;
    bytes internal gamma;
    uint256 internal maxPacketGas;

    function config(bytes calldata g) external pure returns (FlatConfig memory) {
        return FlatBindings.decode(g).cfg;
    }

    function setUp() public {
        vm.skip(!vm.exists(string.concat(DIR, "gamma.bin")));
        gamma = vm.readFileBinary(string.concat(DIR, "gamma.bin"));
        vm.chainId(31337);
        vm.etch(address(0x0100), type(CertBatchDouble).runtimeCode);
        vm.etch(address(0x0102), type(MembershipDouble).runtimeCode);
        receipts = FlatReceipts(deployCode("FlatReceipts.sol:FlatReceipts"));
        lineage = FlatLineage(deployCode("FlatLineage.sol:FlatLineage", abi.encode(receipts)));
        ordinary =
            CorpusOrdinary11(deployCode("FlatHarness.sol:CorpusOrdinary11", abi.encode(lineage)));
        _installRecovery(_gold("generation.bin"));
    }

    function _installRecovery(bytes32 generation) internal {
        address deployed = deployCode(
            "FlatHarness.sol:CorpusRecovery11",
            abi.encode(
                this.config(gamma),
                lineage,
                receipts,
                _gold("pins.bin"),
                generation,
                keccak256(hex"600300")
            )
        );
        vm.etch(RECOVERY, deployed.code);
    }

    function _creationMustFail(bytes memory args) internal {
        bytes memory init =
            bytes.concat(vm.getCode("NativeBridgeRecovery11.sol:NativeBridgeRecovery11"), args);
        address failed;
        assembly ("memory-safe") { failed := create(0, add(init, 32), mload(init)) }
        assertEq(failed, address(0));
    }

    function _scenario(string memory name) internal {
        string memory path = _path(name);
        _loadTrust(path);
        bytes memory evidence = vm.readFileBinary(string.concat(path, "evidence.bin"));
        FlatVerdict memory verdict = ordinary.verifyReturn(gamma, evidence);
        assertEq(abi.encode(verdict), vm.readFileBinary(string.concat(path, "verdict.bin")));
        bytes memory trace = vm.readFileBinary(string.concat(path, "trace.bin"));
        uint256 cursor;
        uint256 calls;
        while (cursor < trace.length) {
            bytes memory input;
            bytes memory topics;
            bytes memory data;
            (input, cursor) = _field(trace, cursor);
            (, cursor) = _field(trace, cursor);
            (, cursor) = _field(trace, cursor);
            (topics, cursor) = _field(trace, cursor);
            (data, cursor) = _field(trace, cursor);
            (, cursor) = _field(trace, cursor);
            _event(input, bytes.concat(topics, data));
            ++calls;
        }
        assertGt(calls, 0);
        emit log_named_uint("transcript calls", calls);
        emit log_named_uint("max Foundry call gas", maxPacketGas);
    }

    function _event(bytes memory input, bytes memory eventBytes) internal {
        vm.recordLogs();
        uint256 start = gasleft();
        (bool ok, bytes memory why) = RECOVERY.call(input);
        uint256 cost = start - gasleft();
        if (cost > maxPacketGas) maxPacketGas = cost;
        assertTrue(ok, vm.toString(why));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].emitter, RECOVERY);
        assertEq(logs[0].topics.length, 2);
        assertEq(abi.encodePacked(logs[0].topics[0], logs[0].topics[1], logs[0].data), eventBytes);
    }

    function _fails(bytes memory input, bytes4 expected) internal {
        _failsNamed(input, expected, "");
    }

    function _failsNamed(bytes memory input, bytes4 expected, string memory name) internal {
        vm.recordLogs();
        (bool ok, bytes memory why) = RECOVERY.call(input);
        assertFalse(ok, name);
        assertEq(why, abi.encodeWithSelector(expected), name);
        assertEq(vm.getRecordedLogs().length, 0);
    }

    function _loadTrust(string memory path) internal {
        string memory raw = vm.readFile(string.concat(path, "trust.json"));
        CertBatchDouble batch = CertBatchDouble(payable(address(0x0100)));
        batch.nb2Reset(vm.parseJsonUint(raw, ".network"));
        uint256[] memory epochs = vm.parseJsonUintArray(raw, ".epochs");
        uint256[] memory starts = vm.parseJsonUintArray(raw, ".starts");
        uint256[] memory ends = vm.parseJsonUintArray(raw, ".ends");
        uint256[] memory totals = vm.parseJsonUintArray(raw, ".totals");
        for (uint256 i; i < epochs.length; ++i) {
            batch.nb2Epoch(epochs[i], starts[i], ends[i], totals[i]);
        }
        uint256[] memory me = vm.parseJsonUintArray(raw, ".memberEpochs");
        bytes[] memory ids = vm.parseJsonBytesArray(raw, ".memberIds");
        bytes[] memory keys = vm.parseJsonBytesArray(raw, ".memberKeys");
        uint256[] memory weights = vm.parseJsonUintArray(raw, ".memberWeights");
        uint256 index;
        for (uint256 i; i < me.length; ++i) {
            if (i == 0 || me[i] != me[i - 1]) index = 0;
            batch.nb2Member(me[i], ids[i], keys[i]);
            batch.nb2MemberWeight(me[i], index++, weights[i]);
        }
    }

    function _field(bytes memory data, uint256 p)
        internal
        pure
        returns (bytes memory out, uint256 end)
    {
        uint256 len = uint32(bytes4(_word(data, p)));
        out = new bytes(len);
        assembly ("memory-safe") { mcopy(add(out, 32), add(add(data, 36), p), len) }
        end = p + 4 + len;
        assert(end <= data.length);
    }

    function _path(string memory name) internal pure returns (string memory) {
        return string.concat(DIR, "transcripts/", name, "/");
    }

    function _descriptor(string memory name) internal view returns (bytes32) {
        return sha256(vm.readFileBinary(string.concat(DIR, "descriptor-", name, ".bin")));
    }

    function _gold(string memory name) internal view returns (bytes32) {
        return bytes32(vm.readFileBinary(string.concat(DIR, name)));
    }

    function _word(bytes memory data, uint256 p) internal pure returns (bytes32) {
        return FlatWire.mword(data, p);
    }
}
