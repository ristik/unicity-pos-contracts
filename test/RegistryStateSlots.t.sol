// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {SealRegistry} from "../src/SealRegistry.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";
import {RootRecord, RecordKind} from "../src/p85/P85Types.sol";

/// @notice The registry storage the root authenticates with Ethereum storage proofs for a Retirement (briefs/p85-pr1c-control-records.md
/// section 3): the imported record count, the authenticated target count and the retirement key of an (id, generation), as the EVM reads
/// and writes them. bft-core derives each slot from the registry's fixed-slot rule and must land on the recorded one. Generated here,
/// compared on every run; regenerate with P85_WRITE_FIXTURES=1.
contract RegistryStateSlotsTest is SealRegistryBase {
    string internal constant FIXTURE = "/test/p85/fixtures/registry-state-slots.json";
    bytes32 internal constant RETIREMENT_PREFIX =
        keccak256("unicity.seal-registry/records.retirement");

    function _slots(bytes32[] memory reads) internal view returns (string memory out) {
        string memory slots = "[";
        string memory words = "[";
        for (uint256 i; i < reads.length; ++i) {
            string memory sep = i == 0 ? "" : ",";
            slots = string.concat(slots, sep, '"', vm.toString(reads[i]), '"');
            words = string.concat(words, sep, '"', vm.toString(vm.load(A_SR, reads[i])), '"');
        }
        out = string.concat('"slots":', slots, '],"words":', words, "]");
    }

    function _view(string memory name, bytes memory callData) internal returns (string memory) {
        vm.record();
        (bool ok,) = A_SR.staticcall(callData);
        require(ok, "view failed");
        (bytes32[] memory reads,) = vm.accesses(A_SR);
        require(reads.length == 1, "a count is one word");
        return string.concat('{"name":"', name, '",', _slots(reads), "}");
    }

    function _retirementKey(uint64 id, uint64 gen) internal pure returns (bytes32) {
        return keccak256(abi.encode(RETIREMENT_PREFIX, id, gen));
    }

    function _scenario(string memory name, uint64 id, uint64 gen) internal returns (string memory) {
        bytes32[] memory key = new bytes32[](1);
        key[0] = _retirementKey(id, gen);
        SealRegistry reg = SealRegistry(A_SR);
        return string.concat(
            '{"name":"',
            name,
            '","id":',
            vm.toString(id),
            ',"generation":',
            vm.toString(gen),
            ',"reads":[',
            _view("recordCount", abi.encodeCall(reg.recordCount, ())),
            ",",
            _view("recordTargetCount", abi.encodeCall(reg.recordTargetCount, ())),
            ',{"name":"retirement",',
            _slots(key),
            '}],"facts":{"count":',
            vm.toString(reg.recordCount()),
            ',"target":',
            vm.toString(reg.recordTargetCount()),
            ',"retirementWord":',
            vm.toString(uint256(vm.load(A_SR, key[0]))),
            "}}"
        );
    }

    function _rec(uint64 index, bytes32 pred, RecordKind kind, bytes memory data)
        internal
        pure
        returns (SealRegistry.ImportedRecord memory)
    {
        RootRecord memory r = RootRecord(
            index,
            keccak256(abi.encode(index, pred, kind, uint64(10), uint64(1_010), data)),
            pred,
            kind,
            10,
            1_010,
            data
        );
        return SealRegistry.ImportedRecord(r, 0);
    }

    function _import(
        OpenArgs memory a,
        SealRegistry.ImportedRecord[] memory es,
        uint64 target,
        bytes32 tip
    ) internal {
        (bool ok,) = callAs(
            A_SYS, abi.encodeCall(SealRegistry.importRootRecords, (a.n, 10, 1_010, target, tip, es))
        );
        require(ok, "import");
    }

    function _scenarios() internal returns (string memory) {
        string memory empty = _scenario("empty", 7, 1);

        OpenArgs memory a = firstPayload();
        openAsSystem(a);
        uint256 snap = vm.snapshotState();

        // the identity's retirement is logged and the registry has caught up with its source
        SealRegistry.ImportedRecord[] memory es = new SealRegistry.ImportedRecord[](2);
        es[0] = _rec(0, bytes32(0), RecordKind.SessionClosed, abi.encode(keccak256("r")));
        es[1] = _rec(
            1,
            es[0].record.recordID,
            RecordKind.Retirement,
            abi.encode(uint64(7), uint64(1), keccak256("ref"))
        );
        vm.record();
        _import(a, es, 2, es[1].record.recordID);
        (, bytes32[] memory writes) = vm.accesses(A_SR);
        bool found;
        for (uint256 i; i < writes.length; ++i) {
            if (writes[i] == _retirementKey(7, 1)) found = true;
        }
        require(found, "the retirement key is a slot the import writes");
        string memory caught = _scenario("retired-caught-up", 7, 1);
        string memory other = _scenario("another-generation", 7, 2);
        vm.revertToState(snap);

        // a backlog beyond one import: 33 records at the source, 32 imported
        SealRegistry.ImportedRecord[] memory batch = new SealRegistry.ImportedRecord[](32);
        bytes32 pred;
        for (uint64 i; i < 32; ++i) {
            batch[i] = _rec(i, pred, RecordKind.SessionClosed, abi.encode(keccak256(abi.encode(i))));
            pred = batch[i].record.recordID;
        }
        _import(a, batch, 33, bytes32(uint256(0x33)));
        string memory behind = _scenario("behind-the-source", 7, 1);
        return string.concat("[", empty, ",", caught, ",", other, ",", behind, "]");
    }

    function test_registryStateSlotsAreTheSharedFixture() public {
        string memory json = string.concat(
            '{"format":"UNICITY_P85_REGISTRY_SLOTS/v1","registry":"',
            vm.toString(A_SR),
            '","codeHash":"',
            vm.toString(A_SR.codehash),
            '","scenarios":',
            _scenarios(),
            "}\n"
        );
        string memory path = string.concat(vm.projectRoot(), FIXTURE);
        if (vm.envOr("P85_WRITE_FIXTURES", false)) vm.writeFile(path, json);
        assertEq(
            vm.readFile(path),
            json,
            "the committed registry-state-slots fixture is stale; regenerate with P85_WRITE_FIXTURES=1"
        );
    }
}
