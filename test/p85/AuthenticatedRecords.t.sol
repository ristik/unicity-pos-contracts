// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {
    RootRecord,
    RecordKind,
    ClosureData,
    RetirementData,
    RecoveryAckData
} from "../../src/p85/P85Types.sol";

/// @notice Replays root records produced by bft-core's projection (`rootrecords`, vectors in
/// `fixtures/root-records-vectors.json`) instead of records authored in this repository. Each
/// identifier is recomputed here with keccak256 (a second implementation of the record ID), each
/// payload is decoded with the contract structs, and the progress/UC-time anchors are the ones the
/// projection derived. Closure and Retirement digests are custody-derived words the projection
/// carries as opaque labels, so those two kinds are decoded and anchor-checked but not applied.
contract AuthenticatedRecordsTest is P85Flow {
    string internal constant VECTORS = "/test/p85/fixtures/root-records-vectors.json";

    function _path(uint256 s, uint256 i, string memory field)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            ".scenarios[", vm.toString(s), "].records[", vm.toString(i), "].", field
        );
    }

    function _count(string memory json, uint256 s) internal view returns (uint256 n) {
        while (vm.keyExistsJson(json, _path(s, n, "index"))) ++n;
    }

    function _load(string memory json, uint256 s, uint256 i)
        internal
        pure
        returns (RootRecord memory r)
    {
        r.index = uint64(vm.parseJsonUint(json, _path(s, i, "index")));
        r.recordID = vm.parseJsonBytes32(json, _path(s, i, "recordId"));
        r.predecessor = vm.parseJsonBytes32(json, _path(s, i, "predecessor"));
        r.kind = RecordKind(uint8(vm.parseJsonUint(json, _path(s, i, "kind"))));
        r.progress = uint64(vm.parseJsonUint(json, _path(s, i, "progress")));
        r.ucTime = uint64(vm.parseJsonUint(json, _path(s, i, "ucTime")));
        r.data = vm.parseJsonBytes(json, _path(s, i, "data"));
    }

    function _vectors() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), VECTORS));
    }

    /// @dev The record ID the registry assigns; recomputed here, never read from the vector.
    function _id(RootRecord memory r) internal pure returns (bytes32) {
        return keccak256(abi.encode(r.index, r.predecessor, r.kind, r.progress, r.ucTime, r.data));
    }

    /// @dev Replays a scenario verbatim into the record source. Returns the records.
    function _replay(string memory json, uint256 s) internal returns (RootRecord[] memory out) {
        uint256 n = _count(json, s);
        out = new RootRecord[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = _load(json, s, i);
            assertEq(out[i].recordID, _id(out[i]), "recordId is keccak of the content");
            assertEq(out[i].predecessor, i == 0 ? bytes32(0) : out[i - 1].recordID, "linked");
            roots.pushRaw(out[i]);
        }
        roots.setClock(out[n - 1].progress, out[n - 1].ucTime);
    }

    function test_theHandoffScenarioIsAppliedFromProjectedRecords() public {
        string memory json = _vectors();
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        RootRecord[] memory rs = _replay(json, 0);
        assertEq(rs.length, 4);

        // SessionClosed(J2) and Ack(J) apply; progress/offset/first-round are the projection's.
        custody.applyRootRecords(2);
        assertEq(custody.recordCursor(), 2);
        assertEq(asg(ASG_J2).state, 3, "J2 aborted");
        Asg memory j = asg(ASG_J);
        assertEq(j.state, 2);
        assertEq(j.offset, 100, "p(1,100)+1");
        assertEq(j.firstRound, 101);
        assertEq(asg(GENESIS_ASSIGNMENT).hRound, 100);
        assertEq(rs[1].progress, 99, "the Ack is anchored at H's endpoint");

        // Closure and Retirement: payloads decode to the structs and carry the projection's anchors.
        ClosureData memory c = abi.decode(rs[2].data, (ClosureData));
        assertEq(c.hRound, 100);
        assertEq(c.assignmentID, keccak256("assignment/genesis"));
        assertEq(rs[2].progress, 150, "p_close = 100 + (151 - 101)");
        assertEq(rs[2].ucTime, 1_200);
        RetirementData memory t = abi.decode(rs[3].data, (RetirementData));
        assertEq(t.id, 1);
        assertEq(t.generation, 1);
        assertEq(rs[3].progress, 150);
    }

    function test_theRecoveryScenarioIsAppliedFromProjectedRecords() public {
        string memory json = _vectors();
        reserve(RES_J, ASG_J, allExcept(0), 1);
        RootRecord[] memory rs = _replay(json, 1);
        assertEq(rs.length, 1);
        RecoveryAckData memory d = abi.decode(rs[0].data, (RecoveryAckData));
        assertEq(d.jOffset, 100);
        assertEq(d.jFirstRound, 101);
        assertEq(d.jHRound, 130);
        assertEq(d.kOffset, 130, "p(J,130)+1 = (100 + 29) + 1");
        assertEq(d.kFirstRound, 131);

        applyAll();
        assertEq(custody.lastAckedAssignment(), ASG_K);
        assertEq(asg(ASG_J).hRound, 130);
        assertEq(asg(ASG_K).firstRound, 131);
        assertEq(asg(ASG_K).offset, 130);
    }

    function test_aTamperedProjectedRecordIsRefused() public view {
        string memory json = _vectors();
        RootRecord memory r = _load(json, 0, 1);
        r.progress += 1; // re-anchoring a record changes its identifier
        assertTrue(r.recordID != _id(r));
        r = _load(json, 0, 1);
        r.data[31] ^= 0x01;
        assertTrue(r.recordID != _id(r));
    }

    // --- closure repeat/conflict: the vectors' cases applied to custody -------------------------

    /// @dev The same second-closure cases bft-core's projection runs (rootrecords closureCases): an identical repeat is a no-op that
    /// keeps both anchors, every other change is rejected. Custody and the projection must agree on each.
    function test_theClosureCasesAreAppliedToCustody() public {
        string memory json = _vectors();
        uint256 n;
        while (vm.keyExistsJson(json, string.concat(".closureCases[", vm.toString(n), "].name"))) {
            ++n;
        }
        assertEq(n, 7, "the vectors carry the seven closure cases");
        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".closureCases[", vm.toString(i), "]");
            string memory change = vm.parseJsonString(json, string.concat(base, ".change"));
            string memory expect = vm.parseJsonString(json, string.concat(base, ".expect"));
            uint256 snap = vm.snapshotState();

            handoffExcluding(0);
            closeGenesisAt(150, 1_200);
            ClosureData memory d =
                abi.decode(closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"), (ClosureData));
            bytes32 c = keccak256(bytes(change));
            if (c == keccak256("assignment")) d.assignmentID = ASG_J;
            else if (c == keccak256("hRound")) d.hRound = H_ROUND + 1;
            else if (c == keccak256("hRecord")) d.hRecordID = keccak256("another H record");
            else if (c == keccak256("terminalRoot")) d.terminalRoot = keccak256("another root");
            else if (c == keccak256("exposureDigest")) d.exposureDigest = keccak256("x");
            else if (c == keccak256("keyHistoryDigest")) d.keyHistoryDigest = keccak256("k");
            clock(900, 9_000);
            pushRecord(RecordKind.Closure, abi.encode(d));
            uint64 cursor = custody.recordCursor();
            if (keccak256(bytes(expect)) == keccak256("repeat")) {
                applyAll();
                assertEq(custody.recordCursor(), cursor + 1, change);
                assertEq(asg(GENESIS_ASSIGNMENT).pClose, 150, change);
                assertEq(asg(GENESIS_ASSIGNMENT).tClose, 1_200, change);
            } else {
                (bool ok,) = address(custody).call(abi.encodeCall(custody.applyRootRecords, (1)));
                assertFalse(ok, change);
                assertEq(custody.recordCursor(), cursor, change);
            }
            vm.revertToState(snap);
        }
    }
}
