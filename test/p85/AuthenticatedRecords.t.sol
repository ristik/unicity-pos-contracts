// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
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
/// projection derived. Closure and Retirement carry custody-derived digest words that the projection
/// holds as opaque labels until the digest formulas are shared; the replay substitutes the words
/// custody derives from its own state (and re-links the chain), applies the whole sequence, and
/// asserts the projected anchors, the hold and evidence protections and the retirement import.
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

    /// @dev Replays scenario `sc` like `_replay`, except that the digest words of Closure and Retirement records, which the projection
    /// carries as opaque labels until the digest formulas are shared (briefs/p85-pr1c-control-records.md section 7), are replaced by the
    /// words custody derives from its own state. Everything else is the projection's: index, kind, both anchors, the closure's assignment,
    /// H round, H record and terminal root, the retirement's identity and generation. Record IDs are recomputed here with keccak256 and
    /// the chain re-linked, so custody applies a well-formed log whose anchors are exactly the projected ones.
    function _replayWithCustodyDigests(string memory json, uint256 sc)
        internal
        returns (RootRecord[] memory out)
    {
        uint256 n = _count(json, sc);
        out = new RootRecord[](n);
        for (uint256 i = 0; i < n; ++i) {
            RootRecord memory r = _load(json, sc, i);
            if (r.kind == RecordKind.Closure) {
                ClosureData memory c = abi.decode(r.data, (ClosureData));
                Asg memory a = asg(c.assignmentID);
                r.data = abi.encode(
                    ClosureData(
                        c.assignmentID,
                        c.hRound,
                        c.hRecordID,
                        c.terminalRoot,
                        a.exposureDigest,
                        a.keyDigest
                    )
                );
            } else if (r.kind == RecordKind.Retirement) {
                RetirementData memory t = abi.decode(r.data, (RetirementData));
                r.data = abi.encode(
                    RetirementData(t.id, t.generation, custody.exposureChain(t.id, t.generation))
                );
            }
            r.predecessor = i == 0 ? bytes32(0) : out[i - 1].recordID;
            r.recordID = _id(r);
            out[i] = r;
            roots.pushRaw(r);
        }
        roots.setClock(out[n - 1].progress, out[n - 1].ucTime);
    }

    function test_theHandoffScenarioIsAppliedFromProjectedRecords() public {
        string memory json = _vectors();
        // J excludes identity 1 (so it can retire), J2 is the aborted attempt that holds all members
        reserve(RES_J, ASG_J, allExcept(0), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        requestRetirement(0);
        RootRecord[] memory projected = new RootRecord[](_count(json, 0));
        for (uint256 i; i < projected.length; ++i) {
            projected[i] = _load(json, 0, i);
        }
        RootRecord[] memory rs = _replayWithCustodyDigests(json, 0);
        assertEq(rs.length, 4);
        for (uint256 i; i < rs.length; ++i) {
            assertEq(uint8(rs[i].kind), uint8(projected[i].kind));
            assertEq(rs[i].progress, projected[i].progress, "the projection's progress anchor");
            assertEq(rs[i].ucTime, projected[i].ucTime, "the projection's UC time anchor");
        }

        // SessionClosed(J2) and Ack(J): progress, offset and first round are the projection's.
        custody.applyRootRecords(2);
        assertEq(custody.recordCursor(), 2);
        assertEq(asg(ASG_J2).state, 3, "J2 aborted");
        Asg memory j = asg(ASG_J);
        assertEq(j.state, 2);
        assertEq(j.offset, 100, "p(1,100)+1");
        assertEq(j.firstRound, 101);
        assertEq(asg(GENESIS_ASSIGNMENT).hRound, 100);
        assertEq(rs[1].progress, 99, "the Ack is anchored at H's endpoint");

        // Closure: first and only, at the projected anchors, with the hold and evidence protections it implies.
        custody.applyRootRecords(1);
        Asg memory g = asg(GENESIS_ASSIGNMENT);
        assertTrue(g.closed);
        assertEq(g.pClose, 150, "p_close = 100 + (151 - 101)");
        assertEq(g.tClose, 1_200);
        LotV memory l = lotv(1);
        assertEq(l.refCount, 0, "identity 1 is in no live assignment");
        assertEq(l.holdUntil, 150 + 2_000);
        assertEq(l.evidenceUntil, 150 + 1_000);
        assertEq(l.timeUntil, 1_200 + 3_600);
        assertEq(custody.maxLiabilityAnchor(gid(0), 1), 150);

        // Retirement of identity 1, generation 1, at the same anchors.
        custody.applyRootRecords(1);
        assertEq(custody.recordCursor(), 4);
        (bool imported, uint64 pRet, uint64 tRet) = custody.retirements(gid(0), 1);
        assertTrue(imported);
        assertEq(pRet, 150);
        assertEq(tRet, 1_200);
        assertConserved();
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
    /// keeps both anchors, every other change is rejected, and custody must reject with the exact error the vectors name. The projection
    /// has no stored digests, so a changed digest is a conflict there but `ClosureDigestMismatch` here; a case with no custody error
    /// (another assignment inside the closed epoch) cannot be expressed in custody, which derives the epoch from the assignment.
    function test_theClosureCasesAreAppliedToCustody() public {
        string memory json = _vectors();
        uint256 n;
        while (vm.keyExistsJson(json, string.concat(".closureCases[", vm.toString(n), "].name"))) {
            ++n;
        }
        assertEq(n, 7, "the vectors carry the seven closure cases");
        uint256 applicable;
        for (uint256 i; i < n; ++i) {
            string memory base = string.concat(".closureCases[", vm.toString(i), "]");
            string memory change = vm.parseJsonString(json, string.concat(base, ".change"));
            string memory expect = vm.parseJsonString(json, string.concat(base, ".expect"));
            string memory custodyError = vm.keyExistsJson(
                json, string.concat(base, ".custodyError")
            )
                ? vm.parseJsonString(json, string.concat(base, ".custodyError"))
                : "";
            bytes32 c = keccak256(bytes(change));
            bool repeat = keccak256(bytes(expect)) == keccak256("repeat");
            if (!repeat && bytes(custodyError).length == 0) continue; // not applicable to custody (see above)
            ++applicable;
            uint256 snap = vm.snapshotState();

            handoffExcluding(0);
            closeGenesisAt(150, 1_200);
            ClosureData memory d =
                abi.decode(closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"), (ClosureData));
            if (c == keccak256("hRound")) d.hRound = H_ROUND + 1;
            else if (c == keccak256("hRecord")) d.hRecordID = keccak256("another H record");
            else if (c == keccak256("terminalRoot")) d.terminalRoot = keccak256("another root");
            else if (c == keccak256("exposureDigest")) d.exposureDigest = keccak256("x");
            else if (c == keccak256("keyHistoryDigest")) d.keyHistoryDigest = keccak256("k");
            clock(900, 9_000);
            pushRecord(RecordKind.Closure, abi.encode(d));
            uint64 cursor = custody.recordCursor();
            if (repeat) {
                applyAll();
                assertEq(custody.recordCursor(), cursor + 1, change);
                assertEq(asg(GENESIS_ASSIGNMENT).pClose, 150, change);
                assertEq(asg(GENESIS_ASSIGNMENT).tClose, 1_200, change);
            } else {
                bytes4 selector = keccak256(bytes(custodyError)) == keccak256("ConflictingClosure")
                    ? StakeCustody.ConflictingClosure.selector
                    : StakeCustody.ClosureDigestMismatch.selector;
                assertTrue(
                    keccak256(bytes(custodyError)) == keccak256("ConflictingClosure")
                        || keccak256(bytes(custodyError)) == keccak256("ClosureDigestMismatch"),
                    "the vectors name a custody error this test knows"
                );
                vm.expectRevert(selector);
                custody.applyRootRecords(1);
                assertEq(custody.recordCursor(), cursor, change);
            }
            vm.revertToState(snap);
        }
        assertEq(applicable, 6, "six of the seven cases apply to custody");
    }
}
