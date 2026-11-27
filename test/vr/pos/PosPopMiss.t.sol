// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";
import {PosBase} from "./PosBase.sol";
import {PosLimitBase} from "./PosLimit.t.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {ElectionStorage} from "../../../src/p85/ElectionPolicy.sol";
import {
    ElectionParams,
    Limits,
    RecordKind,
    OutputRejectedData,
    HolderRetirementData
} from "../../../src/p85/P85Types.sol";

/// @notice #1319: a root-certified handoff-PoP miss (record kind 9 `PoPMissed`) parks the named frozen members of a result, incumbents
/// included, for 2 x LIFETIME of root progress from the record's anchor. Applied once per result from VR's own segment. Only the park
/// is affected: the next election excludes the parked identity (Selection is unchanged), its bond, signing, exit and claim rights stay.
contract PosPopMissTest is PosBase {
    uint64 internal constant PARK = 2 * VRC.LIFETIME;
    bytes32 internal constant PARKED_SIG = keccak256("Parked(bytes32,uint64,uint64)");

    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: 10,
            nMax: 16,
            maxM: 4,
            distNum: 1,
            distDen: 1,
            cadenceRounds: 200,
            cadenceSeconds: 100
        });
    }

    function _join() internal returns (Joiner memory j) {
        j = _joinPos(1_000 * UCT);
        evmPkOf[j.id] = j.evmPk;
    }

    function _missed(bytes32 rid, uint256 bitmap) internal {
        pushRecord(RecordKind.PoPMissed, abi.encode(rid, uint64(progress), bitmap));
    }

    /// @dev The root's projection of a certified miss: OutputRejected(Expired), PoPMissed, SessionClosed, one anchor.
    function _expireMissed(bytes32 rid, uint16 ready, uint16 missed) internal returns (uint64 p) {
        _advance(10, 10);
        p = progress;
        pushRecord(RecordKind.OutputRejected, abi.encode(OutputRejectedData(rid, 1, 0, ready)));
        _missed(rid, missed);
        _closedRecord(rid);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_CLOSED);
        assertEq(election.openResult(), bytes32(0));
    }

    function _ids(bytes32 rid) internal view returns (uint64[] memory ids) {
        ElectionStorage.Frozen[] memory f = election.frozenMembers(rid);
        ids = new uint64[](f.length);
        for (uint256 i; i < f.length; ++i) {
            ids[i] = f[i].id;
        }
    }

    function _has(bytes32 rid, uint64 id) internal view returns (bool) {
        uint64[] memory ids = _ids(rid);
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i] == id) return true;
        }
        return false;
    }

    function _parkedEvents(Vm.Log[] memory logs) internal view returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(election) && logs[i].topics[0] == PARKED_SIG) ++n;
        }
    }

    /// @dev An election at exactly root progress `p` (past the cadence in UC time), returning VR's outcome.
    function _electAtOutcome(uint64 p) internal returns (uint8) {
        progress = p;
        ucTime += 1_000;
        roots.setClock(progress, ucTime);
        vm.roll(block.number + 1);
        return _vrElect(ORIGIN);
    }

    // ---- the park ----

    function test_aCertifiedMissParksTheIncumbentOnlyAndOnce() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_ids(r1).length, 5);
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        // every ready bit is set (Expired parks nobody); the root certified the miss of the first member (incumbent 1)
        vm.recordLogs();
        uint64 p = _expireMissed(r1, 0x1f, 0x01);
        assertEq(_parkedEvents(vm.getRecordedLogs()), 1, "one identity parked");
        assertEq(
            election.parkedUntil(1), p + PARK, "the incumbent is parked for exactly 2 x LIFETIME"
        );
        for (uint64 id = 2; id <= N_GENESIS; ++id) {
            assertEq(election.parkedUntil(id), 0, "nobody else");
        }
        assertEq(election.parkedUntil(j.id), 0);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_aMissAddsToTheExpiredParkAndTakesTheLaterEnd() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        // the joiner's ready bit is clear (parkExpired parks it); the miss names incumbents 2 and 3 (bits 1 and 2)
        uint64 p = _expireMissed(r1, 0x0f, 0x06);
        assertEq(election.parkedUntil(j.id), p + PARK);
        assertEq(election.parkedUntil(2), p + PARK);
        assertEq(election.parkedUntil(3), p + PARK);
        assertEq(election.parkedUntil(1), 0);
        assertEq(election.parkedUntil(4), 0);
    }

    function test_aMissNeverShortensALaterPark() public {
        _join();
        bytes32 r1 = _electFromStake();
        vm.prank(ADAPTER);
        election.parkMissed(r1, 0x01, progress + 10 * PARK);
        uint64 far = election.parkedUntil(1);
        assertEq(far, progress + 11 * PARK);
        // the same id again under a different result does not move it down
        assertEq(_ids(r1)[0], 1);
        vm.prank(ADAPTER);
        election.parkMissed(r1, 0x01, progress);
        assertEq(election.parkedUntil(1), far, "once per result and never shortened");
    }

    function test_theSameRecordTwiceOrASecondMissParksOnce() public {
        _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        _advance(10, 10);
        uint64 p = progress;
        uint64 first = roots.recordCount();
        pushRecord(RecordKind.OutputRejected, abi.encode(OutputRejectedData(r1, 1, 0, 0x1f)));
        _missed(r1, 0x01);
        _closedRecord(r1);
        vm.recordLogs();
        _vrApplyAll();
        // the segment again (a redelivery), then a second PoPMissed of the same result at a later progress naming another member
        vm.prank(VR_ADDR);
        adapter.onRecords(first, 3);
        _advance(500, 10);
        _missed(r1, 0x02);
        _vrApplyAll();
        assertEq(_parkedEvents(vm.getRecordedLogs()), 1, "parked once");
        assertEq(election.parkedUntil(1), p + PARK, "the first application stands");
        assertEq(election.parkedUntil(2), 0, "the second record changed nothing");
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_bitsBeyondTheFrozenLengthAreIgnored() public {
        _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        uint64 p = _expireMissed(r1, 0x1f, 0xffe0 | 0x08); // five frozen members: bit 3 (id 4) plus bits 5..15
        assertEq(election.parkedUntil(4), p + PARK);
        for (uint64 id = 1; id <= 3; ++id) {
            assertEq(election.parkedUntil(id), 0);
        }
        assertEq(election.parkedUntil(5), 0, "the joiner's bit 4 is clear");
    }

    function test_aMissOfAnUnpublishedResultParksToo() public {
        _join();
        bytes32 r1 = _electFromStake();
        uint64 p = _expireMissed(r1, 0, 0x02);
        assertEq(election.parkedUntil(2), p + PARK);
    }

    function test_aForeignResultParksNothing() public {
        _join();
        bytes32 r1 = _electFromStake();
        vm.prank(ADAPTER);
        election.parkMissed(keccak256("foreign"), 0xffff, progress);
        for (uint64 id = 1; id <= 5; ++id) {
            assertEq(election.parkedUntil(id), 0);
        }
        // the foreign id consumed nothing
        uint64 p = _expireMissed(r1, 0, 0x01);
        assertEq(election.parkedUntil(1), p + PARK);
    }

    // ---- the next election ----

    function test_theNextElectionExcludesTheParkedIncumbent() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        _expireMissed(r1, 0x1f, 0x01);
        bytes32 r2 = _electFromStake();
        uint64[] memory ids = _ids(r2);
        assertEq(ids.length, 4, "three incumbents and the joiner");
        assertEq(ids[0], 2);
        assertEq(ids[1], 3);
        assertEq(ids[2], 4);
        assertEq(ids[3], j.id);
        assertEq(_publishResult2(r2), VRC.PUB_PUBLISHED);
        _ackNext(r2);
        assertEq(vr.committee().length, 4);
        assertEq(vr.health(), VRC.HEALTHY);
        assertTrue(election.isIndexed(1), "the parked incumbent is still indexed");
    }

    function test_atTheFloorWithoutAReplacementTheElectionRecordsNoCandidate() public {
        bytes32 r1 = _electFromStake();
        assertEq(_ids(r1).length, 4);
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        uint64 p = _expireMissed(r1, 0x0f, 0x01);
        uint64 until = p + PARK;
        _advance(300, 200);
        assertEq(_vrElect(ORIGIN), VRC.ELECT_NO_CANDIDATE);
        ElectionStorage.Result memory att = election.result(election.lastAttemptResult());
        assertEq(uint8(att.reason), 2, "Reason Cardinality");
        assertEq(vr.committee().length, 4, "the old committee stays");
        assertEq(vr.health(), VRC.HEALTHY);

        // eligibility resumes exactly at until
        uint256 snap = vm.snapshotState();
        assertEq(_electAtOutcome(until - 1), VRC.ELECT_NO_CANDIDATE, "still parked at until - 1");
        vm.revertToState(snap);
        assertEq(_electAtOutcome(until), VRC.ELECT_RESERVED, "eligible again at until");
        assertTrue(_has(vr.openOutput(), 1));
    }

    // ---- what the park does not touch ----

    function test_aParkedIncumbentKeepsItsRights() public {
        Joiner memory j = _join();
        bytes32 r1 = _elect2();
        _ackNext(r1);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, lastH, "genesis"));
        _vrApplyAll();
        // the joiner is an incumbent now; r2 expires and the root certified the joiner's miss
        bytes32 r2 = _elect2();
        assertTrue(_has(r2, j.id));
        uint64 p = _expireMissed(r2, 0x1f, 0x10);
        assertEq(election.parkedUntil(j.id), p + PARK, "the incumbent is parked");
        assertTrue(election.isIndexed(j.id));
        assertEq(custody.liveExposures(j.id, 1), 1, "only r1's exposure remains");

        vm.prank(vm.addr(j.ownerPk));
        custody.requestRetirement(j.id);
        requestedSeen[j.id][1] = true;
        _assertFacts(j.id, 1);
        bytes32 r3 = _elect2();
        assertEq(_ids(r3).length, 4, "excluded");
        _ackNext(r3);
        bytes32 a1 = election.result(r1).assignmentID;
        pushRecord(RecordKind.Closure, closureData(a1, lastH, "r1"));
        _vrApplyAll();
        _anchorIfClosed(a1, "r1");
        assertEq(custody.liveExposures(j.id, 1), 0);
        _advance(400, 400);
        pushRecord(
            RecordKind.HolderRetirement,
            abi.encode(HolderRetirementData(0, j.id, 1, custody.exposureChain(j.id, 1)))
        );
        _vrApplyAll();
        (bool imported,,) = custody.retirements(j.id, 1);
        assertTrue(imported, "a parked incumbent retires");
        _advance(100_000, 100_000);
        uint256[] memory lots = new uint256[](1);
        lots[0] = lotOf(j.id);
        custody.mature(lots);
        address wd = vm.addr(j.ownerPk);
        uint256 credit = custody.credit(wd);
        assertEq(credit, 1_000 * UCT);
        vm.prank(wd);
        custody.claim(credit, wd);
        assertEq(wd.balance, 1_000 * UCT, "and claims");
    }

    // ---- the record in the other modules ----

    function test_vrIgnoresAPoPMissedRecordWithoutAnAnomaly() public {
        bytes32 r1 = _electFromStake();
        _advance(10, 10);
        _missed(r1, 0x01);
        _missed(keccak256("foreign"), 0xffff);
        vm.recordLogs();
        _vrApplyAll();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(
                logs[i].topics[0] != keccak256("RecordAnomaly(uint64,uint8,uint8)"), "no anomaly"
            );
        }
        assertEq(custody.recordCursor(), roots.recordCount(), "custody passed over it");
        assertEq(vr.recordCursor(), roots.recordCount());
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_custodyAppliesPoPMissedAsANoOp() public {
        bytes32 r1 = _electFromStake();
        _advance(10, 10);
        _missed(r1, 0x03);
        custody.applyRootRecords(1);
        assertEq(custody.recordCursor(), roots.recordCount());
        assertEq(election.parkedUntil(1), 0, "custody never parks");
        assertEq(_state(r1), VRC.OUT_RESERVED);
    }

    function test_theCodecAcceptsOnlyAWellFormedPoPMissed() public pure {
        bytes32 r = keccak256("r");
        assertTrue(VRCodec.recordWellFormed(9, abi.encode(r, uint64(7), uint256(1))));
        assertTrue(VRCodec.recordWellFormed(9, abi.encode(r, type(uint64).max, uint256(0xffff))));
        assertFalse(VRCodec.recordWellFormed(9, abi.encode(bytes32(0), uint64(7), uint256(1))));
        assertFalse(VRCodec.recordWellFormed(9, abi.encode(r, uint64(7), uint256(0))));
        assertFalse(VRCodec.recordWellFormed(9, abi.encode(r, uint64(7), uint256(0x10000))));
        assertFalse(VRCodec.recordWellFormed(9, abi.encode(r, uint256(1) << 64, uint256(1))));
        assertFalse(VRCodec.recordWellFormed(9, abi.encode(r, uint64(7))));
        assertFalse(
            VRCodec.recordWellFormed(9, abi.encodePacked(abi.encode(r, uint64(7), uint256(1)), r))
        );
        assertFalse(VRCodec.recordWellFormed(10, abi.encode(r, uint64(7), uint256(1))));
    }

    // ---- the hook caller ----

    function test_onlyTheAdapterParksAMiss() public {
        _join();
        bytes32 r1 = _electFromStake();
        vm.expectRevert(ElectionStorage.NotSystem.selector);
        election.parkMissed(r1, 1, progress);
        vm.prank(SYS);
        vm.expectRevert(ElectionStorage.NotSystem.selector);
        election.parkMissed(r1, 1, progress);
    }

    function test_aFailedMissParkIsReportedAndTheRecordsStillReachCustody() public {
        _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        vm.mockCallRevert(
            address(election), abi.encodeWithSelector(election.parkMissed.selector), "boom"
        );
        vm.recordLogs();
        _expireMissed(r1, 0x1f, 0x01);
        vm.clearMockedCalls();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 skipped;
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == ADAPTER && logs[i].topics[0] == keccak256("ParkSkipped(bytes32)")
                    && logs[i].topics[1] == r1
            ) ++skipped;
        }
        assertEq(skipped, 1, "the skip is reported once");
        assertEq(election.parkedUntil(1), 0, "skipped: not parked");
        assertEq(custody.recordCursor(), roots.recordCount());
        assertEq(vr.health(), VRC.HEALTHY);
    }
}

/// @notice #1319 worst case: a published 16-seat result expires, the root certified every member's miss. The adapter's cold three-record
/// callback (OutputRejected, PoPMissed, SessionClosed) fits the stipend VR gives three records.
contract PosPopMissSixteenTest is PosLimitBase {
    function _nMax() internal pure override returns (uint32) {
        return 16;
    }

    function _manifestLimits() internal pure override returns (Limits memory) {
        return Limits({vMax: 20, lMax: 1, rMax: 4, maxBatch: 32});
    }

    function _recordCap() internal pure override returns (uint256) {
        return 2_500_000;
    }

    function test_aSixteenSeatCertifiedMissParksWithinTheRecordStipend() public {
        _atTheLimit();
        _advance(300, 200);
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED);
        bytes32 r = vr.openOutput();
        bytes32 next = election.result(r).assignmentID;
        assertEq(custody.assignmentSeatCount(next), 16);
        election.submitAssignmentPoPs(r, _popsFor2(r));
        election.finalizeCandidate(r);
        assertEq(vr.publish(r), VRC.PUB_PUBLISHED);
        _advance(10, 10);
        uint64 from = roots.recordCount();
        uint64 p = progress;
        pushRecord(RecordKind.OutputRejected, abi.encode(OutputRejectedData(r, 1, 0, 0)));
        pushRecord(RecordKind.PoPMissed, abi.encode(r, uint64(p), uint256(0xffff)));
        _closedRecord(r);
        _coolAll();
        vm.recordLogs();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        (bool ok,) = address(adapter).call{gas: 3 * _recordCap()}(
            abi.encodeCall(adapter.onRecords, (from, 3))
        );
        uint256 used = g - gasleft();
        emit log_named_uint(
            "16 seats, cold Expired + PoPMissed(0xffff) + SessionClosed onRecords callback", used
        );
        assertTrue(ok);
        assertLe(used, 3 * _recordStipend(), "within the three-record stipend");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(
                logs[i].topics[0] != keccak256("ParkSkipped(bytes32)"), "the parks are not skipped"
            );
        }
        for (uint256 i; i < 16; ++i) {
            uint64 id = custody.assignmentSeat(next, i).binding.id;
            assertEq(election.parkedUntil(id), p + 2 * VRC.LIFETIME, "every member is parked");
        }
        assertEq(custody.recordCursor(), roots.recordCount(), "the records reached custody");
    }
}
