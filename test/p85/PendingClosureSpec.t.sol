// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {UncheckedPolicy} from "./UncheckedPolicy.sol";
import {
    Limits,
    Policy,
    RecordKind,
    RecoveryAckData,
    ClosureData,
    RetirementData,
    SessionClosedData,
    RootRecord
} from "../../src/p85/P85Types.sol";

/// @notice The acceptance tests of the P85 pending-closure path (briefs/p85-recovery-closure-ruling.md, run 25).
///
/// Root order of run 25: the original assignment K0 (here the genesis assignment G, acknowledged) -> J installed but never acknowledged
/// (Reserved in custody) -> the root closes the terminated epochs, G's and J's, -> RecoveryAck derives K. Custody must accept J's closure
/// while J is Reserved: stage it with its own anchors, advance the cursor, release nothing, and apply it inside the RecoveryAck that
/// materializes J. Until then maturity and new elections stay closed; imports, blocks and unrelated records continue.
///
/// The tests observe only the public custody/election/evidence API that exists today (assignments, exposures, lots, cursor, session,
/// openResult): they do not read the new storage, so they are written against the behaviour, not against an implementation. The one
/// name they pin is the error `PendingClosureUnresolved()` for a pending closure that is followed by a record that cannot resolve it.
///
/// Timeline (progress p / UC time t):
///   G closure (120, 1000), J closure (140, 1100), RecoveryAck (150, 1200), K closure (200, 1500).
///   J: offset 100, first round 101, H at round 130 -> J's last ordinary progress 129. K: offset 130, first round 131, epochs 3/3.
///   Default policy: holdNormal = holdSuffix 2000, evidence windows 1000, timeFloor 3600.
contract PendingClosureSpecTest is P85Flow {
    uint64 internal constant J_H = 130;
    uint64 internal constant K_H = 160;
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);
    bytes4 internal constant PENDING_UNRESOLVED = bytes4(keccak256("PendingClosureUnresolved()"));

    // --- builders ------------------------------------------------------------------------------------

    function _recoveryAck(bytes32 resultID, bytes32 k) internal pure returns (bytes memory) {
        return abi.encode(RecoveryAckData(resultID, k, 100, 101, J_H, 130, 131, 3, 3));
    }

    /// @dev G reserved-over and closed; J reserved (attempt 1) and closed by the root before any acknowledgement. Nothing applied.
    function _pushGJClosures() internal {
        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"));
        clock(140, 1_100);
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j"));
    }

    /// @dev Records 0..2 of run 25 pushed, nothing applied: G closure, J closure, RecoveryAck deriving K.
    function _pushRun25() internal {
        _pushGJClosures();
        clock(150, 1_200);
        pushRecord(RecordKind.RecoveryAck, _recoveryAck(RES_J, ASG_K));
    }

    /// @dev Apply `_pushRun25` in full and push K's closure (its digests exist only once K does), without applying it.
    function _run25AndKClosurePushed() internal {
        _pushRun25();
        custody.applyRootRecords(3);
        clock(200, 1_500);
        pushRecord(RecordKind.Closure, closureData(ASG_K, K_H, "k"));
    }

    /// @dev The same four records as `_run25AndKClosurePushed`, all unapplied: K's closure data is read from a throwaway state.
    function _pushRun25WithKClosure() internal {
        _pushRun25();
        uint256 snap = vm.snapshotState();
        custody.applyRootRecords(3);
        bytes memory kClosure = closureData(ASG_K, K_H, "k");
        vm.revertToState(snap);
        clock(200, 1_500);
        pushRecord(RecordKind.Closure, kClosure);
    }

    function _stageG_J() internal {
        _pushGJClosures();
        custody.applyRootRecords(2);
    }

    function _mutatedClosure(bytes32 assignmentID, uint64 hRound, bytes32 tag)
        internal
        view
        returns (ClosureData memory d)
    {
        d = abi.decode(closureData(assignmentID, hRound, tag), (ClosureData));
    }

    /// @dev Every public word the three assignments, their exposures, the lots, the cursor and the session contribute.
    function _fingerprint() internal view returns (bytes32 h) {
        bytes32[3] memory ids = [GENESIS_ASSIGNMENT, ASG_J, ASG_K];
        h = keccak256(
            abi.encode(
                asg(ids[0]),
                asg(ids[1]),
                asg(ids[2]),
                lotv(1),
                lotv(2),
                lotv(3),
                lotv(4),
                custody.recordCursor(),
                custody.lastRecordID(),
                custody.lastAckedAssignment(),
                custody.totalFree(),
                custody.totalEncumbered(),
                custody.totalDraining(),
                custody.totalCredits(),
                custody.session(RES_J),
                election.openResult()
            )
        );
        for (uint256 a; a < 3; ++a) {
            for (uint256 i; i < N_GENESIS; ++i) {
                h = keccak256(abi.encode(h, expo(exposureID(ids[a], gid(i)))));
            }
        }
    }

    // --- (1) run 25, reproduced --------------------------------------------------------------------

    function test_run25_bothTerminatedEpochsAreClosedBeforeTheRecoveryAckAndNothingHaltsTheLog()
        public
    {
        _pushRun25();
        applyAll(); // main: AssignmentNotActive on J's closure; the shard cannot build a block

        assertEq(custody.recordCursor(), 3);
        assertEq(custody.lastAckedAssignment(), ASG_K, "authority is K");
        assertEq(custody.session(RES_J).state, 4, "the session ended as recovered"); // SESSION_RECOVERED

        // J: materialized by the recovery (activation, offset, H) and closed by the saved closure at ITS anchors
        Asg memory j = asg(ASG_J);
        assertEq(j.state, 2, "J is active");
        assertTrue(j.offsetSet);
        assertEq(j.offset, 100);
        assertEq(j.firstRound, 101);
        assertTrue(j.hKnown);
        assertEq(j.hRound, J_H);
        assertTrue(j.closed, "J is closed");
        assertEq(j.pClose, 140, "the closure's own progress, not the RecoveryAck's 150");
        assertEq(j.tClose, 1_100, "the closure's own UC time, not the RecoveryAck's 1200");

        // G: closed by its own closure
        Asg memory g = asg(GENESIS_ASSIGNMENT);
        assertTrue(g.closed);
        assertEq(g.pClose, 120);
        assertEq(g.tClose, 1_000);

        // K: derived from the incumbent slate, not closed, with its own epochs and offsets
        Asg memory k = asg(ASG_K);
        assertEq(k.state, 2);
        assertFalse(k.closed);
        assertEq(k.offset, 130);
        assertEq(k.firstRound, 131);
        assertEq(k.rootEpoch, 3);
        assertEq(k.evmEpoch, 3);
        assertTrue(k.exposureDigest != bytes32(0));
        assertTrue(
            k.exposureDigest != asg(GENESIS_ASSIGNMENT).exposureDigest,
            "K's exposures are its own, not G's"
        );
        assertTrue(
            k.exposureDigest != j.exposureDigest,
            "and not J's: identical members, distinct assignments"
        );

        // the cutoffs keep the first closures' anchors: max over G (120, 1000) and J (140, 1100)
        for (uint256 i = 1; i <= N_GENESIS; ++i) {
            LotV memory l = lotv(i);
            assertEq(l.holdUntil, 140 + 2_000, "J's closure anchor + hold");
            assertEq(l.evidenceUntil, 140 + 1_000, "J's closure anchor + window");
            assertEq(l.timeUntil, 1_100 + 3_600, "J's closure UC time + floor");
        }
        assertConserved();
    }

    function test_run25_allThreeAssignmentHistoriesAreVerifiableThroughKsClosure() public {
        _run25AndKClosurePushed();
        // K closes at its own anchors; every lot is then free of references
        applyAll();
        assertEq(custody.recordCursor(), 4);
        Asg memory k = asg(ASG_K);
        assertTrue(k.closed);
        assertEq(k.pClose, 200);
        assertEq(k.tClose, 1_500);
        assertEq(k.hRound, K_H);
        for (uint256 i; i < N_GENESIS; ++i) {
            assertTrue(expo(genesisExposure(i)).released, "G released");
            assertTrue(expo(exposureID(ASG_J, gid(i))).released, "J released");
            assertTrue(expo(exposureID(ASG_K, gid(i))).released, "K released");
            assertEq(lotv(i + 1).refCount, 0);
            assertEq(lotv(i + 1).category, 1, "free again"); // CAT_FREE
            assertEq(lotv(i + 1).holdUntil, 200 + 2_000, "the latest closure anchor decides");
            assertEq(lotv(i + 1).timeUntil, 1_500 + 3_600);
        }
        assertEq(custody.totalEncumbered(), 0);
        assertEq(custody.totalFree(), N_GENESIS * GENESIS_BOND, "principal intact");
        assertEq(custody.liveExposures(gid(0), 1), 0);
        assertConserved();
    }

    function test_run25_theKReferencesExistBeforeAnyReleaseSoNoLotEverLeavesEncumbered() public {
        _pushRun25();
        custody.applyRootRecords(3);
        assertEq(custody.totalFree(), 0, "no lot was freed by the recovery");
        assertEq(custody.totalEncumbered(), N_GENESIS * GENESIS_BOND);
        for (uint256 i; i < N_GENESIS; ++i) {
            assertEq(lotv(i + 1).refCount, 1, "only K references the lot now");
            assertEq(lotv(i + 1).category, 2, "still encumbered"); // CAT_ENCUMBERED
            assertEq(custody.liveExposures(gid(i), 1), 1);
            assertTrue(
                expo(genesisExposure(i)).released, "G's reference was released after K existed"
            );
            assertTrue(
                expo(exposureID(ASG_J, gid(i))).released,
                "J's reference was released after K existed"
            );
            assertFalse(expo(exposureID(ASG_K, gid(i))).released);
        }
    }

    // --- (2) batch splits ------------------------------------------------------------------------------

    function test_everySplitOfTheLogReachesTheSameStateAtEveryCursorAndTheSameEnd() public {
        _pushRun25WithKClosure();
        uint256 base = vm.snapshotState();

        // reference: one record at a time
        bytes32[5] memory ref;
        for (uint32 c = 1; c <= 4; ++c) {
            custody.applyRootRecords(1);
            ref[c] = _fingerprint();
        }
        assertEq(custody.recordCursor(), 4);

        // every composition of the four records into batches: the state at each boundary equals the reference at that cursor, and
        // resuming from the boundary in ONE batch (a restart there) reaches the reference end state
        for (uint256 mask; mask < 8; ++mask) {
            vm.revertToState(base);
            uint256 start;
            for (uint256 i; i < 4; ++i) {
                if (i < 3 && (mask >> i) & 1 == 0) continue; // no boundary after record i
                custody.applyRootRecords(uint32(i + 1 - start));
                start = i + 1;
                assertEq(
                    _fingerprint(), ref[start], "state at a boundary is independent of the split"
                );
                if (start < 4) {
                    uint256 here = vm.snapshotState();
                    custody.applyRootRecords(uint32(4 - start));
                    assertEq(_fingerprint(), ref[4], "restart at the boundary reaches the same end");
                    vm.revertToState(here);
                }
            }
        }
    }

    function test_theBoundaryRightAfterTheStagedClosureAndBeforeTheRecoveryAckLosesNothing()
        public
    {
        _pushRun25();
        custody.applyRootRecords(2); // G closed, J's closure consumed: the RecoveryAck is not in custody yet
        assertEq(custody.recordCursor(), 2);
        // the consumed record is not absent from accounting: J is still Reserved, its exposures are held, nothing was released
        assertEq(asg(ASG_J).state, 1);
        assertFalse(
            asg(ASG_J).closed, "J has no offsets yet: it cannot be closed until the recovery"
        );
        for (uint256 i; i < N_GENESIS; ++i) {
            assertFalse(expo(exposureID(ASG_J, gid(i))).released);
            assertFalse(
                expo(genesisExposure(i)).released, "G is closed but the session still locks it"
            );
            assertEq(lotv(i + 1).refCount, 2, "G's and J's references");
        }
        assertEq(custody.totalFree(), 0);
        assertEq(custody.lastAckedAssignment(), GENESIS_ASSIGNMENT);
        // G, an active assignment, was closed at once
        assertTrue(asg(GENESIS_ASSIGNMENT).closed);
        assertEq(asg(GENESIS_ASSIGNMENT).pClose, 120);
        // the delayed import: the registry clock is far ahead when the RecoveryAck is finally applied
        clock(900_000, 9_000_000);
        custody.applyRootRecords(1);
        assertTrue(asg(ASG_J).closed);
        assertEq(asg(ASG_J).pClose, 140, "the staged anchors, not the import-time clock");
        assertEq(asg(ASG_J).tClose, 1_100);
        assertEq(lotv(1).holdUntil, 140 + 2_000);
        assertEq(lotv(1).timeUntil, 1_100 + 3_600);
    }

    // --- (3) anchors, closure identity, duplicates and conflicts -------------------------------------

    function test_aRepeatedIdenticalClosureWhilePendingKeepsTheFirstAnchors() public {
        _stageG_J();
        clock(160, 1_300);
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j")); // identical identity, later anchors
        clock(170, 1_400);
        pushRecord(RecordKind.RecoveryAck, _recoveryAck(RES_J, ASG_K));
        applyAll();
        assertEq(asg(ASG_J).pClose, 140);
        assertEq(asg(ASG_J).tClose, 1_100);
        assertEq(lotv(1).holdUntil, 140 + 2_000, "the repeat extended nothing");
    }

    function test_aRepeatedIdenticalClosureAfterTheResolutionIsAlsoANoOp() public {
        _pushRun25();
        applyAll();
        bytes32 before_ = _fingerprint();
        clock(300, 2_000);
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j"));
        applyAll();
        assertEq(asg(ASG_J).pClose, 140);
        assertEq(asg(ASG_J).tClose, 1_100);
        assertEq(lotv(1).holdUntil, 140 + 2_000);
        // only the cursor and the record chain moved
        assertEq(custody.recordCursor(), 4);
        assertTrue(before_ != _fingerprint());
    }

    function test_aDifferentHRecordForTheSameJWhilePendingConflicts() public {
        _stageG_J();
        ClosureData memory d = _mutatedClosure(ASG_J, J_H, "j");
        d.hRecordID = keccak256("another H record");
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ConflictingClosure.selector);
        custody.applyRootRecords(1);
    }

    function test_aDifferentTerminalRootForTheSameJWhilePendingConflicts() public {
        _stageG_J();
        ClosureData memory d = _mutatedClosure(ASG_J, J_H, "j");
        d.terminalRoot = keccak256("another terminal root");
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ConflictingClosure.selector);
        custody.applyRootRecords(1);
    }

    function test_aDifferentHRoundForTheSameJWhilePendingConflicts() public {
        _stageG_J();
        ClosureData memory d = _mutatedClosure(ASG_J, J_H, "j");
        d.hRound = J_H + 1;
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ConflictingClosure.selector);
        custody.applyRootRecords(1);
    }

    function test_aConflictingClosureAfterTheResolutionConflicts() public {
        _pushRun25();
        applyAll();
        ClosureData memory d = _mutatedClosure(ASG_J, J_H, "j");
        d.hRecordID = keccak256("another H record");
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ConflictingClosure.selector);
        custody.applyRootRecords(1);
    }

    function test_theOneSlotIsNeverSilentlySharedWithAnotherReservedAssignment() public {
        // two attempts: J (RES_J) and J2 (RES_J2) are both Reserved. J's closure is staged; a closure of J2 carrying the SAME H record,
        // round and terminal root is not "a repeat of J's": it names another assignment and there is one slot, so it must not be
        // swallowed (a consumed record that is absent from accounting)
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        clock(140, 1_100);
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j"));
        custody.applyRootRecords(1);
        pushRecord(RecordKind.Closure, closureData(ASG_J2, J_H, "j"));
        vm.expectRevert(StakeCustody.ConflictingClosure.selector);
        custody.applyRootRecords(1);
        assertEq(custody.recordCursor(), 1, "the second closure is not consumed");
    }

    function test_aClosureWithAnotherAssignmentsDigestsIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        ClosureData memory d = _mutatedClosure(ASG_J, J_H, "j");
        ClosureData memory g = _mutatedClosure(GENESIS_ASSIGNMENT, H_ROUND, "genesis");
        d.exposureDigest = g.exposureDigest;
        d.keyHistoryDigest = g.keyHistoryDigest;
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ClosureDigestMismatch.selector);
        custody.applyRootRecords(1);
    }

    function test_aBadExposureDigestAloneIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        ClosureData memory d = _mutatedClosure(ASG_J, J_H, "j");
        d.exposureDigest = keccak256("tampered");
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ClosureDigestMismatch.selector);
        custody.applyRootRecords(1);
    }

    function test_aBadKeyHistoryDigestAloneIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        ClosureData memory d = _mutatedClosure(ASG_J, J_H, "j");
        d.keyHistoryDigest = keccak256("tampered");
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ClosureDigestMismatch.selector);
        custody.applyRootRecords(1);
    }

    function test_aClosureOfAnUnknownAssignmentIsRejectedAndKCannotBeClosedBeforeItsRecoveryAck()
        public
    {
        // an assignment custody has never seen: no pending state is created for it
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j"));
        vm.expectRevert(StakeCustody.AssignmentNotActive.selector);
        custody.applyRootRecords(1);
        // K exists only once the RecoveryAck derives it: its closure cannot precede that record
        setUp();
        _stageG_J();
        pushRecord(RecordKind.Closure, closureData(ASG_K, K_H, "k"));
        vm.expectRevert(StakeCustody.AssignmentNotActive.selector);
        custody.applyRootRecords(1);
    }

    function test_aClosureOfAnAbortedAssignmentIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        applyAll();
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j"));
        vm.expectRevert(StakeCustody.AssignmentNotActive.selector);
        custody.applyRootRecords(1);
    }

    function test_aStagedClosureWhoseHRoundIsNotTheRecoveryHRoundFailsTheRecoveryAndKeepsThePendingState()
        public
    {
        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(140, 1_100);
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H + 1, "j"));
        custody.applyRootRecords(1);
        bytes32 staged = _fingerprint();
        clock(150, 1_200);
        pushRecord(RecordKind.RecoveryAck, _recoveryAck(RES_J, ASG_K));
        vm.expectRevert(StakeCustody.HRoundMismatch.selector);
        custody.applyRootRecords(1);
        assertEq(_fingerprint(), staged, "atomic: the failed recovery changed nothing");
        assertEq(custody.recordCursor(), 1);
    }

    function test_aPendingClosureFollowedByAnOrdinaryAckIsRejected() public {
        _stageG_J();
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        bytes32 staged = _fingerprint();
        vm.expectRevert(PENDING_UNRESOLVED);
        custody.applyRootRecords(1);
        assertEq(_fingerprint(), staged);
    }

    function test_aPendingClosureFollowedBySessionClosedIsRejected() public {
        _stageG_J();
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        bytes32 staged = _fingerprint();
        vm.expectRevert(PENDING_UNRESOLVED);
        custody.applyRootRecords(1);
        assertEq(_fingerprint(), staged);
    }

    /// @dev Specification extension (the ruling is silent on it): the only valid resolver of J's pending closure is the RecoveryAck of
    /// J's own result. A RecoveryAck that resolves ANOTHER session while J is pending would leave J's closure pending forever and
    /// derive a second K: one recovery, one pending J.
    function test_aPendingClosureFollowedByTheRecoveryAckOfAnotherSessionIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        clock(140, 1_100);
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j"));
        custody.applyRootRecords(1);
        bytes32 staged = _fingerprint();
        clock(150, 1_200);
        pushRecord(RecordKind.RecoveryAck, _recoveryAck(RES_J2, ASG_K));
        vm.expectRevert(PENDING_UNRESOLVED);
        custody.applyRootRecords(1);
        assertEq(_fingerprint(), staged);
    }

    function test_aSecondRecoveryAckForTheSameResultIsRejected() public {
        _pushRun25();
        applyAll();
        bytes32 after_ = _fingerprint();
        pushRecord(RecordKind.RecoveryAck, _recoveryAck(RES_J, keccak256("assignment/K2")));
        vm.expectRevert(StakeCustody.SessionNotOpen.selector);
        custody.applyRootRecords(1);
        assertEq(_fingerprint(), after_);
    }

    function test_aSecondRecoveryForAnotherSessionAfterTheFirstIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        clock(120, 1_000);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"));
        clock(140, 1_100);
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j"));
        clock(150, 1_200);
        pushRecord(RecordKind.RecoveryAck, _recoveryAck(RES_J, ASG_K));
        applyAll();
        // the incumbent of J2 is G, no longer the acknowledged assignment (K): the second recovery cannot apply
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(
                RecoveryAckData(RES_J2, keccak256("assignment/K2"), 100, 101, J_H, 130, 131, 3, 3)
            )
        );
        vm.expectRevert(StakeCustody.IncumbentMismatch.selector);
        custody.applyRootRecords(1);
    }

    // --- (4) gates while pending -------------------------------------------------------------------------

    /// @dev An identity outside every assignment whose lot is mature at (3000, 9000) once its retirement record is applied; it
    /// isolates the pending gate from every other maturity condition.
    function _spareMatureLot() internal returns (uint256 lot) {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        lot = bondFor(id, 100 * UCT);
        vm.prank(vm.addr(0x9001));
        custody.requestRetirement(id);
        retireRecordAt(id, 110, 900);
    }

    function test_maturityStaysClosedWhileAClosureIsPendingEvenWithTheCursorAtTheRecordCount()
        public
    {
        uint256 lot = _spareMatureLot();
        _pushGJClosures();
        custody.applyRootRecords(2);
        assertEq(
            custody.recordCursor(),
            roots.recordCount(),
            "the registry is fully consumed: cursor equality holds"
        );
        clock(3_000, 9_000);
        vm.expectRevert(StakeCustody.RecordsPending.selector);
        matureOne(lot);
        // the RecoveryAck resolves the pending state; the same lot, the same clock, now matures
        pushRecord(RecordKind.RecoveryAck, _recoveryAck(RES_J, ASG_K));
        custody.applyRootRecords(1);
        matureOne(lot);
        assertEq(creditOf(vm.addr(0x9201)), 100 * UCT);
        assertConserved();
    }

    function test_theElectionStaysDisabledWhilePendingAndTheRecoveryResolvesTheResult() public {
        uint64 cadP = 100_000;
        uint64 cadT = 604_800;
        clock(cadP, cadT);
        vm.prank(SYS);
        assertEq(
            uint8(election.elect(keccak256("origin/1"))), uint8(ElectionPolicy.Outcome.Reserved)
        );
        bytes32 resultID = election.openResult();
        bytes32 asgID = keccak256(abi.encode(keccak256("unicity.p85.primary-assignment"), resultID));

        clock(cadP + 20, cadT + 1_000);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"));
        clock(cadP + 40, cadT + 1_100);
        pushRecord(RecordKind.Closure, closureData(asgID, J_H, "j"));
        custody.applyRootRecords(2);
        assertEq(custody.recordCursor(), roots.recordCount());

        // far past the next cadence: the election is still not allowed to start another result
        clock(3 * cadP, 3 * cadT);
        vm.prank(SYS);
        assertEq(
            uint8(election.elect(keccak256("origin/2"))),
            uint8(ElectionPolicy.Outcome.Disabled),
            "the result is unresolved"
        );
        assertEq(election.openResult(), resultID);

        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(resultID, ASG_K, 100, 101, J_H, 130, 131, 3, 3))
        );
        custody.applyRootRecords(1);
        assertEq(election.openResult(), bytes32(0), "the RecoveryAck resolves it");
        assertEq(
            uint8(election.result(resultID).state), uint8(ElectionPolicy.ResultState.Recovered)
        );
        assertEq(election.anchorProgress(), 0, "a recovery moves no cadence anchor");
    }

    function test_importsAndUnrelatedRecordsContinueWhilePending() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        clock(140, 1_100);
        pushRecord(RecordKind.Closure, closureData(ASG_J, J_H, "j"));
        custody.applyRootRecords(1);
        // the abort of the unrelated later attempt applies while J's closure is pending
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J2)));
        custody.applyRootRecords(1);
        assertEq(custody.recordCursor(), 2);
        assertEq(asg(ASG_J2).state, 3, "aborted");
        assertEq(asg(ASG_J).state, 1, "J is still waiting for its RecoveryAck");
    }

    function test_aRetirementIsRefusedWhileJAndGAreStillReferencingTheIdentity() public {
        _stageG_J();
        vm.prank(vm.addr(ownerPk(0)));
        custody.requestRetirement(gid(0)); // after the reservation: a retiring identity is no primary candidate
        clock(160, 1_300);
        pushRecord(
            RecordKind.Retirement,
            abi.encode(RetirementData(gid(0), 1, custody.exposureChain(gid(0), 1)))
        );
        vm.expectRevert(StakeCustody.RefsStillLive.selector);
        custody.applyRootRecords(1);
    }

    function test_aRetirementIsStillRefusedRightAfterTheRecoveryBecauseKReferencesTheIdentity()
        public
    {
        _pushRun25();
        vm.prank(vm.addr(ownerPk(0)));
        custody.requestRetirement(gid(0));
        custody.applyRootRecords(3);
        assertEq(custody.liveExposures(gid(0), 1), 1, "K's reference exists");
        clock(160, 1_300);
        // the exposure chain already contains K's exposure: the digest is right, the reference is live
        pushRecord(
            RecordKind.Retirement,
            abi.encode(RetirementData(gid(0), 1, custody.exposureChain(gid(0), 1)))
        );
        vm.expectRevert(StakeCustody.RefsStillLive.selector);
        custody.applyRootRecords(1);
    }

    function test_theRetirementAndMaturityPathCompletesAfterKCloses() public {
        _pushRun25WithKClosure();
        vm.prank(vm.addr(ownerPk(0)));
        custody.requestRetirement(gid(0));
        applyAll();
        clock(210, 1_600);
        pushRecord(
            RecordKind.Retirement,
            abi.encode(RetirementData(gid(0), 1, custody.exposureChain(gid(0), 1)))
        );
        applyAll();
        uint256 lot = lotOf(gid(0));
        // round gate: p > max(210 + 2000, 200 + 2000); UC gate: t >= max(1600, 1500) + 3600
        clock(2_210, 5_199);
        vm.expectRevert(StakeCustody.RoundGateNotMet.selector);
        matureOne(lot);
        clock(2_211, 5_199);
        vm.expectRevert(StakeCustody.TimeGateNotMet.selector);
        matureOne(lot);
        clock(2_211, 5_200);
        matureOne(lot);
        assertEq(creditOf(vm.addr(wdPk(0))), GENESIS_BOND);
        assertConserved();
    }

    function test_aZeroBalanceLotDoesNotBreakTheReleaseOfAPendingJ() public {
        // lifetime cap 100%, penalty 100%: one settled offence under G drains identity 1's lot to zero while it is still referenced
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 10_000;
        p.lifetimeCapBps = 10_000;
        _deployManual(
            address(new UncheckedPolicy(p)), Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32})
        );
        _pushRun25();
        // an offence of identity 1 in G's epoch (round 10, still timely at progress 119), admitted and settled before the closures apply
        clock(150, 1_200);
        bytes32 caseID = _submitCase(1, rootPk(0), genesisExposure(0), 10);
        uint256 lot = lotOf(gid(0));
        _settleCase(caseID, lot);
        assertEq(lotv(lot).remaining, 0, "drained to zero while referenced");
        applyAll();
        assertEq(custody.recordCursor(), 3);
        assertEq(lotv(lot).refCount, 1);
        assertEq(
            custody.totalEncumbered(),
            (N_GENESIS - 1) * GENESIS_BOND,
            "the drained lot holds nothing"
        );
        assertConserved();
    }

    // --- evidence ---------------------------------------------------------------------------------------------

    function _vote(Evidence.VoteHeader memory h, bytes32 payload, uint256 keyPk)
        internal
        view
        returns (Evidence.SignedVote memory)
    {
        return Evidence.SignedVote(payload, sign(keyPk, evidence.voteDigest(h, payload)));
    }

    function _submitCase(uint64 epoch, uint256 keyPk, bytes32 exposureID_, uint64 round)
        internal
        returns (bytes32)
    {
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, 1, compressed(keyPk), epoch, round); // domain 1 = root
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), keyPk);
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), keyPk);
        vm.prank(reporter);
        return evidence.submitEvidence(h, a, b, exposureID_);
    }

    function _settleCase(bytes32 caseID, uint256 lotID) internal returns (uint256) {
        uint256[] memory ids = new uint256[](1);
        ids[0] = lotID;
        return evidence.settleEvidence(caseID, ids);
    }

    function _expectLate(uint64 epoch, uint256 keyPk, bytes32 exposureID_, uint64 round) internal {
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, 1, compressed(keyPk), epoch, round);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), keyPk);
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), keyPk);
        vm.expectRevert(Evidence.EvidenceLate.selector);
        evidence.submitEvidence(h, a, b, exposureID_);
    }

    function test_jCannotBeChargedWhilePendingAndItsOrdinaryCutoffCountsFromTheRecoveryOffsets()
        public
    {
        _stageG_J();
        bytes32 j1 = exposureID(ASG_J, gid(1));
        bytes32 j2 = exposureID(ASG_J, gid(2));
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, 1, compressed(rootPk(1)), 2, 105);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(1));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(1));
        vm.expectRevert(Evidence.AssignmentNotActivated.selector);
        evidence.submitEvidence(h, a, b, j1);
        // the recovery imports the activation: round 105 is p = 100 + (105 - 101) = 104, cutoff 1,104 inclusive
        pushRecord(RecordKind.RecoveryAck, _recoveryAck(RES_J, ASG_K));
        custody.applyRootRecords(1);
        clock(1_104, 1_300);
        _submitCase(2, rootPk(1), j1, 105); // equality is timely
        clock(1_105, 1_300);
        _expectLate(2, rootPk(2), j2, 105); // the same round, one progress unit after its cutoff
        _submitCase(2, rootPk(2), j2, 106); // round 106: cutoff 1,105 inclusive
    }

    function test_jsSuffixEvidenceCutoffIsPCloseOfTheStagedClosureWhateverWhenItWasImported()
        public
    {
        _pushRun25();
        // delayed import: the registry clock is already at 1,100 when custody applies the three records
        clock(1_100, 5_000);
        applyAll();
        bytes32 jExposure = exposureID(ASG_J, gid(1));
        // round 131 > H (130): a suffix round of J's epoch, cutoff = p_close + suffix window = 140 + 1,000 inclusive
        clock(1_140, 5_000);
        _submitCase(2, rootPk(1), jExposure, 131);
        clock(1_141, 5_000);
        _expectLate(2, rootPk(1), jExposure, 132);
    }

    function test_theLotCapIsSharedAcrossGJAndKAndTheHoldOfAnAcceptedCaseSurvivesThePendingState()
        public
    {
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 200; // 20 UCT per case on a 1,000 UCT lot
        p.lifetimeCapBps = 300; // 30 UCT lifetime
        _deploy(p);
        _pushRun25WithKClosure();
        // identity 1's lot (index 0) is shared by G, J and K
        uint256 lot = lotOf(gid(0));
        bytes32 cg = _submitCase(1, rootPk(0), genesisExposure(0), 10); // an accepted case under G: a hold on the lot
        assertEq(evidence.pendingHolds(lot), 1);
        applyAll(); // J's closure staged, recovery, K closure
        assertEq(evidence.pendingHolds(lot), 1, "the hold survives staging and the recovery");
        // J's epoch: round 105; K's epoch (3): round 135 (K first round 131)
        bytes32 cj = _submitCase(2, rootPk(0), exposureID(ASG_J, gid(0)), 105);
        bytes32 ck = _submitCase(3, rootPk(0), exposureID(ASG_K, gid(0)), 135);
        assertEq(_settleCase(cg, lot), 20 * UCT);
        assertEq(_settleCase(cj, lot), 10 * UCT, "30 UCT cap: one budget, not one per assignment");
        assertEq(_settleCase(ck, lot), 0);
        assertEq(lotv(lot).penalized, 30 * UCT);
        assertConserved();
    }

    // --- (5) atomic rejection ---------------------------------------------------------------------------------

    function test_aRevertLaterInTheBatchUndoesTheStagingEarlierInIt() public {
        _pushGJClosures();
        pushRecord(RecordKind.Closure, closureData(ASG_K, K_H, "k")); // K is unknown: reverts
        bytes32 before_ = _fingerprint();
        vm.expectRevert(StakeCustody.AssignmentNotActive.selector);
        custody.applyRootRecords(3);
        assertEq(_fingerprint(), before_, "no cursor or state advance, nothing swallowed");
        assertEq(custody.recordCursor(), 0);
        // the same two good records alone still apply: the failed attempt left no staged residue
        custody.applyRootRecords(2);
        assertEq(custody.recordCursor(), 2);
    }

    function test_aBadCursorAfterTheStagedClosureRejectsTheWholeBatch() public {
        _pushGJClosures();
        roots.pushRaw(
            RootRecord(
                9,
                keccak256("id"),
                roots.lastRecordID(),
                RecordKind.SessionClosed,
                150,
                1_200,
                abi.encode(SessionClosedData(RES_J))
            )
        );
        bytes32 before_ = _fingerprint();
        vm.expectRevert(StakeCustody.RecordOutOfOrder.selector);
        custody.applyRootRecords(3);
        assertEq(_fingerprint(), before_);
        assertEq(custody.recordCursor(), 0);
    }

    function test_aBrokenPredecessorAfterAStagedClosureStallsTheLogWithoutLosingTheStagedState()
        public
    {
        _stageG_J();
        bytes32 staged = _fingerprint();
        roots.pushRaw(
            RootRecord(
                2,
                keccak256("id"),
                keccak256("not the previous record"),
                RecordKind.RecoveryAck,
                150,
                1_200,
                _recoveryAck(RES_J, ASG_K)
            )
        );
        vm.expectRevert(StakeCustody.RecordOutOfOrder.selector);
        custody.applyRootRecords(1);
        assertEq(_fingerprint(), staged);
    }

    function test_outOfGasNeverLeavesAPartialStagingOrPartialRecovery() public {
        _pushRun25();
        bytes32 before_ = _fingerprint();
        bytes memory callData = abi.encodeCall(StakeCustody.applyRootRecords, (uint32(3)));
        bool succeeded;
        uint256 gasLimit = 30_000;
        for (; gasLimit <= 6_000_000 && !succeeded; gasLimit += 20_000) {
            (bool ok,) = address(custody).call{gas: gasLimit}(callData);
            if (!ok) {
                assertEq(
                    _fingerprint(), before_, "a failed (out-of-gas) application changed nothing"
                );
            }
            succeeded = ok;
            if (ok) break;
        }
        assertTrue(succeeded, "the batch fits within 6M gas");
        assertEq(custody.recordCursor(), 3);
        assertTrue(asg(ASG_J).closed);
    }

    // --- gas -----------------------------------------------------------------------------------------------------

    function test_gasOfStagingAndOfTheRecoveryThatAppliesTheSavedClosure() public {
        _pushRun25();
        custody.applyRootRecords(1); // G's closure: an active assignment
        uint256 g0 = gasleft();
        custody.applyRootRecords(1); // J's closure: staged
        uint256 staging = g0 - gasleft();
        g0 = gasleft();
        custody.applyRootRecords(1); // RecoveryAck deriving K and applying the saved closure
        uint256 resolution = g0 - gasleft();
        emit log_named_uint("staging a closure of the Reserved J", staging);
        emit log_named_uint("RecoveryAck applying the saved closure", resolution);
        // the staging is no dearer than the ordinary closure bound of the hook gas test (700,000)
        assertLt(staging, 700_000);
        // a recovery (bound 2,000,000 in HookGasTest) plus the closure it now also applies (700,000)
        assertLt(resolution, 2_700_000);
    }
}
