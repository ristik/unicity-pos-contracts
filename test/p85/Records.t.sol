// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {
    RootRecord,
    RecordKind,
    ClosureData,
    RecoveryAckData,
    SessionClosedData,
    RetirementData,
    Delegation,
    DelegationRequest,
    ReserveInput
} from "../../src/p85/P85Types.sol";

/// @notice Authenticated root-record application: ordering, session close/ack/recovery, closure
/// anchors and retirement imports. Every revert is asserted by its custom-error selector and each
/// test mutates only the field its guard checks.
contract RecordsTest is P85Flow {
    // --- ordering and batching -------------------------------------------------------------------

    function test_recordsApplyInOrderAndAdvanceTheCursor() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J2)));
        custody.applyRootRecords(1);
        assertEq(custody.recordCursor(), 1);
        custody.applyRootRecords(32);
        assertEq(custody.recordCursor(), 2);
        assertEq(custody.lastRecordID(), roots.lastRecordID());
    }

    function test_recordWithTheWrongIndexIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        roots.pushRaw(
            RootRecord(
                1,
                keccak256("id"),
                bytes32(0),
                RecordKind.SessionClosed,
                0,
                0,
                abi.encode(SessionClosedData(RES_J))
            )
        );
        vm.expectRevert(StakeCustody.RecordOutOfOrder.selector);
        custody.applyRootRecords(1);
    }

    function test_recordWithAnUnlinkedPredecessorIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        roots.pushRaw(
            RootRecord(
                0,
                keccak256("id"),
                keccak256("not the previous record"),
                RecordKind.SessionClosed,
                0,
                0,
                abi.encode(SessionClosedData(RES_J))
            )
        );
        vm.expectRevert(StakeCustody.RecordOutOfOrder.selector);
        custody.applyRootRecords(1);
    }

    function test_unknownRecordKindIsRejected() public {
        pushRecord(RecordKind.None, "");
        vm.expectRevert(StakeCustody.UnknownRecordKind.selector);
        custody.applyRootRecords(1);
    }

    function test_batchBoundsAndEmptyPrefixAreRejected() public {
        vm.expectRevert(StakeCustody.EmptyBatch.selector);
        custody.applyRootRecords(0);
        vm.expectRevert(StakeCustody.EmptyBatch.selector);
        custody.applyRootRecords(1); // nothing pending
        vm.expectRevert(StakeCustody.BatchTooLarge.selector);
        custody.applyRootRecords(33);
    }

    function test_aFailingRecordRevertsTheWholeBatchAndStallsTheCursor() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J))); // closes twice
        vm.expectRevert(StakeCustody.SessionNotOpen.selector);
        custody.applyRootRecords(2);
        assertEq(custody.recordCursor(), 0, "a failed batch applies nothing");
        custody.applyRootRecords(1);
        assertEq(custody.recordCursor(), 1);
        vm.expectRevert(StakeCustody.SessionNotOpen.selector);
        custody.applyRootRecords(1); // the bad record stays at the head: fail closed
        assertEq(custody.recordCursor(), 1);
    }

    // --- session closed (pre-H abort or ordered rejection) -----------------------------------------

    function test_sessionClosedReleasesOnlyThatAttemptsReferences() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        applyAll();
        assertEq(asg(ASG_J).state, 3, "aborted");
        for (uint256 i; i < N_GENESIS; ++i) {
            assertEq(lotv(i + 1).refCount, 1, "only the genesis reference remains");
            assertEq(expo(genesisExposure(i)).locks, 0);
            assertTrue(expo(exposureID(ASG_J, gid(i))).released);
        }
        assertEq(custody.totalEncumbered(), N_GENESIS * GENESIS_BOND);
        assertEq(custody.liveExposures(gid(0), 1), 1);
        assertConserved();
    }

    function test_abortOfALaterAttemptKeepsTheOriginalSessionLock() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        assertEq(expo(genesisExposure(0)).locks, 2);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J2)));
        applyAll();
        assertEq(expo(genesisExposure(0)).locks, 1, "the first session still holds the incumbents");
        assertEq(lotv(1).refCount, 2, "genesis plus the surviving J");
    }

    function test_sessionClosedRejectsUnknownSessions() public {
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(keccak256("none"))));
        vm.expectRevert(StakeCustody.UnknownSession.selector);
        custody.applyRootRecords(1);
    }

    function test_sessionClosedCannotAbortAnAcknowledgedHandoff() public {
        handoffExcluding(0);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        vm.expectRevert(StakeCustody.SessionNotOpen.selector);
        custody.applyRootRecords(1);
    }

    // --- acknowledgement -------------------------------------------------------------------------

    function test_ackActivatesTheSuccessorAndRecordsTheIncumbentsH() public {
        reserve(RES_J, ASG_J, allExcept(0), 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        Asg memory j = asg(ASG_J);
        assertEq(j.state, 2);
        assertEq(j.rootEpoch, 2);
        assertEq(j.offset, 100);
        assertEq(j.firstRound, 101);
        assertTrue(j.offsetSet);
        Asg memory g = asg(GENESIS_ASSIGNMENT);
        assertTrue(g.hKnown);
        assertEq(g.hRound, H_ROUND);
        assertEq(custody.lastAckedAssignment(), ASG_J);
        for (uint256 i; i < N_GENESIS; ++i) {
            assertEq(expo(genesisExposure(i)).locks, 0);
        }
        // the genesis assignment is not closed yet: its references stay
        assertEq(lotv(1).refCount, 1);
        assertEq(custody.liveExposures(gid(0), 1), 1);
    }

    function _stageRootKey(uint64 id, uint256 newPk) internal returns (bytes memory newKey) {
        newKey = compressed(newPk);
        bytes32 digest = keccak256(
            abi.encode(
                keccak256("unicity.p85.pop.proposeRootKey"),
                NETWORK,
                block.chainid,
                address(custody),
                id,
                uint64(1),
                keccak256(newKey),
                uint64(0)
            )
        );
        bytes memory pop = sign(newPk, digest);
        (address owner,,,,,,,,) = custody.positions(id);
        vm.prank(owner);
        custody.proposeRootKey(id, newKey, pop);
    }

    function test_ackActivatesAStagedRootKeyOnlyWithCommittedMembership() public {
        bytes memory newKey = _stageRootKey(gid(1), 0x9501);
        // J carries the staged key for identity 2
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        in_.members[1].rootKeyHash = keccak256(newKey);
        vm.prank(address(election));
        custody.reserveCandidate(in_);
        (,, bytes32 active, bytes32 staged,,,,,) = custody.positions(gid(1));
        assertEq(active, keccak256(compressed(rootPk(1))), "still the old key while only reserved");
        assertEq(staged, keccak256(newKey));
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        (,, active, staged,,,,,) = custody.positions(gid(1));
        assertEq(active, keccak256(newKey), "activated with the acknowledged membership");
        assertEq(staged, bytes32(0));
    }

    function test_ackRejectsUnknownSessions() public {
        pushRecord(RecordKind.Ack, ackData(keccak256("none"), H_ROUND, 100, 101));
        vm.expectRevert(StakeCustody.UnknownSession.selector);
        custody.applyRootRecords(1);
    }

    function test_ackOfAClosedSessionIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        custody.applyRootRecords(1);
        vm.expectRevert(StakeCustody.SessionNotOpen.selector);
        custody.applyRootRecords(1);
    }

    function test_ackRequiresTheIncumbentToStillBeLastAcknowledged() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        pushRecord(RecordKind.Ack, ackData(RES_J2, H_ROUND, 100, 101)); // incumbent is now J
        custody.applyRootRecords(1);
        vm.expectRevert(StakeCustody.IncumbentMismatch.selector);
        custody.applyRootRecords(1);
    }

    function test_ackRejectsAReplacedRoundBeforeTheIncumbentsFirstRound() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        pushRecord(RecordKind.Ack, ackData(RES_J, 0, 100, 101)); // genesis first round is 1
        vm.expectRevert(StakeCustody.HRoundBeforeActivation.selector);
        custody.applyRootRecords(1);
    }

    function test_conflictingHRoundsAreRejected() public {
        handoffExcluding(0);
        clock(150, 1_200);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND + 1, "genesis"));
        vm.expectRevert(StakeCustody.HRoundMismatch.selector);
        custody.applyRootRecords(1);
    }

    // --- recovery acknowledgement (J committed but never acknowledged; K acknowledged) -------------

    function _recover() internal {
        reserve(RES_J, ASG_J, allExcept(0), 1);
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll();
    }

    function test_recoveryDerivesTheExactIncumbentSlateBeforeAnyReferenceCloses() public {
        // identity 1 retires and is excluded from J; K still contains it
        requestRetirement(0);
        _recover();
        assertEq(custody.lastAckedAssignment(), ASG_K);
        for (uint256 i; i < N_GENESIS; ++i) {
            Expo memory ke = expo(exposureID(ASG_K, gid(i)));
            Expo memory ge = expo(genesisExposure(i));
            assertEq(ke.assignmentID, ASG_K);
            assertEq(ke.id, gid(i));
            assertEq(ke.rootKeyHash, ge.rootKeyHash);
            assertEq(ke.evmKeyHash, ge.evmKeyHash);
            assertEq(ke.weight, ge.weight);
            assertEq(ke.operatorPayee, ge.operatorPayee);
            // genesis reference stays (not yet closed), K adds one, J adds one (members 2..4)
            assertEq(lotv(i + 1).refCount, i == 0 ? 2 : 3);
        }
        Asg memory j = asg(ASG_J);
        assertEq(j.state, 2);
        assertTrue(j.hKnown);
        assertEq(j.hRound, 130);
        Asg memory k = asg(ASG_K);
        assertEq(k.state, 2);
        assertEq(k.firstRound, 131);
        assertEq(
            k.policyID, asg(GENESIS_ASSIGNMENT).policyID, "K keeps the incumbent captured policy"
        );
        assertConserved();
    }

    function test_recoveryKeepsTheIncumbentPayeeEvenAfterANewNominationIsAdmitted() public {
        address payeeB = makeAddr("payeeB");
        reserve(RES_J, ASG_J, allMembers(), 1);
        // an owner-authenticated nomination of payee B is admitted before recovery completes
        DelegationRequest memory r;
        r.id = gid(0);
        r.generation = 1;
        r.binding = Delegation(
            keccak256(abi.encode("root", uint256(0))),
            compressed(rootPk(0)),
            keccak256(abi.encode("evm", uint256(0))),
            compressed(evmPk(0)),
            payeeB
        );
        r.expiry = 1_000;
        bytes32 digest = election.delegationDigest(r);
        election.admitDelegation(r, sign(ownerPk(0), digest), sign(evmPk(0), digest));
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll();
        assertEq(
            expo(exposureID(ASG_J, gid(0))).operatorPayee, vm.addr(payeePk(0)), "frozen J keeps A"
        );
        assertEq(
            expo(exposureID(ASG_K, gid(0))).operatorPayee, vm.addr(payeePk(0)), "exact K keeps A"
        );
        (Delegation memory staged,,) = election.delegation(gid(0), 1);
        assertEq(staged.operatorPayee, payeeB, "the nomination only affects later snapshots");
        // a later primary snapshot carries B
        ReserveInput memory later =
            _reserveInput(keccak256("res/later"), keccak256("asg/later"), allMembers(), 1);
        assertEq(later.members[0].operatorPayee, payeeB);
    }

    function test_recoveryRejectsAnAlreadyUsedRecoveryAssignmentID() public {
        reserve(RES_J, ASG_J, allExcept(0), 1);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_J, 100, 101, 130, 130, 131, 3, 3)) // ASG_J exists
        );
        vm.expectRevert(StakeCustody.AssignmentExists.selector);
        custody.applyRootRecords(1);
    }

    function test_recoveryRejectsAZeroRecoveryAssignmentID() public {
        reserve(RES_J, ASG_J, allExcept(0), 1);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, bytes32(0), 100, 101, 130, 130, 131, 3, 3))
        );
        vm.expectRevert(StakeCustody.AssignmentExists.selector);
        custody.applyRootRecords(1);
    }

    function test_recoveredSessionCannotBeAcknowledgedAgain() public {
        _recover();
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        vm.expectRevert(StakeCustody.SessionNotOpen.selector);
        custody.applyRootRecords(1);
    }

    // --- closure ---------------------------------------------------------------------------------

    function test_closureFixesAnchorsAndClosesReferences() public {
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        Asg memory g = asg(GENESIS_ASSIGNMENT);
        assertTrue(g.hKnown);
        assertTrue(g.closed);
        assertEq(g.pClose, 150);
        assertEq(g.tClose, 1_200);
        // identity 1 (excluded from J): no references left, lot is free again
        LotV memory l = lotv(1);
        assertEq(l.refCount, 0);
        assertEq(l.category, 1);
        // anchor = max(p(1,100) = 99, p_close = 150) = 150
        assertEq(l.holdUntil, 150 + 2_000);
        assertEq(l.evidenceUntil, 150 + 1_000);
        assertEq(l.timeUntil, 1_200 + 3_600);
        assertEq(custody.maxLiabilityAnchor(gid(0), 1), 150);
        // members that J retained keep a J reference
        assertEq(lotv(2).refCount, 1);
        assertConserved();
    }

    function test_closureAnchorIsTheNormalEndpointWhenItExceedsPClose() public {
        reserve(RES_J, ASG_J, allExcept(0), 1);
        clock(40, 900); // anchors lower than the endpoint, as a delayed-progress fixture
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        closeGenesisAt(50, 1_200); // closure imported at progress 50 < endpoint p(1,100) = 99
        LotV memory l = lotv(1);
        assertEq(l.holdUntil, 99 + 2_000);
        assertEq(l.evidenceUntil, 99 + 1_000);
    }

    function test_repeatedClosureCannotResetEitherAnchor() public {
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        clock(900, 9_000);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis")); // same key
        applyAll();
        Asg memory g = asg(GENESIS_ASSIGNMENT);
        assertEq(g.pClose, 150);
        assertEq(g.tClose, 1_200);
        assertEq(lotv(1).holdUntil, 150 + 2_000);
    }

    function test_conflictingClosureIdentityIsRejected() public {
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        clock(160, 1_300);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "another proof"));
        vm.expectRevert(StakeCustody.ConflictingClosure.selector);
        custody.applyRootRecords(1);
    }

    function test_closureMustBindTheStoredExposureDigest() public {
        handoffExcluding(0);
        clock(150, 1_200);
        ClosureData memory d =
            abi.decode(closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"), (ClosureData));
        d.exposureDigest = keccak256("tampered exposure digest");
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ClosureDigestMismatch.selector);
        custody.applyRootRecords(1);
    }

    function test_closureMustBindTheStoredKeyHistoryDigest() public {
        handoffExcluding(0);
        clock(150, 1_200);
        ClosureData memory d =
            abi.decode(closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"), (ClosureData));
        d.keyHistoryDigest = keccak256("tampered key digest");
        pushRecord(RecordKind.Closure, abi.encode(d));
        vm.expectRevert(StakeCustody.ClosureDigestMismatch.selector);
        custody.applyRootRecords(1);
    }

    function test_closureOfAnAssignmentThatIsNotActiveIsRejected() public {
        reserve(RES_J, ASG_J, allMembers(), 1); // Reserved, not committed
        pushRecord(RecordKind.Closure, closureData(ASG_J, H_ROUND, "j"));
        vm.expectRevert(StakeCustody.AssignmentNotActive.selector);
        custody.applyRootRecords(1);
    }

    function test_closureWaitsForTheSessionLockBeforeReleasingReferences() public {
        // G closes while the J session is still open: the lock keeps G's references
        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(150, 1_200);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"));
        applyAll();
        assertFalse(expo(genesisExposure(0)).released, "locked by the open session");
        assertEq(lotv(1).refCount, 2);
        // the session then acknowledges: the lock drops and the closed references release
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        assertTrue(expo(genesisExposure(0)).released);
        assertEq(lotv(1).refCount, 1);
    }

    // --- retirement import ------------------------------------------------------------------------

    function test_retirementImportStoresTheAnchors() public {
        reachMaturable(0);
        (bool imported, uint64 pRet, uint64 tRet) = custody.retirements(gid(0), 1);
        assertTrue(imported);
        assertEq(pRet, 160);
        assertEq(tRet, 1_210);
    }

    function test_retirementRecordNeedsARequest() public {
        pushRecord(RecordKind.Retirement, abi.encode(RetirementData(gid(0), 1, bytes32(0))));
        vm.expectRevert(StakeCustody.RetirementNotRequested.selector);
        custody.applyRootRecords(1);
    }

    function test_retirementRecordNeedsTheCurrentGeneration() public {
        requestRetirement(0);
        pushRecord(RecordKind.Retirement, abi.encode(RetirementData(gid(0), 2, bytes32(0))));
        vm.expectRevert(StakeCustody.StaleGeneration.selector);
        custody.applyRootRecords(1);
    }

    function test_retirementRecordForUnknownIdentityIsRejected() public {
        pushRecord(RecordKind.Retirement, abi.encode(RetirementData(99, 1, bytes32(0))));
        vm.expectRevert(StakeCustody.UnknownIdentity.selector);
        custody.applyRootRecords(1);
    }

    function test_retirementRecordRejectedWhileReferencesAreLive() public {
        requestRetirement(0);
        retireRecordPushOnly(gid(0), 160, 1_210);
        vm.expectRevert(StakeCustody.RefsStillLive.selector);
        custody.applyRootRecords(1);
    }

    function test_retirementRecordMustBindTheReferenceDigest() public {
        requestRetirement(0);
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        clock(160, 1_210);
        pushRecord(
            RecordKind.Retirement, abi.encode(RetirementData(gid(0), 1, keccak256("wrong digest")))
        );
        vm.expectRevert(StakeCustody.RefDigestMismatch.selector);
        custody.applyRootRecords(1);
    }

    function test_retirementProgressMustCoverTheLiabilityAnchor() public {
        requestRetirement(0);
        reserve(RES_J, ASG_J, allExcept(0), 1);
        clock(40, 900);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        closeGenesisAt(50, 1_200); // z = max(p(1,100) = 99, 50) = 99
        retireRecordPushOnly(gid(0), 98, 1_210); // p_ret = 98 < z = 99
        vm.expectRevert(StakeCustody.RetirementBeforeLiability.selector);
        custody.applyRootRecords(1);
    }

    function test_retirementProgressEqualToTheAnchorIsAccepted() public {
        requestRetirement(0);
        reserve(RES_J, ASG_J, allExcept(0), 1);
        clock(40, 900);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        closeGenesisAt(50, 1_200);
        retireRecordAt(gid(0), 99, 1_210); // p_ret == z is enough
        (bool imported,,) = custody.retirements(gid(0), 1);
        assertTrue(imported);
    }

    function test_retirementCannotBeImportedTwice() public {
        reachMaturable(0);
        retireRecordPushOnly(gid(0), 170, 1_300);
        vm.expectRevert(StakeCustody.RetirementAlreadyImported.selector);
        custody.applyRootRecords(1);
    }

    function test_retirementRecordCoversNeverAssignedLots() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        bondFor(id, 100 * UCT);
        vm.prank(vm.addr(0x9001));
        custody.requestRetirement(id);
        // empty exposure set: the digest is the zero chain head
        clock(40, 500);
        pushRecord(RecordKind.Retirement, abi.encode(RetirementData(id, 1, bytes32(0))));
        applyAll();
        (bool imported, uint64 pRet, uint64 tRet) = custody.retirements(id, 1);
        assertTrue(imported);
        assertEq(pRet, 40);
        assertEq(tRet, 500);
    }

    // --- helpers ----------------------------------------------------------------------------------

    function retireRecordPushOnly(uint64 id, uint64 p, uint64 t) internal {
        (,,,, uint64 gen,,,,) = custody.positions(id);
        clock(p, t);
        pushRecord(
            RecordKind.Retirement,
            abi.encode(RetirementData(id, gen, custody.exposureChain(id, gen)))
        );
    }
}
