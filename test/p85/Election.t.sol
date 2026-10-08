// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {FixedPolicy} from "../../src/p85/FixedPolicy.sol";
import {IStakeCustody} from "../../src/p85/IP85.sol";
import {
    ElectionParams,
    Limits,
    Delegation,
    DelegationRequest,
    RecordKind,
    RecoveryAckData,
    SessionClosedData
} from "../../src/p85/P85Types.sol";

/// @notice PR3 slice 3: the threshold, the snapshot, the attempt cursor and `elect(origin)`. The hook caller is the system address; a
/// failure of the election or of the reservation is an ordered NoCandidate, never a revert.
contract ElectionTest is P85Flow {
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);
    bytes32 internal constant ORIGIN = keccak256("origin/1");
    uint64 internal constant CAD_P = 100_000;
    uint64 internal constant CAD_T = 604_800;

    /// @dev Four genesis identities: a smaller cardinality floor than the dev default so single losses are not cardinality failures.
    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 2,
            nTarget: 10,
            nMax: 32,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: CAD_P,
            cadenceSeconds: CAD_T
        });
    }

    function _elect() internal returns (ElectionPolicy.Outcome) {
        vm.prank(SYS);
        return election.elect(ORIGIN);
    }

    function _due() internal {
        clock(CAD_P, CAD_T);
    }

    function _resultID(uint64 attempt, bytes32 origin) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("unicity.p85.election-result"),
                NETWORK,
                block.chainid,
                address(election),
                custody.lastAckedAssignment(),
                attempt,
                origin
            )
        );
    }

    function _assignmentOf(bytes32 resultID) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("unicity.p85.primary-assignment"), resultID));
    }

    // --- the hook gate ---------------------------------------------------------------------------

    function test_onlyTheSystemCallerMayElect() public {
        _due();
        vm.expectRevert(ElectionPolicy.NotSystem.selector);
        election.elect(ORIGIN);
        vm.prank(address(custody));
        vm.expectRevert(ElectionPolicy.NotSystem.selector);
        election.elect(ORIGIN);
    }

    function test_electNowIsNotCallableFromOutside() public {
        vm.expectRevert(ElectionPolicy.NotSelf.selector);
        election.electNow(ORIGIN, 1, 1, bytes32(0));
    }

    function test_nothingIsDueBeforeBothCadences() public {
        uint256 snap = vm.snapshotState();
        clock(CAD_P - 1, CAD_T + 1_000);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NotDue), "rounds short");
        vm.revertToState(snap);
        clock(CAD_P + 1_000, CAD_T - 1);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NotDue), "seconds short");
        assertEq(election.attemptCursor(), 0);
        vm.revertToState(snap);
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
    }

    function test_anIncompleteRecordPrefixDisablesTheElection() public {
        _due();
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(keccak256("unknown"))));
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Disabled));
        assertEq(election.attemptCursor(), 0, "nothing consumed");
    }

    function test_anUnreadableRegistryOrCustodyDisablesInsteadOfReverting() public {
        _due();
        vm.mockCallRevert(address(roots), abi.encodeWithSignature("progress()"), "x");
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Disabled));
        vm.clearMockedCalls();
        vm.mockCallRevert(address(custody), abi.encodeWithSignature("lastAckedAssignment()"), "x");
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Disabled));
        vm.clearMockedCalls();
        assertEq(election.attemptCursor(), 0);
    }

    // --- a successful election ---------------------------------------------------------------------

    function test_theUnchangedCommitteeIsElectedAndReserved() public {
        _due();
        bytes32 resultID = _resultID(1, ORIGIN);
        bytes32 assignmentID = _assignmentOf(resultID);
        vm.expectEmit(true, false, false, false, address(election));
        emit ElectionPolicy.ElectionOpened(resultID, 1, assignmentID, bytes32(0), ORIGIN);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));

        ElectionPolicy.Result memory r = election.result(resultID);
        assertEq(uint8(r.state), uint8(ElectionPolicy.ResultState.Reserved));
        assertEq(r.attempt, 1);
        assertEq(r.progress, CAD_P);
        assertEq(r.ucTime, CAD_T);
        assertEq(r.origin, ORIGIN);
        assertEq(r.predecessor, GENESIS_ASSIGNMENT);
        assertEq(r.assignmentID, assignmentID);
        assertTrue(r.snapshotDigest != bytes32(0));
        assertEq(election.openResult(), resultID);
        assertEq(election.attemptCursor(), 1);

        // custody holds the reservation: same lineage, the next epochs, the incumbent slate locked
        Asg memory a = asg(assignmentID);
        assertEq(a.state, 1);
        assertEq(a.lineage, LINEAGE);
        assertEq(a.rootEpoch, 2);
        assertEq(a.evmEpoch, 2);
        assertEq(custody.session(resultID).incumbentAssignmentID, GENESIS_ASSIGNMENT);
        assertEq(custody.assignmentExposures(assignmentID).length, N_GENESIS);

        // the frozen identity records
        ElectionPolicy.Frozen[] memory f = election.frozenMembers(resultID);
        assertEq(f.length, N_GENESIS);
        for (uint256 i; i < f.length; ++i) {
            assertEq(f[i].id, gid(i));
            assertEq(f[i].generation, 1);
            assertEq(f[i].weight, 10);
            (, bytes32 bindingHash,) = election.delegation(gid(i), 1);
            assertEq(f[i].bindingHash, bindingHash);
        }
        assertEq(
            election.anchorProgress(), 0, "the cadence anchor moves only on an acknowledgement"
        );
    }

    /// Bonds so large that the raw total exceeds the cap B: the elected committee carries the quantized weights q (summing to at most B,
    /// each at most its raw weight), the frozen record and the custody exposure keep the raw weight x, and the lots must cover x.
    function test_heavyBondsAreQuantizedAndTheLotsCoverTheRawWeight() public {
        uint256 extra = 20_000_000 * UCT;
        for (uint256 i; i < N_GENESIS; ++i) {
            bondFor(gid(i), extra);
        }
        uint64 raw = uint64((GENESIS_BOND + extra) / (100 * UCT)); // 200,010 each: X = 800,040 > B
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        bytes32 resultID = _resultID(1, ORIGIN);
        bytes32 assignmentID = _assignmentOf(resultID);

        uint256 s = (uint256(raw) * N_GENESIS + (65_536 - N_GENESIS) - 1) / (65_536 - N_GENESIS);
        uint64 q = uint64(raw / s);
        ElectionPolicy.Frozen[] memory f = election.frozenMembers(resultID);
        bytes32[] memory eids = custody.assignmentExposures(assignmentID);
        uint256 total;
        for (uint256 i; i < f.length; ++i) {
            assertEq(f[i].raw, raw, "the frozen record keeps x");
            assertEq(f[i].weight, q, "and the committed q");
            Expo memory e = expo(eids[i]);
            assertEq(e.weight, q);
            assertEq(e.rawWeight, raw);
            assertGe(coverage(f[i].id), uint256(raw) * 100 * UCT, "the lots cover x");
            total += f[i].weight;
        }
        assertLe(total, 65_536);
        assertGt(s, 1, "the rule was in force");
    }

    function test_oneUnresolvedResultAtATime() public {
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        clock(10 * CAD_P, 10 * CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Disabled));
        assertEq(election.attemptCursor(), 1);
    }

    function test_theSnapshotAndTheResultBindTheOrigin() public {
        _due();
        uint256 snap = vm.snapshotState();
        vm.prank(SYS);
        election.elect(keccak256("origin/A"));
        ElectionPolicy.Result memory a = election.result(_resultID(1, keccak256("origin/A")));
        vm.revertToState(snap);
        vm.prank(SYS);
        election.elect(keccak256("origin/B"));
        ElectionPolicy.Result memory b = election.result(_resultID(1, keccak256("origin/B")));
        assertTrue(a.snapshotDigest != bytes32(0) && a.snapshotDigest != b.snapshotDigest);
        assertTrue(a.assignmentID != b.assignmentID);
    }

    // --- cadence anchors ---------------------------------------------------------------------------

    function test_anAcknowledgementMovesTheAnchorsToTheRecordsOwnAnchors() public {
        _due();
        _elect();
        bytes32 resultID = election.openResult();
        clock(CAD_P + 50, CAD_T + 77);
        pushRecord(RecordKind.Ack, ackData(resultID, H_ROUND, 100, 101));
        clock(CAD_P + 900, CAD_T + 4_000); // the registry has moved on by the time custody applies it
        applyAll();

        assertEq(
            uint8(election.result(resultID).state), uint8(ElectionPolicy.ResultState.Acknowledged)
        );
        assertEq(election.openResult(), bytes32(0));
        assertEq(election.anchorProgress(), CAD_P + 50);
        assertEq(election.anchorTime(), CAD_T + 77);

        // the next threshold is a cadence past the acknowledgement (and past the attempt)
        (uint256 p, uint256 t) = election.thresholds();
        assertEq(p, CAD_P + 50 + CAD_P);
        assertEq(t, CAD_T + 77 + CAD_T);
        clock(uint64(p) - 1, uint64(t));
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NotDue));
        clock(uint64(p), uint64(t));
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(election.attemptCursor(), 2);
    }

    function test_aRecoveryAckResolvesTheResultButDoesNotAdvanceTheAnchors() public {
        _due();
        _elect();
        bytes32 resultID = election.openResult();
        clock(CAD_P + 50, CAD_T + 77);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(resultID, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll();
        assertEq(
            uint8(election.result(resultID).state), uint8(ElectionPolicy.ResultState.Recovered)
        );
        assertEq(election.openResult(), bytes32(0));
        assertEq(election.anchorProgress(), 0);
        assertEq(election.anchorTime(), 0);
        // the cadence still runs from the attempt, so there is no immediate re-election
        (uint256 p, uint256 t) = election.thresholds();
        assertEq(p, CAD_P + CAD_P);
        assertEq(t, CAD_T + CAD_T);
    }

    function test_aClosedResultFreesTheCursorWithoutMovingTheAnchors() public {
        _due();
        _elect();
        bytes32 resultID = election.openResult();
        clock(CAD_P + 10, CAD_T + 10);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(resultID)));
        applyAll();
        assertEq(uint8(election.result(resultID).state), uint8(ElectionPolicy.ResultState.Closed));
        assertEq(election.openResult(), bytes32(0));
        assertEq(election.anchorProgress(), 0);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NotDue));
    }

    function test_resultsThisModuleDidNotCreateAreIgnoredByTheCallback() public {
        reserve(RES_J, ASG_J, allMembers(), 1); // reserved by hand, not by an election
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        assertEq(election.anchorProgress(), 0);
        assertEq(election.openResult(), bytes32(0));
    }

    function test_resultResolvedIsCustodyOnly() public {
        vm.expectRevert(ElectionPolicy.NotCustody.selector);
        election.resultResolved(bytes32(0), 2, 1, 1);
    }

    // --- ordered NoCandidate ---------------------------------------------------------------------

    function _assertNoCandidate(ElectionPolicy.Reason why) internal view {
        bytes32 resultID = _resultID(1, ORIGIN);
        ElectionPolicy.Result memory r = election.result(resultID);
        assertEq(uint8(r.state), uint8(ElectionPolicy.ResultState.NoCandidate));
        assertEq(uint8(r.reason), uint8(why));
        assertEq(r.attempt, 1);
        assertEq(election.attemptCursor(), 1);
        assertEq(election.openResult(), bytes32(0), "no unresolved result");
        assertEq(custody.assignmentExposures(_assignmentOf(resultID)).length, 0, "no reservation");
        assertEq(custody.lastAckedAssignment(), GENESIS_ASSIGNMENT, "the authority continues");
        // the attempt is consumed: a retry waits one cadence
        (uint256 p, uint256 t) = election.thresholds();
        assertEq(p, CAD_P + CAD_P);
        assertEq(t, CAD_T + CAD_T);
    }

    function test_tooFewEligibleIdentitiesIsCardinality() public {
        requestRetirement(0);
        requestRetirement(1);
        requestRetirement(2); // one eligible identity left, below the floor of two
        _due();
        vm.expectEmit(true, false, false, true, address(election));
        emit ElectionPolicy.NoCandidate(
            _resultID(1, ORIGIN), 1, ElectionPolicy.Reason.Cardinality, ORIGIN
        );
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));
        _assertNoCandidate(ElectionPolicy.Reason.Cardinality);
    }

    function test_lossOfAMemberBeyondTheStrictBoundaryIsMembershipChurn() public {
        requestRetirement(0); // 3 of 4 remain: 3 * 1 < min(4, 3) fails
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));
        _assertNoCandidate(ElectionPolicy.Reason.MembershipChurn);
    }

    function test_aWeightShiftBeyondTheDistanceBudgetIsWeightChurn() public {
        bondFor(gid(3), GENESIS_BOND); // weights 10,10,10,20: D = 0.3 > 1/4
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));
        _assertNoCandidate(ElectionPolicy.Reason.WeightChurn);
    }

    function test_aReservationRefusedByCustodyIsRecordedNotRaised() public {
        _due();
        // the assignment the election will name is already taken
        bytes32 resultID = _resultID(1, ORIGIN);
        reserve(keccak256("other"), _assignmentOf(resultID), allMembers(), 7);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));
        assertEq(
            uint8(election.result(resultID).reason), uint8(ElectionPolicy.Reason.ReservationRefused)
        );
        assertEq(election.openResult(), bytes32(0));
    }

    function test_aFailureInsideTheElectionIsRecordedAsInternalFailure() public {
        _due();
        vm.mockCallRevert(address(custody), abi.encodeCall(IStakeCustody.bondUnit, ()), "boom");
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));
        vm.clearMockedCalls();
        bytes32 resultID = _resultID(1, ORIGIN);
        assertEq(
            uint8(election.result(resultID).reason), uint8(ElectionPolicy.Reason.InternalFailure)
        );
        assertEq(election.attemptCursor(), 1);
        assertEq(election.openResult(), bytes32(0));
    }

    // --- a changed committee --------------------------------------------------------------------

    function _admit(uint64 id, uint256 ownerKey, uint256 rootKey, uint256 evmKey) internal {
        DelegationRequest memory r;
        r.id = id;
        r.generation = 1;
        r.binding = Delegation({
            rootNodeID: keccak256(abi.encode("root", id)),
            rootKey: compressed(rootKey),
            evmNodeID: keccak256(abi.encode("evm", id)),
            evmKey: compressed(evmKey),
            operatorPayee: vm.addr(payeePk(id))
        });
        r.expiry = 1_000_000_000;
        bytes32 digest = election.delegationDigest(r);
        election.admitDelegation(r, sign(ownerKey, digest), sign(evmKey, digest));
    }

    function test_aNewLightIdentityJoinsAndTheRestKeepTheirBindings() public {
        uint64 id = register(0x5001, 0x5002, vm.addr(0x5003));
        bondFor(id, 100 * UCT); // weight 1
        _admit(id, 0x5001, 0x5002, 0x5004);
        assertTrue(election.isIndexed(id));
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        ElectionPolicy.Frozen[] memory f = election.frozenMembers(_resultID(1, ORIGIN));
        assertEq(f.length, N_GENESIS + 1);
        assertEq(f[N_GENESIS].id, id);
        assertEq(f[N_GENESIS].weight, 1);
    }

    function test_anIdentityWithoutADelegationOfItsGenerationIsNotEligible() public {
        uint64 id = register(0x5001, 0x5002, vm.addr(0x5003));
        bondFor(id, 100 * UCT); // indexed, but never admitted
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(election.frozenMembers(_resultID(1, ORIGIN)).length, N_GENESIS);
    }

    function test_anIdentityBelowTheMinimumBondOrWithoutAWholeUnitIsNotEligible() public {
        uint64 id = register(0x5001, 0x5002, vm.addr(0x5003));
        bondFor(id, 99 * UCT); // below B_min = U_bond = 100
        _admit(id, 0x5001, 0x5002, 0x5004);
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(election.frozenMembers(_resultID(1, ORIGIN)).length, N_GENESIS);
    }

    function test_aRetiringIdentityIsNotAPrimaryCandidate() public {
        // the churn rule tolerates no loss at four members, so drop to the identity set with a spare first
        uint64 id = register(0x5001, 0x5002, vm.addr(0x5003));
        bondFor(id, 100 * UCT);
        _admit(id, 0x5001, 0x5002, 0x5004);
        vm.prank(vm.addr(0x5001));
        custody.requestRetirement(id);
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(election.frozenMembers(_resultID(1, ORIGIN)).length, N_GENESIS);
    }

    function test_anExcludedIdentityIsNotAPrimaryCandidate() public {
        uint64 id = register(0x5001, 0x5002, vm.addr(0x5003));
        bondFor(id, 100 * UCT);
        _admit(id, 0x5001, 0x5002, 0x5004);
        vm.mockCall(
            address(evidence), abi.encodeWithSignature("excluded(uint64)", id), abi.encode(true)
        );
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(election.frozenMembers(_resultID(1, ORIGIN)).length, N_GENESIS);
    }

    function test_aMinimumBondAboveTheUnitExcludesAnIdentityBelowIt() public {
        manualMinBond = uint128(300 * UCT); // B_min three units; the 1,000 UCT genesis lots are far above
        _deployManual(
            address(new FixedPolicy(_defaultPolicy())),
            Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32})
        );
        // a joiner holding 250 UCT: weight two, below B_min
        uint64 id = register(0x5001, 0x5002, vm.addr(0x5003));
        vm.deal(vm.addr(0x5001), 300 * UCT);
        vm.prank(vm.addr(0x5001));
        // custody itself refuses lots under B_min, so the identity is brought under it by a penalty-sized debit of its only lot
        custody.bond{value: 300 * UCT}(id);
        _admit(id, 0x5001, 0x5002, 0x5004);
        bytes32 slot = bytes32(uint256(keccak256(abi.encode(lotOf(id), uint256(27)))) + 1);
        vm.store(address(custody), slot, bytes32(uint256(250 * UCT))); // remaining: 250 UCT
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(
            election.frozenMembers(_resultID(1, ORIGIN)).length,
            N_GENESIS,
            "below B_min: not eligible"
        );
    }

    function test_reservationEpochsAreTheIncumbentsOwnEpochsPlusOne() public {
        genesisRootEpoch = 7;
        genesisEvmEpoch = 3;
        _deploy(_defaultPolicy());
        _due();
        _elect();
        Asg memory a = asg(election.result(election.openResult()).assignmentID);
        assertEq(a.rootEpoch, 8, "the incumbent's root epoch + 1");
        assertEq(a.evmEpoch, 4, "the incumbent's EVM epoch + 1");
    }

    function _joinerWithKeyOwner(uint64 owner, uint8 role) internal {
        uint64 id = register(0x5001, 0x5002, vm.addr(0x5003));
        bondFor(id, 100 * UCT);
        _admit(id, 0x5001, 0x5002, 0x5004);
        vm.mockCall(
            address(custody),
            abi.encodeCall(IStakeCustody.keyOwner, (keccak256(compressed(0x5004)))),
            abi.encode(owner, role)
        );
    }

    function test_anEvmKeyRegisteredToAnotherIdentityDoesNotQualify() public {
        _joinerWithKeyOwner(gid(0), 2);
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(election.frozenMembers(_resultID(1, ORIGIN)).length, N_GENESIS);
    }

    function test_anEvmKeyRegisteredInAnotherRoleDoesNotQualify() public {
        _joinerWithKeyOwner(5, 1); // the joiner's own id, but registered as a root key
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(election.frozenMembers(_resultID(1, ORIGIN)).length, N_GENESIS);
    }

    // --- reference capacity ------------------------------------------------------------------------

    function test_aFullReferenceTableIsAnOrderedNoCandidateNotARevert() public {
        _deployManual(
            address(new FixedPolicy(_defaultPolicy())),
            Limits({vMax: 128, lMax: 8, rMax: 3, maxBatch: 32})
        );
        reserve(keccak256("hand"), keccak256("hand/asg"), allMembers(), 7); // refCount 2 of 3
        _due();
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));
        assertEq(
            uint8(election.result(_resultID(1, ORIGIN)).reason),
            uint8(ElectionPolicy.Reason.ReferenceCapacity)
        );
        assertEq(election.openResult(), bytes32(0));
    }
}
