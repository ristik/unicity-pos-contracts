// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {ReserveInput, ReserveMember, RecordKind, RecoveryAckData} from "../../src/p85/P85Types.sol";

/// @notice reserveCandidate: exact primary lots, primary coverage and eligibility, and the session
/// locks that hold the incumbent exposures (the recovery slate K).
contract ReservationTest is P85Flow {
    function _input(bytes32 res, bytes32 asg) internal view returns (ReserveInput memory) {
        return _reserveInput(res, asg, allMembers(), 1);
    }

    function _reserveRaw(ReserveInput memory in_) internal {
        vm.prank(address(election));
        custody.reserveCandidate(in_);
    }

    function test_reserveEncumbersExactLotsAndLocksTheIncumbents() public {
        bytes32 digest = reserve(RES_J, ASG_J, allExcept(0), 1);
        // J exposures exist for members 2..4 and reference their lots a second time
        for (uint256 i = 1; i < N_GENESIS; ++i) {
            (uint64 owner,,,,,,, uint32 refs,,,,,) = custody.lots(i + 1);
            assertEq(owner, gid(i));
            assertEq(refs, 2, "genesis and J both reference the lot");
            (bytes32 asg, uint64 id,,,, uint64 weight, address payee,, uint32 locks) =
                custody.exposures(exposureID(ASG_J, gid(i)));
            assertEq(asg, ASG_J);
            assertEq(id, gid(i));
            assertEq(weight, 10);
            assertEq(payee, vm.addr(payeePk(i)));
            assertEq(locks, 0);
        }
        // the excluded identity gets no J exposure, but its incumbent exposure is locked (K)
        (bytes32 none,,,,,,,,) = custody.exposures(exposureID(ASG_J, gid(0)));
        assertEq(none, bytes32(0));
        for (uint256 i; i < N_GENESIS; ++i) {
            (,,,,,,,, uint32 locks) = custody.exposures(genesisExposure(i));
            assertEq(locks, 1, "every incumbent exposure is session-locked");
        }
        (uint8 state,,,,,,,,,,,,, bytes32 exposureDigest,,) = custody.assignments(ASG_J);
        assertEq(state, 1);
        assertEq(exposureDigest, digest);
        assertEq(custody.session(RES_J).incumbentAssignmentID, GENESIS_ASSIGNMENT);
        // principal is counted once: references do not add balance
        assertEq(custody.totalEncumbered(), N_GENESIS * GENESIS_BOND);
        assertConserved();
    }

    function test_reserveOnlyByElection() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        vm.expectRevert(StakeCustody.NotElection.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveRejectsReusedResultAndReusedAssignment() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        ReserveInput memory in_ = _input(RES_J, ASG_J2); // same result, new assignment
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.SessionExists.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J2, ASG_J); // new result, same assignment
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.AssignmentExists.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J2, bytes32(0));
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.AssignmentExists.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveRequiresTheLastAcknowledgedIncumbent() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.incumbentAssignmentID = keccak256("stale");
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.IncumbentMismatch.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveRequiresTheSameLineage() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.lineage = keccak256("foreign lineage");
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.LineageMismatch.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveRejectsEmptyAndUnsortedMembers() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.members = new ReserveMember[](0);
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.InvalidMemberCount.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J, ASG_J);
        (in_.members[0], in_.members[1]) = (in_.members[1], in_.members[0]);
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.MembersUnsorted.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J, ASG_J);
        in_.members[1] = in_.members[0]; // duplicate identity
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.MembersUnsorted.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveRejectsUnknownIdentity() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.members[3].id = 99;
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.UnknownIdentity.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveExcludesAnIdentityThatRequestedRetirementBeforeTheSnapshot() public {
        requestRetirement(2);
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.PrimaryRetiring.selector);
        custody.reserveCandidate(in_);
    }

    function test_retirementAfterReservationDoesNotRewriteFrozenMembership() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        requestRetirement(2);
        (bytes32 asg,,,,,,,,) = custody.exposures(exposureID(ASG_J, gid(2)));
        assertEq(asg, ASG_J, "the frozen primary still contains the retiring identity");
        (,,,,,,, uint32 refs,,,,,) = custody.lots(3);
        assertEq(refs, 2);
    }

    function test_reserveRejectsZeroWeightAndInsufficientCoverage() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.members[0].weight = 0;
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.ZeroWeight.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J, ASG_J);
        in_.members[0].weight = 11; // 1,100 UCT of weight against 1,000 UCT backing
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.InsufficientCoverage.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J, ASG_J);
        in_.members[0].weight = 10; // exactly covered is fine
        _reserveRaw(in_);
    }

    function test_reserveRequiresTheIdentitysCurrentOrStagedRootKeyAndItsBoundEvmKey() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.members[0].rootKeyHash = keccak256("not a key of this identity");
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.WrongKey.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J, ASG_J);
        in_.members[0].evmKeyHash = in_.members[1].evmKeyHash; // another identity's EVM key
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.WrongKey.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J, ASG_J);
        in_.members[0].evmKeyHash = keccak256("unregistered evm key");
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.WrongKey.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveRejectsAZeroOperatorPayee() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.members[0].operatorPayee = address(0);
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.ZeroAddress.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveRequiresEveryOpenLotExactlyOnceInAscendingOrder() public {
        bondFor(gid(0), 100 * UCT); // identity 1 now has two lots
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        assertEq(in_.members[0].lotIDs.length, 2);
        uint256[] memory full = in_.members[0].lotIDs;

        // a lot omitted (dust) is not allowed
        uint256[] memory missing = new uint256[](1);
        missing[0] = full[0];
        in_.members[0].lotIDs = missing;
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.LotSetMismatch.selector);
        custody.reserveCandidate(in_);

        // right count but duplicated entry
        uint256[] memory dup = new uint256[](2);
        dup[0] = full[0];
        dup[1] = full[0];
        in_.members[0].lotIDs = dup;
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.LotSetMismatch.selector);
        custody.reserveCandidate(in_);

        // right count but descending
        uint256[] memory desc = new uint256[](2);
        desc[0] = full[1];
        desc[1] = full[0];
        in_.members[0].lotIDs = desc;
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.LotSetMismatch.selector);
        custody.reserveCandidate(in_);

        // both lots reserved: accepted, including the dust lot
        in_.members[0].lotIDs = full;
        in_.members[0].weight = 11; // 1,100 UCT backing now
        _reserveRaw(in_);
        (,,,,,,, uint32 refs,,,,,) = custody.lots(full[1]);
        assertEq(refs, 1);
    }

    function test_reserveRejectsLotsOfAnotherIdentityOrAnUnknownLot() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.members[0].lotIDs[0] = lotOf(gid(1)); // identity 2's lot listed for identity 1
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.LotNotEligible.selector);
        custody.reserveCandidate(in_);
        in_ = _input(RES_J, ASG_J);
        in_.members[0].lotIDs[0] = 9_999; // unknown lot
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.LotNotEligible.selector);
        custody.reserveCandidate(in_);
    }

    function test_reserveEnforcesTheReferenceCeilingAndKeepsASlotForK() public {
        // rMax = 4. Each incumbent lot is referenced by G; every session adds one J reference and
        // one slot stays free so that deriving K can never fail on capacity: G + J1 + J2 + K = 4.
        reserve(keccak256("res1"), keccak256("asg1"), allMembers(), 1);
        reserve(keccak256("res2"), keccak256("asg2"), allMembers(), 2);
        assertEq(lotv(1).refCount, 3);
        ReserveInput memory in_ = _input(keccak256("res3"), keccak256("asg3"));
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.ReferenceCapacity.selector);
        custody.reserveCandidate(in_);
    }

    function test_theKSlotIsKeptEvenForIncumbentsExcludedFromTheCandidate() public {
        // two sessions that exclude identity 1 still keep identity 1's incumbent lot at G + K <= 4
        reserve(keccak256("res1"), keccak256("asg1"), allExcept(0), 1);
        reserve(keccak256("res2"), keccak256("asg2"), allExcept(0), 2);
        assertEq(lotv(1).refCount, 1, "excluded identity gains no J references");
        // the third session is refused because identity 2's lot has G + J1 + J2 and needs a K slot
        ReserveInput memory in_ =
            _reserveInput(keccak256("res3"), keccak256("asg3"), allExcept(0), 3);
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.ReferenceCapacity.selector);
        custody.reserveCandidate(in_);
    }

    function test_recoveryAfterTheMaximumNumberOfSessionsStillDerivesK() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        reserve(RES_J2, ASG_J2, allMembers(), 2);
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll(); // must not revert: capacity for K was reserved up front
        assertEq(custody.lastAckedAssignment(), ASG_K);
        for (uint256 i; i < N_GENESIS; ++i) {
            assertEq(lotv(i + 1).refCount, 4, "G + J1 + J2 + K");
        }
    }

    function test_incumbentExposuresNeedNoCoverageOrEligibilityToBeLocked() public {
        // identity 1 retires before the snapshot: it is excluded from J, but K (the incumbent
        // slate) still contains its exposure and the session locks it.
        requestRetirement(0);
        reserve(RES_J, ASG_J, allExcept(0), 1);
        (,,,,,,,, uint32 locks) = custody.exposures(genesisExposure(0));
        assertEq(locks, 1);
    }

    function test_reservationFailureLeavesNoPartialState() public {
        ReserveInput memory in_ = _input(RES_J, ASG_J);
        in_.members[3].weight = 11; // last member fails coverage after three members were processed
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.InsufficientCoverage.selector);
        custody.reserveCandidate(in_);
        (uint8 state,,,,,,,,,,,,,,,) = custody.assignments(ASG_J);
        assertEq(state, 0);
        (,,,,,,, uint32 refs,,,,,) = custody.lots(1);
        assertEq(refs, 1);
        assertEq(custody.session(RES_J).incumbentAssignmentID, bytes32(0));
    }
}
