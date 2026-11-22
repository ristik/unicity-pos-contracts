// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosLimitBase} from "./PosLimit.t.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {Evidence} from "../../../src/p85/Evidence.sol";
import {AssignmentSeat, Limits} from "../../../src/p85/P85Types.sol";
import {ElectionPolicy, ElectionStorage} from "../../../src/p85/ElectionPolicy.sol";

contract PosCompactSixteenTest is PosLimitBase {
    function _nMax() internal pure override returns (uint32) {
        return 16;
    }

    function _manifestLimits() internal pure override returns (Limits memory) {
        return Limits({vMax: 20, lMax: 1, rMax: 4, maxBatch: 32});
    }

    function _recordCap() internal pure override returns (uint256) {
        return 2_500_000;
    }

    function test_coldElectionAndPublicationAtSixteenWithFullIndex() public {
        _atTheLimit();
        bytes32 incumbent = custody.lastAckedAssignment();
        _advance(300, 200);
        bytes memory ctx = _ctx();
        uint256 snap = vm.snapshotState();
        _coolAll();
        vm.prank(VR_ADDR);
        uint256 beforeCallback = gasleft();
        (bool ok,) = address(adapter).call{gas: 5_600_000}(abi.encodeCall(adapter.elect, (ctx)));
        emit log_named_uint("16 seats, V=20, cold elect callback", beforeCallback - gasleft());
        assertTrue(ok);
        assertTrue(election.openResult() != bytes32(0));
        vm.revertToState(snap);
        _coolAll();
        uint256 g = gasleft();
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED);
        emit log_named_uint("16 seats, V=20, cold VR.elect", g - gasleft());
        bytes32 r = vr.openOutput();
        bytes32 next = election.result(r).assignmentID;
        assertEq(custody.assignmentSeatCount(next), 16);
        assertTrue(
            custody.assignmentSeat(incumbent, 15).binding.id
                != custody.assignmentSeat(next, 15).binding.id
        );
        election.submitAssignmentPoPs(r, _popsFor2(r));
        election.finalizeCandidate(r);
        _coolAll();
        beforeCallback = gasleft();
        (bool ready, bytes memory output) =
            address(adapter).staticcall{gas: 1_200_000}(abi.encodeCall(adapter.outputOf, (r)));
        emit log_named_uint("16 seats, cold outputOf callback", beforeCallback - gasleft());
        assertTrue(ready);
        assertGt(output.length, 32);
        _coolAll();
        g = gasleft();
        assertEq(vr.publish(r), VRC.PUB_PUBLISHED);
        emit log_named_uint("16 seats, cold VR.publish", g - gasleft());
        assertEq(vr.output(r).members.length, 16);
        assertEq(vr.health(), VRC.HEALTHY);
        vm.expectRevert(ElectionStorage.IndexFull.selector);
        this.joinExtra();
    }

    function test_savedClosureRecoveryAtSixteenWithFullIndex() public {
        _recovery(16, true, true);
    }

    function test_evidenceFindsOnlyTheHistoricalSeatLot() public {
        AssignmentSeat memory member = custody.assignmentSeat(GENESIS_ASSIGNMENT, 0);
        uint256 key = rootPk(0);
        Evidence.VoteHeader memory h = Evidence.VoteHeader(NETWORK, 1, compressed(key), 1, 10);
        Evidence.SignedVote memory a = rootVote(h, keccak256("A"), key);
        Evidence.SignedVote memory b = rootVote(h, keccak256("B"), key);
        vm.expectRevert(Evidence.ExposureUnknown.selector);
        evidence.submitSeatEvidence(h, a, b, GENESIS_ASSIGNMENT, 1, member.exposureID);
        vm.prank(reporter);
        bytes32 caseID =
            evidence.submitSeatEvidence(h, a, b, GENESIS_ASSIGNMENT, 0, member.exposureID);
        assertEq(evidence.pendingHolds(member.lotID), 1);
        uint256[] memory ids = new uint256[](1);
        ids[0] = custody.assignmentSeat(GENESIS_ASSIGNMENT, 1).lotID;
        vm.expectRevert(Evidence.NotNextLot.selector);
        evidence.settleEvidence(caseID, ids);
        ids[0] = member.lotID;
        assertEq(evidence.settleEvidence(caseID, ids), 10 * UCT);
        assertEq(evidence.pendingHolds(member.lotID), 0);
        assertConserved();
    }

    function test_genesisSeatKeepsTheExactHistoricalLotAndDigest() public view {
        AssignmentSeat memory m = custody.assignmentSeat(GENESIS_ASSIGNMENT, 0);
        assertEq(m.binding.id, gid(0));
        assertEq(m.binding.generation, 1);
        assertEq(m.lotID, custody.generationLots(m.binding.id, m.binding.generation)[0]);
        assertEq(m.exposureID, _eid(GENESIS_ASSIGNMENT, gid(0)));
        assertEq(m.memberDigest, vr.committee()[0].exposureDigest);
    }
}
