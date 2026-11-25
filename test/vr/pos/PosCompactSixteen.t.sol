// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosLimitBase} from "./PosLimit.t.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {CustodyStorage} from "../../../src/p85/CustodyStorage.sol";
import {Evidence} from "../../../src/p85/Evidence.sol";
import {
    AssignmentSeat,
    Limits,
    RecordKind,
    RecoveryAckData,
    ReserveInput,
    SeatBinding
} from "../../../src/p85/P85Types.sol";
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

    function test_liveWritesRefuseAChangedCustodyImplementation() public {
        vm.etch(custody.GENESIS_IMPL(), hex"60006000f3");
        SeatBinding memory binding;
        vm.expectRevert(CustodyStorage.InvalidGenesis.selector);
        vm.prank(address(election));
        custody.internSeatBinding(binding);

        ReserveInput memory candidate;
        vm.expectRevert(CustodyStorage.InvalidGenesis.selector);
        vm.prank(address(election));
        custody.reserveCandidate(candidate);
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

    function test_secondRecoveryRetainsPrimarySeatsAndLegacyCommitments() public {
        _recovery(16, true, true);
        bytes32 first = custody.lastAckedAssignment();
        bytes32 slates = bytes32(uint256(45));
        bytes32 primary = vm.load(address(custody), keccak256(abi.encode(first, slates)));
        assertTrue(primary != bytes32(0) && primary != first);

        bytes32 rid = _elect2();
        bytes32 reserved = election.result(rid).assignmentID;
        _advance(10, 10);
        uint64 jH = 120 + progress;
        pushRecord(RecordKind.Closure, closureData(first, jH, "saved first K"));
        pushRecord(RecordKind.Closure, closureData(reserved, jH, "saved second J"));
        _vrApply(2);
        bytes32 next = keccak256("second recovery");
        uint64 epoch = vr.config().knownRootEpoch + 1;
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(
                RecoveryAckData(
                    rid,
                    next,
                    progress + 5,
                    progress + 6,
                    jH,
                    progress + 7,
                    progress + 8,
                    epoch + 1,
                    epoch
                )
            )
        );
        _boundaryRecord(rid, true);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_RECOVERED);
        assertEq(custody.lastAckedAssignment(), next);
        assertEq(vm.load(address(custody), keccak256(abi.encode(next, slates))), primary);
        assertEq(vm.load(address(custody), keccak256(abi.encode(next, uint256(44)))), bytes32(0));
        _assertLegacyCommitments(first, next);
    }

    function _assertLegacyCommitments(bytes32 incumbent, bytes32 recovered) private view {
        bytes32 exposures = keccak256("unicity.p85.exposure-digest");
        bytes32 keys = keccak256("unicity.p85.key-history-digest");
        uint256[] memory lots = new uint256[](1);
        for (uint256 i; i < 16; ++i) {
            AssignmentSeat memory old = custody.assignmentSeat(incumbent, i);
            AssignmentSeat memory seat = custody.assignmentSeat(recovered, i);
            assertEq(abi.encode(seat.binding), abi.encode(old.binding));
            assertEq(seat.weight, old.weight);
            assertEq(seat.rawWeight, old.rawWeight);
            assertEq(seat.lotID, old.lotID);
            assertEq(seat.exposureID, _eid(recovered, old.binding.id));
            lots[0] = old.lotID;
            bytes32 memberDigest = keccak256(abi.encode(lots));
            assertEq(seat.memberDigest, memberDigest);
            exposures = keccak256(
                abi.encode(
                    exposures,
                    seat.exposureID,
                    old.binding.id,
                    old.weight,
                    old.rawWeight,
                    old.binding.payee,
                    memberDigest
                )
            );
            keys = keccak256(
                abi.encode(keys, old.binding.id, old.binding.rootKeyHash, old.binding.evmKeyHash)
            );
            (,,,,,,, uint32 references,,,,,) = custody.lots(old.lotID);
            assertEq(references, 1);
        }
        (,,,,,,,,,,,,, bytes32 exposureDigest, bytes32 keyDigest,) = custody.assignments(recovered);
        assertEq(exposureDigest, exposures);
        assertEq(keyDigest, keys);
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

    /// #1297 in the compact layout: a post-term seal of the genesis term charges exactly the historical seat's lot.
    function test_postTermSealEvidenceChargesTheExactHistoricalSeatLot() public {
        bytes32 r = _elect2();
        _ackNext(r);
        uint64 aStar = lastH + 11; // J's first round
        bytes32 tag = "g";
        bytes32 hID = keccak256(abi.encode("H", tag));
        bytes[] memory keys = new bytes[](N_GENESIS);
        uint64[] memory weights = new uint64[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            keys[i] = compressed(rootPk(i));
            weights[i] = 10;
        }
        roots.setStrictEpochs(true);
        roots.installEpoch(1, 1, true, aStar, 2, bytes32(0), keys, weights);
        roots.installEpoch(2, aStar, false, 0, 2, hID, keys, weights);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, lastH, tag));
        _vrApplyAll();
        custody.anchorTerm(GENESIS_ASSIGNMENT, hID, keccak256(abi.encode("R_H", tag)));

        Evidence.PostTermSeal memory s;
        s.epoch = 1;
        s.commitRound = aStar;
        s.votingRound = aStar + 1;
        s.parent = aStar;
        s.exec = keccak256("a state the genesis committee never handed over");
        s.commitHash = s.exec;
        bytes32 d = evidence.postTermSealDigest(s);
        Evidence.SealQuorum memory q;
        q.members = new uint8[](3);
        q.signatures = new bytes[](3);
        for (uint256 i; i < 3; ++i) {
            q.members[i] = uint8(i);
            q.signatures[i] = signNative(rootPk(i), d);
        }
        AssignmentSeat memory member = custody.assignmentSeat(GENESIS_ASSIGNMENT, 1);
        assertEq(member.binding.rootKeyHash, keccak256(compressed(rootPk(1))));
        vm.expectRevert(Evidence.ExposureUnknown.selector);
        evidence.submitPostTermSeatEvidence(s, q, GENESIS_ASSIGNMENT, 2, member.exposureID);
        vm.prank(reporter);
        bytes32 caseID =
            evidence.submitPostTermSeatEvidence(s, q, GENESIS_ASSIGNMENT, 1, member.exposureID);
        assertEq(evidence.pendingHolds(member.lotID), 1);
        assertEq(evidence.caseInfo(caseID).lotCount, 1);
        (bytes32 asgID, uint256 ordinal) = evidence.caseLocation(caseID);
        assertEq(asgID, GENESIS_ASSIGNMENT);
        assertEq(ordinal, 1);
        uint256[] memory ids = new uint256[](1);
        ids[0] = member.lotID;
        assertEq(evidence.settleEvidence(caseID, ids), 10 * UCT);
        assertEq(evidence.pendingHolds(member.lotID), 0);
        assertConserved();
    }
}
