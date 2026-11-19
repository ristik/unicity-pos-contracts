// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {Member} from "../../../src/vr/VRTypes.sol";
import {ElectionPolicy} from "../../../src/p85/ElectionPolicy.sol";
import {
    ElectionParams,
    RecordKind,
    RecoveryAckData,
    HolderRetirementData
} from "../../../src/p85/P85Types.sol";

/// @notice The 16-member cases of AC-LR (design 3.3.4 "Still separate", section 11): a 16-member election, a 16-member RecoveryAck, with
/// the holder's fact writes inside both. They run at the P85 layer, calling exactly what the adapter calls (`ElectionPolicy.elect` as the
/// hook caller, `StakeCustody.applyRootRecords`), because VR's immutable callback caps (CAP_ELECT 4,000,000 per elect step, CAP_RECORD
/// 1,500,000 per record) cannot carry them: the gas is measured and reported (owner-questions.md, "VT-04: PoS gas against VR's caps").
/// `test_throughVRTheElectionExceedsTheCapFromSixMembers` pins the through-VR boundary.
contract PosSixteenTest is PosBase {
    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4, nTarget: 16, nMax: 16, maxM: 4, distNum: 1, distDen: 1, cadenceRounds: 200, cadenceSeconds: 100
        });
    }

    function _members() internal view returns (uint256) {
        return custody.assignmentExposures(custody.lastAckedAssignment()).length;
    }

    /// @dev One election (the continuity rule admits a bounded change), published and acknowledged; the replaced assignment closes.
    function _step() internal {
        bytes32 rid = _p85Elect();
        bytes32 previous = custody.lastAckedAssignment();
        _p85Publish(rid);
        _advance(10, 10);
        lastH = 150 + progress;
        pushRecord(RecordKind.Ack, ackData(rid, lastH, 160 + progress, 161 + progress));
        // the replaced assignment closes, so references do not pile up past rMax
        pushRecord(RecordKind.Closure, closureData(previous, lastH, "prev"));
        applyAll();
        assertEq(custody.lastAckedAssignment(), election.result(rid).assignmentID);
    }

    uint256 internal lastElectGas;

    /// @dev The adapter's call: ElectionPolicy.elect from the hook caller, once the cadence has passed.
    function _p85Elect() internal returns (bytes32 rid) {
        _advance(300, 200);
        vm.prank(ADAPTER);
        uint256 g = gasleft();
        ElectionPolicy.Outcome o = election.elect(ORIGIN);
        lastElectGas = g - gasleft();
        assertEq(uint8(o), uint8(ElectionPolicy.Outcome.Reserved));
        rid = election.openResult();
    }

    function _p85Publish(bytes32 rid) internal {
        election.submitAssignmentPoPs(rid, _popsFor(rid));
        election.finalizeCandidate(rid);
    }

    function _popsFor(bytes32 rid) internal returns (ElectionPolicy.PoPInput[] memory pops) {
        ElectionPolicy.Frozen[] memory f = election.frozenMembers(rid);
        pops = new ElectionPolicy.PoPInput[](f.length);
        for (uint256 k; k < f.length; ++k) {
            uint256 pk = f[k].id <= N_GENESIS ? evmPk(f[k].id - 1) : evmPkOf[f[k].id];
            bytes memory key = compressed(pk);
            pops[k] = ElectionPolicy.PoPInput(
                f[k].id, key, sign(pk, election.popDigest(rid, f[k].id, keccak256(key)))
            );
        }
    }

    function _toSixteen() internal {
        for (uint256 k; k < 12; ++k) {
            Joiner memory j = _joinPos(1_000 * UCT);
            evmPkOf[j.id] = j.evmPk;
        }
        for (uint256 n; n < 12 && _members() < 16; ++n) {
            _step();
        }
        assertEq(_members(), 16);
    }

    function test_aSixteenMemberElectionAndItsPublication() public {
        _toSixteen();
        bytes32 rid = _p85Elect();
        emit log_named_uint("16-member ElectionPolicy.elect gas (reservation incl. holder facts)", lastElectGas);
        assertEq(election.frozenMembers(rid).length, 16);
        _p85Publish(rid);
        // the adapter serves the 16-member output (outputOf is a staticcall; its gas is reported)
        uint256 g = gasleft();
        bytes memory out = adapter.outputOf(rid);
        emit log_named_uint("16-member PosElectionAdapter.outputOf gas (no VR alignment: VR was not advanced)", g - gasleft());
        assertGt(out.length, 64 + 32 + 192 + 320 * 15);
        for (uint64 id = 1; id <= 16; ++id) {
            _assertFacts(id, 1);
        }
    }

    function test_aSixteenMemberRecoveryAckDerivesKAndRetirementWaitsForClosure() public {
        _toSixteen();
        bytes32 rid = _p85Elect();
        _p85Publish(rid);
        _advance(10, 10);
        bytes32 recovery = keccak256("recovery-assignment");
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(rid, recovery, progress + 5, progress + 6, 100 + progress, progress + 7, progress + 8, 3, 3))
        );
        uint256 g = gasleft();
        custody.applyRootRecords(1);
        emit log_named_uint("16-member RecoveryAck record gas (custody.applyRootRecords(1), holder facts included)", g - gasleft());
        assertEq(custody.lastAckedAssignment(), recovery);
        assertEq(custody.assignmentExposures(recovery).length, 16, "K re-derived");
        // retirement of a K member is refused until closure: its recovery exposure is live
        assertEq(custody.liveExposures(1, 1), 3, "the old K exposure, J's and the derived one");
        vm.prank(vm.addr(ownerPk(0)));
        custody.requestRetirement(1);
        requestedSeen[1][1] = true;
        _advance(500, 500);
        pushRecord(
            RecordKind.HolderRetirement,
            abi.encode(HolderRetirementData(0, 1, 1, custody.exposureChain(1, 1)))
        );
        vm.expectRevert(abi.encodeWithSignature("RefsStillLive()"));
        custody.applyRootRecords(1);
        for (uint64 id = 1; id <= 16; ++id) {
            _assertFacts(id, 1);
        }
    }

    /// @dev One batch touching more than 8 fact keys: the 16-member RecoveryAck writes the facts of 16 (id, generation) keys in one call.
    function test_oneBatchTouchesMoreThanEightFactKeys() public {
        _toSixteen();
        bytes32 rid = _p85Elect();
        _p85Publish(rid);
        _advance(10, 10);
        pushRecord(
            RecordKind.Ack, ackData(rid, 150 + progress, 160 + progress, 161 + progress)
        );
        pushRecord(
            RecordKind.Closure, closureData(custody.lastAckedAssignment(), 150 + progress, "batch")
        );
        applyAll(); // one 2-record batch: 16 reservations' references move and 16 close
        for (uint64 id = 1; id <= 16; ++id) {
            _assertFacts(id, 1);
        }
        assertEq(_cursorFact(), custody.recordCursor());
    }
}
