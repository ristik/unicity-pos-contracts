// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {ElectionPolicy} from "../../../src/p85/ElectionPolicy.sol";
import {Limits, ElectionParams, RecordKind, RecoveryAckData} from "../../../src/p85/P85Types.sol";

/// @notice The prototype's supported deployment limit, through VR (sol review of #92, findings 1 and 2): a committee of at most 6 (nMax)
/// drawn from an index of at most 8 identities (vMax) of one lot each (lMax). The genesis script refuses more
/// (PosGenesis.test_theGenesisRefusesALimitAboveTheMeasuredOne); ElectionPolicy refuses a ninth registration (IndexFull). At that limit
/// the election, `outputOf` (publication) and a RecoveryAck of the maximum K, with its lot references, run inside VR's callback caps.
contract PosLimitTest is PosBase {
    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: 6,
            nMax: 6,
            maxM: 4,
            distNum: 1,
            distDen: 1,
            cadenceRounds: 200,
            cadenceSeconds: 100
        });
    }

    function _manifestLimits() internal pure override returns (Limits memory) {
        return Limits({vMax: 8, lMax: 1, rMax: 4, maxBatch: 32});
    }

    /// @dev Six members elected through VR, then two outsiders that outrank the incumbents fill the index (V = 8).
    function _atTheLimit() internal {
        for (uint256 k; k < 2; ++k) {
            Joiner memory a = _joinPos(1_000 * UCT);
            evmPkOf[a.id] = a.evmPk;
            bytes32 r = _elect2();
            bytes32 previous = custody.lastAckedAssignment();
            _ackNext(r);
            pushRecord(RecordKind.Closure, closureData(previous, lastH, "prev"));
            _vrApplyAll();
        }
        assertEq(vr.committee().length, 6);
        for (uint256 k; k < 2; ++k) {
            Joiner memory o = _joinPos(1_100 * UCT);
            evmPkOf[o.id] = o.evmPk;
        }
        assertEq(election.liveCount(), 8);
    }

    function test_theIndexRefusesANinthIdentity() public {
        _atTheLimit();
        vm.expectRevert(ElectionPolicy.IndexFull.selector);
        this.joinExtra();
    }

    function joinExtra() external {
        _joinPos(1_000 * UCT);
    }

    function _ctx() internal view returns (bytes memory) {
        return abi.encode(
            ORIGIN,
            uint256(progress),
            uint256(ucTime),
            uint256(1),
            vr.lastAcked(),
            VRCodec.limitsWord(4, 6, 6),
            uint256(0),
            uint256(0)
        );
    }

    /// @dev astra's qualification (ruling on option 1): the complete module callbacks cold, with 20% headroom under the new caps.
    /// elect <= 4.0 M of CAP_ELECT 5.0 M, outputOf <= 1.2 M of CAP_OUTPUT 1.5 M, one-record onRecords <= 2.0 M of CAP_RECORD 2.5 M.
    function test_theCallbacksAtTheLimitAreColdWithin20PercentOfTheCaps() public {
        _atTheLimit();
        _advance(300, 200);
        _coolAll();
        uint256 snap = vm.snapshotState();
        bytes memory ctx = _ctx();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        adapter.elect(ctx);
        uint256 electCallback = g - gasleft();
        vm.revertToState(snap);
        emit log_named_uint("cold elect callback (committee 6, index 8)", electCallback);
        assertLe(electCallback, 4_000_000);
        // through VR
        _coolAll();
        g = gasleft();
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED);
        emit log_named_uint("cold VR.elect (enclosing call)", g - gasleft());
        assertEq(vr.health(), VRC.HEALTHY);
        bytes32 rid = vr.openOutput();
        election.submitAssignmentPoPs(rid, _popsFor2(rid));
        election.finalizeCandidate(rid);
        _coolAll();
        g = gasleft();
        bytes memory out = adapter.outputOf(rid);
        uint256 outCallback = g - gasleft();
        emit log_named_uint("cold outputOf callback (6 members)", outCallback);
        assertGt(out.length, 64 + 32 + 192);
        assertLe(outCallback, 1_200_000);
        _coolAll();
        g = gasleft();
        assertEq(vr.publish(rid), VRC.PUB_PUBLISHED);
        emit log_named_uint("cold VR.publish (enclosing call)", g - gasleft());
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function _popsFor2(bytes32 rid) internal returns (ElectionPolicy.PoPInput[] memory pops) {
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

    function _growTo(uint256 n) internal {
        while (vr.committee().length < n) {
            Joiner memory a = _joinPos(1_000 * UCT);
            evmPkOf[a.id] = a.evmPk;
            bytes32 r = _elect2();
            bytes32 previous = custody.lastAckedAssignment();
            _ackNext(r);
            pushRecord(RecordKind.Closure, closureData(previous, lastH, "prev"));
            _vrApplyAll();
        }
    }

    /// @dev A K-member recovery through the real adapter and VR, the RecoveryAck delivered ALONE (a longer segment can hide a one-record
    /// shortfall): healthy VR, the recovery Boundary completes, the cursors and the holder facts match. Also the callback's cold gas and the
    /// least gas the adapter must receive (forwarding slack included).
    function _recovery(uint256 k) internal {
        _growTo(k);
        _advance(300, 200);
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED);
        bytes32 rid = vr.openOutput();
        assertEq(_publishResult2(rid), VRC.PUB_PUBLISHED);
        _advance(10, 10);
        bytes32 recovery = keccak256("rec");
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(
                RecoveryAckData(
                    rid,
                    recovery,
                    progress + 5,
                    progress + 6,
                    100 + progress,
                    progress + 7,
                    progress + 8,
                    3,
                    3
                )
            )
        );
        _boundaryRecord(rid, true);
        uint64 from = vr.recordCursor();
        // the callback alone, cold
        uint256 snap = vm.snapshotState();
        _coolAll();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        adapter.onRecords(from, 1);
        uint256 callback = g - gasleft();
        vm.revertToState(snap);
        emit log_named_uint(
            string.concat("cold RecoveryAck onRecords callback, K=", vm.toString(k)), callback
        );
        assertLe(callback, 2_000_000, "within 20% of CAP_RECORD");
        // the least gas the adapter must receive: the smallest g for which the call succeeds (binary search over snapshots)
        uint256 lo = callback / 2;
        uint256 hi = 2_500_000;
        while (hi - lo > 1_000) {
            uint256 mid = (lo + hi) / 2;
            uint256 s2 = vm.snapshotState();
            _coolAll();
            vm.prank(VR_ADDR);
            (bool ok,) =
                address(adapter).call{gas: mid}(abi.encodeCall(adapter.onRecords, (from, 1)));
            vm.revertToState(s2);
            if (ok) hi = mid;
            else lo = mid;
        }
        emit log_named_uint(
            string.concat("least gas the adapter must receive, K=", vm.toString(k)), hi
        );
        assertLe(hi, 2_400_000, "inside CAP_RECORD 2.5 M with the forwarding slack");
        // through VR: the RecoveryAck alone, then its Boundary
        _coolAll();
        g = gasleft();
        _vrApply(1);
        emit log_named_uint(
            string.concat("cold VR.applyRootRecords(1) of the RecoveryAck, K=", vm.toString(k)),
            g - gasleft()
        );
        assertEq(vr.health(), VRC.HEALTHY, "within CAP_RECORD");
        assertEq(custody.recordCursor(), vr.recordCursor(), "the cursors match");
        assertEq(custody.lastAckedAssignment(), recovery);
        assertEq(custody.assignmentExposures(recovery).length, k, "K re-derived");
        _vrApply(1); // the Boundary
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(_state(rid), VRC.OUT_RECOVERED, "the recovery Boundary completed");
        assertEq(custody.recordCursor(), vr.recordCursor());
        for (uint64 id = 1; id <= custody.nextStakingID(); ++id) {
            _assertFacts(id, 1);
        }
        assertEq(_cursorFact(), custody.recordCursor());
    }

    function test_recoveryK4ThroughVR() public {
        _recovery(4);
    }

    function test_recoveryK5ThroughVR() public {
        _recovery(5);
    }

    function test_recoveryK6ThroughVR() public {
        _recovery(6);
    }
}
