// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {Member} from "../../../src/vr/VRTypes.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {ElectionPolicy} from "../../../src/p85/ElectionPolicy.sol";
import {Limits, ElectionParams, RecordKind, RecoveryAckData} from "../../../src/p85/P85Types.sol";

/// @notice The prototype's supported deployment limit, through VR (sol and astra, #92): a committee of at most 5 (nMax, so K <= 5) drawn
/// from an index of at most 8 identities (vMax) of one lot each (lMax). The genesis script refuses more (PosGenesis);
/// ElectionPolicy refuses a ninth registration (IndexFull). At that limit the election, `outputOf` (publication) and a RecoveryAck of the
/// maximum K (plain, and with the incumbent's and the primary's closures staged first), with its lot references, run inside VR's callback
/// caps with 20% headroom (elect 4.0 M, outputOf 1.2 M, one-record onRecords 2.0 M). K = 6 is OUTSIDE the supported profile:
/// `PosOutsideProfileTest` pins its measurement.
abstract contract PosLimitBase is PosBase {
    /// @dev The generation's committee ceiling under test.
    function _nMax() internal pure virtual returns (uint32) {
        return 5;
    }

    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: _nMax(),
            nMax: _nMax(),
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

    /// @dev nMax members elected through VR, then outsiders that outrank the incumbents fill the index (V = 8).
    function _atTheLimit() internal {
        for (uint256 k; k < _nMax() - 4; ++k) {
            Joiner memory a = _joinPos(1_000 * UCT);
            evmPkOf[a.id] = a.evmPk;
            bytes32 r = _elect2();
            bytes32 previous = custody.lastAckedAssignment();
            _ackNext(r);
            pushRecord(RecordKind.Closure, closureData(previous, lastH, "prev"));
            _vrApplyAll();
        }
        assertEq(vr.committee().length, _nMax());
        for (uint256 k; k < 8 - _nMax(); ++k) {
            Joiner memory o = _joinPos(1_100 * UCT);
            evmPkOf[o.id] = o.evmPk;
        }
        assertEq(election.liveCount(), 8);
    }

    function joinExtra() external {
        _joinPos(1_000 * UCT);
    }

    uint256 internal constant ELECT_STIPEND = 4_000_000;
    uint256 internal constant OUTPUT_STIPEND = 1_200_000;
    uint256 internal constant RECORD_STIPEND = 2_000_000;

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

    /// @dev astra's qualification, enforced (ruling on option 1, round 2): each callback is CALLED with its actual qualification stipend,
    /// cold (state prepared first, every account cooled), and must succeed with the right answer: elect Reserved, outputOf a full Ready
    /// output of 6 members, a one-record onRecords applied. The enclosing VR calls are asserted end to end as well.
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

    /// @dev A K-member recovery through the real adapter and VR in the history a root produces: the incumbent K closes and the reserved
    /// primary's closure is staged (saved) BEFORE the RecoveryAck, so the same one-record callback also closes the primary, updates the
    /// members' liability anchors and lot holds, and releases the incumbent's references on unlock. The RecoveryAck is delivered ALONE with a
    /// one-record allowance, then its Boundary; health, cursors and holder facts are checked.
    function _recovery(uint256 k, bool savedClosure) internal {
        _growTo(k);
        _advance(300, 200);
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED);
        bytes32 rid = vr.openOutput();
        assertEq(_publishResult2(rid), VRC.PUB_PUBLISHED);
        bytes32 incumbent = custody.lastAckedAssignment();
        bytes32 jAssignment = election.result(rid).assignmentID;
        _advance(10, 10);
        uint64 jH = 120 + progress;
        if (savedClosure) {
            pushRecord(RecordKind.Closure, closureData(incumbent, jH, "k"));
            pushRecord(RecordKind.Closure, closureData(jAssignment, jH, "j"));
            _vrApply(2);
            assertEq(vr.health(), VRC.HEALTHY, "the closures apply");
        }
        bytes32 recovery = keccak256("rec");
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(
                RecoveryAckData(
                    rid, recovery, progress + 5, progress + 6, jH, progress + 7, progress + 8, 3, 3
                )
            )
        );
        _boundaryRecord(rid, true);
        uint64 from = vr.recordCursor();
        // the callback alone, cold, with the stipend
        uint256 snap = vm.snapshotState();
        _coolAll();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        (bool ok,) =
            address(adapter).call{gas: 2_500_000}(abi.encodeCall(adapter.onRecords, (from, 1)));
        uint256 callback = g - gasleft();
        assertTrue(ok, "the one-record onRecords succeeds inside the hard cap 2.5 M");
        if (!(savedClosure && k == 6)) {
            assertLe(callback, RECORD_STIPEND, "within the 2.0 M stipend");
        }
        assertEq(custody.recordCursor(), from + 1, "applied");
        vm.revertToState(snap);
        emit log_named_uint(
            string.concat(
                savedClosure ? "saved-closure " : "plain ",
                "RecoveryAck callback, K=",
                vm.toString(k)
            ),
            callback
        );
        // the least gas the adapter must receive (binary search over snapshots): inside the 2.0 M stipend
        uint256 lo = callback / 2;
        uint256 hi = 2_500_000;
        while (hi - lo > 500) {
            uint256 mid = (lo + hi) / 2;
            uint256 s2 = vm.snapshotState();
            _coolAll();
            vm.prank(VR_ADDR);
            (bool ok2,) =
                address(adapter).call{gas: mid}(abi.encodeCall(adapter.onRecords, (from, 1)));
            vm.revertToState(s2);
            if (ok2) hi = mid;
            else lo = mid;
        }
        emit log_named_uint("  least gas the adapter must receive", hi);
        if (!(savedClosure && k == 6)) assertLe(hi, RECORD_STIPEND);
        // through VR: the RecoveryAck alone, then its Boundary
        _coolAll();
        g = gasleft();
        _vrApply(1);
        emit log_named_uint("  cold VR.applyRootRecords(1)", g - gasleft());
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
}

contract PosLimitTest is PosLimitBase {
    function test_theIndexRefusesANinthIdentity() public {
        _atTheLimit();
        vm.expectRevert(ElectionPolicy.IndexFull.selector);
        this.joinExtra();
    }

    function test_theCallbacksAtTheLimitSucceedWithTheStipends() public {
        _atTheLimit();
        _advance(300, 200);
        bytes memory ctx = _ctx(); // read VR before cooling and pranking
        uint256 snap = vm.snapshotState();
        _coolAll();
        vm.prank(VR_ADDR);
        (bool ok, bytes memory ret) =
            address(adapter).call{gas: ELECT_STIPEND}(abi.encodeCall(adapter.elect, (ctx)));
        assertTrue(ok, "elect succeeds with 4.0 M");
        (uint8 err, uint8 outcome, bool ready, bytes32 erid) = VRCodec.decodeElect(ret);
        assertEq(err, VRCodec.OK);
        assertEq(outcome, VRC.ELECT_RESERVED);
        assertFalse(ready);
        assertEq(erid, election.openResult());
        vm.revertToState(snap);
        // through VR, end to end
        _coolAll();
        uint256 g = gasleft();
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED);
        emit log_named_uint("cold VR.elect (enclosing call)", g - gasleft());
        assertEq(vr.health(), VRC.HEALTHY);
        bytes32 rid = vr.openOutput();
        election.submitAssignmentPoPs(rid, _popsFor2(rid));
        election.finalizeCandidate(rid);
        _coolAll();
        (bool ok2, bytes memory out) = address(adapter).staticcall{gas: OUTPUT_STIPEND}(
            abi.encodeCall(adapter.outputOf, (rid))
        );
        assertTrue(ok2, "outputOf succeeds with 1.2 M");
        (uint8 e2, uint8 status, VRCodec.OutputHeader memory h, Member[] memory ms) =
            VRCodec.decodeOutput(out);
        assertEq(e2, VRCodec.OK);
        assertEq(status, VRC.STATUS_READY);
        assertEq(ms.length, _nMax(), "a full Ready output");
        assertEq(h.resultId, rid);
        _coolAll();
        g = gasleft();
        assertEq(vr.publish(rid), VRC.PUB_PUBLISHED);
        emit log_named_uint("cold VR.publish (enclosing call)", g - gasleft());
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_recoveryK4ThroughVR() public {
        _recovery(4, false);
    }

    function test_recoveryK5ThroughVR() public {
        _recovery(5, false);
    }

    function test_savedClosureRecoveryK4ThroughVR() public {
        _recovery(4, true);
    }

    function test_savedClosureRecoveryK5ThroughVR() public {
        _recovery(5, true);
    }
}

/// @notice A committee of 6 is OUTSIDE the supported profile (the genesis script refuses nMax 6): the measurement is pinned. With the
/// incumbent's and the primary's closures staged before the RecoveryAck the K = 6 callback is 2.15 M, above the 2.0 M qualification target
/// and inside CAP_RECORD 2.5 M (the recovery completes healthy); the plain K = 6 recovery is 1.96 M.
contract PosOutsideProfileTest is PosLimitBase {
    function _nMax() internal pure override returns (uint32) {
        return 6;
    }

    function test_recoveryK6PlainIsWithinTheStipendButOutsideTheProfile() public {
        _recovery(6, false);
    }

    function test_savedClosureRecoveryK6ExceedsTheStipend() public {
        _recovery(6, true);
    }
}
