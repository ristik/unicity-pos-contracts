// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PoaBase} from "./PoaBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {OutputView} from "../../../src/vr/VRTypes.sol";

/// @notice The section 11 VT-03 ForceRemove fixtures through the real VR (design 3.6.3, 3.7.3, and gate I3 with VT-02): two infeasible
/// lower ids plus a feasible id 9; two feasible removals with the older one winning, and once overdue the native repair removing it;
/// a repeated-omission run reaching Stalled and then native removal. VR binds exactly the ForceRemoves the chosen trial performs.
contract PoaForceRemoveTest is PoaBase {
    function _fr(uint64 id) internal returns (uint64 changeId) {
        changeId = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(id));
    }

    function test_twoInfeasibleLowerIdsAndFeasibleNine() public {
        // weights 5, 5, 1 x 8 (W = 18): removing 1 or 2 alone gives D = 10/18 > 1/2; removing 9 gives D = 2/18
        uint64[] memory raw = new uint64[](10);
        for (uint256 i = 0; i < 10; ++i) {
            raw[i] = i < 2 ? 5 : 1;
        }
        _setUpPoaWeights(raw, 1, 10, 16);
        uint64 c1 = _fr(1);
        uint64 c2 = _fr(2);
        uint64 c9 = _fr(9);
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(
            _eqIds(_outputIds(rid), _minus(_seq(1, 10), 9)),
            "the feasible id leads the pool and is performed"
        );
        assertEq(_changeState(c9), VRC.CH_BOUND, "the performed removal is bound");
        assertEq(_changeState(c1), VRC.CH_SCHEDULED, "the infeasible ones stay Scheduled");
        assertEq(_changeState(c2), VRC.CH_SCHEDULED);
        OutputView memory o = vr.output(rid);
        assertEq(o.members[0].weight, 5, "incumbents keep their raw weight");
        _acknowledge(rid, 0);
        assertEq(_changeState(c9), VRC.CH_ACTIVE);
        assertEq(_st(9), EXITED);
        // only the infeasible removals remain: no trial passes, and that is no fault
        (out,) = _electPoa();
        assertEq(out, VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_twoFeasibleOlderWinsThenOverdueNativeRemoval() public {
        // n = 7: two removals fail turnover (3 * 2 >= 5), each alone passes
        _setUpPoa(7, 1, 7, 16);
        uint64 older = _fr(5);
        uint64 younger = _fr(3);
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(
            _eqIds(_outputIds(rid), _minus(_seq(1, 7), 5)), "the older (higher id) removal wins"
        );
        assertEq(_changeState(older), VRC.CH_BOUND);
        assertEq(_changeState(younger), VRC.CH_SCHEDULED);
        // the output never completes; once the older removal is overdue VR stalls the module and repairs natively
        _recRejected(rid, VRC.REJ_EXPIRED);
        _recClosed(rid);
        _applyAll();
        assertEq(_changeState(older), VRC.CH_SCHEDULED, "released at closure");
        uint64 sched = vr.change(older).scheduledAt;
        _advance(sched + 1_000 + 2 * VRC.LIFETIME + 1 - progress, 1);
        out = _elect();
        assertEq(vr.health(), VRC.STALLED);
        assertEq(out, VRC.ELECT_RESERVED);
        bytes32 nrid = vr.openOutput();
        assertTrue(vr.output(nrid).native);
        assertTrue(
            _eqIds(_outputIds(nrid), _minus(_seq(1, 7), 5)),
            "the overdue older removal is mandatory"
        );
        assertEq(_changeState(older), VRC.CH_BOUND);
        assertEq(_changeState(younger), VRC.CH_SCHEDULED);
        _acknowledge(nrid, 0);
        assertEq(_st(5), EXITED, "the module follows the native boundary");
        assertTrue(_eqIds(poa.members(), _minus(_seq(1, 7), 5)));
    }

    function test_repeatedOmissionReachesStalledThenNativeRemoval() public {
        // nMin = 5 at n = 5: the removal leaves the limits, so every module output omits it while other work passes empty
        _setUpPoa(5, 5, 5, 16);
        uint64 c = _fr(4);
        uint64 sched = vr.change(c).scheduledAt;
        for (uint64 k = 0; k < 3; ++k) {
            _queueScheduled(
                VRC.K_FEE_PARAMS, abi.encode(uint64(2_000_000 + k), uint64(8), COLLECTOR)
            );
            (uint8 out, bytes32 rid) = _electPoa();
            assertEq(out, VRC.ELECT_RESERVED, "the empty trial");
            assertTrue(_eqIds(_outputIds(rid), _seq(1, 5)), "the ForceRemove is omitted");
            assertEq(_changeState(c), VRC.CH_SCHEDULED);
            _acknowledge(rid, 0);
            assertEq(
                vr.health(),
                VRC.HEALTHY,
                "boundaries reset the work deadline, not the ForceRemove's age"
            );
        }
        _advance(sched + 1_000 + 2 * VRC.LIFETIME + 1 - progress, 1);
        uint8 o2 = _elect();
        assertEq(vr.health(), VRC.STALLED, "the overdue feasible removal stalls the module");
        assertEq(o2, VRC.ELECT_RESERVED);
        bytes32 nrid = vr.openOutput();
        assertTrue(vr.output(nrid).native);
        assertTrue(
            _eqIds(_outputIds(nrid), _minus(_seq(1, 5), 4)),
            "native repair is exempt from the limits"
        );
        _acknowledge(nrid, 0);
        assertEq(_changeState(c), VRC.CH_ACTIVE);
        assertEq(_st(4), EXITED);
    }
}
