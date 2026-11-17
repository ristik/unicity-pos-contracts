// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Vm} from "forge-std/Test.sol";
import {PoaBase} from "./PoaBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {Member, OutputView, IdentityView, ChangeView} from "../../../src/vr/VRTypes.sol";
import {PoaElection} from "../../../src/vr/poa/PoaElection.sol";

/// @notice PoaElection through the real ValidatorRegistry (design 3.7, section 11 VT-03): the states and their guards, the due rule,
/// composition (growth at 4, the swap at 4, pure removal at 4 refused and at 5 allowed, binding replacement), publication in the same
/// call with VR-domain exposure digests, the Boundary effects, closure and parking, NoCandidate(LimitsUnreachable) without a fault and
/// the native repair after it.
contract PoaElectionTest is PoaBase {
    // Each test sets its own generation up (once: VR's storage at 0xff..03 survives a second deployment).

    // ---- metadata ----

    function test_metadataWithinCaps() public {
        _setUpPoa(5, 1, 5, 16);
        assertEq(poa.moduleTag(), POA_TAG);
        assertEq(poa.capabilities(), 0);
        (address h, bytes32 hh) = poa.liabilityHolder();
        assertEq(h, address(0));
        assertEq(hh, bytes32(0));
        // exact static ABI words, at most 32 x 8 bytes each
        bytes4[5] memory sel = [
            PoaElection.moduleTag.selector,
            PoaElection.capabilities.selector,
            PoaElection.gasBounds.selector,
            PoaElection.maxElectionInterval.selector,
            PoaElection.liabilityHolder.selector
        ];
        uint256[5] memory size = [uint256(32), 32, 256, 32, 64];
        for (uint256 i = 0; i < 5; ++i) {
            (bool ok, bytes memory ret) =
                address(poa).staticcall{gas: 50_000}(abi.encodePacked(sel[i]));
            assertTrue(ok);
            assertEq(ret.length, size[i]);
            assertLe(ret.length, 256);
        }
        // VR cached it at genesis, and a second instance passes the SetModule queue checks
        assertEq(vr.activeModule().meta.moduleTag, POA_TAG);
        assertEq(vr.activeModule().meta.maxElectionInterval, 1_000);
        PoaElection other = new PoaElection(VR_ADDR, engine, new uint64[](0));
        _queue(VRC.K_SET_MODULE, abi.encode(address(other), address(other).codehash, bytes("")));
    }

    // ---- due rule ----

    function test_notDueWithoutWorkOrBeforeTheGap() public {
        _setUpPoa(5, 1, 5, 16);
        assertEq(_elect(), VRC.ELECT_NOT_DUE, "no work");
        _queueScheduled(VRC.K_FEE_PARAMS, abi.encode(uint64(2_000_000), uint64(8), COLLECTOR));
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED, "dueWork: the empty trial");
        assertTrue(_eqIds(_outputIds(rid), _seq(1, 5)));
        // work scheduled while the output is open waits for its boundary and then for MIN_EPOCH_GAP
        _queueScheduled(VRC.K_FEE_PARAMS, abi.encode(uint64(3_000_000), uint64(8), COLLECTOR));
        assertEq(_elect(), VRC.ELECT_DISABLED, "an output is open");
        _acknowledge(rid, 0);
        assertEq(_elect(), VRC.ELECT_NOT_DUE, "inside the epoch gap");
        _advance(VRC.MIN_EPOCH_GAP - 1, 1);
        assertEq(_elect(), VRC.ELECT_NOT_DUE, "one short of the gap");
        _advance(1, 1);
        assertEq(_elect(), VRC.ELECT_RESERVED, "at the gap");
    }

    // ---- composition and the boundary ----

    function test_growthFromFourToFive() public {
        _setUpPoa(4, 1, 5, 16);
        uint64 j = _admitNew();
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        OutputView memory o = vr.output(rid);
        assertEq(o.state, VRC.OUT_PUBLISHED, "ready in the same call");
        assertEq(o.moduleTag, POA_TAG);
        assertEq(o.sourceModule, address(poa));
        assertTrue(_eqIds(_outputIds(rid), _with(_seq(1, 4), j)));
        for (uint256 i = 0; i < o.members.length; ++i) {
            assertEq(o.members[i].weight, 1);
            assertEq(o.members[i].rawWeight, 1);
            assertEq(
                o.members[i].exposureDigest,
                keccak256(
                    abi.encode(
                        VRC.EXPOSURE_DOMAIN,
                        NETWORK,
                        block.chainid,
                        VR_ADDR,
                        rid,
                        uint256(o.members[i].id)
                    )
                ),
                "exposure digest in the VR domain"
            );
        }
        assertEq(o.membersDigest, VRCodec.membersDigest(o.members));
        assertEq(_st(j), JOINING);
        // a later publish is a precondition failure (already published)
        assertEq(vr.publish(rid), VRC.PUB_PRECONDITION_FAILED);
        _acknowledge(rid, 0);
        assertEq(_st(j), ACTIVE);
        assertTrue(_eqIds(_committeeIds(), _with(_seq(1, 4), j)));
        assertTrue(_eqIds(poa.members(), _committeeIds()));
        assertEq(poa.queue().length, 0);
    }

    function test_pureRemovalAtFourRefusedThenSwap() public {
        _setUpPoa(4, 1, 4, 16);
        _action(A_REMOVE, 2);
        assertEq(_st(2), REMOVING);
        (uint8 out,) = _electPoa();
        assertEq(out, VRC.ELECT_NO_CANDIDATE, "3 * 1 < 3 fails");
        assertEq(vr.health(), VRC.HEALTHY, "NoCandidate is not a fault");
        assertEq(_st(2), REMOVING);
        uint64 j = _admitNew();
        bytes32 rid;
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED, "the swap passes (D = 1/2)");
        assertTrue(_eqIds(_outputIds(rid), _with(_minus(_seq(1, 4), 2), j)));
        assertEq(_st(2), LEAVING);
        assertEq(_st(j), JOINING);
        _acknowledge(rid, 0);
        assertEq(_st(2), EXITED);
        assertEq(_st(j), ACTIVE);
        assertEq(vr.committee().length, 4);
    }

    function test_exitAtFive() public {
        _setUpPoa(5, 1, 5, 16);
        vm.prank(_ownerOf(3));
        poa.requestExit(3);
        assertEq(_st(3), EXIT_REQUESTED);
        (uint8 out,) = _electPoa();
        assertEq(out, VRC.ELECT_NOT_DUE, "an exit request alone is not work");
        _action(A_CONFIRM_EXIT, 3);
        assertEq(_st(3), REMOVING);
        bytes32 rid;
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED, "pure removal 5 -> 4 (D = 2/5)");
        assertTrue(_eqIds(_outputIds(rid), _minus(_seq(1, 5), 3)));
        _acknowledge(rid, 0);
        assertEq(_st(3), EXITED);
        // an exited identity may apply again
        _submit(3);
        assertEq(_st(3), APPLIED);
    }

    function test_bindingReplacement() public {
        _setUpPoa(5, 1, 5, 16);
        bytes32 ref = _stageBinding(2);
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED, "a staged binding is work");
        Member[] memory ms = vr.output(rid).members;
        assertEq(ms[1].id, 2);
        assertEq(ms[1].generation, 2, "the staged binding is captured at g + 1");
        IdentityView memory v = vr.identity(2);
        assertEq(ms[1].rootKeyHash, v.staged.rootKeyHash);
        assertEq(ms[0].generation, 1);
        _acknowledge(rid, 0);
        v = vr.identity(2);
        assertEq(v.currentRef, ref);
        assertEq(v.stagedRef, bytes32(0));
        assertEq(_st(2), ACTIVE);
    }

    function test_twoJoinersAndTargetPreference() public {
        _setUpPoa(7, 1, 9, 16);
        uint64 a = _admitNew();
        uint64 b = _admitNew();
        uint64 c = _admitNew();
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        // growth by two (7 -> 9: 3 * 2 < 7, D = 4/9) reaches nTarget; the third waits in admission order
        assertTrue(_eqIds(_outputIds(rid), _with(_with(_seq(1, 7), a), b)));
        assertEq(_st(c), ADMITTED);
        _acknowledge(rid, 0);
        assertEq(poa.queue().length, 1);
        assertEq(poa.queue()[0], c);
    }

    function test_growthByTwoAtFourRefused() public {
        _setUpPoa(4, 1, 6, 16);
        uint64 a = _admitNew();
        uint64 b = _admitNew();
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        // 4 -> 6 fails turnover (3 * 2 >= 4); one joiner enters, the other stays Admitted
        assertTrue(_eqIds(_outputIds(rid), _with(_seq(1, 4), a)));
        assertEq(_st(b), ADMITTED);
    }

    // ---- closure and parking ----

    function _recExpired(bytes32 rid, uint256 readyBitmap) internal {
        seal.push(
            VRC.REC_OUTPUT_REJECTED,
            abi.encode(rid, uint256(VRC.REJ_EXPIRED), uint256(0), readyBitmap)
        );
    }

    function test_closureReturnsJoinersAndLeavers() public {
        _setUpPoa(5, 1, 5, 16);
        _action(A_REMOVE, 3);
        uint64 j = _admitNew();
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(_st(3), LEAVING);
        assertEq(_st(j), JOINING);
        _recExpired(rid, 0x1f); // every successor was ready: nobody parks
        _recClosed(rid);
        _applyAll();
        assertEq(_state(rid), VRC.OUT_CLOSED);
        assertEq(_st(3), REMOVING);
        assertEq(_st(j), ADMITTED);
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED, "retried");
        assertEq(_st(j), JOINING);
    }

    function test_parkingAndAutomaticReturn() public {
        _setUpPoa(4, 1, 5, 16);
        uint64 j = _admitNew();
        (, bytes32 rid) = _electPoa();
        // the joiner is the fifth successor (bit 4); the bitmap lacks it
        _recExpired(rid, 0x0f);
        _recClosed(rid);
        _applyAll();
        assertEq(_st(j), PARKED);
        assertEq(vr.health(), VRC.HEALTHY, "parking is no fault");
        (uint8 out,) = _electPoa();
        assertEq(out, VRC.ELECT_NOT_DUE, "a parked joiner is not work");
        // automatic return after PARK_PERIOD
        _advance(poa.PARK_PERIOD(), 1);
        assertEq(_st(j), ADMITTED);
        bytes32 rid2;
        (out, rid2) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(_eqIds(_outputIds(rid2), _with(_seq(1, 4), j)));
        _acknowledge(rid2, 0);
        assertEq(_st(j), ACTIVE);
    }

    function test_parkingSplitBatchAndEarlyRejoin() public {
        _setUpPoa(7, 1, 9, 16);
        uint64 a = _admitNew();
        uint64 b = _admitNew();
        (, bytes32 rid) = _electPoa();
        // successors 1..7, a, b: a is bit 7, b is bit 8; b was not ready. The rejection and the closure arrive in two batches.
        _recExpired(rid, 0xff);
        _applyAll();
        assertEq(_st(b), PARKED);
        assertEq(_st(a), JOINING);
        _recClosed(rid);
        _applyAll();
        assertEq(_st(a), ADMITTED);
        assertEq(_st(b), PARKED);
        vm.prank(_ownerOf(b));
        poa.rejoin(b);
        assertEq(_st(b), ADMITTED);
        (uint8 out, bytes32 rid2) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(_eqIds(_outputIds(rid2), _with(_with(_seq(1, 7), a), b)), "admission order kept");
    }

    // ---- NoCandidate(LimitsUnreachable), then native repair ----

    function test_emptyTrialOutsideLimitsThenNativeRepair() public {
        _setUpPoa(5, 1, 5, 16);
        // limits 5 -> nMin 6 through an ordinary output (O = 5 is inside the old limits)
        _queueScheduled(VRC.K_COMMITTEE_LIMITS, abi.encode(uint32(6), uint32(6), uint32(7)));
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        _acknowledge(rid, 0);
        assertEq(vr.config().nMin, 6);
        // more boundary work: the empty trial is outside the limits and nobody can join
        uint64 fee =
            _queueScheduled(VRC.K_FEE_PARAMS, abi.encode(uint64(2_000_000), uint64(8), COLLECTOR));
        (out,) = _electPoa();
        assertEq(out, VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.HEALTHY, "LimitsUnreachable is not a fault");
        // the work deadline then stalls the module and VR repairs natively (exempt from the limits)
        _advance(1_000 + 2 * VRC.LIFETIME + 1, 1);
        out = _elect();
        assertEq(vr.health(), VRC.STALLED);
        assertEq(out, VRC.ELECT_RESERVED);
        bytes32 nrid = vr.openOutput();
        OutputView memory o = vr.output(nrid);
        assertTrue(o.native);
        assertEq(o.members.length, 5);
        assertEq(_changeState(fee), VRC.CH_BOUND);
        _acknowledge(nrid, 0);
        assertEq(_changeState(fee), VRC.CH_ACTIVE);
        assertTrue(_eqIds(poa.members(), _seq(1, 5)));
    }

    // ---- states and guards ----

    function test_ownerCallsAndGuards() public {
        _setUpPoa(5, 1, 5, 16);
        uint64 id = _registerNew();
        vm.expectRevert(PoaElection.NotOwner.selector);
        poa.submitApplication(id);
        vm.expectRevert(PoaElection.NotOwner.selector);
        poa.submitApplication(999); // unknown identity
        _submit(id);
        vm.prank(_ownerOf(id));
        vm.expectRevert(abi.encodeWithSelector(PoaElection.BadState.selector, APPLIED));
        poa.submitApplication(id);
        vm.prank(_ownerOf(id));
        poa.withdrawApplication(id);
        assertEq(_st(id), NONE);
        vm.prank(_ownerOf(id));
        vm.expectRevert(abi.encodeWithSelector(PoaElection.BadState.selector, NONE));
        poa.withdrawApplication(id);
        // a member cannot apply; only Active may request an exit; only Parked may rejoin
        vm.prank(_ownerOf(1));
        vm.expectRevert(abi.encodeWithSelector(PoaElection.BadState.selector, ACTIVE));
        poa.submitApplication(1);
        vm.prank(_ownerOf(id));
        vm.expectRevert(abi.encodeWithSelector(PoaElection.BadState.selector, NONE));
        poa.requestExit(id);
        vm.prank(_ownerOf(1));
        vm.expectRevert(abi.encodeWithSelector(PoaElection.BadState.selector, ACTIVE));
        poa.rejoin(1);
        // steps are VR's only
        vm.expectRevert(PoaElection.NotVR.selector);
        poa.onGovernance(abi.encode(uint64(1), id));
        vm.expectRevert(PoaElection.NotVR.selector);
        poa.elect(new bytes(256));
        vm.expectRevert(PoaElection.NotVR.selector);
        poa.onRecords(0, 0);
    }

    function test_refusedActionsAreNoFaultAndOweABoundary() public {
        _setUpPoa(5, 1, 5, 16);
        uint64 id = _registerNew();
        // Admit needs Applied; ConfirmExit needs ExitRequested; Remove needs a non-terminal state; unknown actions and bad shapes are
        // refused too. A failing onGovernance would fault the module (design 3.3.1), so each is refused without reverting.
        bytes[6] memory bad = [
            abi.encode(A_ADMIT, id),
            abi.encode(A_CONFIRM_EXIT, uint64(1)),
            abi.encode(A_REMOVE, id),
            abi.encode(uint64(4), uint64(1)),
            abi.encodePacked(uint64(1), id),
            abi.encode(A_ADMIT, uint256(1) << 64)
        ];
        for (uint256 i = 0; i < bad.length; ++i) {
            vm.recordLogs();
            uint64 c = _queueScheduled(VRC.K_MODULE_ACTION, abi.encode(address(poa), bad[i]));
            assertEq(vr.change(c).state, VRC.CH_ACTIVE, "executed");
            Vm.Log[] memory logs = vm.getRecordedLogs();
            bool refused = false;
            for (uint256 k = 0; k < logs.length; ++k) {
                if (
                    logs[k].emitter == address(poa)
                        && logs[k].topics[0] == PoaElection.ActionRefused.selector
                ) {
                    refused = true;
                }
            }
            assertTrue(refused, "ActionRefused");
        }
        assertEq(vr.health(), VRC.HEALTHY, "a refused action is no fault");
        assertEq(_st(id), NONE);
        assertEq(_st(1), ACTIVE);
        // the executed actions armed VR's work deadline: the module owes a boundary and settles it with the empty trial
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(_eqIds(_outputIds(rid), _seq(1, 5)));
        _acknowledge(rid, 0);
        (out,) = _electPoa();
        assertEq(out, VRC.ELECT_NOT_DUE, "settled");
        _advance(1_000 + 2 * VRC.LIFETIME + 1, 1);
        _elect();
        assertEq(vr.health(), VRC.HEALTHY, "no stall");
    }

    function test_removeApplicantOwesABoundary() public {
        _setUpPoa(5, 1, 5, 16);
        uint64 id = _registerNew();
        _submit(id);
        _action(A_REMOVE, id);
        assertEq(_st(id), REMOVING);
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED, "the boundary the action owes");
        assertTrue(_eqIds(_outputIds(rid), _seq(1, 5)));
        _acknowledge(rid, 0);
        assertEq(_st(id), EXITED, "a Removing non-member exits at the boundary");
        (out,) = _electPoa();
        assertEq(out, VRC.ELECT_NOT_DUE);
    }

    function test_removeFromEveryNonTerminalState() public {
        _setUpPoa(5, 1, 5, 16);
        // Applied, Admitted, Parked (non-members): Removing, out at the next boundary
        uint64 ap = _registerNew();
        _submit(ap);
        uint64 ad = _admitNew();
        _action(A_REMOVE, ap);
        _action(A_REMOVE, ad);
        assertEq(_st(ap), REMOVING);
        assertEq(_st(ad), REMOVING);
        // Active and ExitRequested members
        vm.prank(_ownerOf(4));
        poa.requestExit(4);
        _action(A_REMOVE, 4);
        assertEq(_st(4), REMOVING);
        // Removing again is a no-op success
        uint64 c = _action(A_REMOVE, 4);
        assertEq(_changeState(c), VRC.CH_ACTIVE);
        // the removal of 4 goes out (5 -> 4); the Removing non-members exit at that boundary
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(
            _eqIds(_outputIds(rid), _minus(_seq(1, 5), 4)), "Removing non-members never join"
        );
        // Leaving -> Removing while the output is open
        _action(A_REMOVE, 4);
        assertEq(_st(4), REMOVING);
        _acknowledge(rid, 0);
        assertEq(_st(4), EXITED);
        assertEq(_st(ap), EXITED);
        assertEq(_st(ad), EXITED);
        assertEq(poa.queue().length, 0);
        // terminal states refuse Remove (without a fault)
        _action(A_REMOVE, uint64(4));
        assertEq(_st(4), EXITED);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_removeJoining() public {
        _setUpPoa(7, 1, 9, 16);
        uint64 a = _admitNew();
        uint64 b = _admitNew();
        (, bytes32 rid) = _electPoa();
        // Joining a is removed while the output is open; it is installed with the output and then leaves as a Removing member
        _action(A_REMOVE, a);
        assertEq(_st(a), REMOVING);
        _acknowledge(rid, 0);
        assertEq(_st(a), REMOVING);
        assertEq(_st(b), ACTIVE);
        assertTrue(_eqIds(poa.members(), _committeeIds()));
        (uint8 out, bytes32 rid2) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(_eqIds(_outputIds(rid2), _minus(_committeeIds(), a)));
    }
}
