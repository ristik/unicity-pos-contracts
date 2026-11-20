// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "./VRBase.sol";
import {MockModule, MockHolder} from "./VRMocks.sol";
import {VRShared} from "../../src/vr/VRShared.sol";
import {VRChanges} from "../../src/vr/VRChanges.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {Member, FeeSet} from "../../src/vr/VRTypes.sol";

/// @notice Governance (design section 3.5) and the watchdogs (section 3.6.3): queue-time checks through VR, the change state machine
/// with cancel and binding races, the ForceRemove queue bound, the Boundary effects of every kind, and the stall deadlines, including
/// a deadline that reservation, expiry and withdrawal loops never reset.
contract VRGovernanceTest is VRBase {
    function setUp() public {
        _setUpVR(5, 1, 5, 16);
    }

    function _refused(uint8 kind, bytes memory payload, uint8 code) internal {
        vm.prank(governor);
        vm.expectRevert(abi.encodeWithSelector(VRShared.QueueRefused.selector, code));
        vr.queue(kind, payload);
    }

    // ---------------------------------------------------------------------------------------------
    // queue
    // ---------------------------------------------------------------------------------------------

    function test_onlyTheGovernorQueuesAndCancels() public {
        vm.expectRevert(VRShared.NotGovernor.selector);
        vm.prank(address(0xBAD));
        vr.queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        uint64 id = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        vm.expectRevert(VRShared.NotGovernor.selector);
        vm.prank(address(0xBAD));
        vr.cancel(id);
    }

    function test_queueRecordsDelaysAndPayload() public {
        bytes memory p = _limitsPayload(2, 5, 9);
        uint64 id = _queue(VRC.K_COMMITTEE_LIMITS, p);
        assertEq(id, 1);
        assertEq(_changeState(id), VRC.CH_QUEUED);
        assertEq(vr.change(id).notBeforeProgress, progress + VRC.DELAY_ROUNDS);
        assertEq(vr.change(id).notBeforeTime, ucTime + VRC.DELAY_SECONDS);
        assertEq(vr.change(id).payload, p);
        assertEq(vr.change(id).payloadHash, keccak256(p));
    }

    /// @dev CAP_ELECT of the build under test (VR_BUILD=pos: the PoS-capable build).
    function _electCap() internal view returns (uint64) {
        return keccak256(bytes(vm.envOr("VR_BUILD", string("")))) == keccak256("pos")
            ? 5_000_000
            : 4_000_000;
    }

    function test_setModuleChainChecks() public {
        MockModule m = new MockModule(keccak256("m2"));
        _refused(
            VRC.K_SET_MODULE,
            abi.encode(address(0x1234), bytes32(uint256(1)), bytes("")),
            VRChanges.NO_CODE
        );
        _refused(
            VRC.K_SET_MODULE,
            abi.encode(address(m), keccak256("wrong"), bytes("")),
            VRChanges.CODE_HASH_MISMATCH
        );
        m.setCaps(4); // an unknown capability bit
        _refused(
            VRC.K_SET_MODULE,
            abi.encode(address(m), address(m).codehash, bytes("")),
            VRChanges.BAD_METADATA
        );
        m.setCaps(0);
        m.setBounds([_electCap() + 1, 1, 1, 1, 1, 1, 1, 1]); // electGas above VR's cap
        _refused(
            VRC.K_SET_MODULE,
            abi.encode(address(m), address(m).codehash, bytes("")),
            VRChanges.BAD_METADATA
        );
        m.setBounds([uint64(1), 1, 1, 1, 1, 1, 1, 1]);
        m.setCaps(VRC.CAP_LIABILITY_HOLDER); // a holder without an address
        _refused(
            VRC.K_SET_MODULE,
            abi.encode(address(m), address(m).codehash, bytes("")),
            VRChanges.BAD_METADATA
        );
        MockHolder h = new MockHolder();
        m.setHolder(address(h));
        uint64 id =
            _queue(VRC.K_SET_MODULE, abi.encode(address(m), address(m).codehash, bytes("init")));
        assertEq(_changeState(id), VRC.CH_QUEUED);
    }

    function test_metadataGetterReturnsAreCapped() public {
        MockModule m = new MockModule(keccak256("m2"));
        m.setMode(0, 0);
        // a module whose getters return oversized data: etch a contract that returns 1 MiB for every call
        bytes memory huge = hex"62100000" // PUSH3 0x100000 PUSH1 0 RETURN
            hex"6000" hex"f3";
        vm.etch(address(m), huge);
        _refused(
            VRC.K_SET_MODULE,
            abi.encode(address(m), address(m).codehash, bytes("")),
            VRChanges.BAD_METADATA
        );
    }

    function test_pendingAndForceRemoveBounds() public {
        for (uint64 i = 0; i < 4; ++i) {
            _queue(VRC.K_FORCE_REMOVE, abi.encode(uint64(1 + i)));
        }
        _refused(VRC.K_FORCE_REMOVE, abi.encode(uint64(5)), VRChanges.TOO_MANY_FORCE_REMOVES);
        _refused(VRC.K_FORCE_REMOVE, abi.encode(uint64(9)), VRChanges.NOT_IN_COMMITTEE);
        // cancelling one frees a slot
        vm.prank(governor);
        vr.cancel(1);
        _queue(VRC.K_FORCE_REMOVE, abi.encode(uint64(5)));
        for (uint256 i = 0; i < 28; ++i) {
            _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        }
        _refused(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16), VRChanges.TOO_MANY_PENDING);
    }

    function test_scheduleActivationQueueRules() public {
        uint64 e = vr.config().knownRootEpoch;
        bytes32 rule = keccak256("unicity.rule/cancun-extra");
        _refused(
            VRC.K_SCHEDULE_ACTIVATION,
            abi.encode(rule, bytes32(0), e + 2, uint64(ucTime + 3600), "x"),
            VRChanges.SCHEDULE_TOO_EARLY
        );
        _refused(
            VRC.K_SCHEDULE_ACTIVATION,
            abi.encode(rule, bytes32(0), e + 3, uint64(ucTime + 3599), "x"),
            VRChanges.SCHEDULE_TOO_SOON
        );
        _queue(
            VRC.K_SCHEDULE_ACTIVATION,
            abi.encode(rule, bytes32(0), e + 3, uint64(ucTime + 3600), "x")
        );
    }

    // ---------------------------------------------------------------------------------------------
    // the change state machine
    // ---------------------------------------------------------------------------------------------

    function test_cancelBeforeBindingWins() public {
        uint64 id = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        vm.prank(governor);
        vr.cancel(id);
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        assertEq(vr.output(r).changes.length, 0, "a cancelled change is never bound");
        assertEq(_changeState(id), VRC.CH_CANCELLED);
    }

    function test_bindingBeforeCancelWins() public {
        uint64 id = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED);
        assertEq(_changeState(id), VRC.CH_BOUND, "bound at reservation");
        vm.prank(governor);
        vm.expectRevert(VRShared.NotCancellable.selector);
        vr.cancel(id);
        // closure releases it back to Scheduled, where it is cancellable again
        _recRejected(r, VRC.REJ_EXPIRED);
        _recClosed(r);
        _applyAll();
        assertEq(_changeState(id), VRC.CH_SCHEDULED);
        vm.prank(governor);
        vr.cancel(id);
        assertEq(_changeState(id), VRC.CH_CANCELLED);
    }

    function test_bindingSelectionDefersSingletonsAndModuleActions() public {
        uint64 a = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        uint64 b = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(2, 5, 16));
        uint64 c =
            _queue(VRC.K_FEE_PARAMS, abi.encode(uint64(2_000_000), uint64(8), address(0xFEE)));
        uint64 fr = _queue(VRC.K_FORCE_REMOVE, abi.encode(uint64(5)));
        _passDelays();
        vr.execute(a);
        vr.execute(b);
        vr.execute(c);
        vr.execute(fr);
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        uint64[] memory bound = vr.output(r).changes;
        assertEq(bound.length, 2);
        assertEq(bound[0], a);
        assertEq(bound[1], c);
        assertEq(_changeState(b), VRC.CH_SCHEDULED, "a second limits change defers");
        assertEq(
            _changeState(fr), VRC.CH_SCHEDULED, "a ForceRemove the output does not perform defers"
        );
    }

    /// @dev VT-07a: the activation table is bounded at MAX_ACTIVATIONS by the queue-time check, which counts the schedules still pending
    /// (not yet terminal) together with the entries recorded, so the roots' committed schedule (an append per accepted change) can never
    /// see more than 64 entries. Fill the table to 64 through the real path (queue, execute, bind, acknowledge), then try to exceed it.
    function test_activationTableNeverExceeds64() public {
        uint256 done;
        uint256 round;
        while (done < 56) {
            uint256 cnt = 8;
            uint64[] memory ids = new uint64[](cnt);
            uint64 e = vr.config().knownRootEpoch + 50;
            for (uint256 i = 0; i < cnt; ++i) {
                ids[i] = _queue(
                    VRC.K_SCHEDULE_ACTIVATION,
                    abi.encode(
                        keccak256(abi.encode("unicity.rule/fill", done + i)),
                        keccak256("rel"),
                        e,
                        uint64(ucTime + 3600),
                        "f"
                    )
                );
            }
            _passDelays();
            for (uint256 i = 0; i < cnt; ++i) {
                vr.execute(ids[i]);
            }
            bytes32 r = _rid(string(abi.encode("fill", round)));
            assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
            _acknowledge(r, 0);
            done += cnt;
            ++round;
        }
        assertEq(uint256(vr.activationCount()), 56);
        // the next eight are pending (queued): they count against the bound, so a ninth is refused although only 56 are recorded
        for (uint256 i = 0; i < 8; ++i) {
            _queue(
                VRC.K_SCHEDULE_ACTIVATION,
                abi.encode(
                    keccak256(abi.encode("unicity.rule/pending", i)),
                    keccak256("rel"),
                    vr.config().knownRootEpoch + 50,
                    uint64(ucTime + 3600),
                    "p"
                )
            );
        }
        _refused(
            VRC.K_SCHEDULE_ACTIVATION,
            abi.encode(
                keccak256("unicity.rule/over"),
                keccak256("rel"),
                vr.config().knownRootEpoch + 50,
                uint64(ucTime + 3600),
                "o"
            ),
            VRChanges.TOO_MANY_ACTIVATIONS
        );
    }

    function test_boundaryEffectsOfEveryEvmKind() public {
        // limits, fees, governor, schedule; the governor's code hash is checked at activation
        MockHolder newGov = new MockHolder();
        uint64 limits = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(3, 5, 12));
        uint64 fees =
            _queue(VRC.K_FEE_PARAMS, abi.encode(uint64(5_000_000), uint64(4), address(0xFEE)));
        uint64 gov =
            _queue(VRC.K_SET_GOVERNOR, abi.encode(address(newGov), address(newGov).codehash));
        bytes32 rule = keccak256("unicity.rule/x");
        uint64 e = vr.config().knownRootEpoch;
        uint64 sched = _queue(
            VRC.K_SCHEDULE_ACTIVATION,
            abi.encode(rule, keccak256("rel"), e + 3, uint64(ucTime + 3600), "x")
        );
        _passDelays();
        vr.execute(limits);
        vr.execute(fees);
        vr.execute(gov);
        vr.execute(sched);
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        uint256 bAck = block.number;
        _acknowledge(r, 0);
        assertEq(_changeState(limits), VRC.CH_ACTIVE);
        assertEq(vr.config().nMin, 3);
        assertEq(vr.config().nMax, 12);
        assertEq(vr.config().governor, address(newGov));
        assertEq(vr.config().feesEffectiveBlock, bAck + 1);
        FeeSet memory before = vr.feesFor(uint64(bAck));
        FeeSet memory afterward = vr.feesFor(uint64(bAck + 1));
        assertEq(before.baseFeeFloor, 1_000_000, "F(B_ack) is the previous set");
        assertEq(afterward.baseFeeFloor, 5_000_000, "F(B_ack + 1) is the new set");
        assertEq(afterward.feeCollector, address(0xFEE));
        assertEq(vr.activationCount(), 1);
        assertEq(vr.activationAt(0).ruleId, rule);
        assertEq(vr.activationAt(0).state, VRC.ACT_ACTIVE);
        assertEq(vr.change(limits).activeRootEpoch, e + 1);
    }

    function test_rejectedBitmapAndGovernorCodeMismatch() public {
        MockHolder newGov = new MockHolder();
        uint64 limits = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(3, 5, 12));
        uint64 gov =
            _queue(VRC.K_SET_GOVERNOR, abi.encode(address(newGov), keccak256("not its code")));
        _passDelays();
        vr.execute(limits);
        vr.execute(gov);
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _acknowledge(r, 1); // bit 0: the first bound change (limits) rejected by the roots
        assertEq(_changeState(limits), VRC.CH_REJECTED);
        assertEq(vr.change(limits).rejectReason, VRC.V_CONFLICT);
        assertEq(vr.config().nMin, 1, "a rejected change has no effect");
        assertEq(_changeState(gov), VRC.CH_REJECTED);
        assertEq(vr.change(gov).rejectReason, VRC.R_CODE_MISMATCH);
        assertEq(vr.config().governor, governor);
    }

    function test_postponementSupersedesAndLatch() public {
        bytes32 rule = keccak256("unicity.rule/y");
        uint64 e = vr.config().knownRootEpoch; // 4
        uint64 s1 = _queueScheduled(
            VRC.K_SCHEDULE_ACTIVATION,
            abi.encode(rule, keccak256("a"), e + 3, uint64(ucTime + 3600), "a")
        );
        bytes32 r1 = _rid("R1");
        assertEq(_moduleReserve(r1, true), VRC.ELECT_RESERVED);
        _acknowledge(r1, 0); // epoch 5
        assertEq(vr.activationAt(0).state, VRC.ACT_ACTIVE);
        uint64 e2 = vr.config().knownRootEpoch;
        uint64 s2 = _queueScheduled(
            VRC.K_SCHEDULE_ACTIVATION,
            abi.encode(rule, keccak256("b"), e2 + 4, uint64(ucTime + 3600), "b")
        );
        _advance(VRC.MIN_EPOCH_GAP, 1);
        bytes32 r2 = _rid("R2");
        assertEq(_moduleReserve(r2, true), VRC.ELECT_RESERVED);
        _acknowledge(r2, 0); // epoch 6
        assertEq(vr.activationAt(0).state, VRC.ACT_SUPERSEDED, "the postponement supersedes");
        assertEq(vr.activationAt(1).state, VRC.ACT_ACTIVE);
        assertEq(vr.activationAt(1).changeId, s2);
        assertEq(_changeState(s1), VRC.CH_ACTIVE);
        // three more boundaries reach epoch 9 = e2 + 4: latched
        for (uint256 i = 0; i < 3; ++i) {
            _advance(VRC.MIN_EPOCH_GAP, 1);
            bytes32 r = keccak256(abi.encode("R", i));
            uint64 q = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
            assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
            _acknowledge(r, 0);
            assertEq(_changeState(q), VRC.CH_ACTIVE);
        }
        assertEq(vr.config().knownRootEpoch, e2 + 4);
        assertEq(vr.activationAt(1).state, VRC.ACT_LATCHED);
    }

    function test_moduleActionExecutesIntoTheActiveModuleOnly() public {
        uint64 a = _queue(
            VRC.K_MODULE_ACTION, abi.encode(address(module), abi.encode(uint64(1), uint64(3)))
        );
        uint64 b = _queue(
            VRC.K_MODULE_ACTION, abi.encode(address(0xBEEF), abi.encode(uint64(1), uint64(3)))
        );
        _passDelays();
        vr.execute(a);
        vr.execute(b);
        assertEq(_changeState(a), VRC.CH_ACTIVE);
        assertEq(_changeState(b), VRC.CH_REJECTED);
        assertEq(vr.change(b).rejectReason, VRC.R_NOT_ACTIVE);
        assertTrue(vr.activeModule().workPending, "an executed ModuleAction is work");
    }

    function test_executeRefusals() public {
        uint64 id = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        vm.expectRevert(VRShared.DelayNotElapsed.selector);
        vr.execute(id);
        _advance(VRC.DELAY_ROUNDS, VRC.DELAY_SECONDS - 1);
        vm.expectRevert(VRShared.DelayNotElapsed.selector);
        vr.execute(id);
        _advance(0, 1);
        vr.execute(id);
        vm.expectRevert(VRShared.PreconditionFailed.selector);
        vr.execute(id);
    }

    function test_inconsistentRefusesExecuteAndReservations() public {
        uint64 id = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        _recClosed(_rid("unknown")); // an anomaly
        _applyAll();
        assertEq(vr.health(), VRC.INCONSISTENT);
        _passDelays();
        vm.expectRevert(VRShared.Inconsistent.selector);
        vr.execute(id);
        module.setElect(VRC.ELECT_RESERVED, true, _rid("R"));
        assertEq(_elect(), VRC.ELECT_DISABLED);
        _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16)); // queueing is still possible
    }

    // ---------------------------------------------------------------------------------------------
    // watchdogs (design 3.6.3)
    // ---------------------------------------------------------------------------------------------

    function _deadline() internal view returns (uint64) {
        return module.interval() + 2 * VRC.LIFETIME;
    }

    function test_workDeadlineStallsAnIdleModule() public {
        _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        uint64 since = vr.activeModule().workSince;
        assertTrue(vr.activeModule().workPending);
        progress = since + _deadline();
        seal.setClock(progress, ucTime);
        assertEq(_elect(), VRC.ELECT_NOT_DUE);
        assertEq(vr.health(), VRC.HEALTHY, "not yet past the deadline");
        _advance(1, 1);
        _elect();
        assertEq(vr.health(), VRC.STALLED);
    }

    /// @dev A module that keeps reserving and letting its outputs expire, or withdrawing them with an economic (LOST) invalidation,
    /// never resets the deadline: only a Boundary of its own output does.
    function test_deadlineNeverResetByReservationOrWithdrawalLoops() public {
        _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        uint64 since = vr.activeModule().workSince;
        for (uint256 i = 0; vr.health() == VRC.HEALTHY; ++i) {
            bytes32 r = keccak256(abi.encode("loop", i));
            if (_moduleReserve(r, i % 2 == 0) != VRC.ELECT_RESERVED) break;
            if (i % 2 == 1) module.invalidate(r, VRC.INVALID_LOST);
            _advance(VRC.LIFETIME / 2, 600);
            _recRejected(r, i % 2 == 1 ? VRC.REJ_INVALIDATED : VRC.REJ_EXPIRED);
            _recClosed(r);
            _applyAll();
            assertEq(vr.activeModule().workSince, since, "the deadline is not reset");
            _elect();
        }
        assertEq(vr.health(), VRC.STALLED);
        assertGt(progress, since + _deadline());
        assertLe(
            progress,
            since + _deadline() + VRC.LIFETIME / 2 + 1,
            "stalled at the first election past it"
        );
    }

    function test_ownBoundaryResetsTheDeadline() public {
        _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        uint64 second = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(2, 5, 16));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _advance(1000, 1);
        _acknowledge(r, 0);
        assertEq(_changeState(second), VRC.CH_SCHEDULED, "the deferred one remains");
        assertEq(vr.activeModule().workSince, progress, "restarted at the boundary");
    }

    function test_withdrawalWithAnOutputLevelReasonFaults() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        module.invalidate(r, VRC.INVALID_WITHDRAWN);
        _recRejected(r, VRC.REJ_INVALIDATED);
        _recClosed(r);
        _applyAll();
        assertEq(vr.health(), VRC.FAULTED, "Invalidated with an output-level reason");
    }

    function test_lostInvalidationIsNotAFault() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        module.invalidate(r, VRC.INVALID_LOST);
        _recRejected(r, VRC.REJ_INVALIDATED);
        _recClosed(r);
        _applyAll();
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_rootInvalidRejectionFaults() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _recRejected(r, VRC.REJ_INVALID);
        _applyAll();
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_overdueFeasibleForceRemoveStalls() public {
        uint64 fr = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(5)));
        uint64 at_ = vr.change(fr).scheduledAt;
        // keep the work deadline out of the way: a module boundary every so often would reset it; here the FR age alone decides
        progress = at_ + _deadline();
        seal.setClock(progress, ucTime);
        _elect();
        assertEq(vr.health(), VRC.HEALTHY);
        _advance(1, 1);
        _elect();
        assertEq(vr.health(), VRC.STALLED);
    }
}

/// @notice Four members: a pure removal fails continuity, so a ForceRemove there is infeasible and never stalls the module.
contract VRGovernanceFourTest is VRBase {
    function setUp() public {
        _setUpVR(4, 1, 4, 16);
    }

    function _deadline() internal view returns (uint64) {
        return module.interval() + 2 * VRC.LIFETIME;
    }

    function test_infeasibleForceRemoveNeverStalls() public {
        // four members: a pure removal fails continuity (3 * 1 >= 3), so the removal alone is infeasible
        uint64 fr = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(4)));
        uint64 at_ = vr.change(fr).scheduledAt;
        // the work deadline is the same length; reset it with a module boundary just before the FR deadline
        progress = at_ + _deadline() - 10;
        seal.setClock(progress, ucTime);
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _acknowledge(r, 0);
        _advance(20, 1);
        _elect();
        assertEq(vr.health(), VRC.HEALTHY, "an infeasible removal never stalls the module");
    }
}
