// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Vm} from "forge-std/Test.sol";
import {VRBase} from "./VRBase.sol";
import {MockModule} from "./VRMocks.sol";
import {VRShared} from "../../src/vr/VRShared.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {Member} from "../../src/vr/VRTypes.sol";

/// @notice Containment acceptance (design section 3.3, section 11 VT-02, section 12 gate): every contained step against a module that
/// reverts, runs out of gas, returns malformed or oversized (1 MiB) data, re-enters every VR mutator, griefs its whole cap, or writes
/// and then fails; the lock is clear after a failing step in the same transaction; a failing step rolls back VR's own partial writes;
/// faults are attributed only to funded calls whose preconditions held.
contract VRContainmentTest is VRBase {
    // module behaviours (MockModule)
    uint8 internal constant OK = 0;
    uint8 internal constant REVERT = 1;
    uint8 internal constant BURN = 2;
    uint8 internal constant MALFORMED = 3;
    uint8 internal constant HUGE = 4;
    uint8 internal constant REENTER = 5;
    uint8 internal constant REENTER_BUBBLE = 6;
    uint8 internal constant GRIEF = 7;
    uint8 internal constant WRITE_THEN_REVERT = 8;
    uint8 internal constant INVALIDATE_OPEN = 9;
    uint8 internal constant RETURN_WORD = 10;

    uint8 internal constant S_ELECT = 1;
    uint8 internal constant S_OUTPUT = 2;
    uint8 internal constant S_RECORDS = 3;
    uint8 internal constant S_RESOLVED = 4;
    uint8 internal constant S_GOV = 7;

    function setUp() public {
        _setUpVR(5, 1, 5, 16);
    }

    function _failing() internal pure returns (uint8[6] memory) {
        return [REVERT, BURN, MALFORMED, HUGE, REENTER_BUBBLE, WRITE_THEN_REVERT];
    }

    /// @dev After a failing step in this same transaction, the lock must be clear: a mutator succeeds.
    function _assertUnlocked() internal {
        vm.prank(address(0xA001)); // owner of identity 1
        vr.setEndpoints(1, bytes("/ip4/127.0.0.1/tcp/1"));
        assertEq(vr.identity(1).endpoints, bytes("/ip4/127.0.0.1/tcp/1"));
    }

    // ---------------------------------------------------------------------------------------------
    // elect
    // ---------------------------------------------------------------------------------------------

    function test_electStepFailuresFaultAndReturnNoCandidate() public {
        uint8[6] memory modes = _failing();
        for (uint256 i = 0; i < modes.length; ++i) {
            uint256 snap = vm.snapshotState();
            uint64 c = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
            module.setMode(S_ELECT, modes[i]);
            module.setElect(VRC.ELECT_RESERVED, true, _rid("R"));
            assertEq(_elect(), VRC.ELECT_NO_CANDIDATE, "a failed elect returns 3");
            assertEq(vr.health(), VRC.FAULTED, "the module is Faulted");
            assertEq(vr.openOutput(), bytes32(0), "nothing reserved");
            assertEq(_changeState(c), VRC.CH_SCHEDULED, "nothing bound");
            assertEq(module.sideEffect(), 0, "the module's own writes rolled back");
            _assertUnlocked();
            vm.revertToState(snap);
        }
    }

    function test_electOutputFailuresRollBackTheReservation() public {
        uint8[5] memory modes = [REVERT, BURN, MALFORMED, HUGE, GRIEF];
        for (uint256 i = 0; i < modes.length; ++i) {
            uint256 snap = vm.snapshotState();
            uint64 c = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
            module.setMode(S_OUTPUT, modes[i]);
            if (modes[i] == GRIEF) module.setOutputStatus(VRC.STATUS_PENDING); // ready, then not Ready: refused
            assertEq(_moduleReserve(_rid("R"), true), VRC.ELECT_NO_CANDIDATE);
            assertEq(vr.health(), VRC.FAULTED);
            assertEq(_state(_rid("R")), VRC.OUT_NONE, "partial write (the reservation) rolled back");
            assertEq(vr.openOutput(), bytes32(0));
            assertEq(_changeState(c), VRC.CH_SCHEDULED, "binding rolled back");
            _assertUnlocked();
            vm.revertToState(snap);
        }
    }

    function test_electNonFreshResultIdIsAFault() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _recRejected(r, VRC.REJ_EXPIRED);
        _recClosed(r);
        _applyAll();
        assertEq(_moduleReserve(r, true), VRC.ELECT_NO_CANDIDATE, "a reused id is not fresh");
        assertEq(vr.health(), VRC.FAULTED);
        assertEq(
            _moduleReserve(VRC.GENESIS_RESULT, true),
            VRC.ELECT_NOT_DUE,
            "faulted: native path, nothing due"
        );
    }

    function test_electGriefAtTheCapStillCompletes() public {
        module.setMode(S_ELECT, GRIEF);
        uint256 g0 = gasleft();
        assertEq(_elect(), VRC.ELECT_NOT_DUE, "the module used its whole cap and answered");
        uint256 used = g0 - gasleft();
        assertEq(vr.health(), VRC.HEALTHY);
        assertLt(used, 3_000_000 + 2_600_000 + 1_000_000, "bounded by the step budget");
    }

    function test_electBurnIsBoundedByTheCap() public {
        module.setMode(S_ELECT, BURN);
        uint256 g0 = gasleft();
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE);
        uint256 used = g0 - gasleft();
        // the module had min(electGas 3,000,000, CAP_ELECT) gas; VR's outer frame finished within its reserve
        assertLt(used, 3_000_000 + 200_000, "VR never forwards more than the cap");
        assertGt(used, 3_000_000, "the module consumed its cap");
    }

    function test_hugeReturnIsNeverCopied() public {
        module.setMode(S_ELECT, HUGE);
        uint256 g0 = gasleft();
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE, "a 1 MiB return is Oversize");
        uint256 used = g0 - gasleft();
        assertEq(vr.health(), VRC.FAULTED);
        // the module paid ~2.2M for its own memory; copying 1 MiB into VR would cost another ~2.2M
        assertLt(used, 2_700_000, "VR did not copy the return");
    }

    function test_electBudgetShortIsDisabledWithoutHealthChange() public {
        vm.prank(VRC.SYSTEM_CALLER);
        vm.recordLogs();
        uint8 outcome = vr.elect{gas: 1_000_000}(bytes32(uint256(1)));
        assertEq(outcome, VRC.ELECT_DISABLED, "too little gas: outcome 0");
        assertEq(vr.health(), VRC.HEALTHY, "no health change");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool short;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] == keccak256("StepBudgetShort(uint8,uint256,uint256)")) {
                short = true;
            }
        }
        assertTrue(short, "BudgetShort event");
        _assertUnlocked();
    }

    // ---------------------------------------------------------------------------------------------
    // reentrancy
    // ---------------------------------------------------------------------------------------------

    function test_reentryIntoEveryMutatorIsRefusedFromElect() public {
        module.setMode(S_ELECT, REENTER);
        assertEq(_elect(), VRC.ELECT_NOT_DUE, "the module's own frame survives its refused calls");
        assertEq(module.reentryAttempts(), 12);
        assertEq(module.reentryRefusals(), 12, "every re-entrant mutator call was refused");
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_reentryFromRecordsAndResolvedIsRefused() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        module.setMode(S_RECORDS, REENTER);
        module.setMode(S_RESOLVED, REENTER);
        _acknowledge(r, 0);
        assertEq(_state(r), VRC.OUT_ACKNOWLEDGED);
        assertEq(module.reentryAttempts(), 24);
        assertEq(module.reentryRefusals(), 24);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_reentryFromGovernanceIsRefused() public {
        module.setMode(S_GOV, REENTER);
        uint64 id = _queue(VRC.K_MODULE_ACTION, abi.encode(address(module), bytes("admit")));
        _passDelays();
        vr.execute(id);
        assertEq(_changeState(id), VRC.CH_ACTIVE);
        assertEq(module.reentryRefusals(), module.reentryAttempts());
    }

    function test_bubbledReentryIsAFault() public {
        module.setMode(S_ELECT, REENTER_BUBBLE);
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_invalidateIsLockExemptDuringAStep() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED);
        module.setMode(S_RECORDS, INVALIDATE_OPEN);
        _closure(0);
        _applyAll();
        assertTrue(module.invalidatedInStep(), "invalidate works under VR's lock");
        assertEq(_state(r), VRC.OUT_INVALIDATED);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_stepsAreSelfOnly() public {
        vm.expectRevert(VRShared.NotSelf.selector);
        vr.stepVoid(address(module), 1000, "");
        vm.expectRevert(VRShared.NotSelf.selector);
        vr.stepElect(new bytes(256));
        vm.expectRevert(VRShared.NotSelf.selector);
        vr.stepPublish(bytes32(0));
        vm.expectRevert(VRShared.NotSelf.selector);
        vr.stepAdoption(address(module), 1000, "");
        vm.expectRevert(VRShared.NotSystemCaller.selector);
        vr.elect(bytes32(0));
        vm.expectRevert(VRShared.NotSystemCaller.selector);
        vr.applyRootRecords(1);
    }

    // ---------------------------------------------------------------------------------------------
    // publish and fault attribution
    // ---------------------------------------------------------------------------------------------

    function test_hundredEarlyPublishesLeaveHealthUnchanged() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED);
        module.setOutputStatus(VRC.STATUS_PENDING);
        for (uint256 i = 0; i < 100; ++i) {
            assertEq(vr.publish(r), VRC.PUB_PENDING);
        }
        assertEq(vr.publish(_rid("unknown")), VRC.PUB_NOT_MINE, "unknown id");
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(_state(r), VRC.OUT_RESERVED);
        // a low-gas publish is BudgetShort, never a fault
        module.setOutputStatus(VRC.STATUS_READY);
        vm.expectRevert(abi.encodeWithSelector(VRShared.BudgetShort.selector, uint8(2)));
        vr.publish{gas: 500_000}(r);
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(vr.publish(r), VRC.PUB_PUBLISHED);
        assertEq(vr.publish(r), VRC.PUB_PRECONDITION_FAILED, "already published: no-op");
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_publishStepFailuresFault() public {
        uint8[5] memory modes = [REVERT, BURN, MALFORMED, HUGE, GRIEF];
        for (uint256 i = 0; i < modes.length; ++i) {
            uint256 snap = vm.snapshotState();
            bytes32 r = _rid("R");
            uint64 c = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
            assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED);
            module.setMode(S_OUTPUT, modes[i]);
            module.setGriefLeave(400_000); // GRIEF: burn the cap down to what building the answer needs
            uint8 st = vr.publish(r);
            if (modes[i] == GRIEF) {
                assertEq(st, VRC.PUB_PUBLISHED, "a valid answer at the cap is not a fault");
            } else {
                assertEq(st, VRC.PUB_PRECONDITION_FAILED);
                assertEq(vr.health(), VRC.FAULTED);
                assertEq(_state(r), VRC.OUT_RESERVED, "the output is untouched");
                assertEq(_changeState(c), VRC.CH_BOUND, "its bindings are untouched");
                _assertUnlocked();
            }
            vm.revertToState(snap);
        }
    }

    function _invalidReady(uint256 variant) internal {
        Member[] memory ms = _members();
        if (variant == 0) ms[0].weight = 2; // not the quantized weight
        if (variant == 1) ms[1].id = 99; // unknown identity (still ascending)
        if (variant == 2) ms[2].generation = 2; // no staged binding for generation + 1
        if (variant == 3) ms[3].payee = address(0xdead); // binding words differ
        if (variant == 4) ms[0].rawWeight = 0;
        if (variant == 5) {
            // continuity: two of five replaced at once (3 * 2 >= 5)
            ms = _without(_without(ms, 4), 5);
        }
        if (variant != 6 && variant != 7) module.setMembers(ms);
        if (variant == 6) module.setOverrides(_rid("other"), 0);
        if (variant == 7) module.setOverrides(0, _rid("not the predecessor"));
    }

    function test_fundedInvalidReadyIsFaulted() public {
        for (uint256 v = 0; v < 8; ++v) {
            uint256 snap = vm.snapshotState();
            bytes32 r = _rid("R");
            assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED);
            _invalidReady(v);
            assertEq(vr.publish(r), VRC.PUB_PRECONDITION_FAILED, vm.toString(v));
            assertEq(vr.health(), VRC.FAULTED, vm.toString(v));
            assertEq(_state(r), VRC.OUT_RESERVED, vm.toString(v));
            vm.revertToState(snap);
        }
    }

    function test_limitsMustHoldOrMoveTowardTheRange() public {
        // limits 6..7 with five members: an output of 5 does not move toward the range
        uint64 c = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(6, 6, 7));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _acknowledge(r, 0);
        assertEq(_changeState(c), VRC.CH_ACTIVE);
        assertEq(vr.config().nMin, 6);
        bytes32 r2 = _rid("R2");
        module.setElect(VRC.ELECT_RESERVED, false, r2);
        assertEq(_elect(), VRC.ELECT_RESERVED);
        assertEq(vr.publish(r2), VRC.PUB_PRECONDITION_FAILED, "|S| = |O| = 5 < nMin: refused");
        assertEq(vr.health(), VRC.FAULTED);
    }

    // ---------------------------------------------------------------------------------------------
    // records and resolution
    // ---------------------------------------------------------------------------------------------

    function test_recordsStepFailuresNeverStopTheCursor() public {
        uint8[7] memory modes =
            [REVERT, BURN, MALFORMED, HUGE, REENTER_BUBBLE, WRITE_THEN_REVERT, RETURN_WORD];
        for (uint256 i = 0; i < modes.length; ++i) {
            uint256 snap = vm.snapshotState();
            module.setMode(S_RECORDS, modes[i]);
            for (uint64 k = 0; k < 5; ++k) {
                _closure(k);
            }
            _apply(5);
            assertEq(vr.recordCursor(), 5, "cursor += exactly min(max, available)");
            assertEq(vr.health(), VRC.FAULTED);
            _assertUnlocked();
            vm.revertToState(snap);
        }
    }

    function test_resolvedStepFailureStillReleases() public {
        uint64 c = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        module.setMode(S_RESOLVED, REVERT);
        _acknowledge(r, 0);
        assertEq(_state(r), VRC.OUT_ACKNOWLEDGED);
        assertEq(_changeState(c), VRC.CH_ACTIVE, "release happened");
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_anomalyWhilePublishedThenFailingCallbackKeepsInconsistent() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _recBoundary(r, _nextEpoch(), false, 0); // a Boundary without its pair
        _applyAll();
        assertEq(vr.health(), VRC.INCONSISTENT);
        module.setMode(S_RECORDS, REVERT);
        module.setMode(S_RESOLVED, REVERT);
        _acknowledge(r, 0); // the committed pair still completes
        assertEq(_state(r), VRC.OUT_ACKNOWLEDGED);
        assertEq(vr.health(), VRC.INCONSISTENT, "a fault never overwrites Inconsistent");
        assertEq(_elect(), VRC.ELECT_DISABLED);
    }

    /// @dev astra VT-02 finding 6: a fully funded failing onGovernance rejects the action and faults the module.
    function test_governanceStepFailureIsRejectedAndFaulted() public {
        uint8[4] memory modes = [REVERT, BURN, HUGE, RETURN_WORD];
        for (uint256 i = 0; i < modes.length; ++i) {
            uint256 snap = vm.snapshotState();
            module.setMode(S_GOV, modes[i]);
            uint64 id = _queue(VRC.K_MODULE_ACTION, abi.encode(address(module), bytes("x")));
            _passDelays();
            vr.execute(id);
            assertEq(_changeState(id), VRC.CH_REJECTED);
            assertEq(vr.change(id).rejectReason, VRC.R_ACTION_FAILED);
            assertEq(vr.health(), VRC.FAULTED, "a funded step failure is a module fault");
            _assertUnlocked();
            vm.revertToState(snap);
        }
    }

    function test_governanceBudgetShortReverts() public {
        uint64 id = _queue(VRC.K_MODULE_ACTION, abi.encode(address(module), bytes("x")));
        _passDelays();
        vm.expectRevert(abi.encodeWithSelector(VRShared.BudgetShort.selector, uint8(7)));
        vr.execute{gas: 200_000}(id);
        assertEq(_changeState(id), VRC.CH_QUEUED);
    }

    function _closure(uint64 k) internal {
        seal.push(
            VRC.REC_CLOSURE,
            abi.encode(
                keccak256(abi.encode("assignment", k)),
                uint256(1),
                bytes32(uint256(2)),
                bytes32(uint256(3)),
                bytes32(uint256(4)),
                bytes32(uint256(5))
            )
        );
    }
}
