// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Vm} from "forge-std/Test.sol";
import {VRBase} from "./VRBase.sol";
import {FastJson} from "./FastJson.sol";
import {MockModule, MockHolder} from "./VRMocks.sol";
import {VRShared} from "../../src/vr/VRShared.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {VRChanges} from "../../src/vr/VRChanges.sol";

/// @notice Drives the real ValidatorRegistry through the frozen state-machine traces of schema v1 (bft-core
/// testvectors/validator-registry/statemachine.json, generated from vrschema/vrmodel.go): the design 3.4.2 output table (every
/// state x event cell), the change lifecycle, the S2a VR steps and the pointer-switch order. Each trace step's VR actor is executed
/// against VR (root-actor steps only produce the records a later VR step imports); after every step the VR snapshot the vector asserts
/// (outputs, changes with their release counts, openOutput, pendingPair, lastAcked, health, cursor), the step's refusal and its effects
/// (record anomalies and `onResolved` calls) are compared.
///
/// Two model inputs have no VR call: `reserveNative` sets health Faulted and `sinceEpochStart` sets the epoch's first ordinary progress.
/// The harness writes those two fields directly (`_setHealth`, `_setEpochStart`); everything else goes through VR's public interface.
contract VRStateMachineTest is VRBase, FastJson {
    string internal constant FILE = "/test/vr/fixtures/statemachine.json";
    string[] internal ops;

    // per-vector harness state
    mapping(bytes32 => string) internal nameOf;
    mapping(bytes32 => bytes32) internal ridOf; // keccak(name) => rid
    string[] internal names;
    mapping(uint64 => uint256) internal released;
    uint64 internal baseP;
    uint64 internal baseT;
    string internal vname;
    uint256 internal vectorsRun;
    bool internal governanceFaulted; // set once the ModuleAction vector's failing onGovernance has run

    bytes32 internal constant RELEASED_TOPIC =
        keccak256("ChangeReleased(uint64,bytes32,uint8,uint8)");
    bytes32 internal constant ANOMALY_TOPIC = keccak256("RecordAnomaly(uint64,uint8,uint8)");

    function setUp() public {
        _setUpVR(5, 1, 5, 16);
        baseP = progress;
        baseT = ucTime;
    }

    // =============================================================================================
    // entry points
    // =============================================================================================

    /// @dev The vector document is loaded into this call's memory once per test function (FastJson).
    function _load() internal {
        _jload(string.concat(vm.projectRoot(), FILE));
        ops = _jsarr(".vectors[*].op");
    }

    function test_outputTable() public {
        _load();
        assertEq(_runOps("output.table"), 74, "output.table vector count");
    }

    function test_changeLifecycle() public {
        _load();
        assertEq(_runOps("change.lifecycle"), 4, "change.lifecycle vector count");
    }

    function test_s2aVrSteps() public {
        _load();
        uint256 n = _runOps("s2a.lapse") + _runOps("s2a.rejectFirst") + _runOps("s2a.prepareFirst")
            + _runOps("s2a.success") + _runOps("s2a.abort") + _runOps("s2a.cursorGate")
            + _runOps("s2a.inconsistent") + _runOps("s2a.native");
        assertEq(n, 13, "s2a.* vector count");
    }

    function test_switchSequence() public {
        _load();
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "switch.sequence")) continue;
            uint256 snap = vm.snapshotState();
            _switchVector(i);
            vm.revertToState(snap);
            ++n;
        }
        assertEq(n, 5, "switch.sequence vector count");
    }

    function _runOps(string memory op) internal returns (uint256 n) {
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], op)) continue;
            uint256 snap = vm.snapshotState();
            _runTrace(i);
            vm.revertToState(snap);
            ++n;
        }
    }

    // =============================================================================================
    // trace interpreter
    // =============================================================================================

    function _runTrace(uint256 i) internal {
        vname = _js(_p(i, ".name"));
        uint256 steps = _ju(_p(i, ".input.steps"));
        delete names;
        governanceFaulted = false;
        for (uint256 s = 0; s < steps; ++s) {
            string memory sp =
                string.concat(".vectors[", vm.toString(i), "].expect.trace[", vm.toString(s), "]");
            string memory actor = _js(string.concat(sp, ".actor"));
            if (_is(actor, "root")) continue; // root-only steps; their records arrive through a later VR step
            string memory op = _js(string.concat(sp, ".op"));
            uint256 resolvedBefore = _resolvedCalls();
            vm.recordLogs();
            _step(sp, op);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            _checkEffects(sp, op, logs, resolvedBefore);
            _checkState(sp, op);
        }
        ++vectorsRun;
    }

    function _step(string memory sp, string memory op) internal {
        string memory a = string.concat(sp, ".args");
        string memory want = _js(string.concat(sp, ".error"));
        if (_is(op, "state")) return _setupState(_js(string.concat(a, ".state")));
        if (_is(op, "queue+execute")) {
            uint64 id = uint64(_ju(string.concat(a, ".id")));
            uint8 kind = uint8(_ju(string.concat(a, ".kind")));
            assertEq(_queue(kind, _payload(kind, id)), id, _m("queue id"));
            _passDelays();
            vr.execute(id);
            return;
        }
        if (_is(op, "queue")) return _queueStep(a, want);
        if (_is(op, "execute")) return _executeStep(a, want);
        if (_is(op, "cancel")) return _cancelStep(a, want);
        if (_is(op, "reserve")) {
            bytes32 rid = _name(_js(string.concat(a, ".result")));
            uint8 outcome = _moduleReserve(rid, false);
            if (bytes(want).length == 0) assertEq(outcome, VRC.ELECT_RESERVED, _m("reserve"));
            else assertTrue(outcome != VRC.ELECT_RESERVED && _state(rid) == 0, _m(want));
            return;
        }
        if (_is(op, "reserveNative")) return _reserveNative(a, want);
        if (_is(op, "publish") && _jhas(string.concat(a, ".result"))) {
            bytes32 rid = _name(_js(string.concat(a, ".result")));
            uint8 st = vr.publish(rid);
            if (bytes(want).length == 0) assertEq(st, VRC.PUB_PUBLISHED, _m("publish"));
            else assertEq(st, VRC.PUB_PRECONDITION_FAILED, _m(want));
            return;
        }
        if (_is(op, "invalidate")) {
            bytes32 rid = _name(_js(string.concat(a, ".result")));
            module.invalidate(rid, uint8(_ju(string.concat(a, ".reason"))));
            return;
        }
        if (_is(op, "import") || _is(op, "applyRootRecords")) return _recordsStep(a);
        if (_is(op, "redeliver")) {
            // a replayed index is never re-applied: the cursor is already past it
            assertLt(_ju(string.concat(a, ".index")), vr.recordCursor(), _m("replay"));
            return;
        }
        // output.table events
        _eventStep(op, a, want);
    }

    // ---- setup of an output.table cell (vrschema genOutputTable) ----

    function _setupState(string memory st) internal {
        if (_is(st, "Unknown")) {
            _name("R");
            return;
        }
        bytes32 r = _name("R");
        assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED, _m("setup reserve"));
        if (_is(st, "Reserved")) return;
        assertEq(vr.publish(r), VRC.PUB_PUBLISHED, _m("setup publish"));
        if (_is(st, "Invalidated")) {
            module.invalidate(r, VRC.INVALID_WITHDRAWN);
        } else if (_is(st, "Rejected") || _is(st, "Closed")) {
            _recRejected(r, VRC.REJ_EXPIRED);
            _applyAll();
            if (_is(st, "Closed")) {
                _recClosed(r);
                _applyAll();
            }
        } else if (_is(st, "Acknowledged") || _is(st, "Recovered")) {
            bool rec = _is(st, "Recovered");
            if (rec) _recRecoveryAck(r);
            else _recAck(r);
            _recBoundary(r, vr.config().knownRootEpoch + 1, rec, 0);
            _applyAll();
        }
    }

    function _eventStep(string memory op, string memory a, string memory want) internal {
        bytes32 r = _name("R");
        if (_is(op, "invalidateBySource") || _is(op, "invalidateReason0")) {
            uint8 reason = _is(op, "invalidateReason0") ? 0 : VRC.INVALID_WITHDRAWN;
            bool got = module.invalidate(r, reason);
            assertEq(got, _jbool(string.concat(a, ".return")), _m(op));
        } else if (_is(op, "invalidateByOther")) {
            if (_is(want, "NotSource")) {
                vm.expectRevert(VRShared.NotSource.selector);
                vr.invalidate(r, VRC.INVALID_WITHDRAWN);
            } else {
                assertEq(
                    vr.invalidate(r, VRC.INVALID_WITHDRAWN),
                    _jbool(string.concat(a, ".return")),
                    _m(op)
                );
            }
        } else if (_is(op, "publish")) {
            assertEq(vr.publish(r), _ju(string.concat(a, ".return")), _m(op));
        } else if (_is(op, "OutputRejected")) {
            _recRejected(r, VRC.REJ_EXPIRED);
            _apply(1);
        } else if (_is(op, "SessionClosed")) {
            _recClosed(r);
            _apply(1);
        } else if (_is(op, "Ack")) {
            _recAck(r);
            _apply(1);
        } else if (_is(op, "RecoveryAck")) {
            _recRecoveryAck(r);
            _apply(1);
        } else if (_is(op, "BoundaryWithPair") || _is(op, "BoundaryWithoutPair")) {
            _recBoundary(r, vr.config().knownRootEpoch + 1, false, 0);
            _apply(1);
        } else {
            revert(string.concat("unhandled op ", op));
        }
    }

    // ---- governance steps ----

    function _payload(uint8 kind, uint64 id) internal view returns (bytes memory) {
        if (kind == VRC.K_COMMITTEE_LIMITS) return abi.encode(uint32(1), uint32(5), uint32(16));
        if (kind == VRC.K_SCHEDULE_ACTIVATION) {
            return abi.encode(
                keccak256(abi.encode("unicity.rule/vector", id)),
                keccak256("release"),
                uint64(vr.config().knownRootEpoch + 3),
                uint64(ucTime + VRC.DELAY_SECONDS),
                "vector"
            );
        }
        if (kind == VRC.K_FORCE_REMOVE) return abi.encode(uint64(5));
        revert("no default payload");
    }

    function _queueStep(string memory a, string memory want) internal {
        if (_jhas(string.concat(a, ".pending"))) {
            uint256 k = _ju(string.concat(a, ".pending"));
            for (uint256 j = 0; j < k; ++j) {
                _queue(VRC.K_COMMITTEE_LIMITS, _payload(VRC.K_COMMITTEE_LIMITS, 0));
            }
            vm.prank(governor);
            vm.expectRevert(
                abi.encodeWithSelector(VRShared.QueueRefused.selector, VRChanges.TOO_MANY_PENDING)
            );
            vr.queue(VRC.K_COMMITTEE_LIMITS, _payload(VRC.K_COMMITTEE_LIMITS, 0));
            assertEq(want, "TooManyPending");
            return;
        }
        _clock(a);
        uint8 kind = uint8(_ju(string.concat(a, ".kind")));
        uint64 id = uint64(_ju(string.concat(a, ".id")));
        assertEq(_queue(kind, _payload(kind, id)), id, _m("queue id"));
    }

    function _executeStep(string memory a, string memory want) internal {
        uint64 id = uint64(_ju(string.concat(a, ".id")));
        if (_jhas(string.concat(a, ".case"))) {
            string memory c = _js(string.concat(a, ".case"));
            address target = _is(c, "not the active module") ? address(0xBEEF) : address(module);
            module.setMode(7, _is(c, "active, onGovernance fails") ? 1 : 0);
            if (_is(c, "active, onGovernance fails")) governanceFaulted = true;
            assertEq(
                _queue(VRC.K_MODULE_ACTION, abi.encode(target, abi.encode(uint64(1), uint64(1)))),
                id
            );
            _passDelays();
            vr.execute(id);
            module.setMode(7, 0);
            return;
        }
        _clock(a);
        if (_is(want, "DelayNotElapsed")) {
            vm.expectRevert(VRShared.DelayNotElapsed.selector);
        } else if (bytes(want).length != 0) {
            revert(string.concat("unmapped execute error ", want));
        }
        vr.execute(id);
    }

    function _cancelStep(string memory a, string memory want) internal {
        uint64 id = uint64(_ju(string.concat(a, ".id")));
        if (_changeState(id) == VRC.CH_NONE) {
            assertEq(_queue(VRC.K_COMMITTEE_LIMITS, _payload(VRC.K_COMMITTEE_LIMITS, id)), id);
        }
        vm.prank(governor);
        if (_is(want, "NotCancellable")) vm.expectRevert(VRShared.NotCancellable.selector);
        vr.cancel(id);
    }

    function _clock(string memory a) internal {
        if (!_jhas(string.concat(a, ".progress"))) return;
        progress = baseP + uint64(_ju(string.concat(a, ".progress")));
        ucTime = baseT + uint64(_ju(string.concat(a, ".ucTime")));
        seal.setClock(progress, ucTime);
    }

    // ---- native repair ----

    function _reserveNative(string memory a, string memory want) internal {
        _setHealth(VRC.FAULTED);
        if (_jhas(string.concat(a, ".sinceEpochStart"))) {
            _setEpochStart(progress - uint64(_ju(string.concat(a, ".sinceEpochStart"))));
        }
        uint8 outcome = _elect();
        if (bytes(want).length == 0) {
            assertEq(outcome, VRC.ELECT_RESERVED, _m("reserveNative"));
            bytes32 n = vr.openOutput();
            nameOf[n] = "N";
            ridOf[keccak256("N")] = n;
            names.push("N");
        } else {
            assertTrue(outcome != VRC.ELECT_RESERVED, _m(want));
        }
    }

    function _setHealth(uint8 h) internal {
        bytes32 slot = bytes32(uint256(VRC.NAMESPACE) + 6);
        uint256 w = uint256(vm.load(VR_ADDR, slot));
        vm.store(VR_ADDR, slot, bytes32((w & ~uint256(0xff)) | h));
    }

    function _setEpochStart(uint64 p) internal {
        bytes32 slot = bytes32(uint256(VRC.NAMESPACE) + 22);
        uint256 w = uint256(vm.load(VR_ADDR, slot));
        uint256 mask = uint256(type(uint64).max) << 80;
        vm.store(VR_ADDR, slot, bytes32((w & ~mask) | (uint256(p) << 80)));
        assertEq(vr.config().epochStartProgress, p);
    }

    // ---- records ----

    function _recordsStep(string memory a) internal {
        (bool some, uint256[] memory kinds) = _juarrTry(string.concat(a, ".imported"));
        if (some) {
            bytes32 r = _jhas(string.concat(a, ".result"))
                ? _name(_js(string.concat(a, ".result")))
                : vr.openOutput();
            uint16 bitmap = 0;
            if (_jhas(string.concat(a, ".rejectedBitmap"))) {
                bitmap = uint16(_ju(string.concat(a, ".rejectedBitmap")));
            }
            bool recovered = false;
            for (uint256 k = 0; k < kinds.length; ++k) {
                uint8 kind = uint8(kinds[k]);
                if (kind == VRC.REC_ACK) {
                    _recAck(r);
                } else if (kind == VRC.REC_RECOVERY_ACK) {
                    _recRecoveryAck(r);
                    recovered = true;
                } else if (kind == VRC.REC_BOUNDARY) {
                    _recBoundary(r, vr.config().knownRootEpoch + 1, recovered, bitmap);
                } else if (kind == VRC.REC_SESSION_CLOSED) {
                    _recClosed(r);
                } else if (kind == VRC.REC_OUTPUT_REJECTED) {
                    _recRejected(r, VRC.REJ_EXPIRED);
                } else {
                    revert("unhandled record kind");
                }
            }
            if (!_jhas(string.concat(a, ".apply"))) {
                _apply(uint32(kinds.length));
                return;
            }
        }
        uint256 n = _ju(string.concat(a, ".apply"));
        if (n > 0) _apply(uint32(n));
    }

    // =============================================================================================
    // assertions
    // =============================================================================================

    function _resolvedCalls() internal view returns (uint256 c) {
        uint256 n = module.logLength();
        for (uint256 i = 0; i < n; ++i) {
            if (_starts(module.log(i), "onResolved:")) ++c;
        }
    }

    function _checkEffects(
        string memory sp,
        string memory op,
        Vm.Log[] memory logs,
        uint256 resolvedBefore
    ) internal {
        uint256 wantAnomaly;
        uint256 wantResolved;
        string memory ep = string.concat(sp, ".effects");
        (bool some, string[] memory eff) = _jsarrTry(ep); // null: no effects
        if (_is(op, "state")) some = false; // the setup's own effects are not part of the cell (vrschema resets them)
        for (uint256 k = 0; some && k < eff.length; ++k) {
            if (_starts(eff[k], "RecordAnomaly(")) ++wantAnomaly;
            if (_starts(eff[k], "onResolved(")) ++wantResolved;
        }
        uint256 gotAnomaly;
        for (uint256 k = 0; k < logs.length; ++k) {
            if (logs[k].emitter != VR_ADDR) continue;
            if (logs[k].topics[0] == ANOMALY_TOPIC) ++gotAnomaly;
            if (logs[k].topics[0] == RELEASED_TOPIC) {
                ++released[uint64(uint256(logs[k].topics[1]))];
            }
        }
        if (_is(op, "state")) return;
        assertEq(gotAnomaly, wantAnomaly, _m(string.concat(op, ": anomalies")));
        assertEq(
            _resolvedCalls() - resolvedBefore,
            wantResolved,
            _m(string.concat(op, ": onResolved calls"))
        );
    }

    function _checkState(string memory sp, string memory op) internal view {
        string memory st = string.concat(sp, ".state");
        // outputs
        string[] memory outs = _jkeys(string.concat(st, ".outputs"));
        for (uint256 k = 0; k < names.length; ++k) {
            string memory want = "None";
            for (uint256 j = 0; j < outs.length; ++j) {
                if (_is(outs[j], names[k])) {
                    want = _js(string.concat(st, ".outputs.", outs[j]));
                }
            }
            assertEq(
                _outName(_state(ridOf[keccak256(bytes(names[k]))])),
                want,
                _m(string.concat(op, ": output ", names[k]))
            );
        }
        // changes
        string[] memory chs = _jkeys(string.concat(st, ".changes"));
        for (uint256 k = 0; k < chs.length; ++k) {
            uint64 id = uint64(vm.parseUint(chs[k]));
            string memory want = _js(string.concat(st, ".changes.", chs[k]));
            assertEq(_changeName(id), want, _m(string.concat(op, ": change ", chs[k])));
        }
        assertEq(
            _nm(vr.openOutput()),
            _js(string.concat(st, ".openOutput")),
            _m(string.concat(op, ": openOutput"))
        );
        assertEq(
            _nm(vr.pendingPair()),
            _js(string.concat(st, ".pendingPair")),
            _m(string.concat(op, ": pendingPair"))
        );
        assertEq(
            _nm(vr.lastAcked()),
            _js(string.concat(st, ".lastAcked")),
            _m(string.concat(op, ": lastAcked"))
        );
        uint256 wantHealth = _ju(string.concat(st, ".health"));
        // Documented deviation (astra VT-02 finding 6): a fully funded failing onGovernance is a module fault (design 3.3.1). The
        // reference model's Execute does not model health (schema 14: a model's silence waives nothing), so the vector keeps 0 here.
        if (governanceFaulted) wantHealth = VRC.FAULTED;
        assertEq(vr.health(), wantHealth, _m(string.concat(op, ": health")));
        assertEq(
            vr.recordCursor(), _ju(string.concat(st, ".cursor")), _m(string.concat(op, ": cursor"))
        );
    }

    function _changeName(uint64 id) internal view returns (string memory) {
        string[7] memory sn =
            ["None", "Queued", "Scheduled", "Bound", "Active", "Rejected", "Cancelled"];
        (uint8 s, uint8 reason) = (vr.change(id).state, vr.change(id).rejectReason);
        string memory v = sn[s];
        if (reason != 0) v = string.concat(v, "(", _verdictName(reason), ")");
        return string.concat(v, " released=", vm.toString(released[id]));
    }

    function _verdictName(uint8 r) internal pure returns (string memory) {
        if (r == 1) return "Conflict";
        if (r == 16) return "CodeMismatch";
        if (r == 17) return "HolderMismatch";
        if (r == 18) return "AdoptionNotReady";
        if (r == 19) return "ActionFailed";
        if (r == 20) return "NotActive";
        if (r == 21) return "HolderCeiling";
        return vm.toString(r);
    }

    function _outName(uint8 s) internal pure returns (string memory) {
        string[8] memory n = [
            "None",
            "Reserved",
            "Published",
            "Invalidated",
            "Rejected",
            "Acknowledged",
            "Recovered",
            "Closed"
        ];
        return n[s];
    }

    function _nm(bytes32 w) internal view returns (string memory) {
        if (w == 0) return "";
        if (w == VRC.GENESIS_RESULT) return "GENESIS_RESULT";
        return nameOf[w];
    }

    function _name(string memory n) internal returns (bytes32 r) {
        r = ridOf[keccak256(bytes(n))];
        if (r != 0) return r;
        r = keccak256(abi.encode("result/", n));
        ridOf[keccak256(bytes(n))] = r;
        nameOf[r] = n;
        names.push(n);
    }

    // =============================================================================================
    // switch.sequence (design 3.6.1)
    // =============================================================================================

    function _switchVector(uint256 i) internal {
        vname = _js(_p(i, ".name"));
        string memory in_ = _p(i, ".input");
        uint64 from = uint64(_ju(string.concat(in_, ".from")));
        uint64 count = uint64(_ju(string.concat(in_, ".count")));
        uint64 bAt = uint64(_ju(string.concat(in_, ".boundaryAt")));
        bool codeOK = _jbool(string.concat(in_, ".codeOK"));
        bool adoptOK = _jbool(string.concat(in_, ".adoptionReady"));
        bool attachOK = _jbool(string.concat(in_, ".attachOK"));
        bool holder = _jbool(string.concat(in_, ".liabilityHolder"));

        MockModule next = new MockModule(keccak256("unicity.vr.next-module"));
        next.setVR(VR_ADDR);
        MockHolder h = new MockHolder();
        next.setCaps(VRC.CAP_ADOPTION_CHECK | (holder ? VRC.CAP_LIABILITY_HOLDER : 0));
        if (holder) next.setHolder(address(h));
        next.setAdoption(adoptOK ? VRC.STATUS_READY : VRC.STATUS_NOT_READY);
        if (!attachOK) next.setMode(5, 1);
        uint64 cid = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(next), address(next).codehash, bytes("init"))
        );
        bytes32 r = keccak256("switch/R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        assertEq(_changeState(cid), VRC.CH_BOUND);
        if (!codeOK) vm.etch(address(next), address(new MockHolder()).code);

        // records before the batch: fillers (Closure) up to `from`, with the Ack right before the Boundary
        for (uint64 k = 0; k < from; ++k) {
            if (k + 1 == bAt) _recAck(r);
            else _closure(k);
        }
        _applyAll();
        module.clearLog();
        uint8 holdersBefore = vr.holderCount();
        for (uint64 k = from; k < from + count; ++k) {
            if (k + 1 == bAt) _recAck(r);
            else if (k == bAt) _recBoundary(r, vr.config().knownRootEpoch + 1, false, 0);
            else _closure(k);
        }
        _apply(uint32(count));

        bool refused = !codeOK || !adoptOK;
        string memory st = _p(i, ".expect.steps");
        uint256 nsteps = _jsarr(string.concat(st, "[*].step")).length;
        for (uint256 s = 0; s < nsteps; ++s) {
            string memory e = string.concat(st, "[", vm.toString(s), "]");
            string memory step = _js(string.concat(e, ".step"));
            if (_is(step, "reject")) {
                assertEq(_changeState(cid), VRC.CH_REJECTED, _m("reject"));
                assertEq(
                    vr.change(cid).rejectReason,
                    codeOK ? VRC.R_ADOPTION_NOT_READY : VRC.R_CODE_MISMATCH,
                    _m("reason")
                );
                assertEq(vr.activeModule().module, address(module), _m("old module stays"));
            } else if (_is(step, "onRecords")) {
                bool old = _is(_js(string.concat(e, ".module")), "old");
                string memory want = string.concat(
                    "onRecords:",
                    vm.toString(_ju(string.concat(e, ".from"))),
                    ":",
                    vm.toString(_ju(string.concat(e, ".count")))
                );
                MockModule m = old ? module : next;
                assertTrue(_logged(m, want), _m(string.concat(old ? "old " : "new ", want)));
            } else if (_is(step, "detach")) {
                assertTrue(_logged(module, "detach"), _m("detach"));
            } else if (_is(step, "setPointer")) {
                assertEq(vr.activeModule().module, address(next), _m("pointer"));
                assertEq(_changeState(cid), VRC.CH_ACTIVE, _m("SetModule active"));
            } else if (_is(step, "attach")) {
                assertTrue(_logged(next, "attach") || !attachOK, _m("attach"));
            } else if (_is(step, "allocateHolder")) {
                assertEq(vr.holderCount(), holdersBefore + 1, _m("holder allocated"));
                assertEq(vr.holderAt(holdersBefore).holder, address(h), _m("holder entry"));
            } else if (_is(step, "fault")) {
                assertEq(vr.health(), VRC.FAULTED, _m("attach failure faults"));
            }
        }
        // the converse assertions: what the sequence omits did not happen
        if (refused) {
            assertFalse(_logged(module, "detach"), _m("no detach on a refused switch"));
            assertEq(
                _countPrefix(module, "onRecords:"), 1, _m("old module gets the whole batch once")
            );
        }
        if (!attachOK || !holder || refused) {
            assertEq(vr.holderCount(), holdersBefore, _m("no holder entry"));
        }
        if (attachOK && !refused) {
            assertEq(vr.health(), VRC.HEALTHY, _m("attached module healthy"));
        }
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

    function _countPrefix(MockModule m, string memory prefix) internal view returns (uint256 c) {
        uint256 n = m.logLength();
        for (uint256 i = 0; i < n; ++i) {
            if (_starts(m.log(i), prefix)) ++c;
        }
    }

    function _logged(MockModule m, string memory entry) internal view returns (bool) {
        uint256 n = m.logLength();
        for (uint256 i = 0; i < n; ++i) {
            if (_is(m.log(i), entry)) return true;
        }
        return false;
    }

    // ---- small helpers ----

    function _p(uint256 i, string memory rel) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(i), "]", rel);
    }

    function _is(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _starts(string memory a, string memory prefix) internal pure returns (bool) {
        bytes memory x = bytes(a);
        bytes memory p = bytes(prefix);
        if (x.length < p.length) return false;
        for (uint256 i = 0; i < p.length; ++i) {
            if (x[i] != p[i]) return false;
        }
        return true;
    }

    function _m(string memory what) internal view returns (string memory) {
        return string.concat(vname, ": ", what);
    }
}
