// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "./VRBase.sol";
import {MockModule, MockHolder} from "./VRMocks.sol";
import {VRShared} from "../../src/vr/VRShared.sol";
import {VRChanges} from "../../src/vr/VRChanges.sol";
import {VRCodec} from "../../src/vr/VRCodec.sol";
import {ValidatorRegistry} from "../../src/vr/ValidatorRegistry.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {Member, Binding, Registration, IdentityView} from "../../src/vr/VRTypes.sol";

/// @notice Regressions for the VT-02 review findings (briefs/astra-review-vt02-answer.md, briefs/sol-review-vt02-answer.md).
contract VRReviewRegressionsTest is VRBase {
    uint8 internal constant GRIEF = 7;

    function setUp() public {
        _setUpVR(5, 1, 5, 16);
    }

    // ---------------------------------------------------------------------------------------------
    // astra 1 / sol P1: a recovery installs K, not J
    // ---------------------------------------------------------------------------------------------

    function _stage(uint64 id, string memory tag) internal returns (bytes32 ref) {
        Keys memory k = _freshKeys();
        IdentityView memory v = vr.identity(id);
        Registration memory r = _reg(k, tag, address(uint160(0xB000 + id)), v.bindingNonce);
        bytes32 d = _regDigest(VRC.BINDING_DOMAIN, v.owner, id, r);
        vm.prank(v.owner);
        vr.proposeBinding(id, r, _sig(k.rootPk, d), _sig(k.evmPk, d));
        ref = vr.identity(id).stagedRef;
    }

    function test_recoveryKeepsKAndItsBindings() public {
        bytes32 x = _stage(3, "three-x");
        uint64 lim = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 4, 16));
        // J: member 3 on its staged binding (generation 2); continuity allows one replacement out of five
        Member[] memory j = _members();
        Binding memory bx = vr.binding(x);
        j[2].generation = 2;
        j[2].rootNodeWord = bx.rootNodeWord;
        j[2].rootKeyHash = bx.rootKeyHash;
        j[2].evmNodeWord = bx.evmNodeWord;
        j[2].evmKeyHash = bx.evmKeyHash;
        j[2].payee = bx.payee;
        module.setMembers(j);
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        bytes32 kDigest = vr.output(r).kDigest;
        bytes32 kRef = vr.identity(3).currentRef;
        _recRecoveryAck(r);
        _recBoundary(r, _nextEpoch(), true, 0);
        _applyAll();
        assertEq(_state(r), VRC.OUT_RECOVERED);
        assertEq(vr.committee().length, 5, "K stays installed");
        assertEq(vr.identity(3).currentRef, kRef, "K's binding stays current");
        assertEq(vr.identity(3).generation, 1);
        assertEq(vr.identity(3).stagedRef, x, "J's capture never installed: staging kept");
        assertEq(_changeState(lim), VRC.CH_ACTIVE, "the committed changes still activate");
        assertEq(vr.lastAcked(), r);
        // the next output's K digest is still K's
        module.clearMembers();
        bytes32 r2 = _rid("R2");
        _advance(VRC.MIN_EPOCH_GAP, 1);
        assertEq(_moduleReserve(r2, true), VRC.ELECT_RESERVED);
        assertEq(vr.output(r2).kDigest, kDigest);
    }

    function test_recoverySwitchAttachesWithK() public {
        MockModule next = new MockModule(keccak256("next"));
        next.setVR(VR_ADDR);
        uint64 cid = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(next), address(next).codehash, bytes(""))
        );
        module.setMembers(_without(_members(), 5));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _recRecoveryAck(r);
        _recBoundary(r, _nextEpoch(), true, 0);
        _applyAll();
        assertEq(_changeState(cid), VRC.CH_ACTIVE);
        assertEq(vr.committee().length, 5, "K (five) stays installed, not the four-member J");
        assertEq(next.attachMembers(), 5, "the attach context carries K");
    }

    // ---------------------------------------------------------------------------------------------
    // astra 2 / sol P1: step budgets fund the inner call's EIP-150 headroom
    // ---------------------------------------------------------------------------------------------

    function _maxBounds(MockModule m) internal {
        m.setBounds(
            [
                uint64(4_000_000),
                1_000_000,
                1_500_000,
                500_000,
                3_000_000,
                500_000,
                1_000_000,
                1_000_000
            ]
        );
    }

    function test_fullRecordBatchIsDeliveredToAHealthyModule() public {
        for (uint64 k = 0; k < 32; ++k) {
            seal.push(
                VRC.REC_CLOSURE,
                abi.encode(
                    keccak256(abi.encode("a", k)),
                    uint256(1),
                    bytes32(uint256(2)),
                    bytes32(uint256(3)),
                    bytes32(uint256(4)),
                    bytes32(uint256(5))
                )
            );
        }
        module.setMode(3, GRIEF); // onRecords uses its whole 32 x 200,000 cap
        _apply(32);
        assertEq(vr.recordCursor(), 32);
        assertEq(module.logLength(), 1, "the callback ran");
        assertEq(module.log(0), "onRecords:0:32");
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_maximumCapsAreActuallyFunded() public {
        // a module at VR's maximum caps for every step, griefing each one
        MockModule next = new MockModule(keccak256("max"));
        next.setVR(VR_ADDR);
        _maxBounds(next);
        next.setCaps(VRC.CAP_ADOPTION_CHECK);
        next.setMode(5, GRIEF); // attach at 3,000,000
        next.setMode(8, GRIEF); // adoptionReady at 1,000,000
        next.setGriefLeave(60_000);
        uint64 cid = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(next), address(next).codehash, new bytes(16_000))
        );
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _acknowledge(r, 0);
        assertEq(_changeState(cid), VRC.CH_ACTIVE, "adoption answered at its cap");
        assertEq(vr.activeModule().module, address(next));
        assertEq(next.logLength() > 0, true);
        assertEq(next.log(0), "attach");
        assertEq(
            vr.health(), VRC.HEALTHY, "attach at 3,000,000 with a 16,000-byte initData is funded"
        );
        // elect at 4,000,000 + outputOf at 1,000,000, both griefing
        _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        next.setMembers(vr.committee());
        next.setMode(1, GRIEF);
        next.setMode(2, GRIEF);
        next.setGriefLeave(400_000);
        bytes32 r2 = _rid("R2");
        next.setElect(VRC.ELECT_RESERVED, true, r2);
        assertEq(_elect(), VRC.ELECT_RESERVED);
        assertEq(vr.health(), VRC.HEALTHY);
        // governance at 1,000,000
        next.setMode(7, GRIEF);
        next.setGriefLeave(20_000);
        uint64 a = _queue(VRC.K_MODULE_ACTION, abi.encode(address(next), bytes("x")));
        _passDelays();
        vr.execute(a);
        assertEq(_changeState(a), VRC.CH_ACTIVE);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_maximumOutputCapFundedOnPublish() public {
        MockModule next = new MockModule(keccak256("max"));
        next.setVR(VR_ADDR);
        _maxBounds(next);
        _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(next), address(next).codehash, bytes(""))
        );
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _acknowledge(r, 0);
        next.setMembers(vr.committee());
        bytes32 r2 = _rid("R2");
        next.setElect(VRC.ELECT_RESERVED, false, r2);
        _advance(VRC.MIN_EPOCH_GAP, 1);
        assertEq(_elect(), VRC.ELECT_RESERVED);
        next.setMode(2, GRIEF);
        next.setGriefLeave(400_000);
        assertEq(vr.publish(r2), VRC.PUB_PUBLISHED);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    // ---------------------------------------------------------------------------------------------
    // astra 3 / sol P2: the work age survives binding, open-output elections, expiry and withdrawal
    // ---------------------------------------------------------------------------------------------

    function test_workAgeSurvivesOpenOutputElectionLoops() public {
        _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        uint64 since = vr.activeModule().workSince;
        uint256 deadline = since + module.interval() + 2 * VRC.LIFETIME;
        for (uint256 i = 0; vr.health() == VRC.HEALTHY && i < 20; ++i) {
            bytes32 r = keccak256(abi.encode("loop", i));
            if (_moduleReserve(r, false) != VRC.ELECT_RESERVED) break; // Pending: its changes are Bound
            // elections every block while the output is open
            for (uint256 b = 0; b < 4; ++b) {
                _advance(VRC.LIFETIME / 8, 60);
                assertEq(_elect(), VRC.ELECT_DISABLED);
                assertEq(vr.activeModule().workSince, since, "binding does not end the work");
            }
            if (i % 2 == 1) module.invalidate(r, VRC.INVALID_LOST); // a withdrawal loop
            _advance(VRC.LIFETIME / 2, 60);
            _recRejected(r, i % 2 == 1 ? VRC.REJ_INVALIDATED : VRC.REJ_EXPIRED);
            _recClosed(r);
            _applyAll();
            assertEq(vr.activeModule().workSince, since, "closure does not restart it");
        }
        assertEq(vr.health(), VRC.STALLED);
        assertGt(progress, deadline);
    }

    function test_cancellingAllWorkEndsTheAge() public {
        uint64 c = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        _elect();
        assertTrue(vr.activeModule().workPending);
        vm.prank(governor);
        vr.cancel(c);
        _elect();
        assertFalse(vr.activeModule().workPending, "genuine cancellation clears it");
    }

    // ---------------------------------------------------------------------------------------------
    // astra 4: the reserved native tag is refused from modules
    // ---------------------------------------------------------------------------------------------

    function test_reservedNativeTagRefusedAtQueue() public {
        MockModule m = new MockModule(VRC.REGISTRY_NATIVE);
        vm.prank(governor);
        vm.expectRevert(
            abi.encodeWithSelector(VRShared.QueueRefused.selector, VRChanges.BAD_METADATA)
        );
        vr.queue(VRC.K_SET_MODULE, abi.encode(address(m), address(m).codehash, bytes("")));
    }

    function test_reservedNativeTagRefusedAtGenesis() public {
        module = new MockModule(VRC.REGISTRY_NATIVE);
        ValidatorRegistry.Genesis memory g = _genesis(5, 1, 5, 16);
        g.governanceFacet = govFacet;
        g.repairFacet = repairFacet;
        g.recordsFacet = recordsFacet;
        vm.expectRevert(abi.encodeWithSelector(VRShared.BadGenesis.selector, uint8(6)));
        new ValidatorRegistry(g);
    }

    /// @dev Every reachable output record satisfies the frozen reader rules (schema 2.2, vrschema DecodeOutput): a known state,
    /// expires = reserved + LIFETIME, native == (moduleTag == REGISTRY_NATIVE), invalidAtProgress == 0 when invalidReason == 0,
    /// and canonical packed words.
    function _assertReadable(bytes32 rid) internal view {
        bytes32 base = keccak256(abi.encode(rid, uint256(VRC.NAMESPACE) + 32));
        uint256 w0 = uint256(vm.load(VR_ADDR, base));
        uint256 w2 = uint256(vm.load(VR_ADDR, bytes32(uint256(base) + 2)));
        bytes32 w3 = vm.load(VR_ADDR, bytes32(uint256(base) + 3));
        uint256 w10 = uint256(vm.load(VR_ADDR, bytes32(uint256(base) + 10)));
        uint256 state = w0 & 0xff;
        assertTrue(state >= 1 && state <= 7, "state");
        assertEq(w0 >> 200, 0, "word0 reserved bytes");
        uint256 reserved = (w0 >> 72) & type(uint64).max;
        uint256 expires = (w0 >> 136) & type(uint64).max;
        assertEq(expires, reserved + VRC.LIFETIME, "expires");
        uint256 native = (w2 >> 160) & 0xff;
        assertLe(native, 1, "native bool");
        assertEq(w2 >> 168, 0, "word2 reserved bytes");
        assertEq(native == 1, w3 == VRC.REGISTRY_NATIVE, "native == (moduleTag == REGISTRY_NATIVE)");
        assertEq(w10 >> 72, 0, "word10 reserved bytes");
        if (w10 & 0xff == 0) assertEq(w10 >> 8, 0, "invalidAtProgress without a reason");
    }

    function test_reachableOutputsDecodeUnderTheFrozenReader() public {
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED);
        _assertReadable(r);
        assertEq(vr.publish(r), VRC.PUB_PUBLISHED);
        _assertReadable(r);
        module.invalidate(r, VRC.INVALID_WITHDRAWN);
        _assertReadable(r);
        _recRejected(r, VRC.REJ_INVALIDATED);
        _recClosed(r);
        _applyAll();
        _assertReadable(r);
        // a native output
        _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        _advance(VRC.MIN_EPOCH_GAP, 1);
        assertEq(vr.health(), VRC.FAULTED);
        assertEq(_elect(), VRC.ELECT_RESERVED);
        _assertReadable(vr.openOutput());
        bytes32 n = vr.openOutput();
        _acknowledge(n, 0);
        _assertReadable(n);
    }

    // ---------------------------------------------------------------------------------------------
    // sol P2: a zero result id in OutputRejected is malformed
    // ---------------------------------------------------------------------------------------------

    function test_zeroResultIdOutputRejectedIsMalformed() public {
        assertFalse(this.wellFormed(7, abi.encode(bytes32(0), uint256(1), uint256(0), uint256(0))));
        assertTrue(
            this.wellFormed(7, abi.encode(bytes32(uint256(1)), uint256(1), uint256(0), uint256(0)))
        );
        seal.push(
            VRC.REC_OUTPUT_REJECTED, abi.encode(bytes32(0), uint256(1), uint256(0), uint256(0))
        );
        _applyAll();
        assertEq(vr.health(), VRC.INCONSISTENT, "a malformed record is an anomaly");
    }

    function wellFormed(uint8 kind, bytes calldata d) external pure returns (bool) {
        return VRCodec.recordWellFormed(kind, d);
    }
}

/// @notice astra 5: an infeasible ForceRemove never stalls the module, through either deadline; a feasible overdue one does.
contract VRInfeasibleForceRemoveTest is VRBase {
    function setUp() public {
        // member 6 carries half the weight: removing it alone fails continuity; removing member 1 passes
        uint64[6] memory w = [uint64(1), 1, 1, 1, 1, 5];
        for (uint256 i = 0; i < 6; ++i) {
            genesisWeights.push(w[i]);
        }
        _setUpVR(6, 1, 6, 16);
    }

    function _deadline() internal view returns (uint64) {
        return module.interval() + 2 * VRC.LIFETIME;
    }

    function test_isolatedInfeasibleRemovalOverTheFullDeadline() public {
        uint64 fr = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(6)));
        assertFalse(
            vr.activeModule().workPending, "a ForceRemove does not start the generic work clock"
        );
        progress = vr.change(fr).scheduledAt + 3 * _deadline();
        seal.setClock(progress, ucTime);
        _elect();
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(_changeState(fr), VRC.CH_SCHEDULED);
    }

    function test_mixedRemovalsStallOnlyOnTheFeasibleOne() public {
        uint64 infeasible = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(6)));
        _advance(5_000, 1);
        uint64 feasible = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(1)));
        progress = vr.change(infeasible).scheduledAt + _deadline() + 1;
        seal.setClock(progress, ucTime);
        _elect();
        assertEq(vr.health(), VRC.HEALTHY, "only the infeasible one is overdue");
        progress = vr.change(feasible).scheduledAt + _deadline() + 1;
        seal.setClock(progress, ucTime);
        assertEq(
            _elect(), VRC.ELECT_RESERVED, "stalled, then native removal of the feasible member"
        );
        assertEq(vr.health(), VRC.STALLED);
        assertEq(vr.output(vr.openOutput()).members.length, 5);
    }
}
