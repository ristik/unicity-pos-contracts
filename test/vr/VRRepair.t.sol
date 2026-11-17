// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "./VRBase.sol";
import {MockModule} from "./VRMocks.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {VRCodec} from "../../src/vr/VRCodec.sol";
import {Member, OutputView} from "../../src/vr/VRTypes.sol";

/// @notice Native repair (design section 3.6.2) and the VT-02 repair fixtures of section 11: a limits change to nMin = 6 over five
/// members followed by a module fault gives an admitted five-member native output; an unavailable incumbent removed by ForceRemove;
/// Reserved-never-published; Published-never-ready; a fault while an output is still open. The native output's commitments are
/// recomputed here from the schema formulas, as the roots recompute them from the candidate.
contract VRRepairTest is VRBase {
    uint8 internal constant REVERT = 1;
    uint8 internal constant S_ELECT = 1;

    function setUp() public {
        _setUpVR(5, 1, 5, 16);
    }

    function _fault() internal {
        module.setMode(S_ELECT, REVERT);
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE);
        module.setMode(S_ELECT, 0);
        assertEq(vr.health(), VRC.FAULTED);
    }

    function _repairModule() internal returns (MockModule m, uint64 id) {
        m = new MockModule(keccak256("unicity.vr.repair-module"));
        id = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(m), address(m).codehash, bytes(""))
        );
    }

    /// @dev The native output's outputCommit recomputed from its parts with the schema formula.
    function _checkCommit(bytes32 rid) internal view {
        OutputView memory o = vr.output(rid);
        assertTrue(o.native);
        assertEq(o.moduleTag, VRC.REGISTRY_NATIVE);
        assertEq(o.sourceModule, address(0));
        assertEq(o.expiresAtProgress, o.reservedProgress + VRC.LIFETIME);
        assertEq(o.membersDigest, VRCodec.membersDigest(o.members));
        bytes32 commit = keccak256(
            bytes.concat(
                abi.encode(
                    VRC.OUTPUT_DOMAIN,
                    NETWORK,
                    block.chainid,
                    VR_ADDR,
                    rid,
                    o.predecessor,
                    uint256(o.attempt)
                ),
                abi.encode(
                    o.moduleTag,
                    true,
                    o.snapshotDigest,
                    o.policyDigest,
                    o.membersDigest,
                    o.kDigest,
                    o.changesDigest
                )
            )
        );
        assertEq(o.outputCommit, commit);
        for (uint256 i = 0; i < o.members.length; ++i) {
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
                )
            );
        }
    }

    function test_nativeIdentityFormula() public {
        (, uint64 cid) = _repairModule();
        _fault();
        _advance(VRC.MIN_EPOCH_GAP, 1);
        bytes32 origin = keccak256("origin-1");
        assertEq(_electWith(origin), VRC.ELECT_RESERVED);
        bytes32 rid = vr.openOutput();
        assertEq(
            rid,
            keccak256(
                abi.encode(
                    VRC.NATIVE_RESULT_DOMAIN,
                    NETWORK,
                    block.chainid,
                    VR_ADDR,
                    VRC.GENESIS_RESULT,
                    uint256(0),
                    origin
                )
            )
        );
        assertEq(vr.output(rid).state, VRC.OUT_PUBLISHED, "native outputs are written Published");
        assertEq(vr.output(rid).changes[0], cid);
        _checkCommit(rid);
    }

    /// Fixture 1: limits 5 -> nMin = 6, then the module faults; the native output keeps the five members (exempt from limits).
    function test_limitsToSixThenFaultGivesAFiveMemberNativeOutput() public {
        uint64 lim = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(6, 6, 16));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _acknowledge(r, 0);
        assertEq(_changeState(lim), VRC.CH_ACTIVE);
        assertEq(vr.config().nMin, 6);
        (MockModule m, uint64 cid) = _repairModule();
        _fault();
        _advance(VRC.MIN_EPOCH_GAP, 1);
        assertEq(_elect(), VRC.ELECT_RESERVED);
        bytes32 n = vr.openOutput();
        assertEq(vr.output(n).members.length, 5, "five members although nMin = 6");
        _checkCommit(n);
        // admitted: the roots acknowledge it; the bound SetModule switches the pointer at its Boundary
        _acknowledge(n, 0);
        assertEq(vr.activeModule().module, address(m));
        assertEq(_changeState(cid), VRC.CH_ACTIVE);
        assertEq(vr.health(), VRC.HEALTHY, "a successful SetModule clears Faulted");
        assertEq(vr.committee().length, 5);
    }

    /// Fixture 2: an unavailable incumbent removed by ForceRemove: the module never performs it, stalls, and the native output removes
    /// the member (the remaining members provide readiness).
    function test_unavailableIncumbentRemovedByForceRemove() public {
        uint64 fr = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(3)));
        uint64 since = vr.change(fr).scheduledAt;
        progress = since + module.interval() + 2 * VRC.LIFETIME + 1;
        seal.setClock(progress, ucTime);
        assertEq(_elect(), VRC.ELECT_RESERVED, "stalled, then native in the same election");
        assertEq(vr.health(), VRC.STALLED);
        bytes32 n = vr.openOutput();
        OutputView memory o = vr.output(n);
        assertEq(o.members.length, 4);
        for (uint256 i = 0; i < 4; ++i) {
            assertTrue(o.members[i].id != 3, "the force-removed member is out");
        }
        assertEq(o.changes.length, 1);
        assertEq(o.changes[0], fr);
        _checkCommit(n);
        _acknowledge(n, 0);
        assertEq(_changeState(fr), VRC.CH_ACTIVE);
        assertEq(vr.committee().length, 4);
    }

    /// Fixture 3: Reserved, never published: the roots expire it; the closure releases its changes and is not a fault.
    function test_reservedNeverPublished() public {
        uint64 c = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED);
        module.setOutputStatus(VRC.STATUS_PENDING);
        assertEq(vr.publish(r), VRC.PUB_PENDING);
        _advance(VRC.LIFETIME, 1);
        _recRejected(r, VRC.REJ_EXPIRED);
        _recClosed(r);
        _applyAll();
        assertEq(_state(r), VRC.OUT_CLOSED);
        assertEq(_changeState(c), VRC.CH_SCHEDULED);
        assertEq(vr.health(), VRC.HEALTHY, "expiry is not a fault");
        assertEq(vr.openOutput(), bytes32(0));
    }

    /// Fixture 4: Published, never ready (successors never ready): expiry, closure, no fault; the next output binds the changes again.
    function test_publishedNeverReady() public {
        uint64 c = _queueScheduled(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _advance(VRC.LIFETIME, 1);
        seal.push(
            VRC.REC_OUTPUT_REJECTED,
            abi.encode(r, uint256(VRC.REJ_EXPIRED), uint256(0), uint256(0x1e))
        );
        _recClosed(r);
        _applyAll();
        assertEq(_state(r), VRC.OUT_CLOSED);
        assertEq(vr.health(), VRC.HEALTHY);
        bytes32 r2 = _rid("R2");
        assertEq(_moduleReserve(r2, true), VRC.ELECT_RESERVED);
        assertEq(vr.output(r2).changes[0], c, "released once and bound again");
    }

    /// Fixture 5: a fault while an output is still open: no native output until the open one resolves.
    function test_faultWhileAnOutputIsOpen() public {
        _repairModule();
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, false), VRC.ELECT_RESERVED);
        module.setMode(2, REVERT); // outputOf
        assertEq(vr.publish(r), VRC.PUB_PRECONDITION_FAILED);
        assertEq(vr.health(), VRC.FAULTED);
        _advance(VRC.MIN_EPOCH_GAP, 1);
        assertEq(_elect(), VRC.ELECT_DISABLED, "R is open: no repair yet");
        _recRejected(r, VRC.REJ_EXPIRED);
        _recClosed(r);
        _applyAll();
        assertEq(_elect(), VRC.ELECT_RESERVED, "native repair after closure");
        assertTrue(vr.output(vr.openOutput()).native);
    }

    function test_nativeRepairWaitsForTheEpochGap() public {
        // a ForceRemove the module does not perform stays Scheduled across its boundary: the repair work
        uint64 lim = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 5, 16));
        uint64 fr = _queue(VRC.K_FORCE_REMOVE, abi.encode(uint64(5)));
        _passDelays();
        vr.execute(lim);
        vr.execute(fr);
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _acknowledge(r, 0); // the epoch's first ordinary progress is now
        assertEq(_changeState(fr), VRC.CH_SCHEDULED);
        _fault();
        _advance(VRC.MIN_EPOCH_GAP - 1, 1);
        assertEq(_elect(), VRC.ELECT_NOT_DUE, "EpochGap");
        _advance(1, 1);
        assertEq(_elect(), VRC.ELECT_RESERVED);
        assertEq(vr.output(vr.openOutput()).changes[0], fr);
    }

    function test_nativeRepairNeedsScheduledWork() public {
        _fault();
        _advance(VRC.MIN_EPOCH_GAP, 1);
        assertEq(_elect(), VRC.ELECT_NOT_DUE, "NoScheduledWork");
        assertEq(vr.openOutput(), bytes32(0));
    }
}

/// @notice Native repair over ten members: two ForceRemoves, both taken when continuity allows.
contract VRRepairTenTest is VRBase {
    function setUp() public {
        _setUpVR(10, 1, 8, 16);
    }

    /// The oldest overdue feasible ForceRemove is mandatory; with two candidates both removals are taken when continuity allows.
    function test_trialSearchPrefersMoreRemovals() public {
        uint64 a = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(6)));
        _advance(10, 1);
        uint64 b = _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(2)));
        progress = vr.change(a).scheduledAt + module.interval() + 2 * VRC.LIFETIME + 1;
        seal.setClock(progress, ucTime);
        assertEq(_elect(), VRC.ELECT_RESERVED);
        OutputView memory o = vr.output(vr.openOutput());
        assertEq(o.members.length, 8, "10 -> 8: 3 * 2 < 8, D = 2/10 within 1/2, overlap 8/10");
        assertEq(o.changes.length, 2);
        assertEq(o.changes[0], a);
        assertEq(o.changes[1], b);
    }
}

/// @notice Native repair over four members: a pure removal is a new-generation case (design 3.6.2).
contract VRRepairFourTest is VRBase {
    uint8 internal constant REVERT = 1;
    uint8 internal constant S_ELECT = 1;

    function setUp() public {
        _setUpVR(4, 1, 4, 16);
    }

    function _fault() internal {
        module.setMode(S_ELECT, REVERT);
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE);
        module.setMode(S_ELECT, 0);
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_pureRemovalFromFourIsANewGenerationCase() public {
        _queueScheduled(VRC.K_FORCE_REMOVE, abi.encode(uint64(2)));
        _fault();
        _advance(VRC.MIN_EPOCH_GAP, 1);
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE, "no trial passes continuity: not repairable");
        assertEq(vr.openOutput(), bytes32(0));
    }
}
