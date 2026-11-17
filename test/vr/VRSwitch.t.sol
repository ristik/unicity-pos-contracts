// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "./VRBase.sol";
import {MockModule, MockHolder} from "./VRMocks.sol";
import {VRC} from "../../src/vr/VRConstants.sol";

/// @notice The pointer switch (design section 3.6.1) and the holder namespace (section 3.9.1) beyond the frozen switch vectors:
/// contained adoption and detach failures, the attach context, holder reuse, a holder whose code changed, and the eighth-holder
/// ceiling.
contract VRSwitchTest is VRBase {
    uint8 internal constant REVERT = 1;
    uint8 internal constant BURN = 2;
    uint8 internal constant MALFORMED = 3;
    uint8 internal constant HUGE = 4;
    uint8 internal constant S_DETACH = 6;
    uint8 internal constant S_ADOPT = 8;

    uint256 internal salt;

    function setUp() public {
        _setUpVR(5, 1, 5, 16);
    }

    function _newModule(address holder, bool adoption) internal returns (MockModule m) {
        m = new MockModule(keccak256(abi.encode("unicity.vr.module", ++salt)));
        m.setVR(VR_ADDR);
        uint32 caps = adoption ? VRC.CAP_ADOPTION_CHECK : 0;
        if (holder != address(0)) {
            caps |= VRC.CAP_LIABILITY_HOLDER;
            m.setHolder(holder);
        }
        m.setCaps(caps);
    }

    /// @dev Queue SetModule(m), schedule it, have the active module reserve and the roots acknowledge an output binding it.
    function _switchTo(MockModule m) internal returns (uint64 cid) {
        cid = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(m), address(m).codehash, bytes("init"))
        );
        MockModule active = MockModule(vr.activeModule().module);
        bytes32 r = keccak256(abi.encode("switch", cid));
        active.setElect(VRC.ELECT_RESERVED, true, r);
        vm.prank(VRC.SYSTEM_CALLER);
        assertEq(vr.elect(keccak256(abi.encode("origin", cid))), VRC.ELECT_RESERVED);
        active.setElect(VRC.ELECT_NOT_DUE, false, 0);
        _acknowledge(r, 0);
        _advance(VRC.MIN_EPOCH_GAP, 1);
    }

    function test_attachContextCarriesTheCommitteeAndTheHolderIndex() public {
        MockHolder h = new MockHolder();
        MockModule m = _newModule(address(h), false);
        _switchTo(m);
        assertEq(vr.activeModule().module, address(m));
        assertEq(m.attachHolderIndex(), 0);
        assertEq(m.attachPrevious(), address(module));
        assertEq(m.attachNamespace(), VR_ADDR, "liabilityNamespace = VR");
        assertEq(m.attachMembers(), 5);
        assertEq(m.attachInit(), bytes("init"));
        assertEq(vr.holderCount(), 1);
        assertEq(vr.holderAt(0).holder, address(h));
        assertEq(vr.holderAt(0).module, address(m));
        MockModule plain = _newModule(address(0), false);
        _switchTo(plain);
        assertEq(plain.attachHolderIndex(), VRC.NO_HOLDER, "0xff: not a holder");
    }

    function test_adoptionFailuresRejectAndKeepTheOldModule() public {
        uint8[4] memory modes = [REVERT, BURN, MALFORMED, HUGE];
        for (uint256 i = 0; i < modes.length; ++i) {
            uint256 snap = vm.snapshotState();
            MockModule m = _newModule(address(0), true);
            m.setMode(S_ADOPT, modes[i]);
            uint64 cid = _switchTo(m);
            assertEq(_changeState(cid), VRC.CH_REJECTED);
            assertEq(vr.change(cid).rejectReason, VRC.R_ADOPTION_NOT_READY);
            assertEq(vr.activeModule().module, address(module));
            assertEq(vr.health(), VRC.HEALTHY, "adoption is not a fault");
            vm.revertToState(snap);
        }
    }

    function test_detachFailureDoesNotStopTheSwitch() public {
        uint8[3] memory modes = [REVERT, BURN, HUGE];
        for (uint256 i = 0; i < modes.length; ++i) {
            uint256 snap = vm.snapshotState();
            module.setMode(S_DETACH, modes[i]);
            MockModule m = _newModule(address(0), false);
            uint64 cid = _switchTo(m);
            assertEq(_changeState(cid), VRC.CH_ACTIVE);
            assertEq(vr.activeModule().module, address(m));
            assertEq(vr.health(), VRC.HEALTHY);
            vm.revertToState(snap);
        }
    }

    function test_holderReuseKeepsItsIndex() public {
        MockHolder h = new MockHolder();
        MockModule a = _newModule(address(h), false);
        _switchTo(a);
        _switchTo(_newModule(address(0), false));
        MockModule b = _newModule(address(h), false);
        _switchTo(b);
        assertEq(vr.holderCount(), 1, "no second entry for the same holder");
        assertEq(b.attachHolderIndex(), 0, "the original index");
        assertEq(vr.holderAt(0).module, address(a), "entries are permanent");
    }

    function test_holderWhoseCodeChangedIsHolderMismatch() public {
        MockHolder h = new MockHolder();
        _switchTo(_newModule(address(h), false));
        _switchTo(_newModule(address(0), false));
        vm.etch(address(h), address(new MockModule(bytes32(0))).code); // the same address, other code
        MockModule b = _newModule(address(h), false); // declares the new hash
        uint64 cid = _switchTo(b);
        assertEq(_changeState(cid), VRC.CH_REJECTED);
        assertEq(vr.change(cid).rejectReason, VRC.R_HOLDER_MISMATCH);
        assertEq(vr.holderCount(), 1);
    }

    function test_ninthHolderIsHolderCeiling() public {
        for (uint256 i = 0; i < VRC.MAX_HOLDERS; ++i) {
            _switchTo(_newModule(address(new MockHolder()), false));
        }
        assertEq(vr.holderCount(), VRC.MAX_HOLDERS);
        MockModule ninth = _newModule(address(new MockHolder()), false);
        address before = vr.activeModule().module;
        uint64 cid = _switchTo(ninth);
        assertEq(_changeState(cid), VRC.CH_REJECTED);
        assertEq(vr.change(cid).rejectReason, VRC.R_HOLDER_CEILING);
        assertEq(vr.activeModule().module, before, "a ninth holder needs a new generation");
    }

    function test_failedAttachConsumesNoHolderEntryAndFaults() public {
        MockHolder h = new MockHolder();
        MockModule m = _newModule(address(h), false);
        m.setMode(5, REVERT);
        uint64 cid = _switchTo(m);
        assertEq(_changeState(cid), VRC.CH_ACTIVE, "the pointer switched");
        assertEq(vr.activeModule().module, address(m));
        assertEq(vr.health(), VRC.FAULTED, "repair mode follows");
        assertEq(vr.holderCount(), 0, "no entry for a failed attach");
    }
}
