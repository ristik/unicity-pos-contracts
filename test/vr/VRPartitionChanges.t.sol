// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "./VRBase.sol";
import {VRShared} from "../../src/vr/VRShared.sol";
import {VRChanges} from "../../src/vr/VRChanges.sol";
import {VRC} from "../../src/vr/VRConstants.sol";

/// @notice The live partition changes through VR (design sections 3.5 and 6; VT-06d AddPartition and VT-06e UpdatePartition, bft-core
/// #1162 and #1163): the queue-time scope read of an AddPartition (FD-25), binding by scope (a partition for kind 7, a shard shared by
/// kinds 6 and 8), the root-side bound, and the Boundary outcome of each kind. They have no EVM-side effect: the roots install them, and VR
/// records only the committed verdict (Active, or Rejected by the bitmap), or releases them back to Scheduled on closure.
contract VRPartitionChangesTest is VRBase {
    function setUp() public {
        _setUpVR(5, 1, 5, 16);
    }

    /// @dev The leading bytes of a canonical CBOR PDR VR reads (tag 39008, an array head, version, network, partition); the rest is the
    /// roots' to judge.
    function _pdr(uint8 partition) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"d998608f010518", partition, hex"418003f6");
    }

    function _add(uint8 partition) internal pure returns (bytes memory) {
        return abi.encode(_pdr(partition), hex"80");
    }

    function _update(uint32 partition, bytes32 expected) internal pure returns (bytes memory) {
        return abi.encode(partition, hex"80", expected, _pdr(uint8(partition)));
    }

    function _replace(uint32 partition) internal pure returns (bytes memory) {
        return abi.encode(partition, hex"80", keccak256("old"), _pdr(uint8(partition)), hex"80");
    }

    function test_addPartitionNeedsAReadablePartitionAtQueue() public {
        vm.startPrank(governor);
        vm.expectRevert(
            abi.encodeWithSelector(VRShared.QueueRefused.selector, VRChanges.UNREADABLE_SCOPE)
        );
        vr.queue(VRC.K_ADD_PARTITION, abi.encode(hex"a0", hex"80"));
        vm.expectRevert(abi.encodeWithSelector(VRShared.QueueRefused.selector, VRChanges.LENGTH));
        vr.queue(VRC.K_UPDATE_PARTITION, abi.encode(uint32(9)));
        vm.stopPrank();
        assertGt(_queue(VRC.K_ADD_PARTITION, _add(40)), 0);
        assertGt(_queue(VRC.K_UPDATE_PARTITION, _update(9, keccak256("h"))), 0);
    }

    function test_partitionChangesBindByScopeAndResolveAtTheBoundary() public {
        uint64 add40 = _queue(VRC.K_ADD_PARTITION, _add(40));
        uint64 add40again = _queue(VRC.K_ADD_PARTITION, _add(40)); // the same partition: defers
        uint64 add41 = _queue(VRC.K_ADD_PARTITION, _add(41));
        uint64 upd9 = _queue(VRC.K_UPDATE_PARTITION, _update(9, keccak256("h9")));
        uint64 rep9 = _queue(VRC.K_REPLACE_AGGREGATOR, _replace(9)); // shares shard 9's scope with the update: defers
        uint64 upd12 = _queue(VRC.K_UPDATE_PARTITION, _update(12, keccak256("h12")));
        _passDelays();
        uint64[6] memory ids = [add40, add40again, add41, upd9, rep9, upd12];
        for (uint256 i = 0; i < ids.length; ++i) {
            vr.execute(ids[i]);
        }
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        uint64[] memory bound = vr.output(r).changes;
        assertEq(bound.length, 4);
        assertEq(bound[0], add40);
        assertEq(bound[1], add41);
        assertEq(bound[2], upd9);
        assertEq(bound[3], upd12);
        assertEq(
            _changeState(add40again), VRC.CH_SCHEDULED, "a second addition of a partition defers"
        );
        assertEq(
            _changeState(rep9),
            VRC.CH_SCHEDULED,
            "a second change of a shard defers, across kinds 6 and 8"
        );

        // the roots accept the additions and the first update, and reject the update of shard 12 (bit 3, say a stale expected hash)
        uint64 e = vr.config().knownRootEpoch;
        _acknowledge(r, uint16(1) << 3);
        assertEq(_changeState(add40), VRC.CH_ACTIVE);
        assertEq(_changeState(add41), VRC.CH_ACTIVE);
        assertEq(_changeState(upd9), VRC.CH_ACTIVE);
        assertEq(vr.change(upd9).activeRootEpoch, e + 1, "active from the successor root epoch");
        assertEq(_changeState(upd12), VRC.CH_REJECTED);
        assertEq(vr.change(upd12).rejectReason, VRC.V_CONFLICT);

        // the deferred changes bind into the next output
        bytes32 r2 = _rid("R2");
        assertEq(_moduleReserve(r2, true), VRC.ELECT_RESERVED);
        bound = vr.output(r2).changes;
        assertEq(bound.length, 2);
        assertEq(bound[0], add40again);
        assertEq(bound[1], rep9);
    }

    function test_aClosedOutputReleasesItsPartitionChanges() public {
        uint64 add = _queueScheduled(VRC.K_ADD_PARTITION, _add(40));
        uint64 upd = _queueScheduled(VRC.K_UPDATE_PARTITION, _update(9, keccak256("h9")));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        assertEq(_changeState(add), VRC.CH_BOUND);
        assertEq(_changeState(upd), VRC.CH_BOUND);
        vm.prank(governor);
        vm.expectRevert(VRShared.NotCancellable.selector);
        vr.cancel(add);
        _recRejected(r, VRC.REJ_EXPIRED);
        _recClosed(r);
        _applyAll();
        assertEq(
            _changeState(add), VRC.CH_SCHEDULED, "released, never activated by a closed output"
        );
        assertEq(_changeState(upd), VRC.CH_SCHEDULED);
    }

    function test_rootSideChangesAreBoundAtMostEightPerOutput() public {
        uint64[] memory ids = new uint64[](10);
        for (uint256 i = 0; i < 10; ++i) {
            ids[i] = _queue(VRC.K_ADD_PARTITION, _add(uint8(40 + i)));
        }
        _passDelays();
        for (uint256 i = 0; i < 10; ++i) {
            vr.execute(ids[i]);
        }
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        assertEq(vr.output(r).changes.length, VRC.MAX_BOUND_ROOT_SIDE);
        assertEq(_changeState(ids[8]), VRC.CH_SCHEDULED);
        assertEq(_changeState(ids[9]), VRC.CH_SCHEDULED);
    }
}
