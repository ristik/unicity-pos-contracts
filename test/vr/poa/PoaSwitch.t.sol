// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PoaBase} from "./PoaBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {PoaElection} from "../../../src/vr/poa/PoaElection.sol";

/// @notice The module switch through the real VR (design 3.6.1): a SetModule bound to a PoA output; at its Boundary the PoA module
/// receives its records through and including that Boundary, is detached, and the next module is attached with the committee in force.
/// Covered: PoA -> another module -> a fresh PoA instance (attach takes the committee over), and PoA -> PoA directly (the upgrade path).
contract PoaSwitchTest is PoaBase {
    function test_poaToMockAndBackToAFreshPoa() public {
        _setUpPoa(5, 1, 6, 16);
        uint64 j = _admitNew();
        uint64 sw = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(module), address(module).codehash, bytes(""))
        );
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(_changeState(sw), VRC.CH_BOUND, "the SetModule is bound to the PoA output");
        assertEq(_st(j), JOINING);
        _acknowledge(rid, 0);
        assertEq(vr.activeModule().module, address(module));
        assertEq(_changeState(sw), VRC.CH_ACTIVE);
        assertEq(_st(j), ACTIVE, "the old module saw its Boundary before the detach");
        assertEq(module.attachMembers(), 6);
        assertEq(module.attachPrevious(), address(poa));
        // the detached PoA module receives nothing more
        uint256 before = poa.outputCount();
        module.setElect(VRC.ELECT_NOT_DUE, false, 0);
        _elect();
        assertEq(poa.outputCount(), before);

        // back to a fresh PoA instance: its attach takes the committee over
        PoaElection fresh = new PoaElection(VR_ADDR, engine, new uint64[](0));
        uint64 sw2 = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(fresh), address(fresh).codehash, bytes(""))
        );
        bytes32 mrid = keccak256("mock output");
        assertEq(_moduleReserve(mrid, true), VRC.ELECT_RESERVED);
        assertEq(_changeState(sw2), VRC.CH_BOUND);
        _acknowledge(mrid, 0);
        assertEq(vr.activeModule().module, address(fresh));
        assertEq(vr.health(), VRC.HEALTHY);
        assertTrue(_eqIds(fresh.members(), _committeeIds()));
        (uint8 s,) = fresh.status(j);
        assertEq(s, ACTIVE);
        // the fresh module runs the next election
        poa = fresh;
        uint64 k = _admitNew();
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(vr.output(rid).sourceModule, address(fresh));
        assertTrue(_eqIds(_outputIds(rid), _with(_committeeIds(), k)));
        _acknowledge(rid, 0);
        assertEq(_st(k), ACTIVE);
    }

    function test_poaToPoaUpgrade() public {
        _setUpPoa(5, 1, 6, 16);
        PoaElection next = new PoaElection(VR_ADDR, engine, new uint64[](0));
        _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(address(next), address(next).codehash, bytes(""))
        );
        // the old module still has a Removing member: it leaves with the switching output
        _action(A_REMOVE, 2);
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(_eqIds(_outputIds(rid), _minus(_seq(1, 5), 2)));
        _acknowledge(rid, 0);
        assertEq(vr.activeModule().module, address(next));
        assertEq(_st(2), EXITED);
        assertTrue(_eqIds(next.members(), _minus(_seq(1, 5), 2)));
        poa = next;
        _stageBinding(3);
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(vr.output(rid).members[1].generation, 2, "member 3 takes its staged binding");
    }
}
