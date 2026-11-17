// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PoaBase} from "./PoaBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";

/// @notice How a Boundary resolves the module's open output (design 3.7.1 with 4.1's J/K distinction; VT-03 review, astra 1 and sol
/// P2): a primary Boundary installs J (joiners Active, leavers Exited); a recovered Boundary keeps K, so the joiners return to
/// Admitted and the leavers to Removing and the next election retries them. Split record imports, intervening governance, and the
/// raw-total bound through the real VR (astra 2).
contract PoaRecoveryTest is PoaBase {
    function _swapAtFive() internal returns (uint64 j, bytes32 rid) {
        _setUpPoa(5, 1, 5, 16);
        _action(A_REMOVE, 3);
        j = _admitNew();
        uint8 out;
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(_eqIds(_outputIds(rid), _with(_minus(_seq(1, 5), 3), j)));
        assertEq(_st(3), LEAVING);
        assertEq(_st(j), JOINING);
    }

    function _growthAtFour() internal returns (uint64 j, bytes32 rid) {
        _setUpPoa(4, 1, 5, 16);
        j = _admitNew();
        uint8 out;
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(_st(j), JOINING);
    }

    function _recover(bytes32 rid, bool split) internal {
        _recRecoveryAck(rid);
        if (split) _applyAll();
        _recBoundary(rid, _nextEpoch(), true, 0);
        _applyAll();
    }

    function _primary(bytes32 rid, bool split) internal {
        _recAck(rid);
        if (split) _applyAll();
        _recBoundary(rid, _nextEpoch(), false, 0);
        _applyAll();
    }

    // ---- recovered: K is kept, the changes are retried ----

    function _recoveredSwap(bool split) internal {
        (uint64 j, bytes32 rid) = _swapAtFive();
        _recover(rid, split);
        assertEq(vr.output(rid).state, VRC.OUT_RECOVERED);
        assertTrue(_eqIds(_committeeIds(), _seq(1, 5)), "VR keeps K");
        assertTrue(_eqIds(poa.members(), _seq(1, 5)));
        assertEq(_st(3), REMOVING, "the retained leaver is Removing again");
        assertEq(_st(j), ADMITTED, "the uninstalled joiner is Admitted again");
        (uint8 out, bytes32 rid2) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED, "the next election retries");
        assertTrue(_eqIds(_outputIds(rid2), _with(_minus(_seq(1, 5), 3), j)));
        _primary(rid2, split);
        assertEq(_st(3), EXITED);
        assertEq(_st(j), ACTIVE);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_recoveredSwapIsRetried() public {
        _recoveredSwap(false);
    }

    function test_recoveredSwapSplitImportIsRetried() public {
        _recoveredSwap(true);
    }

    function _recoveredGrowth(bool split) internal {
        (uint64 j, bytes32 rid) = _growthAtFour();
        _recover(rid, split);
        assertTrue(_eqIds(_committeeIds(), _seq(1, 4)));
        assertEq(_st(j), ADMITTED);
        assertEq(poa.queue().length, 1);
        (uint8 out, bytes32 rid2) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(_eqIds(_outputIds(rid2), _with(_seq(1, 4), j)));
        _primary(rid2, false);
        assertEq(_st(j), ACTIVE);
        assertEq(poa.queue().length, 0);
    }

    function test_recoveredGrowthIsRetried() public {
        _recoveredGrowth(false);
    }

    function test_recoveredGrowthSplitImportIsRetried() public {
        _recoveredGrowth(true);
    }

    /// @dev The reviewers' reproduction, inverted: after recovery the work is not lost, and the module does not sit idle.
    function test_recoveryLeavesNoStrandedState() public {
        (uint64 j, bytes32 rid) = _swapAtFive();
        _recover(rid, false);
        assertTrue(_st(3) != LEAVING && _st(j) != JOINING);
        (uint8 out,) = _electPoa();
        assertTrue(out != VRC.ELECT_NOT_DUE, "the remaining intent is due");
    }

    // ---- primary: J is installed ----

    function test_primarySwap() public {
        (uint64 j, bytes32 rid) = _swapAtFive();
        _primary(rid, true);
        assertEq(_st(3), EXITED);
        assertEq(_st(j), ACTIVE);
        assertTrue(_eqIds(_committeeIds(), _with(_minus(_seq(1, 5), 3), j)));
    }

    function test_primaryGrowthSplitImport() public {
        (uint64 k, bytes32 rid2) = _growthAtFour();
        _primary(rid2, true);
        assertEq(_st(k), ACTIVE);
        assertTrue(_eqIds(_committeeIds(), _with(_seq(1, 4), k)));
    }

    // ---- intervening governance stands ----

    function test_recoveryKeepsInterveningGovernance() public {
        (uint64 j, bytes32 rid) = _swapAtFive();
        // while the output is open: the joiner is removed (a Removing non-member), the leaver is removed again (Removing)
        _action(A_REMOVE, j);
        _action(A_REMOVE, 3);
        assertEq(_st(j), REMOVING);
        assertEq(_st(3), REMOVING);
        _recover(rid, false);
        assertEq(
            _st(j), EXITED, "a Removing non-member exits at the boundary, it is not re-admitted"
        );
        assertEq(_st(3), REMOVING);
        (uint8 out, bytes32 rid2) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertTrue(
            _eqIds(_outputIds(rid2), _minus(_seq(1, 5), 3)), "the pure removal at five, no joiner"
        );
    }

    function test_primaryKeepsInterveningGovernance() public {
        (uint64 j, bytes32 rid) = _swapAtFive();
        _action(A_REMOVE, j); // installed with the output, then a Removing member
        _primary(rid, false);
        assertEq(_st(j), REMOVING);
        assertEq(_st(3), EXITED);
        assertTrue(_eqIds(poa.members(), _committeeIds()));
    }

    // ---- the raw-total bound (astra 2) ----

    function test_maximumRawTotalJoinerIsNoCandidateNotAFault() public {
        uint64[] memory raw = new uint64[](5);
        for (uint256 i = 0; i < 5; ++i) {
            raw[i] = type(uint64).max / 5; // total exactly 2^64 - 1
        }
        _setUpPoaWeights(raw, 1, 6, 16);
        _admitNew();
        (uint8 out,) = _electPoa();
        assertEq(out, VRC.ELECT_NO_CANDIDATE, "the growth trial exceeds the raw-total bound");
        assertEq(vr.health(), VRC.HEALTHY);
        // another valid trial: the swap keeps the total within the bound
        _action(A_REMOVE, 3);
        bytes32 rid;
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(vr.output(rid).members.length, 5);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    // ---- the owed boundary survives a closure (astra ruling 2) ----

    function test_owedBoundarySurvivesAClosure() public {
        _setUpPoa(5, 1, 5, 16);
        uint64 id = _registerNew();
        _submit(id);
        _action(A_REMOVE, id); // a Remove of a non-member owes a boundary
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        _recRejected(rid, VRC.REJ_EXPIRED);
        _recClosed(rid);
        _applyAll();
        assertEq(_st(id), REMOVING, "no boundary yet");
        (out, rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED, "still owed after the closure");
        _primary(rid, false);
        assertEq(_st(id), EXITED);
        (out,) = _electPoa();
        assertEq(out, VRC.ELECT_NOT_DUE, "settled by the own Boundary");
    }
}
