// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {ElectionPolicy} from "../../../src/p85/ElectionPolicy.sol";
import {Limits, ElectionParams, RecordKind, RecoveryAckData} from "../../../src/p85/P85Types.sol";

/// @notice The prototype's supported deployment limit, through VR (sol review of #92, findings 1 and 2): a committee of at most 6 (nMax)
/// drawn from an index of at most 8 identities (vMax) of one lot each (lMax). The genesis script refuses more
/// (PosGenesis.test_theGenesisRefusesALimitAboveTheMeasuredOne); ElectionPolicy refuses a ninth registration (IndexFull). At that limit
/// the election, `outputOf` (publication) and a RecoveryAck of the maximum K, with its lot references, run inside VR's callback caps.
contract PosLimitTest is PosBase {
    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: 6,
            nMax: 6,
            maxM: 4,
            distNum: 1,
            distDen: 1,
            cadenceRounds: 200,
            cadenceSeconds: 100
        });
    }

    function _manifestLimits() internal pure override returns (Limits memory) {
        return Limits({vMax: 8, lMax: 1, rMax: 4, maxBatch: 32});
    }

    /// @dev Six members elected through VR, then two outsiders that outrank the incumbents fill the index (V = 8).
    function _atTheLimit() internal {
        for (uint256 k; k < 2; ++k) {
            Joiner memory a = _joinPos(1_000 * UCT);
            evmPkOf[a.id] = a.evmPk;
            bytes32 r = _elect2();
            bytes32 previous = custody.lastAckedAssignment();
            _ackNext(r);
            pushRecord(RecordKind.Closure, closureData(previous, lastH, "prev"));
            _vrApplyAll();
        }
        assertEq(vr.committee().length, 6);
        for (uint256 k; k < 2; ++k) {
            Joiner memory o = _joinPos(1_100 * UCT);
            evmPkOf[o.id] = o.evmPk;
        }
        assertEq(election.liveCount(), 8);
    }

    function test_theIndexRefusesANinthIdentity() public {
        _atTheLimit();
        vm.expectRevert(ElectionPolicy.IndexFull.selector);
        this.joinExtra();
    }

    function joinExtra() external {
        _joinPos(1_000 * UCT);
    }

    /// @dev Cold, at the limit: the election with the committee at nMax and the index full (V = 8), outsiders outranking incumbents.
    function test_electionAndPublicationAtTheLimitFitTheCapsCold() public {
        _atTheLimit();
        _advance(300, 200);
        _coolAll();
        uint256 g = gasleft();
        uint8 o = _vrElect(ORIGIN);
        uint256 used = g - gasleft();
        emit log_named_uint("cold VR.elect at the limit (committee 6, index 8)", used);
        assertEq(o, VRC.ELECT_RESERVED);
        assertEq(vr.health(), VRC.HEALTHY);
        assertLt(used, 4_000_000, "inside CAP_ELECT");
        bytes32 rid = vr.openOutput();
        election.submitAssignmentPoPs(rid, _popsFor2(rid));
        election.finalizeCandidate(rid);
        _coolAll();
        g = gasleft();
        assertEq(vr.publish(rid), VRC.PUB_PUBLISHED);
        emit log_named_uint("cold VR.publish (outputOf, 6 members)", g - gasleft());
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(election.frozenMembers(rid).length, 6);
    }

    function _popsFor2(bytes32 rid) internal returns (ElectionPolicy.PoPInput[] memory pops) {
        ElectionPolicy.Frozen[] memory f = election.frozenMembers(rid);
        pops = new ElectionPolicy.PoPInput[](f.length);
        for (uint256 k; k < f.length; ++k) {
            uint256 pk = f[k].id <= N_GENESIS ? evmPk(f[k].id - 1) : evmPkOf[f[k].id];
            bytes memory key = compressed(pk);
            pops[k] = ElectionPolicy.PoPInput(
                f[k].id, key, sign(pk, election.popDigest(rid, f[k].id, keccak256(key)))
            );
        }
    }

    function _growTo(uint256 n) internal {
        while (vr.committee().length < n) {
            Joiner memory a = _joinPos(1_000 * UCT);
            evmPkOf[a.id] = a.evmPk;
            bytes32 r = _elect2();
            bytes32 previous = custody.lastAckedAssignment();
            _ackNext(r);
            pushRecord(RecordKind.Closure, closureData(previous, lastH, "prev"));
            _vrApplyAll();
        }
    }

    function _recoveryAt(uint256 k) internal returns (uint256 used) {
        _growTo(k);
        _advance(300, 200);
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED);
        bytes32 rid = vr.openOutput();
        assertEq(_publishResult2(rid), VRC.PUB_PUBLISHED);
        _advance(10, 10);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(
                RecoveryAckData(
                    rid,
                    keccak256("rec"),
                    progress + 5,
                    progress + 6,
                    100 + progress,
                    progress + 7,
                    progress + 8,
                    3,
                    3
                )
            )
        );
        _boundaryRecord(rid, true);
        _coolAll();
        uint256 g = gasleft();
        _vrApply(1); // the RecoveryAck record alone: one record of an onRecords segment, capped at CAP_RECORD
        used = g - gasleft();
    }

    /// @dev FINDING (sol #92 finding 2): a RecoveryAck derives K exposures in one record, about 390 k each cold with the holder facts, and VR
    /// gives a record 1,500,000. Even the smallest committee (K = 4, nMin) does not fit, so a PoS generation's recovery faults VR (outcome:
    /// health Faulted, the cursors still advance together after custody's catch-up). The prototype therefore supports ordinary rotations
    /// only; a supported recovery needs custody's per-exposure storage cut (astra's option 2) or a higher CAP_RECORD. This pins the boundary.
    function test_aRecoveryAckThroughVRExceedsCapRecordEvenAtK4() public {
        uint256 used = _recoveryAt(4);
        emit log_named_uint("cold K=4 RecoveryAck record through VR", used);
        assertEq(vr.health(), VRC.FAULTED, "CAP_RECORD 1,500,000 is below the K = 4 recovery");
        // custody's catch-up is permissionless: the cursors match once it has applied the record itself
        custody.applyRootRecords(1);
        assertEq(custody.assignmentExposures(keccak256("rec")).length, 4);
        for (uint64 id = 1; id <= 4; ++id) {
            _assertFacts(id, 1);
        }
        assertEq(_cursorFact(), custody.recordCursor());
    }

    function _recoveryDirect(uint256 k) internal returns (uint256 used) {
        _growTo(k);
        _advance(300, 200);
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED);
        bytes32 rid = vr.openOutput();
        assertEq(_publishResult2(rid), VRC.PUB_PUBLISHED);
        _advance(10, 10);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(
                RecoveryAckData(
                    rid,
                    keccak256("rec"),
                    progress + 5,
                    progress + 6,
                    100 + progress,
                    progress + 7,
                    progress + 8,
                    3,
                    3
                )
            )
        );
        _coolAll();
        uint256 g = gasleft();
        custody.applyRootRecords(1);
        used = g - gasleft();
    }

    function test_measureDirectK4() public {
        emit log_named_uint("cold custody RecoveryAck K=4", _recoveryDirect(4));
    }

    function test_measureDirectK5() public {
        emit log_named_uint("cold custody RecoveryAck K=5", _recoveryDirect(5));
    }

    function test_measureDirectK6() public {
        emit log_named_uint("cold custody RecoveryAck K=6", _recoveryDirect(6));
    }
}
