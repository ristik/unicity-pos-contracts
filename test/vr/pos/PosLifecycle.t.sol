// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {Member, OutputView} from "../../../src/vr/VRTypes.sol";
import {ElectionPolicy} from "../../../src/p85/ElectionPolicy.sol";
import {
    Delegation,
    DelegationRequest,
    ElectionParams,
    RecordKind,
    RetirementData,
    HolderRetirementData
} from "../../../src/p85/P85Types.sol";

/// @notice The PoS prototype through VR (design 3.8): an election from stake, the handoff, the boundary, a joiner, the exit, the holder
/// facts after every step. AC-LR's PoS half (design section 11).
contract PosLifecycleTest is PosBase {
    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: 10,
            nMax: 16,
            maxM: 4,
            distNum: 1,
            distDen: 1,
            cadenceRounds: 200,
            cadenceSeconds: 100
        });
    }

    function _assertAllFacts() internal view {
        for (uint64 id = 1; id <= custody.nextStakingID(); ++id) {
            _assertFacts(id, 1);
        }
        assertEq(_cursorFact(), custody.recordCursor(), "the facts cursor is custody's cursor");
    }

    /// @dev Elect, publish, acknowledge: the next committee in force.
    function _handoff() internal returns (bytes32 rid) {
        rid = _electFromStake();
        assertEq(vr.publish(rid), VRC.PUB_PENDING, "pending until P85 publishes");
        assertEq(_publishResult(rid), VRC.PUB_PUBLISHED);
        _ackRecord(rid);
        _boundaryRecord(rid, false);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
    }

    function test_anElectionFromStakeHandsOffAndTheBoundaryIsAcknowledged() public {
        _assertAllFacts();
        bytes32 rid = _handoff();
        assertEq(vr.lastAcked(), rid);
        assertEq(custody.lastAckedAssignment(), election.result(rid).assignmentID);
        assertEq(election.openResult(), bytes32(0));
        assertEq(vr.committee().length, N_GENESIS);
        // the exposures use the VR domain: the result's member digest is custody's exposure id, which names VR
        Member[] memory out = vr.output(rid).members;
        assertEq(out.length, N_GENESIS);
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(custody.recordCursor(), vr.recordCursor());
        _assertAllFacts();
    }

    function test_theGenesisSeatDigestIsCustodysMemberDigest() public view {
        Member[] memory c = vr.committee();
        for (uint256 i; i < c.length; ++i) {
            bytes32 eid = _eid(GENESIS_ASSIGNMENT, gid(i));
            assertEq(
                custody.exposureMemberDigest(eid),
                c[i].exposureDigest,
                "custody carries VR's seat digest"
            );
            assertEq(
                c[i].exposureDigest,
                VRCodec.exposureDigest(NETWORK, VR_ADDR, VRC.GENESIS_RESULT, gid(i))
            );
            assertEq(expo(eid).id, gid(i), "the exposure id is in the VR domain");
        }
    }

    function test_theMultisigIsTheAuthorityAndTheGovernor() public view {
        assertEq(address(election.policySource()), address(factory.POLICY()));
        assertEq(factory.POLICY().AUTHORITY(), MULTISIG);
        assertEq(vr.config().governor, MULTISIG);
    }

    function test_onlyTheAdapterElectsAndNoSystemCallerBypassesVR() public {
        _advance(300, 200);
        vm.prank(SYS);
        vm.expectRevert(ElectionPolicy.NotSystem.selector);
        election.elect(ORIGIN);
        vm.expectRevert(ElectionPolicy.NotSystem.selector);
        election.elect(ORIGIN);
    }

    // ---- atomic loss (design 3.8 change 2): every interleaving ----

    uint256 internal constant CUSTODY_LOTS = 27;

    /// @dev Lowers the remaining principal of member `i`'s lot by one base unit, as a settled penalty would, and reports it as Evidence does.
    function _lose(uint256 i) internal {
        bytes32 slot = bytes32(uint256(keccak256(abi.encode(lotOf(gid(i)), CUSTODY_LOTS))) + 1);
        vm.store(address(custody), slot, bytes32(uint256(vm.load(address(custody), slot)) - 1));
        vm.prank(address(evidence));
        election.coverageChanged(gid(i));
    }

    function test_lossBeforePublicationInvalidatesAndBlocksPublication() public {
        bytes32 rid = _electFromStake();
        _lose(1);
        OutputView memory o = vr.output(rid);
        assertEq(o.state, VRC.OUT_INVALIDATED);
        assertEq(o.invalidReason, VRC.INVALID_LOST);
        assertEq(vr.publish(rid), VRC.PUB_PRECONDITION_FAILED);
        vm.expectRevert(ElectionPolicy.CoverageLost.selector);
        election.finalizeCandidate(rid);
        assertEq(vr.health(), VRC.HEALTHY, "a loss is no module fault");
    }

    function test_lossAfterPublicationBeforePrepareInvalidates() public {
        bytes32 rid = _electFromStake();
        _publishResult(rid);
        assertEq(_state(rid), VRC.OUT_PUBLISHED);
        _lose(2);
        assertEq(_state(rid), VRC.OUT_INVALIDATED, "Freeze is refused on an Invalidated output");
        assertEq(vr.output(rid).invalidReason, VRC.INVALID_LOST);
    }

    function test_lossAfterOutputRejectedIsANoOp() public {
        bytes32 rid = _electFromStake();
        _publishResult(rid);
        _rejectedRecord(rid, 1);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_REJECTED);
        _lose(0);
        assertEq(_state(rid), VRC.OUT_REJECTED, "no-op");
        assertEq(vr.output(rid).invalidReason, 0);
        _closedRecord(rid);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_CLOSED);
        assertEq(election.openResult(), bytes32(0));
        _assertAllFacts();
    }

    function test_lossInASplitBatchBetweenOutputRejectedAndSessionClosedIsANoOp() public {
        bytes32 rid = _electFromStake();
        _publishResult(rid);
        _rejectedRecord(rid, 1);
        _closedRecord(rid);
        _vrApply(1); // OutputRejected only
        assertEq(_state(rid), VRC.OUT_REJECTED);
        assertEq(election.openResult(), rid, "P85's session is still open");
        _lose(3);
        assertEq(_state(rid), VRC.OUT_REJECTED);
        _vrApply(1); // SessionClosed
        assertEq(_state(rid), VRC.OUT_CLOSED);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_lossAfterTheAckBlockBeforeTheAckImportIsInvalidatedThenAcknowledged() public {
        bytes32 rid = _electFromStake();
        _publishResult(rid);
        _ackRecord(rid);
        _boundaryRecord(rid, false);
        _lose(1); // user transactions resume before VR imports the Ack
        assertEq(_state(rid), VRC.OUT_INVALIDATED);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED, "a committed H always wins");
        assertEq(vr.lastAcked(), rid);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_lossAfterTheOutputIsTerminalIsANoOp() public {
        bytes32 rid = _handoff();
        vm.prank(address(election));
        adapter.outputLost(rid); // no revert, nothing written
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
        vm.expectRevert(ElectionPolicy.NotReserved.selector);
        election.reconcileCandidate(rid);
    }

    function test_onlyTheElectionMayReportALoss() public {
        bytes32 rid = _electFromStake();
        vm.expectRevert(abi.encodeWithSignature("NotElection()"));
        adapter.outputLost(rid);
    }

    /// @dev With too little gas the whole loss transaction reverts (the `lost` bit is not set without the invalidation) and can be
    /// retried; with enough gas it always succeeds.
    function test_theLossIsAtomicAtEveryGasLevel() public {
        bytes32 rid = _electFromStake();
        _publishResult(rid);
        bytes32 slot = bytes32(uint256(keccak256(abi.encode(lotOf(gid(1)), CUSTODY_LOTS))) + 1);
        vm.store(address(custody), slot, bytes32(uint256(vm.load(address(custody), slot)) - 1));
        uint256 succeeded;
        for (uint256 g = 20_000; g <= 140_000; g += 6_000) {
            uint256 snap = vm.snapshotState();
            vm.prank(address(evidence));
            (bool ok,) = address(election).call{gas: g}(
                abi.encodeCall(ElectionPolicy.coverageChanged, (gid(1)))
            );
            bool lost = election.publication(rid).lost;
            uint8 st = _state(rid);
            if (ok) {
                assertTrue(lost && st == VRC.OUT_INVALIDATED, "success is both");
                ++succeeded;
            } else {
                assertTrue(!lost && st == VRC.OUT_PUBLISHED, "failure is neither");
            }
            vm.revertToState(snap);
        }
        assertGt(succeeded, 0, "enough gas succeeds");
    }

    // ---- a PoS joiner and a PoS exit ----

    function test_aPoSJoinerIsElectedAndTheCommitteeIncludesIt() public {
        Joiner memory j = _joinPos(1_000 * UCT);
        evmPkOf[j.id] = j.evmPk;
        assertEq(j.id, 5);
        bytes32 rid = _elect2();
        _ackNext(rid);
        Member[] memory c = vr.committee();
        assertEq(c.length, 5);
        assertEq(c[4].id, j.id);
        assertEq(c[4].payee, j.payee);
        assertEq(vr.health(), VRC.HEALTHY);
        _assertAllFacts();
    }

    function test_aPoSExitRequestRetirementExcludedHolderRetirementMatureClaim() public {
        Joiner memory j = _joinPos(1_000 * UCT);
        evmPkOf[j.id] = j.evmPk;
        bytes32 r1 = _elect2();
        _ackNext(r1); // J = genesis + joiner
        // the genesis assignment closes
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, lastH, "genesis"));
        _vrApplyAll();
        assertEq(
            custody.liveExposures(1, 1), 1, "genesis exposures are released at closure, r1's remain"
        );

        // the joiner asks to retire: it is excluded at the next election
        vm.prank(vm.addr(j.ownerPk));
        custody.requestRetirement(j.id);
        requestedSeen[j.id][1] = true;
        _assertFacts(j.id, 1);
        bytes32 r2 = _elect2();
        assertEq(election.frozenMembers(r2).length, 4, "the retiring identity is excluded");
        _ackNext(r2);
        assertEq(vr.committee().length, 4);

        // r1's assignment closes; only then does the joiner's last reference go
        bytes32 a1 = election.result(r1).assignmentID;
        assertEq(custody.liveExposures(j.id, 1), 1);
        _assertFacts(j.id, 1);
        pushRecord(RecordKind.Closure, closureData(a1, lastH, "r1"));
        _vrApplyAll();
        assertEq(custody.liveExposures(j.id, 1), 0);
        _assertFacts(j.id, 1);

        _advance(400, 400); // past the liability anchor
        // HolderRetirement for holder 0 authorizes; custody applies its own protection rules
        pushRecord(
            RecordKind.HolderRetirement,
            abi.encode(HolderRetirementData(0, j.id, 1, custody.exposureChain(j.id, 1)))
        );
        _vrApplyAll();
        (bool imported,,) = custody.retirements(j.id, 1);
        assertTrue(imported, "HolderRetirement retired it");
        _advance(100_000, 100_000);
        uint256 lot = lotOf(j.id);
        uint256[] memory lots = new uint256[](1);
        lots[0] = lot;
        custody.mature(lots);
        address wd = vm.addr(j.ownerPk);
        uint256 credit = custody.credit(wd);
        assertEq(credit, 1_000 * UCT);
        vm.prank(wd);
        custody.claim(credit, wd);
        assertEq(wd.balance, 1_000 * UCT, "claimed");
        _assertAllFacts();
    }

    function test_theRetirementRequestBarrierRefusesNewPrimaryObligations() public {
        Joiner memory j = _joinPos(1_000 * UCT);
        evmPkOf[j.id] = j.evmPk;
        vm.prank(vm.addr(j.ownerPk));
        custody.requestRetirement(j.id);
        bytes32 rid = _electFromStake();
        assertEq(
            election.frozenMembers(rid).length,
            N_GENESIS,
            "a requested key takes no new primary obligation"
        );
    }

    /// @dev VR's CAP_ELECT (4,000,000) carries the PoS election only to a small committee: growing it one election at a time, a contained
    /// step eventually fails, which VR records as a module fault (outcome 3, health Faulted). The 16-member election needs 7.9 M
    /// (PosSixteen): owner-questions.md.
    function test_throughVRTheElectionExceedsTheCapForALargerCommittee() public {
        uint256 fitted;
        bool faulted;
        for (uint256 k; k < 8 && !faulted; ++k) {
            Joiner memory a = _joinPos(1_000 * UCT);
            evmPkOf[a.id] = a.evmPk;
            _advance(300, 200);
            uint256 g = gasleft();
            uint8 o = _vrElect(ORIGIN);
            uint256 used = g - gasleft();
            if (o != VRC.ELECT_RESERVED) {
                emit log_named_uint("VR.elect gas at the failing election", used);
                assertEq(o, VRC.ELECT_NO_CANDIDATE, "a failed elect step returns outcome 3");
                assertEq(vr.health(), VRC.FAULTED);
                faulted = true;
                break;
            }
            bytes32 r = vr.openOutput();
            assertEq(_publishResult2(r), VRC.PUB_PUBLISHED);
            bytes32 previous = custody.lastAckedAssignment();
            _ackNext(r);
            pushRecord(RecordKind.Closure, closureData(previous, lastH, "prev"));
            _vrApplyAll();
            fitted = vr.committee().length;
        }
        emit log_named_uint("largest committee elected through VR", fitted);
        assertTrue(faulted, "the cap is reached before 16 members");
        assertGe(fitted, 6);
        assertLt(fitted, 16);
    }

    /// @dev The Ack can reach custody before VR (custody's `applyRootRecords` is permissionless). That resolves P85's result, so a later loss
    /// has nothing to invalidate and VR still shows Published until it imports the pair: the outcome (Acknowledged) is the same as in the
    /// VR-first order (test_lossAfterTheAckBlockBeforeTheAckImportIsInvalidatedThenAcknowledged); only the intermediate state differs.
    function test_custodyFirstAckImportLeavesVRPublishedThenAcknowledged() public {
        bytes32 rid = _electFromStake();
        _publishResult(rid);
        _ackRecord(rid);
        _boundaryRecord(rid, false);
        custody.applyRootRecords(2); // custody imports the Ack (and skips the Boundary) before VR
        assertEq(election.openResult(), bytes32(0), "P85 resolved the result");
        _lose(1); // nothing reserved to mark: no loss, no invalidation
        assertEq(_state(rid), VRC.OUT_PUBLISHED, "VR has not imported yet");
        _vrApplyAll(); // the adapter finds custody ahead and does nothing; VR acknowledges
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
        assertEq(vr.lastAcked(), rid);
        assertEq(custody.recordCursor(), vr.recordCursor());
        _assertAllFacts();
    }

    /// @dev A misaligned identity (its delegation is not its VR binding) is not eligible, so it cannot be selected and hold up rotations: an
    /// aligned alternative is elected and the rotation goes through.
    function test_aMisalignedIdentityIsNotEligibleAndAnAlignedOneIsElected() public {
        Joiner memory bad = _joinPosX(1_000 * UCT, true);
        evmPkOf[bad.id] = bad.evmPk;
        Joiner memory good = _joinPos(1_000 * UCT);
        evmPkOf[good.id] = good.evmPk;
        bytes32 rid = _elect2();
        ElectionPolicy.Frozen[] memory f = election.frozenMembers(rid);
        assertEq(f.length, N_GENESIS + 1);
        assertEq(f[N_GENESIS].id, good.id);
        _ackNext(rid);
        assertEq(vr.committee().length, N_GENESIS + 1);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    /// @dev A delegation changed after the snapshot cannot make the aligned frozen member unservable: VR is the authority for the words.
    function test_aLaterDelegationDoesNotMakeAFrozenAlignedSnapshotUnservable() public {
        bytes32 rid = _electFromStake();
        (Delegation memory d,, uint64 nonce) = election.delegation(1, 1);
        DelegationRequest memory dr;
        dr.id = 1;
        dr.generation = 1;
        dr.binding = d;
        dr.binding.operatorPayee = address(0xBEEF);
        dr.delegationNonce = nonce;
        dr.expiry = type(uint64).max;
        bytes32 dd = election.delegationDigest(dr);
        election.admitDelegation(dr, sign(ownerPk(0), dd), sign(evmPk(0), dd));
        assertEq(
            _publishResult(rid),
            VRC.PUB_PUBLISHED,
            "served from the frozen exposure and VR's binding"
        );
        _ackRecord(rid);
        _boundaryRecord(rid, false);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
    }
}
