// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {Member, OutputView, Registration, IdentityView} from "../../../src/vr/VRTypes.sol";
import {ElectionPolicy, ElectionStorage} from "../../../src/p85/ElectionPolicy.sol";
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
        vm.expectRevert(ElectionStorage.NotSystem.selector);
        election.elect(ORIGIN);
        vm.expectRevert(ElectionStorage.NotSystem.selector);
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
        vm.expectRevert(ElectionStorage.CoverageLost.selector);
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
        vm.expectRevert(ElectionStorage.NotReserved.selector);
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
        for (uint256 g = 20_000; g <= 220_000; g += 6_000) {
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
        _anchorIfClosed(a1, "r1");
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

    function test_legacyReservationCanExhaustTheOriginalElectionStipend() public {
        for (uint256 k; k < 8; ++k) {
            Joiner memory a = _joinPos(1_000 * UCT);
            evmPkOf[a.id] = a.evmPk;
            bytes32 r = _elect2();
            bytes32 previous = custody.lastAckedAssignment();
            _ackNext(r);
            pushRecord(RecordKind.Closure, closureData(previous, lastH, "prev"));
            _vrApplyAll();
        }
        _advance(300, 200);
        bytes memory ctx = abi.encode(
            ORIGIN,
            uint256(progress),
            uint256(ucTime),
            uint256(1),
            vr.lastAcked(),
            VRCodec.limitsWord(4, 10, 16),
            uint256(0),
            uint256(0)
        );
        _coolAll();
        vm.prank(VR_ADDR);
        (bool ok, bytes memory result) =
            address(adapter).call{gas: 4_000_000}(abi.encodeCall(adapter.elect, (ctx)));
        if (ok) {
            (, uint8 outcome,,) = VRCodec.decodeElect(result);
            assertTrue(
                outcome != VRC.ELECT_RESERVED, "old stipend cannot reserve this legacy slate"
            );
        }
        assertEq(election.openResult(), bytes32(0));
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
        ElectionStorage.Frozen[] memory f = election.frozenMembers(rid);
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

    /// @dev astra r2: the adapter compares VR's complete candidate binding with the frozen binding hash. A staged VR binding replaced at the
    /// same prospective generation (same keys and payee, other node words) is not served; the same binding is. VR's `bindingOf` is mocked
    /// so that the identity's current binding does not match and the staged one is the candidate.
    function test_aStagedVRBindingWithOtherNodeWordsIsNotServed() public {
        bytes32 rid = _electFromStake();
        election.submitAssignmentPoPs(rid, _pops(rid, _allIdx()));
        election.finalizeCandidate(rid);
        assertEq(
            VRCodec.wordAt(adapter.outputOf(rid), 0),
            VRC.STATUS_READY,
            "Ready with the real bindings"
        );
        Member memory real = vr.bindingOf(1, false);
        Member memory none;
        vm.mockCall(VR_ADDR, abi.encodeCall(vr.bindingOf, (1, false)), abi.encode(none));
        vm.mockCall(VR_ADDR, abi.encodeCall(vr.bindingOf, (1, true)), abi.encode(real));
        assertEq(
            VRCodec.wordAt(adapter.outputOf(rid), 0),
            VRC.STATUS_READY,
            "the identical staged binding is served"
        );
        Member memory other = real;
        other.evmNodeWord = keccak256("another evm node");
        vm.mockCall(VR_ADDR, abi.encodeCall(vr.bindingOf, (1, true)), abi.encode(other));
        assertEq(
            VRCodec.wordAt(adapter.outputOf(rid), 0),
            VRC.STATUS_NOT_MINE,
            "other node words: not the frozen binding"
        );
        Member memory payee = real;
        payee.payee = address(0xBEEF);
        vm.mockCall(VR_ADDR, abi.encodeCall(vr.bindingOf, (1, true)), abi.encode(payee));
        assertEq(VRCodec.wordAt(adapter.outputOf(rid), 0), VRC.STATUS_NOT_MINE);
    }

    // ---- #1286: recovering a bonded identity whose EVM authority is lost (astra: delegation first, the generation is custody's) ----

    /// @dev Genesis identity `i`'s binding with a fresh EVM node id and key; the root node, root key and payee stay.
    function _rotatedEvm(uint256 i, uint256 newEvmPk) internal returns (Registration memory r) {
        string memory letter = string(abi.encodePacked(bytes1(uint8(97 + i))));
        r = Registration({
            rootNodeID: string.concat("root-", letter),
            rootKey: _rootKey(i),
            evmNodeID: string.concat("evm-", letter, "-", vm.toString(newEvmPk)),
            evmKey: compressed(newEvmPk),
            payee: vm.addr(payeePk(i)),
            nonce: 0
        });
    }

    function _custodyGeneration(uint64 id) internal view returns (uint64 g) {
        (,,,, g,,,,) = custody.positions(id);
    }

    /// @dev `admitDelegation` of `r`'s words at custody's current generation, signed by the owner and the new EVM key.
    function _admitWords(uint64 id, uint256 ownerKey, uint256 evmKey, Registration memory r)
        internal
    {
        (,,,, uint64 g, uint64 roleNonce,,,) = custody.positions(id);
        (,, uint64 nonce) = election.delegation(id, g);
        DelegationRequest memory dr;
        dr.id = id;
        dr.generation = g;
        dr.binding = Delegation({
            rootNodeID: keccak256(bytes(r.rootNodeID)),
            rootKey: r.rootKey,
            evmNodeID: keccak256(bytes(r.evmNodeID)),
            evmKey: r.evmKey,
            operatorPayee: r.payee
        });
        dr.roleNonce = roleNonce;
        dr.delegationNonce = nonce;
        dr.expiry = type(uint64).max;
        bytes32 dd = election.delegationDigest(dr);
        election.admitDelegation(dr, sign(ownerKey, dd), sign(evmKey, dd));
    }

    /// @dev `VR.proposeBinding` of the same words, both keys proving possession.
    function _stageWords(
        uint64 id,
        uint256 ownerKey,
        uint256 rootKey,
        uint256 evmKey,
        Registration memory r
    ) internal {
        r.nonce = vr.identity(id).bindingNonce;
        address owner = vm.addr(ownerKey);
        bytes32 d = keccak256(
            abi.encode(
                VRC.BINDING_DOMAIN,
                NETWORK,
                block.chainid,
                VR_ADDR,
                owner,
                uint256(id),
                keccak256(bytes(r.rootNodeID)),
                keccak256(r.rootKey),
                keccak256(bytes(r.evmNodeID)),
                keccak256(r.evmKey),
                r.payee,
                uint256(r.nonce)
            )
        );
        vm.prank(owner);
        vr.proposeBinding(id, r, sign(rootKey, d), sign(evmKey, d));
    }

    function _refOf(Registration memory r) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(bytes(r.rootNodeID)),
                keccak256(r.rootKey),
                keccak256(bytes(r.evmNodeID)),
                keccak256(r.evmKey),
                r.payee
            )
        );
    }

    function _frozenOf(bytes32 rid, uint64 id)
        internal
        view
        returns (bool found, ElectionStorage.Frozen memory m)
    {
        ElectionStorage.Frozen[] memory f = election.frozenMembers(rid);
        for (uint256 k; k < f.length; ++k) {
            if (f[k].id == id) return (true, f[k]);
        }
    }

    /// @dev The recovery: delegation to the fresh EVM key at the custody generation (it fences the dead key), then the identical words
    /// staged in VR. The next election freezes the new key, a proof by the old key is refused, and the boundary installs the new binding
    /// at the unchanged custody generation; the bond's lots stay where they were.
    function test_anInPlaceEvmRotationIsElectedPublishedAndInstalled() public {
        uint256 newEvm = 0x9101;
        Registration memory r = _rotatedEvm(0, newEvm);
        uint256[] memory lotsBefore = custody.generationLots(1, 1);
        _admitWords(1, ownerPk(0), newEvm, r);
        _stageWords(1, ownerPk(0), rootPk(0), newEvm, r);
        IdentityView memory iv = vr.identity(1);
        assertEq(iv.generation, 1);
        assertEq(iv.stagedRef, _refOf(r), "staged words = delegated words");

        bytes32 rid = _electFromStake();
        (bool found, ElectionStorage.Frozen memory f) = _frozenOf(rid, 1);
        assertTrue(found, "the rotated identity is elected");
        assertEq(f.generation, 1, "at the custody generation");
        (, bytes32 delegated,) = election.delegation(1, 1);
        assertEq(f.bindingHash, delegated, "the frozen binding is the new delegation");

        // the old (dead) key's proof is refused: its key is not the frozen one
        ElectionStorage.PoPInput[] memory old = new ElectionStorage.PoPInput[](1);
        bytes memory oldKey = compressed(evmPk(0));
        old[0] = ElectionStorage.PoPInput(
            1, oldKey, sign(evmPk(0), election.popDigest(rid, 1, keccak256(oldKey)))
        );
        vm.expectRevert(abi.encodeWithSelector(ElectionStorage.WrongEvmKey.selector, uint64(1)));
        election.submitAssignmentPoPs(rid, old);

        evmPkOf[1] = newEvm;
        assertEq(_publishResult2(rid), VRC.PUB_PUBLISHED);
        Member[] memory out = vr.output(rid).members;
        assertEq(out[0].id, 1);
        assertEq(out[0].generation, 1, "VR publishes the custody generation, not VR's staged g + 1");
        assertEq(out[0].evmKeyHash, keccak256(r.evmKey));
        assertEq(out[0].evmNodeWord, keccak256(bytes(r.evmNodeID)));

        _ackNext(rid);
        iv = vr.identity(1);
        assertEq(iv.generation, 1, "VR's installed generation is custody's");
        assertEq(iv.currentRef, _refOf(r), "the new binding is current");
        assertEq(iv.stagedRef, bytes32(0), "and no longer staged");
        assertEq(vr.committee()[0].evmKeyHash, keccak256(r.evmKey));
        // custody's lot lookup at VR's generation finds the same bond, and the exposure names the new key at generation 1
        uint256[] memory lotsAfter = custody.generationLots(1, iv.generation);
        assertEq(lotsAfter.length, lotsBefore.length);
        assertEq(lotsAfter[0], lotsBefore[0], "the bond stays in its lots");
        (, uint64 eid, uint64 eg,,,, bytes32 ek,,,) =
            custody.exposures(_eid(election.result(rid).assignmentID, 1));
        assertEq(eid, 1);
        assertEq(eg, 1);
        assertEq(ek, keccak256(r.evmKey));
        assertEq(vr.health(), VRC.HEALTHY);
        _assertAllFacts();

        // the installed identity stays electable at the same generation with its new key
        bytes32 r2 = _elect2();
        _ackNext(r2);
        assertEq(vr.identity(1).generation, 1);
        assertEq(vr.committee()[0].evmKeyHash, keccak256(r.evmKey));
    }

    /// @dev Delegation first: with only the new delegation (not yet staged in VR) the identity is not eligible, so the dead key is fenced
    /// from the next snapshot; once the identical words are staged it is elected with the new key.
    function test_delegationFirstFencesTheDeadKey() public {
        Joiner memory j = _joinPos(1_000 * UCT);
        evmPkOf[j.id] = j.evmPk;
        uint256 newEvm = 0x9102;
        Registration memory r = _rotatedEvm(0, newEvm);
        _admitWords(1, ownerPk(0), newEvm, r);
        bytes32 rid = _elect2();
        (bool found,) = _frozenOf(rid, 1);
        assertFalse(found, "delegated but not staged in VR: not eligible");
        assertEq(election.frozenMembers(rid).length, N_GENESIS);
        _ackNext(rid);

        _stageWords(1, ownerPk(0), rootPk(0), newEvm, r);
        evmPkOf[1] = newEvm;
        bytes32 r2 = _elect2();
        (found,) = _frozenOf(r2, 1);
        assertTrue(found, "staged: elected with the new key");
        _ackNext(r2);
        assertEq(vr.identity(1).currentRef, _refOf(r));
        assertEq(vr.identity(1).generation, 1);
    }

    /// @dev The stall this ordering avoids (regression): a VR stage alone leaves the old delegation aligned with VR's current binding, so
    /// the identity is still elected with the old key, and only the old (dead) key can prove possession.
    function test_aVRStageOnlyRotationStillElectsTheOldKey() public {
        uint256 newEvm = 0x9103;
        Registration memory r = _rotatedEvm(0, newEvm);
        _stageWords(1, ownerPk(0), rootPk(0), newEvm, r);
        bytes32 rid = _electFromStake();
        (bool found, ElectionStorage.Frozen memory f) = _frozenOf(rid, 1);
        assertTrue(found, "still eligible with the old delegation");
        (, bytes32 delegated,) = election.delegation(1, 1);
        assertEq(f.bindingHash, delegated);
        ElectionStorage.PoPInput[] memory nw = new ElectionStorage.PoPInput[](1);
        nw[0] = ElectionStorage.PoPInput(
            1, r.evmKey, sign(newEvm, election.popDigest(rid, 1, keccak256(r.evmKey)))
        );
        vm.expectRevert(abi.encodeWithSelector(ElectionStorage.WrongEvmKey.selector, uint64(1)));
        election.submitAssignmentPoPs(rid, nw);
        assertEq(_publishResult(rid), VRC.PUB_PUBLISHED, "only the old key's proof publishes");
    }

    /// @dev A full exit and a re-bond with the same keys: custody opens generation 2, the same words are delegated at 2 (VR's current
    /// binding is unchanged, so nothing is staged), the identity is elected at 2 and VR installs 2.
    function test_aSameKeyRejoinAtTheNextGeneration() public {
        Joiner memory j = _joinPos(1_000 * UCT);
        evmPkOf[j.id] = j.evmPk;
        bytes32 r1 = _elect2();
        _ackNext(r1);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, lastH, "genesis"));
        _vrApplyAll();
        vm.prank(vm.addr(j.ownerPk));
        custody.requestRetirement(j.id);
        bytes32 r2 = _elect2();
        _ackNext(r2);
        bytes32 a1 = election.result(r1).assignmentID;
        pushRecord(RecordKind.Closure, closureData(a1, lastH, "r1"));
        _vrApplyAll();
        _anchorIfClosed(a1, "r1");
        _advance(400, 400);
        pushRecord(
            RecordKind.HolderRetirement,
            abi.encode(HolderRetirementData(0, j.id, 1, custody.exposureChain(j.id, 1)))
        );
        _vrApplyAll();
        _advance(100_000, 100_000);
        uint256[] memory lots = new uint256[](1);
        lots[0] = lotOf(j.id);
        custody.mature(lots);
        assertEq(vr.identity(j.id).generation, 1);

        bondFor(j.id, 1_000 * UCT);
        assertEq(_custodyGeneration(j.id), 2, "the re-bond opens custody generation 2");
        Registration memory same = Registration({
            rootNodeID: string.concat("root-j", vm.toString(uint256(1))),
            rootKey: compressed(j.rootPk),
            evmNodeID: string.concat("evm-j", vm.toString(uint256(1))),
            evmKey: compressed(j.evmPk),
            payee: j.payee,
            nonce: 0
        });
        assertEq(vr.identity(j.id).currentRef, _refOf(same), "VR's current binding is the same");
        _admitWords(j.id, j.ownerPk, j.evmPk, same);
        bytes32 r3 = _elect2();
        (bool found, ElectionStorage.Frozen memory f) = _frozenOf(r3, j.id);
        assertTrue(found, "the same keys rejoin");
        assertEq(f.generation, 2);
        Member[] memory out = vr.output(r3).members;
        assertEq(out[out.length - 1].id, j.id);
        assertEq(out[out.length - 1].generation, 2, "published at custody generation 2");
        _ackNext(r3);
        assertEq(vr.identity(j.id).generation, 2, "VR installs generation 2");
        assertEq(custody.generationLots(j.id, 2).length, 1, "custody's lots of generation 2");
        assertEq(vr.health(), VRC.HEALTHY);
    }

    /// @dev VR refuses a PoS output whose member generation is not custody's for that identity, even with a valid ref and a generation
    /// above VR's (an invented future generation would otherwise be installed): the module faults instead of publishing.
    function test_anInventedFutureGenerationIsRefused() public {
        bytes32 rid = _electFromStake();
        election.submitAssignmentPoPs(rid, _pops(rid, _allIdx()));
        election.finalizeCandidate(rid);
        // VR decodes the module's return data as is (the ABI envelope of the packed words)
        (bool ok, bytes memory real) = ADAPTER.staticcall(abi.encodeCall(adapter.outputOf, (rid)));
        assertTrue(ok);
        (uint8 err, uint8 status, VRCodec.OutputHeader memory h, Member[] memory ms) =
            VRCodec.decodeOutput(real);
        assertEq(err, VRCodec.OK);
        assertEq(status, VRC.STATUS_READY);
        assertEq(ms[0].generation, 1);
        assertEq(abi.encode(VRCodec.packOutput(h, ms)), real, "the codec round-trips the output");

        uint256 snap = vm.snapshotState();
        vm.mockCall(
            ADAPTER, abi.encodeCall(adapter.outputOf, (rid)), abi.encode(VRCodec.packOutput(h, ms))
        );
        assertEq(vr.publish(rid), VRC.PUB_PUBLISHED, "the re-packed real output publishes");
        vm.revertToState(snap);

        ms[0].generation = 2; // the current ref, a generation above VR's 1, but custody's is 1
        vm.mockCall(
            ADAPTER, abi.encodeCall(adapter.outputOf, (rid)), abi.encode(VRCodec.packOutput(h, ms))
        );
        assertEq(vr.publish(rid), VRC.PUB_PRECONDITION_FAILED);
        assertEq(vr.health(), VRC.FAULTED, "an invented generation is a module fault");
        assertEq(_state(rid), VRC.OUT_RESERVED, "never published");
    }

    /// @dev A staged ref replaced after the snapshot froze it is not served: the frozen binding hash names the replaced words.
    function test_aReplacedStagedRefIsNotServed() public {
        uint256 newEvm = 0x9104;
        Registration memory r = _rotatedEvm(0, newEvm);
        _admitWords(1, ownerPk(0), newEvm, r);
        _stageWords(1, ownerPk(0), rootPk(0), newEvm, r);
        bytes32 rid = _electFromStake();
        evmPkOf[1] = newEvm;
        ElectionStorage.Frozen[] memory f = election.frozenMembers(rid);
        ElectionStorage.PoPInput[] memory pops = new ElectionStorage.PoPInput[](f.length);
        for (uint256 k; k < f.length; ++k) {
            uint256 pk = evmPkOf[f[k].id] != 0 ? evmPkOf[f[k].id] : evmPk(f[k].id - 1);
            bytes memory key = compressed(pk);
            pops[k] = ElectionStorage.PoPInput(
                f[k].id, key, sign(pk, election.popDigest(rid, f[k].id, keccak256(key)))
            );
        }
        election.submitAssignmentPoPs(rid, pops);
        election.finalizeCandidate(rid);
        assertEq(VRCodec.wordAt(adapter.outputOf(rid), 0), VRC.STATUS_READY);
        uint256 third = 0x9105;
        _stageWords(1, ownerPk(0), rootPk(0), third, _rotatedEvm(0, third));
        assertEq(
            VRCodec.wordAt(adapter.outputOf(rid), 0),
            VRC.STATUS_NOT_MINE,
            "the frozen staged words were replaced: not served"
        );
        assertEq(vr.publish(rid), VRC.PUB_NOT_MINE);
        assertEq(vr.health(), VRC.HEALTHY, "no fault: the adapter serves nothing");
    }
}
