// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {CustodyStorage} from "../../src/p85/CustodyStorage.sol";
import {RootVoteCbor} from "../../src/p85/RootVoteCbor.sol";
import {CaseView} from "../../src/p85/IP85.sol";
import {RecordKind, ReserveInput} from "../../src/p85/P85Types.sol";

/// @notice The post-term seal offence (#1297) against the installed B1 history (the mock's strict mode) and custody's applied Closure.
///
/// Root epoch 1 is the genesis committee: the four genesis root keys, weight 10 each (total 40, threshold floor(80/3) + 1 = 27, so three
/// signers suffice and two do not), signing scheme 2, start 1, closed at A* = 101. Epoch 2 starts at A* = J's first round and was activated
/// by G's H record. G is the custody assignment of root epoch 1; H is ordered at round 100; its Closure applies at progress 150 / UC 1,200
/// unless a test says otherwise, so p0 = 150 and t0 = 1,200: the report deadline is p <= 1,150 OR t <= 1,200 + 1,800 = 3,000.
contract PostTermEvidenceTest is P85Flow {
    uint64 internal constant A_STAR = 101;
    bytes32 internal constant TAG = "genesis";
    bytes32 internal constant OTHER = keccak256("a state the old committee never handed over");

    function _hID() internal pure returns (bytes32) {
        return keccak256(abi.encode("H", TAG));
    }

    function _rH() internal pure returns (bytes32) {
        return keccak256(abi.encode("R_H", TAG));
    }

    function setUp() public override {
        super.setUp();
        roots.setStrictEpochs(true);
    }

    // --- fixture helpers -----------------------------------------------------------------------------

    function _committee() internal returns (bytes[] memory keys, uint64[] memory weights) {
        keys = new bytes[](N_GENESIS);
        weights = new uint64[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            keys[i] = compressed(rootPk(i));
            weights[i] = 10;
        }
    }

    /// @dev Epoch 1 closed at A*, epoch 2 open from A* and activated by `activation`.
    function _installEpochs(bytes32 activation) internal {
        (bytes[] memory keys, uint64[] memory weights) = _committee();
        roots.installEpoch(1, 1, true, A_STAR, 2, bytes32(0), keys, weights);
        roots.installEpoch(2, A_STAR, false, 0, 2, activation, keys, weights);
    }

    /// @dev The standard history: installed epochs, J acknowledged (H at 100, J from 101), G closed at progress 150 / UC 1,200.
    function _history() internal {
        _installEpochs(_hID());
        handoffExcluding(3);
        closeGenesisAt(150, 1_200);
    }

    function _seal(uint64 commitRound, bytes32 hash)
        internal
        pure
        returns (Evidence.PostTermSeal memory s)
    {
        s.epoch = 1;
        s.commitRound = commitRound;
        s.votingRound = commitRound + 1;
        s.parent = commitRound;
        s.exec = hash;
        s.commitHash = hash;
        s.commitTimestamp = 1_700_000_123;
    }

    function _members(uint256 a, uint256 b, uint256 c) internal pure returns (uint8[] memory m) {
        m = new uint8[](3);
        (m[0], m[1], m[2]) = (uint8(a), uint8(b), uint8(c));
    }

    function _quorumOf(Evidence.PostTermSeal memory s, uint8[] memory members)
        internal
        view
        returns (Evidence.SealQuorum memory q)
    {
        bytes32 d = evidence.postTermSealDigest(s);
        q.members = members;
        q.signatures = new bytes[](members.length);
        for (uint256 i; i < members.length; ++i) {
            q.signatures[i] = signNative(rootPk(members[i]), d);
        }
    }

    function _quorum(Evidence.PostTermSeal memory s)
        internal
        view
        returns (Evidence.SealQuorum memory)
    {
        return _quorumOf(s, _members(0, 1, 2));
    }

    function _submit(Evidence.PostTermSeal memory s, Evidence.SealQuorum memory q, uint256 i)
        internal
        returns (bytes32)
    {
        vm.prank(reporter);
        return evidence.submitPostTermEvidence(s, q, genesisExposure(i));
    }

    function _expectRefused(
        Evidence.PostTermSeal memory s,
        Evidence.SealQuorum memory q,
        uint256 i,
        bytes4 err
    ) internal {
        bytes32 eid = genesisExposure(i);
        vm.expectRevert(err);
        evidence.submitPostTermEvidence(s, q, eid);
    }

    function _settle(bytes32 caseID, uint256 lotID) internal returns (uint256) {
        uint256[] memory ids = new uint256[](1);
        ids[0] = lotID;
        return evidence.settleEvidence(caseID, ids);
    }

    /// @dev The seal digest rebuilt independently of the contract, under any network and genesis.
    function _digestUnder(uint64 n, bytes32 g, Evidence.PostTermSeal memory s)
        internal
        pure
        returns (bytes32)
    {
        bytes32 vh = sha256(
            RootVoteCbor.voteInfo(
                n, RootVoteCbor.voteDomain(g), s.epoch, s.votingRound, s.parent, s.exec, s.timestamp
            )
        );
        return sha256(
            RootVoteCbor.sealSigBytes(
                n, s.commitRound, s.epoch, s.commitTimestamp, vh, s.commitHash
            )
        );
    }

    // --- the offence and its boundary ----------------------------------------------------------------

    function test_aDifferentRootQuorumAtTheSuccessorStartIsCharged() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER); // equality counts
        bytes32 caseID = _submit(s, _quorum(s), 0);
        CaseView memory c = evidence.caseInfo(caseID);
        assertEq(
            c.offenceID,
            evidence.postTermOffenceID(
                1, evidence.postTermSealDigest(s), keccak256(compressed(rootPk(0)))
            )
        );
        assertEq(c.exposureID, genesisExposure(0));
        assertEq(c.id, gid(0));
        assertEq(c.reporter, reporter);
        assertEq(c.budget, 10 * UCT, "1% of the exposed 1,000 UCT");
        assertEq(c.lotCount, 1);
        assertEq(evidence.pendingHolds(lotOf(gid(0))), 1);
        assertTrue(evidence.excluded(gid(0)));
        assertConserved();
    }

    function test_theRoundBelowTheStartIsNotPostTermEvenWithALateVotingRound() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR - 1, OTHER);
        s.votingRound = A_STAR + 50; // the VoteInfo round is past A*, the committed round is not
        s.parent = A_STAR - 1;
        _expectRefused(s, _quorum(s), 0, Evidence.NotPostTerm.selector);
    }

    function test_theScheme2CommittingShapeIsRequired() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        s.votingRound = A_STAR; // commitRound must be below the voting round
        _expectRefused(s, _quorum(s), 0, Evidence.BadStatement.selector);
        s = _seal(A_STAR, OTHER);
        s.parent = s.votingRound; // parent below the voting round
        _expectRefused(s, _quorum(s), 0, Evidence.BadStatement.selector);
        s = _seal(0, OTHER);
        _expectRefused(s, _quorum(s), 0, Evidence.BadStatement.selector);
    }

    function test_aLoneSignerOrTwoOfFourAreBelowTheThreshold() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR + 5, OTHER);
        uint8[] memory one = new uint8[](1);
        _expectRefused(s, _quorumOf(s, one), 0, Evidence.QuorumTooSmall.selector);
        uint8[] memory two = new uint8[](2);
        two[1] = 1;
        _expectRefused(s, _quorumOf(s, two), 0, Evidence.QuorumTooSmall.selector);
        // three of four (30 >= 27) are a quorum
        _submit(s, _quorum(s), 0);
    }

    function test_theFrozenRootIsExemptAtAndAfterTheStart() public {
        _history();
        // H's own commit at c >= A* and an arbitrarily late honest empty-suffix repeat both carry R_H
        Evidence.PostTermSeal memory s = _seal(A_STAR, _rH());
        _expectRefused(s, _quorum(s), 0, Evidence.FrozenRoot.selector);
        s = _seal(A_STAR + 10_000, _rH());
        s.exec = OTHER; // nothing about VI.exec turns a seal over R_H into a charge
        _expectRefused(s, _quorum(s), 0, Evidence.FrozenRoot.selector);
    }

    // --- the installed lineage and the applied Closure -----------------------------------------------

    function test_aMissingClosureIsRefused() public {
        _installEpochs(_hID());
        handoffExcluding(3);
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        _expectRefused(s, _quorum(s), 0, Evidence.TermNotClosed.selector);
    }

    function test_anUninstalledOrDetachedSuccessorIsRefused() public {
        (bytes[] memory keys, uint64[] memory weights) = _committee();
        roots.installEpoch(1, 1, false, 0, 2, bytes32(0), keys, weights);
        handoffExcluding(3);
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        _expectRefused(s, _quorum(s), 0, Evidence.SuccessorUnknown.selector);
        // a successor whose start is not the predecessor's end
        roots.installEpoch(1, 1, true, A_STAR + 1, 2, bytes32(0), keys, weights);
        roots.installEpoch(2, A_STAR, false, 0, 2, _hID(), keys, weights);
        _expectRefused(s, _quorum(s), 0, Evidence.SuccessorUnknown.selector);
    }

    function test_aScheme1EpochIsNotChargeable() public {
        (bytes[] memory keys, uint64[] memory weights) = _committee();
        roots.installEpoch(1, 1, true, A_STAR, 1, bytes32(0), keys, weights);
        roots.installEpoch(2, A_STAR, false, 0, 2, _hID(), keys, weights);
        handoffExcluding(3);
        closeGenesisAt(150, 1_200);
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        _expectRefused(s, _quorum(s), 0, Evidence.UnsupportedScheme.selector);
    }

    function test_aSuccessorActivatedByAnotherHIsARootOnlyTerm() public {
        _installEpochs(keccak256("a root-only handoff's H record"));
        handoffExcluding(3);
        closeGenesisAt(150, 1_200);
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        _expectRefused(s, _quorum(s), 0, Evidence.RootOnlyTerm.selector);
    }

    function test_anHOrderedAtOrAfterTheSuccessorStartConflicts() public {
        (bytes[] memory keys, uint64[] memory weights) = _committee();
        roots.installEpoch(1, 1, true, H_ROUND, 2, bytes32(0), keys, weights);
        roots.installEpoch(2, H_ROUND, false, 0, 2, _hID(), keys, weights);
        handoffExcluding(3);
        closeGenesisAt(150, 1_200);
        Evidence.PostTermSeal memory s = _seal(H_ROUND, OTHER);
        _expectRefused(s, _quorum(s), 0, Evidence.HandoffMismatch.selector);
    }

    function test_aTermWithoutItsOwnAssignmentFailsClosed() public {
        _history();
        // epoch 2 is J's; a seal of epoch 1 cannot be charged to J's exposure, nor epoch 2's seals to G's
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        Evidence.SealQuorum memory q = _quorum(s);
        bytes32 jExposure = exposureID(ASG_J, gid(0));
        vm.expectRevert(Evidence.EpochMismatch.selector);
        evidence.submitPostTermEvidence(s, q, jExposure);
        // epoch 3 activated by a root-only handoff of epoch 2: no custody assignment of root epoch 3 exists, J's is epoch 2
        (bytes[] memory keys, uint64[] memory weights) = _committee();
        roots.installEpoch(2, A_STAR, true, 500, 2, _hID(), keys, weights);
        roots.installEpoch(3, 500, false, 0, 2, keccak256("root-only H"), keys, weights);
        s = _seal(600, OTHER);
        s.epoch = 2;
        q = _quorum(s);
        vm.expectRevert(Evidence.TermNotClosed.selector); // J's term is still open: not post-term attributable
        evidence.submitPostTermEvidence(s, q, jExposure);
    }

    function test_theWrongRootNetworkOrGenesisSignsAnotherStatement() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        assertEq(_digestUnder(ROOT_NETWORK, ROOT_GENESIS, s), evidence.postTermSealDigest(s));
        uint8[] memory m = _members(0, 1, 2);
        bytes32[2] memory wrong = [
            _digestUnder(ROOT_NETWORK + 1, ROOT_GENESIS, s),
            _digestUnder(ROOT_NETWORK, keccak256("other genesis"), s)
        ];
        for (uint256 w; w < 2; ++w) {
            Evidence.SealQuorum memory q;
            q.members = m;
            q.signatures = new bytes[](3);
            for (uint256 i; i < 3; ++i) {
                q.signatures[i] = signNative(rootPk(i), wrong[w]);
            }
            _expectRefused(s, q, 0, Evidence.BadSignature.selector);
        }
    }

    function test_theWrongHistoricalKeyOrAnUnsignedChargedSeatIsRefused() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        // identity 3 holds a seat in epoch 1 but did not sign this quorum
        _expectRefused(s, _quorum(s), 3, Evidence.KeyMismatch.selector);
        // a quorum signed by keys that are not epoch 1's members is not a quorum of the term
        Evidence.SealQuorum memory q = _quorum(s);
        bytes32 d = evidence.postTermSealDigest(s);
        q.signatures[0] = signNative(0x9999, d);
        _expectRefused(s, q, 1, Evidence.BadSignature.selector);
    }

    // --- signatures and the quorum subset ------------------------------------------------------------

    function test_signatureShapesFollowTheStrictNativeRule() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        bytes32 d = evidence.postTermSealDigest(s);
        (uint8 v, bytes32 r, bytes32 sv) = vm.sign(rootPk(1), d);
        uint8 parity = v - 27;
        bytes[6] memory bad = [
            abi.encodePacked(r, sv), // 64 bytes
            abi.encodePacked(r, sv, uint8(1 - parity)), // the opposite parity
            abi.encodePacked(r, sv, uint8(parity + 2)), // recovery ID 2/3: ineligible
            abi.encodePacked(r, bytes32(KN - uint256(sv)), uint8(1 - parity)), // the high-s twin
            abi.encodePacked(r, sv, parity, uint8(0)), // 66 bytes
            abi.encodePacked(bytes32(0), sv, parity) // r = 0
        ];
        for (uint256 i; i < bad.length; ++i) {
            Evidence.SealQuorum memory q = _quorum(s);
            q.signatures[1] = bad[i];
            _expectRefused(s, q, 0, Evidence.BadSignature.selector);
        }
        // the well-formed one verifies
        Evidence.SealQuorum memory ok = _quorum(s);
        ok.signatures[1] = abi.encodePacked(r, sv, parity);
        _submit(s, ok, 0);
    }

    uint256 internal constant KN =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function test_theSubsetIsBoundedStrictlyIncreasingAndEveryExtraMustVerify() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        // a repeated index
        _expectRefused(s, _quorumOf(s, _members(0, 1, 1)), 0, Evidence.BadQuorum.selector);
        // a decreasing order
        _expectRefused(s, _quorumOf(s, _members(0, 2, 1)), 0, Evidence.BadQuorum.selector);
        // an index past the installed members
        Evidence.SealQuorum memory q = _quorumOf(s, _members(0, 1, 2));
        q.members = new uint8[](4);
        (q.members[0], q.members[1], q.members[2], q.members[3]) = (0, 1, 2, 7);
        bytes[] memory sigs = new bytes[](4);
        for (uint256 i; i < 3; ++i) {
            sigs[i] = q.signatures[i];
        }
        sigs[3] = signNative(rootPk(3), evidence.postTermSealDigest(s));
        q.signatures = sigs;
        bytes32 eid = genesisExposure(0);
        vm.expectRevert(); // the registry refuses the index
        evidence.submitPostTermEvidence(s, q, eid);
        // a valid quorum with an invalid extra member signature is refused whole
        q.members[3] = 3;
        q.signatures[3] = signNative(rootPk(3), keccak256("another statement"));
        _expectRefused(s, q, 0, Evidence.BadSignature.selector);
        // a count mismatch, an empty and an oversized subset
        q = _quorum(s);
        q.signatures = new bytes[](2);
        _expectRefused(s, q, 0, Evidence.BadQuorum.selector);
        q.members = new uint8[](0);
        q.signatures = new bytes[](0);
        _expectRefused(s, q, 0, Evidence.BadQuorum.selector);
        q.members = new uint8[](17);
        q.signatures = new bytes[](17);
        _expectRefused(s, q, 0, Evidence.BadQuorum.selector);
        // dropping the bad extra leaves an admissible quorum
        _submit(s, _quorum(s), 0);
    }

    // --- one case per statement and signer -----------------------------------------------------------

    function test_aRepeatWithAnotherSubsetOrReporterDebitsOnce() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR + 3, OTHER);
        bytes32 caseID = _submit(s, _quorum(s), 0);
        Evidence.SealQuorum memory q2 = _quorumOf(s, _members(0, 2, 3));
        _expectRefused(s, q2, 0, Evidence.DuplicateOffence.selector);
        Evidence.SealQuorum memory q1 = _quorum(s);
        bytes32 eid = genesisExposure(0);
        vm.prank(makeAddr("another reporter"));
        vm.expectRevert(Evidence.DuplicateOffence.selector);
        evidence.submitPostTermEvidence(s, q1, eid);
        assertEq(evidence.pendingHolds(lotOf(gid(0))), 1);
        assertEq(_settle(caseID, lotOf(gid(0))), 10 * UCT);
        // another signer of the same seal is a separate case
        bytes32 other = _submit(s, q2, 2);
        assertTrue(other != caseID);
        assertEq(evidence.pendingHolds(lotOf(gid(2))), 1);
    }

    function test_aSameRoundEquivocationIsADistinctOffence() public {
        _history();
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        bytes32 post = _submit(s, _quorum(s), 1);
        // the same key equivocates at the same voting epoch and round
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, 1, compressed(rootPk(1)), 1, s.votingRound);
        Evidence.SignedVote memory a = rootVote(h, keccak256("A"), rootPk(1));
        Evidence.SignedVote memory b = rootVote(h, keccak256("B"), rootPk(1));
        vm.prank(reporter);
        bytes32 eq = evidence.submitEvidence(h, a, b, genesisExposure(1));
        assertTrue(post != eq);
        assertTrue(evidence.caseInfo(post).offenceID != evidence.caseInfo(eq).offenceID);
        assertEq(evidence.pendingHolds(lotOf(gid(1))), 2);
    }

    function test_afterKeyRotationTheHistoricalLotSettlesOnceWithCapsAndBounty() public {
        _installEpochs(_hID());
        // identity 1 stages a new root key; J is reserved with it and the Ack activates it
        bytes memory newKey = compressed(0x9501);
        bytes32 digest = keccak256(
            abi.encode(
                keccak256("unicity.p85.pop.proposeRootKey"),
                NETWORK,
                block.chainid,
                address(custody),
                gid(1),
                uint64(1),
                keccak256(newKey),
                uint64(0)
            )
        );
        bytes memory pop = sign(0x9501, digest);
        vm.prank(vm.addr(ownerPk(1)));
        custody.proposeRootKey(gid(1), newKey, pop);
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        in_.members[1].rootKeyHash = keccak256(newKey);
        vm.prank(address(election));
        custody.reserveCandidate(in_);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        closeGenesisAt(150, 1_200);
        (,, bytes32 current,,,,,,) = custody.positions(gid(1));
        assertEq(current, keccak256(newKey), "the new key is active");

        // the OLD key signed a post-term seal of epoch 1: G's historical exposure carries it
        Evidence.PostTermSeal memory s = _seal(A_STAR + 1, OTHER);
        bytes32 caseID = _submit(s, _quorum(s), 1);
        uint256 lot = lotOf(gid(1));
        uint256 treasuryBefore = creditOf(treasury);
        uint256 debit = _settle(caseID, lot);
        assertEq(debit, 10 * UCT, "1% of 1,000 UCT, below the 5% lifetime cap");
        assertEq(creditOf(reporter), 1 * UCT, "10% bounty, capped at 1 UCT");
        assertEq(creditOf(treasury) - treasuryBefore, 9 * UCT);
        assertEq(lotv(lot).penalized, 10 * UCT);
        vm.expectRevert(Evidence.CaseSettled.selector);
        _settle(caseID, lot);
        assertConserved();
    }

    // --- the report deadline -------------------------------------------------------------------------

    function test_aDelayedClosureApplicationPreservesTheWholeWindow() public {
        _installEpochs(_hID());
        handoffExcluding(3);
        clock(150, 1_200);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, TAG));
        // custody applies the Closure much later, and the term is anchored later still: the anchors are the anchoring's clock
        clock(5_000, 90_000);
        applyAll();
        clock(7_000, 95_000);
        anchorClosed(GENESIS_ASSIGNMENT, TAG);
        (bytes32 rH, bytes32 hID, uint64 p0, uint64 t0, bool anchored) =
            custody.termAnchors(GENESIS_ASSIGNMENT);
        assertEq(rH, _rH());
        assertEq(hID, _hID());
        assertEq(p0, 7_000);
        assertEq(t0, 95_000);
        assertTrue(anchored);
        assertEq(lotv(lotOf(gid(0))).timeUntil, 95_000 + 3_600, "t0 + time floor");
        assertEq(lotv(lotOf(gid(0))).evidenceUntil, 7_000 + 1_000, "p0 + window");
        assertEq(lotv(lotOf(gid(0))).holdUntil, 7_000 + 2_000, "p0 + hold");
        clock(9_000, 96_800); // both record-dated deadlines long passed; t <= t0 + 1,800
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        _submit(s, _quorum(s), 0);
    }

    function test_fastProgressInsideTheReportWindowIsAdmittedAtTheInclusiveCutoff() public {
        _history();
        clock(50_000, 3_000); // progress far past p0 + 1,000; t == t0 + reportWindow
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        _submit(s, _quorum(s), 0);
        clock(50_000, 3_001); // both cutoffs passed
        Evidence.PostTermSeal memory s2 = _seal(A_STAR + 1, OTHER);
        _expectRefused(s2, _quorum(s2), 0, Evidence.EvidenceLate.selector);
    }

    function test_theReverseClockOrderingIsAdmittedUntilTheProgressCutoff() public {
        _history();
        clock(1_150, 500_000); // UC time far past t0 + 1,800; progress == p0 + suffix window
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        _submit(s, _quorum(s), 0);
        clock(1_151, 500_000);
        Evidence.PostTermSeal memory s2 = _seal(A_STAR + 1, OTHER);
        _expectRefused(s2, _quorum(s2), 0, Evidence.EvidenceLate.selector);
    }

    function test_aTimelyCaseSettledAfterTheTimeFloorStillHoldsAndThenReleasesOnce() public {
        requestRetirement(0);
        _installEpochs(_hID());
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        retireRecordAt(gid(0), 160, 1_210);
        uint256 lot = lotOf(gid(0));
        clock(1_500, 3_000); // the last admissible UC second
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        bytes32 caseID = _submit(s, _quorum(s), 0);
        // every floor has passed, the hold decides
        clock(100_000, 1_000_000);
        vm.expectRevert(CustodyStorage.EvidenceHoldPending.selector);
        matureOne(lot);
        uint256 debit = _settle(caseID, lot);
        matureOne(lot);
        address wd = vm.addr(wdPk(0));
        assertEq(creditOf(wd), GENESIS_BOND - debit, "principal less the penalty, exactly once");
        vm.expectRevert(CustodyStorage.LotAlreadyReleased.selector);
        matureOne(lot);
        vm.prank(wd);
        custody.claim(GENESIS_BOND - debit, wd);
        assertEq(wd.balance, GENESIS_BOND - debit);
        vm.prank(wd);
        vm.expectRevert(CustodyStorage.InsufficientCredit.selector);
        custody.claim(1, wd);
        assertConserved();
    }

    // --- the anchor fail-safe ------------------------------------------------------------------------

    function test_aClosureBeforeTheSuccessorIsInstalledBlocksMaturityUntilAnchored() public {
        (bytes[] memory keys, uint64[] memory weights) = _committee();
        roots.installEpoch(1, 1, false, 0, 2, bytes32(0), keys, weights);
        requestRetirement(0);
        handoffExcluding(0);
        closeGenesisUnanchoredAt(150, 1_200);
        retireRecordAt(gid(0), 160, 1_210);
        uint256 lot = lotOf(gid(0));
        (,,,, bool anchored) = custody.termAnchors(GENESIS_ASSIGNMENT);
        assertFalse(anchored);
        assertEq(custody.lotUnanchoredTerms(lot), 1);
        (,,,,, uint64 shownUntil,) = evidence.releaseState(lot);
        assertEq(shownUntil, type(uint64).max, "the time gate is not determined yet");
        // no clock has started for the post-term offence: nothing is admissible, nothing matures, anchoring needs the successor
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        _expectRefused(s, _quorum(s), 0, Evidence.SuccessorUnknown.selector);
        clock(100_000, 1_000_000);
        vm.expectRevert(CustodyStorage.TermAnchorPending.selector);
        matureOne(lot);
        bytes32 h = _hID();
        bytes32 r = _rH();
        vm.expectRevert(CustodyStorage.SuccessorNotInstalled.selector);
        custody.anchorTerm(GENESIS_ASSIGNMENT, h, r);
        // the successor is installed much later; anyone anchors the term at the clock of that call
        roots.installEpoch(1, 1, true, A_STAR, 2, bytes32(0), keys, weights);
        roots.installEpoch(2, A_STAR, false, 0, 2, h, keys, weights);
        Evidence.SealQuorum memory q = _quorum(s);
        _expectRefused(s, q, 0, Evidence.TermNotAnchored.selector);
        vm.expectRevert(CustodyStorage.ClosureOpeningMismatch.selector);
        custody.anchorTerm(GENESIS_ASSIGNMENT, h, keccak256("another root"));
        vm.expectRevert(CustodyStorage.ClosureOpeningMismatch.selector);
        custody.anchorTerm(GENESIS_ASSIGNMENT, keccak256("another H"), r);
        vm.prank(makeAddr("anyone"));
        custody.anchorTerm(GENESIS_ASSIGNMENT, h, r);
        vm.expectRevert(CustodyStorage.TermNotPending.selector);
        custody.anchorTerm(GENESIS_ASSIGNMENT, h, r);
        assertEq(custody.lotUnanchoredTerms(lot), 0);
        (,, uint64 p0, uint64 t0, bool now_) = custody.termAnchors(GENESIS_ASSIGNMENT);
        assertTrue(now_);
        assertEq(p0, 100_000);
        assertEq(t0, 1_000_000);
        assertEq(lotv(lot).timeUntil, 1_000_000 + 3_600, "the floors run from the anchors");
        assertEq(lotv(lot).holdUntil, 100_000 + 2_000);
        (,,,,, shownUntil,) = evidence.releaseState(lot);
        assertEq(shownUntil, 1_000_000 + 3_600);
        vm.expectRevert(CustodyStorage.RoundGateNotMet.selector);
        matureOne(lot);
        // the full window is open from the anchors
        clock(100_000, 1_001_800);
        _submit(s, q, 0);
    }

    function test_anOpenTermCannotBeAnchored() public {
        vm.expectRevert(CustodyStorage.TermNotPending.selector);
        custody.anchorTerm(GENESIS_ASSIGNMENT, _hID(), _rH());
    }

    // --- bounds --------------------------------------------------------------------------------------

    /// The largest installed committee (16) with a full 16-signature quorum stays far inside one transaction.
    function test_aSixteenMemberQuorumFitsInOneTransaction() public {
        bytes[] memory keys = new bytes[](16);
        uint64[] memory weights = new uint64[](16);
        for (uint256 i; i < 16; ++i) {
            keys[i] = compressed(i < N_GENESIS ? rootPk(i) : 0x7000 + i);
            weights[i] = 1;
        }
        roots.installEpoch(1, 1, true, A_STAR, 2, bytes32(0), keys, weights);
        roots.installEpoch(2, A_STAR, false, 0, 2, _hID(), keys, weights);
        handoffExcluding(3);
        closeGenesisAt(150, 1_200);
        Evidence.PostTermSeal memory s = _seal(A_STAR, OTHER);
        bytes32 d = evidence.postTermSealDigest(s);
        Evidence.SealQuorum memory q;
        q.members = new uint8[](16);
        q.signatures = new bytes[](16);
        for (uint256 i; i < 16; ++i) {
            q.members[i] = uint8(i);
            q.signatures[i] = signNative(i < N_GENESIS ? rootPk(i) : 0x7000 + i, d);
        }
        bytes32 eid = genesisExposure(0);
        vm.prank(reporter);
        uint256 g = gasleft();
        evidence.submitPostTermEvidence(s, q, eid);
        uint256 used = g - gasleft();
        emit log_named_uint("post-term evidence, 16 signers", used);
        assertLt(used, 3_000_000);
    }
}
