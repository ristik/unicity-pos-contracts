// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {UncheckedPolicy} from "./UncheckedPolicy.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {CaseView} from "../../src/p85/IP85.sol";
import {
    Policy,
    Limits,
    RecordKind,
    SessionClosedData,
    RecoveryAckData,
    ReserveInput
} from "../../src/p85/P85Types.sol";

/// @notice Ordinary-EVM evidence under option A: admission, offence identity, historical
/// attribution, the inclusive cutoffs, holds, capped settlement and exclusion.
///
/// Genesis assignment G: root/EVM epoch 1, offset 0, first round 1, so p(1, r) = r - 1.
/// Default policy: evidence window 1,000, penalty 1%, lifetime cap 5%, bounty 10% capped at 1 UCT.
contract EvidenceTest is P85Flow {
    uint8 internal constant ROOT = 1;
    uint8 internal constant EVM = 2;

    function _header(uint8 domain, uint256 keyPk, uint64 epoch, uint64 round)
        internal
        returns (Evidence.VoteHeader memory)
    {
        return Evidence.VoteHeader(NETWORK, domain, compressed(keyPk), epoch, round);
    }

    function _vote(Evidence.VoteHeader memory h, bytes32 payload, uint256 keyPk)
        internal
        view
        returns (Evidence.SignedVote memory)
    {
        return Evidence.SignedVote(payload, sign(keyPk, evidence.voteDigest(h, payload)));
    }

    function _submitAs(
        address who,
        uint8 domain,
        uint256 keyPk,
        uint64 epoch,
        uint64 round,
        bytes32 exposureID_
    ) internal returns (bytes32 caseID) {
        Evidence.VoteHeader memory h = _header(domain, keyPk, epoch, round);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), keyPk);
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), keyPk);
        vm.prank(who);
        caseID = evidence.submitEvidence(h, a, b, exposureID_);
    }

    function _submit(uint8 domain, uint256 keyPk, uint64 epoch, uint64 round, bytes32 exposureID_)
        internal
        returns (bytes32)
    {
        return _submitAs(reporter, domain, keyPk, epoch, round, exposureID_);
    }

    function _settle(bytes32 caseID, uint256 lotID) internal returns (uint256 debit) {
        uint256[] memory ids = new uint256[](1);
        ids[0] = lotID;
        return evidence.settleEvidence(caseID, ids);
    }

    // --- admission ----------------------------------------------------------------------------------

    function test_admissionInstallsHoldsExclusionAndTheFrozenBudgetAtomically() public {
        bytes32 expectedOffence;
        {
            Evidence.VoteHeader memory h = _header(ROOT, rootPk(0), 1, 10);
            expectedOffence = evidence.offenceIDOf(h);
        }
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        CaseView memory c = evidence.caseInfo(caseID);
        assertEq(c.offenceID, expectedOffence);
        assertEq(c.exposureID, genesisExposure(0));
        assertEq(c.id, gid(0));
        assertEq(c.reporter, reporter);
        assertEq(c.budget, 10 * UCT, "1% of the 1,000 UCT exposed initial principal");
        assertEq(c.debited, 0, "no debit yet");
        assertEq(c.cursor, 0);
        assertEq(c.lotCount, 1);
        assertEq(evidence.pendingHolds(lotOf(gid(0))), 1);
        assertTrue(evidence.excluded(gid(0)));
        assertTrue(evidence.offenceSeen(expectedOffence));
        assertEq(lotv(lotOf(gid(0))).remaining, GENESIS_BOND, "admission debits nothing");
        assertConserved();
    }

    function test_theSameOffenceDebitsOnceWhateverTheStatementOrder() public {
        _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(0), 1, 10);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(0));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(0));
        vm.expectRevert(Evidence.DuplicateOffence.selector); // reordered pair
        evidence.submitEvidence(h, b, a, genesisExposure(0));
        Evidence.SignedVote memory third = _vote(h, keccak256("C"), rootPk(0));
        vm.expectRevert(Evidence.DuplicateOffence.selector); // a third conflicting statement
        evidence.submitEvidence(h, a, third, genesisExposure(0));
        vm.expectRevert(Evidence.DuplicateOffence.selector); // another reporter
        vm.prank(makeAddr("other reporter"));
        evidence.submitEvidence(h, a, b, genesisExposure(0));
    }

    function test_aDistinctRoundOrDomainIsADistinctOffence() public {
        bytes32 c1 = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        bytes32 c2 = _submit(ROOT, rootPk(0), 1, 11, genesisExposure(0));
        bytes32 c3 = _submit(EVM, evmPk(0), 1, 10, genesisExposure(0));
        assertTrue(c1 != c2 && c1 != c3 && c2 != c3);
        assertEq(evidence.pendingHolds(lotOf(gid(0))), 3);
    }

    function test_admissionRejectsEachMalformedPairIsolated() public {
        bytes32 expo_ = genesisExposure(0);
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(0), 1, 10);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(0));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(0));

        Evidence.VoteHeader memory wrongNet = _header(ROOT, rootPk(0), 1, 10);
        wrongNet.network = keccak256("another network");
        vm.expectRevert(Evidence.WrongNetwork.selector);
        evidence.submitEvidence(wrongNet, a, b, expo_);

        Evidence.VoteHeader memory badDomain = _header(0, rootPk(0), 1, 10);
        vm.expectRevert(Evidence.BadDomain.selector);
        evidence.submitEvidence(badDomain, a, b, expo_);
        badDomain.domain = 3;
        vm.expectRevert(Evidence.BadDomain.selector);
        evidence.submitEvidence(badDomain, a, b, expo_);

        vm.expectRevert(Evidence.IdenticalStatements.selector);
        evidence.submitEvidence(h, a, a, expo_);

        // statement a signed by the wrong key
        Evidence.SignedVote memory forged = Evidence.SignedVote(
            keccak256("A"), sign(rootPk(1), evidence.voteDigest(h, keccak256("A")))
        );
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(h, forged, b, expo_);
        // statement b signed over a different round
        Evidence.VoteHeader memory otherRound = _header(ROOT, rootPk(0), 1, 11);
        Evidence.SignedVote memory wrongRound = _vote(otherRound, keccak256("B"), rootPk(0));
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(h, a, wrongRound, expo_);
        // a malformed signature length
        Evidence.SignedVote memory shortSig = Evidence.SignedVote(keccak256("B"), hex"01");
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(h, a, shortSig, expo_);
    }

    function test_attributionNeedsTheKeyEpochAndAKnownLiveAssignment() public {
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(0), 1, 10);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(0));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(0));

        vm.expectRevert(Evidence.ExposureUnknown.selector);
        evidence.submitEvidence(h, a, b, keccak256("no such exposure"));

        // identity 2's exposure does not hold identity 1's root key
        vm.expectRevert(Evidence.KeyMismatch.selector);
        evidence.submitEvidence(h, a, b, genesisExposure(1));

        // the EVM domain checks the EVM key: a root-key pair with domain EVM mismatches
        Evidence.VoteHeader memory evmHeader = _header(EVM, rootPk(0), 1, 10);
        Evidence.SignedVote memory ea = _vote(evmHeader, keccak256("A"), rootPk(0));
        Evidence.SignedVote memory eb = _vote(evmHeader, keccak256("B"), rootPk(0));
        vm.expectRevert(Evidence.KeyMismatch.selector);
        evidence.submitEvidence(evmHeader, ea, eb, genesisExposure(0));

        // epoch 2 is not the epoch G held the key in
        Evidence.VoteHeader memory wrongEpoch = _header(ROOT, rootPk(0), 2, 10);
        Evidence.SignedVote memory wa = _vote(wrongEpoch, keccak256("A"), rootPk(0));
        Evidence.SignedVote memory wb = _vote(wrongEpoch, keccak256("B"), rootPk(0));
        vm.expectRevert(Evidence.EpochMismatch.selector);
        evidence.submitEvidence(wrongEpoch, wa, wb, genesisExposure(0));
        Evidence.VoteHeader memory wrongEvmEpoch = _header(EVM, evmPk(0), 7, 10);
        Evidence.SignedVote memory xa = _vote(wrongEvmEpoch, keccak256("A"), evmPk(0));
        Evidence.SignedVote memory xb = _vote(wrongEvmEpoch, keccak256("B"), evmPk(0));
        vm.expectRevert(Evidence.EpochMismatch.selector);
        evidence.submitEvidence(wrongEvmEpoch, xa, xb, genesisExposure(0));

        // a round before the epoch's first round
        Evidence.VoteHeader memory early = _header(ROOT, rootPk(0), 1, 0);
        Evidence.SignedVote memory ya = _vote(early, keccak256("A"), rootPk(0));
        Evidence.SignedVote memory yb = _vote(early, keccak256("B"), rootPk(0));
        vm.expectRevert(Evidence.RoundBeforeEpoch.selector);
        evidence.submitEvidence(early, ya, yb, genesisExposure(0));
    }

    function test_anExposureOfAnAbortedAttemptIsNotAttributable() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        applyAll();
        // epoch 2 never existed: no honest key signed in it
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(0), 2, 5);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(0));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(0));
        bytes32 jExposure = exposureID(ASG_J, gid(0));
        vm.expectRevert(Evidence.NotAttributable.selector);
        evidence.submitEvidence(h, a, b, jExposure);
    }

    function test_aReservedAssignmentCannotBeChargedBeforeItsActivationIsImported() public {
        reserve(RES_J, ASG_J, allMembers(), 1);
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(0), 2, 5);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(0));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(0));
        bytes32 jExposure = exposureID(ASG_J, gid(0));
        vm.expectRevert(Evidence.AssignmentNotActivated.selector);
        evidence.submitEvidence(h, a, b, jExposure);
        // once the acknowledgement is imported, J's epoch is chargeable
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        _submit(ROOT, rootPk(0), 2, 105, jExposure);
    }

    // --- option A cutoffs ---------------------------------------------------------------------------

    function test_cutoffIsInclusiveAndTheNextProgressUnitIsLate() public {
        // offence at round 10: p(1,10) = 9, cutoff = 9 + 1,000 = 1,009 inclusive
        clock(1_009, 1);
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        assertEq(evidence.caseInfo(caseID).lotCount, 1, "equality is timely");
        clock(1_010, 1);
        // the same offence identity can no longer be new, so probe with a different round: round 11
        // has p = 10 and cutoff 1,010, still timely; round 10's own cutoff has passed
        _submit(ROOT, rootPk(0), 1, 11, genesisExposure(0));
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(1), 1, 10); // fresh offence, cutoff 1,009
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(1));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(1));
        bytes32 g1 = genesisExposure(1);
        vm.expectRevert(Evidence.EvidenceLate.selector);
        evidence.submitEvidence(h, a, b, g1); // one progress unit after the cutoff
    }

    function test_unseenEvidenceDoesNotBlockMaturity() public {
        // option A: only an admitted case holds a lot; an unsubmitted offence has no effect
        reachMaturable(0);
        clock(3_000, 5_000);
        matureOne(lotOf(gid(0)));
        assertEq(creditOf(vm.addr(wdPk(0))), GENESIS_BOND);
    }

    function test_suffixRoundsHaveNoExpiryBeforeClosureThenAnInclusiveCutoffFromPClose() public {
        handoffExcluding(0); // G's H is imported at round 100; G is not closed yet
        // round 101 > h: an old suffix signing context, p(1, 101) is not even defined by the epoch
        clock(5_000_000, 5_000_000);
        _submit(ROOT, rootPk(1), 1, 101, genesisExposure(1)); // no expiry before closure
        // closure fixes p_close = 5,000,000; the suffix cutoff is p_close + 1,000 inclusive
        closeGenesisAt(5_000_000, 5_000_000);
        _submit(ROOT, rootPk(1), 1, 102, genesisExposure(1)); // still within p_close + window
        clock(5_001_000, 5_000_000);
        _submit(ROOT, rootPk(1), 1, 103, genesisExposure(1)); // equality is timely
        clock(5_001_001, 5_000_000);
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(1), 1, 104);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(1));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(1));
        bytes32 g1 = genesisExposure(1);
        vm.expectRevert(Evidence.EvidenceLate.selector);
        evidence.submitEvidence(h, a, b, g1);
    }

    function test_roundsThroughHKeepTheOrdinaryWindowAfterTheHandoff() public {
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        // round 100 == h: ordinary, p = 99, cutoff 1,099
        clock(1_099, 1_200);
        _submit(ROOT, rootPk(1), 1, 100, genesisExposure(1));
        clock(1_100, 1_200);
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(1), 1, 99); // p = 98, cutoff 1,098
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(1));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(1));
        bytes32 g1 = genesisExposure(1);
        vm.expectRevert(Evidence.EvidenceLate.selector);
        evidence.submitEvidence(h, a, b, g1);
        // round == h is ordinary, not suffix: another identity's round-100 offence is late at 1,100
        // although a suffix classification (cutoff 1,150) would still accept it
        Evidence.VoteHeader memory atH = _header(ROOT, rootPk(2), 1, 100);
        Evidence.SignedVote memory ha = _vote(atH, keccak256("A"), rootPk(2));
        Evidence.SignedVote memory hb = _vote(atH, keccak256("B"), rootPk(2));
        bytes32 g2 = genesisExposure(2);
        vm.expectRevert(Evidence.EvidenceLate.selector);
        evidence.submitEvidence(atH, ha, hb, g2);
        // but a suffix round above h is still within p_close (150) + 1,000 = 1,150
        _submit(ROOT, rootPk(1), 1, 101, genesisExposure(1));
    }

    // --- holds and settlement -----------------------------------------------------------------------

    function test_aPendingHoldBlocksMaturityUntilSettlement() public {
        reachMaturable(0); // clock is at progress 160: an offence at round 10 is still timely
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        clock(3_000, 5_000); // every other maturity gate is now open
        uint256 lot = lotOf(gid(0));
        vm.expectRevert(StakeCustody.EvidenceHoldPending.selector);
        matureOne(lot);
        _settle(caseID, lot);
        assertEq(evidence.pendingHolds(lot), 0);
        matureOne(lot);
        // principal after the capped penalty went to credit; the penalty went to bounty and treasury
        assertEq(creditOf(vm.addr(wdPk(0))), GENESIS_BOND - 10 * UCT);
        assertEq(creditOf(reporter), 1 * UCT);
        assertEq(creditOf(treasury), 9 * UCT);
        assertConserved();
    }

    function test_evidenceAtTheCutoffHoldsMaturityThroughDelayedSettlement() public {
        reachMaturable(0);
        clock(1_009, 1_300); // round 10's cutoff is exactly 1,009
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        clock(9_000, 90_000); // far past every gate; settlement is simply delayed
        uint256 lot = lotOf(gid(0));
        vm.expectRevert(StakeCustody.EvidenceHoldPending.selector);
        matureOne(lot);
        _settle(caseID, lot);
        matureOne(lot);
    }

    function test_settlementDebitsTheCapAndSplitsBountyAndTreasury() public {
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        uint256 lot = lotOf(gid(0));
        vm.expectEmit(true, false, false, true, address(evidence));
        emit Evidence.EvidenceSettled(caseID, 1, 10 * UCT, 1 * UCT);
        uint256 debit = _settle(caseID, lot);
        assertEq(debit, 10 * UCT);
        LotV memory l = lotv(lot);
        assertEq(l.remaining, GENESIS_BOND - 10 * UCT);
        assertEq(l.penalized, 10 * UCT);
        assertEq(custody.caseDebited(caseID), 10 * UCT);
        assertEq(
            custody.totalEncumbered(),
            N_GENESIS * GENESIS_BOND - 10 * UCT,
            "principal falls by exactly the credits created"
        );
        assertEq(custody.totalCredits(), 10 * UCT);
        assertEq(creditOf(reporter), 1 * UCT, "10% bounty, below the 1 UCT cap");
        assertEq(creditOf(treasury), 9 * UCT);
        assertEq(evidence.pendingHolds(lot), 0);
        assertEq(address(custody).balance, N_GENESIS * GENESIS_BOND, "settlement moves nothing out");
        assertConserved();
    }

    function test_bountyIsCappedPerCase() public {
        // 2% penalty of 1,000 UCT = 20 UCT; 10% would be 2 UCT but the cap is 1 UCT
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 200;
        p.lifetimeCapBps = 1_000;
        _deployAs(p);
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        _settle(caseID, lotOf(gid(0)));
        assertEq(creditOf(reporter), 1 * UCT);
        assertEq(creditOf(treasury), 19 * UCT);
    }

    function _deployAs(Policy memory p) internal {
        _deploy(p);
    }

    function test_theLifetimeCapIsAgainstInitialPrincipalAcrossOffences() public {
        // penalty 2% (20 UCT per case), cap 3% (30 UCT lifetime) of the 1,000 UCT lot
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 200;
        p.lifetimeCapBps = 300;
        _deployAs(p);
        uint256 lot = lotOf(gid(0));
        bytes32 c1 = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        bytes32 c2 = _submit(ROOT, rootPk(0), 1, 11, genesisExposure(0));
        bytes32 c3 = _submit(ROOT, rootPk(0), 1, 12, genesisExposure(0));
        assertEq(_settle(c1, lot), 20 * UCT);
        assertEq(_settle(c2, lot), 10 * UCT, "cap leaves 10 UCT");
        assertEq(_settle(c3, lot), 0, "cap exhausted: a valid offence still records, debits zero");
        assertEq(lotv(lot).penalized, 30 * UCT);
        assertEq(lotv(lot).remaining, GENESIS_BOND - 30 * UCT);
        assertEq(evidence.pendingHolds(lot), 0);
        assertTrue(evidence.excluded(gid(0)));
    }

    function test_sharedAssignmentsNeverMultiplyTheCap() public {
        // Identity 2's lot is referenced by both G (epoch 1) and J (epoch 2). Offences under each
        // assignment draw on the same lifetime cap of 30 UCT.
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 200;
        p.lifetimeCapBps = 300;
        _deployAs(p);
        handoffExcluding(0);
        uint256 lot = lotOf(gid(1));
        bytes32 cg = _submit(ROOT, rootPk(1), 1, 10, genesisExposure(1)); // under G
        bytes32 cj = _submit(ROOT, rootPk(1), 2, 105, exposureID(ASG_J, gid(1))); // under J
        assertEq(_settle(cg, lot), 20 * UCT);
        assertEq(_settle(cj, lot), 10 * UCT);
        assertEq(lotv(lot).penalized, 30 * UCT, "one cap, not one per assignment");
    }

    function test_aFullPrincipalCapNeverDebitsMoreThanTheLot() public {
        // An unbounded policy (cap 100%, penalty 50%) so that remaining principal binds.
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 5_000;
        p.lifetimeCapBps = 10_000;
        UncheckedPolicy source = new UncheckedPolicy(p);
        _deployManual(address(source), Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32}));
        uint256 lot = lotOf(gid(0));
        bytes32 c1 = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        bytes32 c2 = _submit(ROOT, rootPk(0), 1, 11, genesisExposure(0));
        bytes32 c3 = _submit(ROOT, rootPk(0), 1, 12, genesisExposure(0));
        assertEq(_settle(c1, lot), GENESIS_BOND / 2);
        assertEq(_settle(c2, lot), GENESIS_BOND / 2, "all that remains");
        assertEq(lotv(lot).remaining, 0);
        assertEq(_settle(c3, lot), 0, "a zero-principal lot still records the offence and excludes");
        assertTrue(evidence.excluded(gid(0)));
        assertConserved();
    }

    function test_aZeroPenaltyPolicyStillRecordsAndExcludes() public {
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 0;
        _deployAs(p);
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        assertEq(evidence.caseInfo(caseID).budget, 0);
        assertEq(_settle(caseID, lotOf(gid(0))), 0);
        assertTrue(evidence.excluded(gid(0)));
        assertEq(custody.totalCredits(), 0);
    }

    function test_budgetIsConsumedByAscendingLotsAndEarlierLotsFirst() public {
        // identity 1 has three lots by the time J is reserved: 1,000 + 500 + 500 UCT. The case
        // budget is 1% of 2,000 = 20 UCT, drawn from the first lot (cap 50 UCT) in full.
        uint256 second = bondFor(gid(0), 500 * UCT);
        uint256 third = bondFor(gid(0), 500 * UCT);
        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        bytes32 caseID = _submit(ROOT, rootPk(0), 2, 105, exposureID(ASG_J, gid(0)));
        assertEq(evidence.caseInfo(caseID).budget, 20 * UCT);
        assertEq(evidence.caseInfo(caseID).lotCount, 3);
        uint256 first = lotOf(gid(0));
        assertEq(evidence.pendingHolds(first), 1);
        assertEq(evidence.pendingHolds(second), 1);
        assertEq(evidence.pendingHolds(third), 1);
        uint256[] memory batch = new uint256[](3);
        batch[0] = first;
        batch[1] = second;
        batch[2] = third;
        assertEq(evidence.settleEvidence(caseID, batch), 20 * UCT);
        assertEq(lotv(first).penalized, 20 * UCT);
        assertEq(lotv(second).penalized, 0);
        assertEq(lotv(third).penalized, 0);
        assertEq(evidence.pendingHolds(second), 0, "holds drop as the corresponding work settles");
    }

    function test_settlementMustProceedThroughTheNextAscendingPrefix() public {
        uint256 second = bondFor(gid(0), 500 * UCT);
        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        bytes32 caseID = _submit(ROOT, rootPk(0), 2, 105, exposureID(ASG_J, gid(0)));
        uint256[] memory skip = new uint256[](1);
        skip[0] = second; // the first lot must come first
        vm.expectRevert(Evidence.NotNextLot.selector);
        evidence.settleEvidence(caseID, skip);
        uint256[] memory dup = new uint256[](2);
        dup[0] = lotOf(gid(0));
        dup[1] = lotOf(gid(0));
        vm.expectRevert(Evidence.NotNextLot.selector);
        evidence.settleEvidence(caseID, dup);
        uint256[] memory first = new uint256[](1);
        first[0] = lotOf(gid(0));
        evidence.settleEvidence(caseID, first);
        assertEq(evidence.caseInfo(caseID).cursor, 1);
        skip[0] = second;
        evidence.settleEvidence(caseID, skip);
        assertEq(evidence.caseInfo(caseID).cursor, 2);
    }

    function test_settlementRejectsUnknownSettledEmptyAndOversizedBatches() public {
        uint256[] memory one = new uint256[](1);
        one[0] = lotOf(gid(0));
        vm.expectRevert(Evidence.UnknownCase.selector);
        evidence.settleEvidence(keccak256("none"), one);
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        uint256[] memory none = new uint256[](0);
        vm.expectRevert(Evidence.EmptyBatch.selector);
        evidence.settleEvidence(caseID, none);
        uint256[] memory many = new uint256[](33);
        vm.expectRevert(Evidence.BatchTooLarge.selector);
        evidence.settleEvidence(caseID, many);
        evidence.settleEvidence(caseID, one);
        vm.expectRevert(Evidence.CaseSettled.selector);
        evidence.settleEvidence(caseID, one);
    }

    // --- historical attribution ---------------------------------------------------------------------

    function test_rotatedKeysChargeOnlyTheHistoricalLots() public {
        // identity 2 stages a new root key; a deposit made after G is not liable for G's offences
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
        uint256 later = bondFor(gid(1), 400 * UCT);
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        in_.members[1].rootKeyHash = keccak256(newKey);
        vm.prank(address(election));
        custody.reserveCandidate(in_);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();

        // the OLD key signs a conflicting pair in epoch 1: only G's lot is charged
        uint256 old = lotOf(gid(1));
        bytes32 caseOld = _submit(ROOT, rootPk(1), 1, 10, genesisExposure(1));
        assertEq(evidence.caseInfo(caseOld).lotCount, 1);
        assertEq(evidence.caseInfo(caseOld).budget, 10 * UCT);
        _settle(caseOld, old);
        assertEq(lotv(later).penalized, 0, "later deposits are not liable for earlier assignments");
        assertEq(lotv(old).penalized, 10 * UCT);

        // the NEW key signs in epoch 2: J's exposure carries both lots
        bytes32 caseNew = _submit(ROOT, 0x9501, 2, 105, exposureID(ASG_J, gid(1)));
        assertEq(evidence.caseInfo(caseNew).lotCount, 2);
        assertEq(evidence.caseInfo(caseNew).budget, 14 * UCT, "1% of 1,400 UCT");

        // the old key cannot be attributed to J's exposure, nor the new key to G's
        Evidence.VoteHeader memory h = _header(ROOT, rootPk(1), 2, 106);
        Evidence.SignedVote memory a = _vote(h, keccak256("A"), rootPk(1));
        Evidence.SignedVote memory b = _vote(h, keccak256("B"), rootPk(1));
        bytes32 jExposure = exposureID(ASG_J, gid(1));
        vm.expectRevert(Evidence.KeyMismatch.selector);
        evidence.submitEvidence(h, a, b, jExposure);
    }

    // --- exclusion and K -----------------------------------------------------------------------------

    function test_exclusionBlocksFuturePrimariesButNeverExactK() public {
        _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.IdentityExcluded.selector);
        custody.reserveCandidate(in_);
        // J without the excluded identity reserves, and K (the incumbent slate) still contains it
        reserve(RES_J, ASG_J, allExcept(0), 1);
        assertEq(
            expo(genesisExposure(0)).locks,
            1,
            "the excluded identity's incumbent exposure is locked"
        );
        // the excluded incumbent can still be recovered as part of the exact K
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll();
        assertEq(
            expo(exposureID(ASG_K, gid(0))).id, gid(0), "K still contains the slashed identity"
        );
    }

    function test_applyPenaltyIsReservedToTheFixedEvidenceModule() public {
        vm.expectRevert(StakeCustody.NotEvidence.selector);
        custody.applyPenalty(keccak256("case"), 1);
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.NotEvidence.selector);
        custody.applyPenalty(keccak256("case"), 1);
    }

    function test_applyPenaltyRechecksTheCaseLotMembershipAndTheDebitMarker() public {
        bytes32 caseID = _submit(ROOT, rootPk(0), 1, 10, genesisExposure(0));
        uint256 lot = lotOf(gid(0));
        uint256 otherLot = lotOf(gid(1));
        // a lot that the case's exposure does not contain
        vm.prank(address(evidence));
        vm.expectRevert(StakeCustody.LotNotInExposure.selector);
        custody.applyPenalty(caseID, otherLot);
        // an unknown case has no exposure at all
        vm.prank(address(evidence));
        vm.expectRevert(StakeCustody.LotNotInExposure.selector);
        custody.applyPenalty(keccak256("unknown case"), lot);
        // a settled (case, lot) pair cannot be debited again, even by the evidence module itself
        _settle(caseID, lot);
        vm.prank(address(evidence));
        vm.expectRevert(StakeCustody.PenaltyAlreadyApplied.selector);
        custody.applyPenalty(caseID, lot);
    }
}
