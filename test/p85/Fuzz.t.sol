// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {Policy, ReserveInput, RecordKind} from "../../src/p85/P85Types.sol";

/// @notice Property tests with independent reference models: the penalty formula, bounty
/// chunk-independence, the maturity gates, coverage boundaries and caller permissions.
contract FuzzTest is P85Flow {
    function _expectedDebit(
        uint256 budget,
        uint256 remaining,
        uint256 initial,
        uint256 capBps,
        uint256 penalized
    ) internal pure returns (uint256 debit) {
        uint256 capRoom = (initial * capBps) / 10_000 - penalized;
        debit = budget;
        if (remaining < debit) debit = remaining;
        if (capRoom < debit) debit = capRoom;
    }

    /// Penalty = min(case budget, remaining principal, remaining lifetime cap), for any bounded
    /// policy and any sequence of offences against one lot.
    function testFuzz_debitIsTheMinimumOfBudgetRemainingAndCap(
        uint16 penaltyBps,
        uint16 capBps,
        uint8 offences
    ) public {
        Policy memory p = _defaultPolicy();
        p.penaltyBps = uint16(bound(penaltyBps, 0, 200));
        p.lifetimeCapBps = uint16(bound(capBps, 0, 1_000));
        _deploy(p);
        uint256 lot = lotOf(gid(0));
        uint256 n = bound(offences, 1, 12);
        uint256 penalized;
        for (uint256 i; i < n; ++i) {
            bytes32 caseID = _submitRoot(0, uint64(10 + i));
            uint256 budget = (GENESIS_BOND * p.penaltyBps) / 10_000;
            uint256 expected = _expectedDebit(
                budget, GENESIS_BOND - penalized, GENESIS_BOND, p.lifetimeCapBps, penalized
            );
            uint256[] memory one = new uint256[](1);
            one[0] = lot;
            assertEq(evidence.settleEvidence(caseID, one), expected);
            penalized += expected;
            assertEq(lotv(lot).penalized, penalized);
            assertEq(lotv(lot).remaining, GENESIS_BOND - penalized);
        }
        assertLe(penalized, (GENESIS_BOND * p.lifetimeCapBps) / 10_000);
        assertConserved();
    }

    function _submitRoot(uint256 identityIdx, uint64 round) internal returns (bytes32 caseID) {
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, 1, compressed(rootPk(identityIdx)), 1, round);
        Evidence.SignedVote memory a = Evidence.SignedVote(
            keccak256("A"), sign(rootPk(identityIdx), evidence.voteDigest(h, keccak256("A")))
        );
        Evidence.SignedVote memory b = Evidence.SignedVote(
            keccak256("B"), sign(rootPk(identityIdx), evidence.voteDigest(h, keccak256("B")))
        );
        vm.prank(reporter);
        caseID = evidence.submitEvidence(h, a, b, genesisExposure(identityIdx));
    }

    /// Bounty depends only on the cumulative actual debit: any chunking of the same settlement gives
    /// the same total bounty and treasury credit as one batch.
    function testFuzz_bountyIsIndependentOfSettlementChunking(
        uint256 seed,
        uint8 lotCount,
        uint16 penaltyBps,
        uint16 bountyBps
    ) public {
        Policy memory p = _defaultPolicy();
        p.penaltyBps = uint16(bound(penaltyBps, 1, 200));
        // a tiny per-lot cap makes the budget spill across the lots, so each settlement chunk debits
        // several lots and bounty rounding depends on cumulative, not per-lot, debit
        p.lifetimeCapBps = uint16(bound(seed >> 8, 5, 40));
        p.bountyBps = uint16(bound(bountyBps, 0, 2_000));
        p.bountyCap = uint128(bound(seed, 0, 10 ether));
        _deploy(p);
        uint256 extra = bound(lotCount, 1, 7);
        // small first lots make the budget spill across lots, so chunk boundaries matter
        for (uint256 i; i < extra; ++i) {
            bondFor(
                gid(0),
                bound(uint256(keccak256(abi.encode(seed, i))), 100 * UCT, 400 * UCT) + (seed % 7)
            );
        }
        uint256[] memory members = new uint256[](1);
        members[0] = 0;
        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        bytes32 caseID = _submitJ(0, 105);
        uint256[] memory lots = custody.exposureLots(exposureID(ASG_J, gid(0)));

        uint256 snap = vm.snapshotState();
        evidence.settleEvidence(caseID, lots); // one batch (maxBatch is 32)
        uint256 bountyWhole = creditOf(reporter);
        uint256 treasuryWhole = creditOf(treasury);
        uint256 debitWhole = custody.caseDebited(caseID);
        vm.revertToState(snap);

        uint256 done;
        uint256 s2 = seed;
        while (done < lots.length) {
            s2 = uint256(keccak256(abi.encode(s2)));
            uint256 size = bound(s2, 1, lots.length - done);
            uint256[] memory chunk = new uint256[](size);
            for (uint256 k; k < size; ++k) {
                chunk[k] = lots[done + k];
            }
            evidence.settleEvidence(caseID, chunk);
            done += size;
        }
        assertEq(custody.caseDebited(caseID), debitWhole);
        assertEq(creditOf(reporter), bountyWhole, "bounty is chunk independent");
        assertEq(creditOf(treasury), treasuryWhole);
        uint256 cumulative = (debitWhole * p.bountyBps) / 10_000;
        if (cumulative > p.bountyCap) cumulative = p.bountyCap;
        assertEq(bountyWhole, cumulative, "bounty = min(floor(cumulative debit * rate), cap)");
        assertEq(
            bountyWhole + treasuryWhole, debitWhole, "every debited unit is credited exactly once"
        );
        assertConserved();
    }

    function _submitJ(uint256 identityIdx, uint64 round) internal returns (bytes32) {
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, 1, compressed(rootPk(identityIdx)), 2, round);
        Evidence.SignedVote memory a = Evidence.SignedVote(
            keccak256("A"), sign(rootPk(identityIdx), evidence.voteDigest(h, keccak256("A")))
        );
        Evidence.SignedVote memory b = Evidence.SignedVote(
            keccak256("B"), sign(rootPk(identityIdx), evidence.voteDigest(h, keccak256("B")))
        );
        vm.prank(reporter);
        return evidence.submitEvidence(h, a, b, exposureID(ASG_J, gid(identityIdx)));
    }

    /// mature() succeeds exactly when p > roundUntil and t >= timeUntil, for arbitrary anchors.
    function testFuzz_matureGatesMatchTheIndependentFormula(
        uint32 pAck,
        uint32 dClose,
        uint32 dRet,
        uint32 tClose,
        uint32 dtRet,
        uint8 hOffset,
        int16 pDelta,
        int16 tDelta
    ) public {
        uint64 h = 100 + uint64(hOffset); // G's H round; p(1, h) = h - 1
        requestRetirement(0);
        reserve(RES_J, ASG_J, allExcept(0), 1);
        uint64 pA = pAck;
        clock(pA, 100);
        pushRecord(RecordKind.Ack, ackData(RES_J, h, 100, h + 1));
        uint64 pC = pA + dClose;
        uint64 tC = 100 + uint64(tClose);
        clock(pC, tC);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, h, "genesis"));
        uint64 pR = pC + dRet;
        uint64 tR = tC + dtRet;
        // the anchor must cover the liability anchor for the record to be accepted
        uint64 anchor = pC > h - 1 ? pC : h - 1;
        vm.assume(pR >= anchor);
        retireRecordAt(gid(0), pR, tR);

        uint64 roundUntil = pR + 2_000 > anchor + 2_000 ? pR + 2_000 : anchor + 2_000;
        uint64 timeUntil = tR + 3_600 > tC + 3_600 ? tR + 3_600 : tC + 3_600;
        uint64 p = uint64(int64(roundUntil) + int64(pDelta % 3));
        uint64 t = uint64(int64(timeUntil) + int64(tDelta % 3));
        vm.assume(p >= roots.progress() && t >= roots.ucTime());
        clock(p, t);
        uint256 lot = lotOf(gid(0));
        bool shouldPass = p > roundUntil && t >= timeUntil;
        uint256[] memory one = new uint256[](1);
        one[0] = lot;
        if (shouldPass) {
            custody.mature(one);
            assertEq(lotv(lot).category, 4);
        } else if (p <= roundUntil) {
            vm.expectRevert(StakeCustody.RoundGateNotMet.selector);
            custody.mature(one);
        } else {
            vm.expectRevert(StakeCustody.TimeGateNotMet.selector);
            custody.mature(one);
        }
    }

    /// Coverage boundary: weight * unit <= backing passes, one more unit fails.
    function testFuzz_coverageBoundaryIsExact(uint256 extraLot, uint8 weightDelta) public {
        uint256 extra = bound(extraLot, 0, 1_500 * UCT);
        if (extra != 0) bondFor(gid(0), extra);
        uint256 backing = GENESIS_BOND + extra;
        uint64 maxWeight = uint64(backing / (100 * UCT));
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        uint64 w = maxWeight + uint64(bound(weightDelta, 0, 2));
        in_.members[0].weight = w;
        in_.members[0].rawWeight = w;
        vm.prank(address(election));
        if (w > maxWeight) {
            vm.expectRevert(StakeCustody.InsufficientCoverage.selector);
            custody.reserveCandidate(in_);
        } else {
            custody.reserveCandidate(in_);
        }
    }

    /// Dust below the bond unit still counts as exposure: weight is the floor, all lots reserve.
    function testFuzz_allLotsIncludingDustAreReserved(uint16 dust) public {
        uint256 d = bound(dust, 1, 100 * UCT - 1);
        uint256 dustLot = bondFor(gid(0), d);
        reserve(RES_J, ASG_J, allMembers(), 1);
        assertEq(lotv(dustLot).refCount, 1, "weight-quantization dust is reserved too");
    }

    /// No caller other than the fixed module (or the owner/creditor) can use a restricted entry point.
    function testFuzz_restrictedEntryPointsRejectEveryoneElse(address caller, uint256 amount)
        public
    {
        vm.assume(
            caller != address(0) && caller != address(election) && caller != address(evidence)
        );
        vm.assume(caller != vm.addr(ownerPk(0)) && caller != vm.addr(wdPk(0)));
        vm.assume(custody.credit(caller) == 0);
        amount = bound(amount, 1, 1 ether);
        ReserveInput memory in_;
        vm.startPrank(caller);
        vm.expectRevert(StakeCustody.NotElection.selector);
        custody.reserveCandidate(in_);
        vm.expectRevert(StakeCustody.NotElection.selector);
        custody.registerEvmKey(gid(0), keccak256("k"));
        vm.expectRevert(StakeCustody.NotEvidence.selector);
        custody.applyPenalty(keccak256("c"), 1);
        vm.expectRevert(StakeCustody.NotOwner.selector);
        custody.requestRetirement(gid(0));
        vm.expectRevert(StakeCustody.NotOwner.selector);
        custody.proposeRoles(gid(0), caller, caller, 0);
        vm.expectRevert(StakeCustody.InsufficientCredit.selector);
        custody.claim(amount, caller);
        vm.stopPrank();
        vm.deal(caller, amount);
        vm.prank(caller);
        vm.expectRevert(StakeCustody.NotOwner.selector);
        custody.bond{value: amount}(gid(0));
    }
}
