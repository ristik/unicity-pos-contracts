// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {RewardPool} from "../../src/p85/RewardPool.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {GovernanceParams} from "../../src/p85/GovernanceParams.sol";
import {Policy, ElectionParams, RecordKind} from "../../src/p85/P85Types.sol";

/// @dev A payee contract that tries to claim again while it is being paid.
contract ReenteringPayee {
    RewardPool internal immutable POOL;
    bool public reentered;

    constructor(RewardPool p) {
        POOL = p;
    }

    receive() external payable {
        POOL.claim(1, payable(address(this)));
    }
}

contract RejectingPayee {
    function claim(RewardPool pool, uint256 amount) external {
        pool.claim(amount, payable(address(this)));
    }

    receive() external payable {
        revert("no");
    }
}

/// @notice T8 step 2 (briefs/t8-p7-design.md sections 4, 5): the funded reward pool over the authenticated timeline. The genesis committee
/// is four identities of weight 10 each, paid to four distinct payees; the genesis assignment owns progress [0, ...).
abstract contract RewardsBase is P85Flow {
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);
    uint64 internal constant CAD_P = 5_000;
    uint64 internal constant CAD_T = 1_000;

    RewardPool internal pool;
    GovernanceParams internal gov;

    function setUp() public virtual override {
        super.setUp();
        pool = factory.REWARDS();
        gov = factory.POLICY();
    }

    function _electionParams() internal pure virtual override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 2,
            nTarget: 10,
            nMax: 16,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: CAD_P,
            cadenceSeconds: CAD_T
        });
    }

    function payee(uint256 i) internal pure returns (address) {
        return vm.addr(payeePk(i));
    }

    /// @dev Close intervals until the pool has nothing more to close; returns how many it closed.
    function _drain() internal returns (uint256 closed) {
        while (true) {
            try pool.closeInterval() {
                ++closed;
            } catch {
                return closed;
            }
        }
    }

    function _advanceAll() internal {
        while (pool.recordCursor() < roots.recordCount()) {
            try pool.advanceRecords(2) {}
            catch {
                return;
            }
        }
    }

    /// @dev J over every identity but `excluded`, acknowledged with offset `off` (the previous owner ends there).
    function _handoff(uint256 excluded, uint64 off) internal {
        reserve(RES_J, ASG_J, allExcept(excluded), 1);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, off, off + 1));
        applyAll();
    }

    function _conserved() internal view {
        assertEq(address(pool).balance, pool.accounted() + pool.surplus());
        assertGe(address(pool).balance, pool.accounted());
    }
}

contract RewardsTest is RewardsBase {
    function test_genesisFundsThePoolAndStartsTheTimelineAtTheGenesisOffset() public view {
        assertEq(address(pool).balance, REWARD_FUNDING);
        assertEq(pool.available(), REWARD_FUNDING);
        assertEq(pool.START(), 0);
        assertEq(pool.nextStart(), 0);
        assertEq(pool.segmentCount(), 1);
        RewardPool.Segment memory s = pool.segmentAt(0);
        assertEq(s.assignmentID, GENESIS_ASSIGNMENT);
        assertEq(s.start, 0);
        assertFalse(s.ended);
        assertEq(pool.rateCursor(), 1);
        assertEq(pool.surplus(), 0);
    }

    function test_noIntervalClosesBeforeTheGridPointIsReached() public {
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        clock(999, 10);
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        clock(1_000, 10);
        (uint64 a, uint64 b, uint256 budget) = pool.closeInterval();
        assertEq(a, 0);
        assertEq(b, 1_000);
        assertEq(budget, 1 ether, "1 UCT per 1,000 progress units");
        // 1 UCT over four equal weights
        for (uint256 i; i < 4; ++i) {
            assertEq(pool.credits(payee(i)), 0.25 ether);
        }
        assertEq(pool.totalCredits(), 1 ether);
        assertEq(pool.available(), REWARD_FUNDING - 1 ether);
        assertEq(pool.nextStart(), 1_000);
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        _conserved();
    }

    function test_theCallerChoosesNeitherEndpointNorLength() public {
        clock(4_321, 10);
        uint256 n = _drain();
        assertEq(n, 4, "four whole grid intervals, [4000, 4321) waits for its grid point");
        assertEq(pool.nextStart(), 4_000);
        clock(4_999, 10);
        assertEq(_drain(), 0);
        clock(5_000, 10);
        assertEq(_drain(), 1);
        assertEq(pool.totalCredits(), 5 ether);
    }

    function test_theTailWaitsForTheRecordPrefixAndForAnOpenElectionResult() public {
        clock(2_000, 1_000);
        // a record custody has not applied (and the pool has not read) keeps the tail open
        pushRecord(RecordKind.SessionClosed, abi.encode(bytes32(uint256(1))));
        vm.expectRevert(RewardPool.NotCaughtUp.selector);
        pool.closeInterval();
    }

    function test_anOpenElectionResultKeepsTheTailOpenUntilItIsResolved() public {
        clock(CAD_P, CAD_T);
        vm.prank(SYS);
        election.elect(keccak256("origin"));
        bytes32 resultID = election.openResult();
        assertTrue(resultID != bytes32(0));
        vm.expectRevert(RewardPool.NotCaughtUp.selector);
        pool.closeInterval();
        // acknowledged at offset 5,050: the genesis assignment ends there
        clock(5_100, CAD_T + 100);
        pushRecord(RecordKind.Ack, ackData(resultID, H_ROUND, 5_050, 5_051));
        applyAll();
        _advanceAll();
        assertEq(pool.segmentCount(), 2);
        assertTrue(pool.segmentAt(0).ended);
        assertEq(pool.segmentAt(0).end, 5_050);
        assertEq(pool.segmentAt(1).start, 5_050);
        // [0,5000) in five grid intervals, then [5000,5050) owned by the genesis assignment
        assertEq(_drain(), 6);
        assertEq(pool.nextStart(), 5_050);
        assertEq(pool.credits(payee(0)), (5 ether + 0.05 ether) / 4);
    }

    function test_aHandoffSplitsTheOwnersAtTheAckOffset() public {
        clock(40, 10);
        _handoff(3, 100); // identity 3 is not in J
        clock(1_500, 20);
        _advanceAll();
        assertEq(_drain(), 2);
        // [0,100) belongs to the four genesis members: 0.1 UCT, 0.025 each
        // [100,1000) belongs to J's three: 0.9 UCT, 0.3 each
        assertEq(pool.credits(payee(0)), 0.025 ether + 0.3 ether);
        assertEq(pool.credits(payee(2)), 0.025 ether + 0.3 ether);
        assertEq(pool.credits(payee(3)), 0.025 ether);
        assertEq(pool.totalCredits(), 1 ether);
        _conserved();
    }

    function test_theTimelineReadsRecordsInOrderAndOnlyWhenCustodyHasAppliedThem() public {
        clock(40, 10);
        reserve(RES_J, ASG_J, allExcept(3), 1);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        // custody has not applied the record: the pool does not read it
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.advanceRecords(2);
        applyAll();
        assertEq(pool.advanceRecords(2), 1);
        assertEq(pool.recordCursor(), 1);
        vm.expectRevert(RewardPool.TooManyRecords.selector);
        pool.advanceRecords(3);
    }

    function test_aSessionClosedRecordMovesNoBoundary() public {
        clock(40, 10);
        reserve(RES_J, ASG_J, allExcept(3), 1);
        pushRecord(RecordKind.SessionClosed, abi.encode(RES_J));
        applyAll();
        _advanceAll();
        assertEq(pool.recordCursor(), 1);
        assertEq(pool.segmentCount(), 1, "an aborted candidate earns nothing");
        clock(1_000, 20);
        _drain();
        assertEq(pool.credits(payee(3)), 0.25 ether);
    }

    function test_zeroFundingGivesAZeroBudgetAndLaterFundingNeverReopensAnInterval() public {
        vm.deal(address(this), 10 ether);
        // drain the pool: a funded rate over a long stretch
        clock(1_000, 10);
        pool.closeInterval();
        // a pool with nothing available: use a second pool over the same timeline
        RewardPool empty = new RewardPool(
            address(roots), address(custody), address(election), address(gov), GENESIS_ASSIGNMENT
        );
        assertEq(empty.available(), 0);
        (uint64 a, uint64 b, uint256 budget) = empty.closeInterval();
        assertEq(a, 0);
        assertEq(b, 1_000);
        assertEq(budget, 0);
        assertEq(empty.totalCredits(), 0);
        assertEq(empty.nextStart(), 1_000, "the cursor advanced");
        empty.fund{value: 5 ether}();
        clock(2_000, 20);
        (a, b, budget) = empty.closeInterval();
        assertEq(a, 1_000);
        assertEq(budget, 1 ether, "funding applies to the not-yet-closed interval only");
        assertEq(empty.totalCredits(), 1 ether);
        assertEq(empty.available(), 4 ether);
    }

    function test_exhaustionPaysWhatIsAvailable() public {
        vm.deal(address(this), 10 ether);
        RewardPool small = new RewardPool{value: 1.5 ether}(
            address(roots), address(custody), address(election), address(gov), GENESIS_ASSIGNMENT
        );
        clock(3_000, 10);
        (,, uint256 b1) = small.closeInterval();
        (,, uint256 b2) = small.closeInterval();
        (,, uint256 b3) = small.closeInterval();
        assertEq(b1, 1 ether);
        assertEq(b2, 0.5 ether, "the available remainder");
        assertEq(b3, 0);
        assertEq(small.available(), 0);
        assertEq(small.totalCredits(), 1.5 ether);
        assertEq(address(small).balance, 1.5 ether);
    }

    function test_forcedValueIsSurplusAndNeverAllocated() public {
        vm.deal(address(this), 1 ether);
        // a direct payment is refused; value can only arrive through fund() or by force
        (bool ok,) = address(pool).call{value: 1 ether}("");
        assertFalse(ok);
        vm.deal(address(pool), address(pool).balance + 3 ether); // a forced transfer
        assertEq(pool.surplus(), 3 ether);
        assertEq(pool.available(), REWARD_FUNDING);
        clock(1_000, 10);
        pool.closeInterval();
        assertEq(pool.surplus(), 3 ether);
        pool.fund{value: 1 ether}();
        assertEq(pool.available(), REWARD_FUNDING - 1 ether + 1 ether);
        _conserved();
    }

    // --- claims ----------------------------------------------------------------------------------

    function test_claimPaysTheCreditToTheNamedRecipient() public {
        clock(1_000, 10);
        pool.closeInterval();
        address to = makeAddr("recipient");
        vm.startPrank(payee(1));
        vm.expectRevert(RewardPool.InsufficientCredit.selector);
        pool.claim(0.25 ether + 1, payable(to));
        vm.expectRevert(RewardPool.InsufficientCredit.selector);
        pool.claim(0, payable(to));
        pool.claim(0.1 ether, payable(to));
        vm.stopPrank();
        assertEq(to.balance, 0.1 ether);
        assertEq(pool.credits(payee(1)), 0.15 ether);
        assertEq(pool.totalCredits(), 0.9 ether);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(RewardPool.InsufficientCredit.selector);
        pool.claim(1, payable(to));
        _conserved();
    }

    function test_aRevertingRecipientFailsOnlyItsOwnClaim() public {
        clock(1_000, 10);
        pool.closeInterval();
        RejectingPayee bad = new RejectingPayee();
        // the credit belongs to a payee, who nominates a reverting recipient
        vm.prank(payee(0));
        vm.expectRevert(RewardPool.TransferFailed.selector);
        pool.claim(0.1 ether, payable(address(bad)));
        assertEq(pool.credits(payee(0)), 0.25 ether, "the failed claim changed nothing");
        // another payee's claim, and the same payee's other claim, are unaffected
        vm.prank(payee(1));
        pool.claim(0.25 ether, payable(payee(1)));
        vm.prank(payee(0));
        pool.claim(0.25 ether, payable(payee(0)));
        _conserved();
    }

    function test_aRecipientCannotReenterTheClaim() public {
        clock(1_000, 10);
        pool.closeInterval();
        // payee 0 is a contract that claims again from its receive hook while it holds credit
        vm.etch(payee(0), address(new ReenteringPayee(pool)).code);
        vm.prank(payee(0));
        vm.expectRevert(RewardPool.TransferFailed.selector);
        pool.claim(0.2 ether, payable(payee(0)));
        assertEq(pool.credits(payee(0)), 0.25 ether, "nothing was paid or debited");
        assertEq(payee(0).balance, 0);
        _conserved();
    }

    // --- rate changes ----------------------------------------------------------------------------

    /// @dev A governed rate change takes effect at its activation progress, which is an interval boundary of its own.
    function test_aRateChangeSplitsTheIntervalAtItsActivationProgress() public {
        // queue a rate of 3 UCT per 1,000, pass both delays, schedule
        bytes32 h = gov.currentPolicyHash();
        Policy memory p = gov.policy();
        vm.prank(governanceAuthority);
        uint64 n = gov.queue(p, 3 ether, h, 1);
        clock(2_000, 3_600);
        gov.execute(n);
        // the election at progress 5,037 activates it
        clock(5_037, 3_600);
        vm.prank(SYS);
        election.elect(keccak256("origin"));
        assertEq(gov.currentPolicyID(), 2);
        assertEq(gov.snapshotAt(2).effectiveProgress, 5_037);
        bytes32 resultID = election.openResult();
        clock(5_100, 3_700);
        pushRecord(RecordKind.Ack, ackData(resultID, H_ROUND, 5_050, 5_051));
        applyAll();
        _advanceAll();
        clock(7_000, 3_800);

        uint64[] memory starts = new uint64[](16);
        uint64[] memory ends = new uint64[](16);
        uint256[] memory budgets = new uint256[](16);
        uint256 k;
        while (true) {
            try pool.closeInterval() returns (uint64 a, uint64 b, uint256 bud) {
                starts[k] = a;
                ends[k] = b;
                budgets[k] = bud;
                ++k;
            } catch {
                break;
            }
        }
        // [0,1000) ... [4000,5000) at 1 UCT; [5000,5037) old rate; [5037,5050) new rate (genesis owner ends at 5050); then [5050,6000) and
        // [6000,7000) at the new rate for the elected assignment
        assertEq(k, 9);
        assertEq(ends[4], 5_000);
        assertEq(starts[5], 5_000);
        assertEq(ends[5], 5_037);
        assertEq(budgets[5], 37 * 1e15, "old rate: 1 UCT * 37 / 1000");
        assertEq(starts[6], 5_037);
        assertEq(ends[6], 5_050);
        assertEq(budgets[6], 39 * 1e15, "new rate: 3 UCT * 13 / 1000");
        assertEq(ends[7], 6_000);
        assertEq(budgets[7], 2.85 ether, "3 UCT * 950 / 1000");
        assertEq(ends[8], 7_000);
        assertEq(budgets[8], 3 ether);
        assertEq(pool.rateCursor(), 2);
        _conserved();
    }
}

/// @dev Tiny wei amounts: a rate of 7 wei per 1,000 units and a pool of 20 wei, so rounding dust and exhaustion decide the credits.
contract RewardsDustTest is RewardsBase {
    function _rewardRate() internal pure override returns (uint128) {
        return 7;
    }

    function _rewardFunding() internal pure override returns (uint256) {
        return 20;
    }

    function test_dustReturnsToTheAvailableFundingInTheSameCall() public {
        clock(1_000, 10);
        (,, uint256 budget) = pool.closeInterval();
        assertEq(budget, 7);
        // 7 wei over four equal weights: 1 each, 3 wei of dust back to available
        for (uint256 i; i < 4; ++i) {
            assertEq(pool.credits(payee(i)), 1);
        }
        assertEq(pool.totalCredits(), 4);
        assertEq(pool.available(), 20 - 4);
        _conserved();
        clock(2_000, 20);
        (,, budget) = pool.closeInterval();
        assertEq(budget, 7, "the next budget does not depend on how the dust was held");
        clock(3_000, 30);
        (,, budget) = pool.closeInterval();
        assertEq(budget, 7);
        assertEq(pool.available(), 20 - 12);
    }

    /// @dev An independent model of the whole schedule against randomized call partitions: the clock moves in random steps, the
    /// pool is asked to read records and to close intervals at random moments, with one handoff at a random offset; at the end
    /// the credits equal the model's, whatever the partition.
    function testFuzz_creditsDoNotDependOnHowTheWorkIsPartitioned(uint256 seed) public {
        uint64 progress;
        uint64 off;
        bool handedOff;
        uint256 excluded = seed % 4;
        for (uint256 step; step < 10; ++step) {
            seed = uint256(keccak256(abi.encode(seed, step)));
            progress += uint64(1 + (seed % 1_700));
            clock(progress, uint64(10 + step));
            if (!handedOff && step >= 2 && (seed >> 8) % 3 == 0) {
                off = progress + 1 + uint64((seed >> 16) % 900);
                _handoff(excluded, off);
                handedOff = true;
            }
            if ((seed >> 32) % 2 == 0) _advanceAll();
            uint256 closes = (seed >> 40) % 3;
            for (uint256 i; i < closes; ++i) {
                try pool.closeInterval() {} catch {}
            }
        }
        progress += 3_000;
        clock(progress, 100);
        _advanceAll();
        _drain();

        uint256[4] memory want = _model(progress, handedOff, off, excluded);
        for (uint256 i; i < 4; ++i) {
            assertEq(pool.credits(payee(i)), want[i], "credit of payee");
        }
        _conserved();
    }

    /// @dev From-scratch arithmetic over the canonical boundaries: grid points of 1,000 and the owner change at `off`.
    function _model(uint64 progress, bool handedOff, uint64 off, uint256 excluded)
        internal
        pure
        returns (uint256[4] memory credit)
    {
        uint256 avail = 20;
        uint64 a;
        while (true) {
            bool second = handedOff && a >= off;
            uint64 end = (a / 1_000 + 1) * 1_000;
            if (handedOff && !second && off < end) end = off;
            if (end > progress) break;
            uint256 nominal = (7 * uint256(end - a)) / 1_000;
            uint256 budget = nominal < avail ? nominal : avail;
            avail -= budget;
            uint256 n = second ? 3 : 4;
            uint256 share = budget / n;
            for (uint256 i; i < 4; ++i) {
                if (second && i == excluded) continue;
                credit[i] += share;
            }
            avail += budget - share * n;
            a = end;
        }
    }
}

/// @dev Two identities nominate the same payee: their credits aggregate.
contract RewardsSharedPayeeTest is RewardsBase {
    function payeePk(uint256 i) internal pure override returns (uint256) {
        return i < 2 ? 0x1200 : 0x1200 + i;
    }

    function test_sharedPayeesAggregate() public {
        clock(1_000, 10);
        pool.closeInterval();
        assertEq(pool.credits(vm.addr(0x1200)), 0.5 ether);
        assertEq(pool.credits(vm.addr(0x1202)), 0.25 ether);
        assertEq(pool.totalCredits(), 1 ether);
    }
}
