// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {UncheckedPolicy} from "./UncheckedPolicy.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {Policy, Limits, RecordKind, SessionClosedData} from "../../src/p85/P85Types.sol";

/// @notice Exact maturity: closed references, imported retirement, the strict round gates, the
/// inclusive UC-time gate, the full import prefix, and conversion of principal into credit.
///
/// Timeline of reachMaturable(0): G closes at progress 150 / UC 1,200, the retirement record lands
/// at progress 160 / UC 1,210. Round gate: p > max(160 + 2,000, 150 + 2,000) = 2,160. UC gate:
/// t >= max(1,210 + 3,600, 1,200 + 3,600) = 4,810.
contract MaturityTest is P85Flow {
    function test_roundGateIsStrict() public {
        reachMaturable(0);
        uint256 lot = lotOf(gid(0));
        clock(2_160, 90_000); // time is far past its floor, progress equals the round deadline
        vm.expectRevert(StakeCustody.RoundGateNotMet.selector);
        matureOne(lot);
        clock(2_161, 90_000);
        matureOne(lot);
        assertEq(creditOf(vm.addr(wdPk(0))), GENESIS_BOND);
    }

    function test_timeGateIsInclusive() public {
        reachMaturable(0);
        uint256 lot = lotOf(gid(0));
        clock(9_000, 4_809); // rounds far past the deadline, one UC second short
        vm.expectRevert(StakeCustody.TimeGateNotMet.selector);
        matureOne(lot);
        clock(9_000, 4_810); // equality passes
        matureOne(lot);
        assertEq(creditOf(vm.addr(wdPk(0))), GENESIS_BOND);
    }

    function test_maturityConvertsPrincipalToWithdrawalCreditAndClosesTheLot() public {
        reachMaturable(0);
        uint256 lot = lotOf(gid(0));
        clock(3_000, 5_000);
        uint256 freeBefore = custody.totalDraining();
        assertEq(freeBefore, GENESIS_BOND, "retired lot is draining");
        vm.expectEmit(true, true, false, true, address(custody));
        emit StakeCustody.LotMatured(lot, vm.addr(wdPk(0)), GENESIS_BOND);
        matureOne(lot);
        LotV memory l = lotv(lot);
        assertEq(l.remaining, 0);
        assertEq(l.category, 4);
        assertEq(custody.totalDraining(), 0);
        assertEq(custody.totalCredits(), GENESIS_BOND);
        assertEq(address(custody).balance, N_GENESIS * GENESIS_BOND, "maturity moves nothing out");
        (,,,,,, uint32 openLots,,) = custody.positions(gid(0));
        assertEq(openLots, 0);
        assertFalse(election.isIndexed(gid(0)), "a closed generation leaves the live index");
        assertEq(election.liveCount(), N_GENESIS - 1);
        assertConserved();
    }

    function test_releaseStateReportsOnlyAuthenticatedGates() public {
        reachMaturable(0);
        uint256 lot = lotOf(gid(0));
        (
            bool released,
            uint32 references,
            bool retirementImported,
            uint64 roundUntil,
            uint64 evidenceUntil,
            uint64 timeUntil,
            uint32 holds
        ) = evidence.releaseState(lot);
        assertFalse(released);
        assertEq(references, 0);
        assertTrue(retirementImported);
        assertEq(roundUntil, 2_160, "max(p_ret + hold, anchor + hold)");
        assertEq(evidenceUntil, 1_150, "anchor + evidence window");
        assertEq(timeUntil, 4_810, "max(t_ret + floor, t_close + floor)");
        assertEq(holds, 0);
        // a referenced lot reports its references; a matured lot reports released
        (, references,,,,,) = evidence.releaseState(lotOf(gid(1)));
        assertEq(references, 1);
        clock(3_000, 5_000);
        matureOne(lot);
        (released,,,,,,) = evidence.releaseState(lot);
        assertTrue(released);
    }

    function test_aLotCannotMatureTwice() public {
        reachMaturable(0);
        uint256 lot = lotOf(gid(0));
        clock(3_000, 5_000);
        matureOne(lot);
        vm.expectRevert(StakeCustody.LotAlreadyReleased.selector);
        matureOne(lot);
    }

    function test_unknownLotAndEmptyAndOversizedBatchesAreRejected() public {
        reachMaturable(0);
        clock(3_000, 5_000);
        vm.expectRevert(StakeCustody.LotUnknown.selector);
        matureOne(9_999);
        uint256[] memory none = new uint256[](0);
        vm.expectRevert(StakeCustody.EmptyBatch.selector);
        custody.mature(none);
        uint256[] memory many = new uint256[](33);
        vm.expectRevert(StakeCustody.BatchTooLarge.selector);
        custody.mature(many);
    }

    function test_aReferencedLotCannotMatureEvenWhenGatesPass() public {
        reachMaturable(0);
        clock(3_000, 5_000);
        uint256 lot = lotOf(gid(1)); // identity 2 is still in J
        vm.expectRevert(StakeCustody.LotStillReferenced.selector);
        matureOne(lot);
    }

    function test_maturityNeedsTheImportedRetirementRecord() public {
        requestRetirement(0);
        handoffExcluding(0);
        closeGenesisAt(150, 1_200); // closed, but no retirement record yet
        clock(9_000, 90_000);
        uint256 lot = lotOf(gid(0));
        vm.expectRevert(StakeCustody.RetirementNotImported.selector);
        matureOne(lot);
    }

    function test_maturityNeedsAnyRetirementRequestAtAll() public {
        // a free lot with no retirement can never mature: no partial voluntary withdrawal exists
        clock(9_000, 90_000);
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        uint256 lot = bondFor(id, 100 * UCT);
        vm.expectRevert(StakeCustody.RetirementNotImported.selector);
        matureOne(lot);
    }

    function test_maturityRequiresTheWholeRecordPrefixToBeApplied() public {
        reachMaturable(0);
        clock(3_000, 5_000);
        // an authenticated but unapplied record blocks maturity of everything
        reserveForClosedRecord();
        uint256 lot = lotOf(gid(0));
        vm.expectRevert(StakeCustody.RecordsPending.selector);
        matureOne(lot);
        applyAll();
        matureOne(lot);
    }

    function reserveForClosedRecord() internal {
        bytes32 res = keccak256("res/late");
        reserve(res, keccak256("asg/late"), allExcept(0), 3);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(res)));
    }

    function test_unrelatedCleanLotsStayClaimableBesideHeldLots() public {
        // identity 1 retires cleanly; identity 2's lot stays referenced and unmatured
        reachMaturable(0);
        clock(3_000, 5_000);
        matureOne(lotOf(gid(0)));
        vm.prank(vm.addr(wdPk(0)));
        custody.claim(GENESIS_BOND, vm.addr(wdPk(0)));
        assertEq(vm.addr(wdPk(0)).balance, GENESIS_BOND);
        assertEq(lotv(lotOf(gid(1))).remaining, GENESIS_BOND, "the held lot is untouched");
    }

    function test_newGenerationOpensAfterEveryOldLotMatures() public {
        reachMaturable(0);
        clock(3_000, 5_000);
        matureOne(lotOf(gid(0)));
        uint256 lot = bondFor(gid(0), 200 * UCT);
        (,,,, uint64 gen,,,,) = custody.positions(gid(0));
        assertEq(gen, 2);
        assertEq(lotv(lot).generation, 2);
        assertTrue(election.isIndexed(gid(0)), "the live index follows the new generation");
        (bool imported,,) = custody.retirements(gid(0), 2);
        assertFalse(imported, "the new generation has its own retirement state");
        assertConserved();
    }

    function test_roleChangeAfterMaturityLeavesTheCreditWithItsOriginalCreditor() public {
        reachMaturable(0);
        clock(3_000, 5_000);
        matureOne(lotOf(gid(0)));
        address newWd = makeAddr("newWithdrawal");
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), vm.addr(ownerPk(0)), newWd, 0);
        vm.prank(newWd);
        custody.acceptRoles(gid(0), 0, vm.addr(ownerPk(0)), newWd);
        vm.prank(vm.addr(wdPk(0)));
        custody.acceptRoles(gid(0), 0, vm.addr(ownerPk(0)), newWd);
        assertEq(creditOf(vm.addr(wdPk(0))), GENESIS_BOND, "existing credit keeps its creditor");
        assertEq(creditOf(newWd), 0);
    }

    function test_maturityCreditsTheCurrentWithdrawalAuthority() public {
        reachMaturable(0);
        address newWd = makeAddr("newWithdrawal");
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), vm.addr(ownerPk(0)), newWd, 0);
        vm.prank(newWd);
        custody.acceptRoles(gid(0), 0, vm.addr(ownerPk(0)), newWd);
        vm.prank(vm.addr(wdPk(0)));
        custody.acceptRoles(gid(0), 0, vm.addr(ownerPk(0)), newWd);
        clock(3_000, 5_000);
        matureOne(lotOf(gid(0)));
        assertEq(creditOf(newWd), GENESIS_BOND);
    }

    // --- policy capture -------------------------------------------------------------------------

    function test_laterPolicyReductionsCannotShortenCapturedProtection() public {
        // genesis captured 2,000-round holds / 3,600 s; a later snapshot lowers them
        UncheckedPolicy source = new UncheckedPolicy(_defaultPolicy());
        _deployManual(address(source), Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32}));
        Policy memory lax = _defaultPolicy();
        lax.holdNormal = 401;
        lax.holdSuffix = 401;
        lax.holdRetirement = 401;
        lax.timeFloor = 1;
        source.addSnapshot(lax);
        reachMaturable(0);
        uint256 lot = lotOf(gid(0));
        clock(2_160, 4_809);
        vm.expectRevert(StakeCustody.RoundGateNotMet.selector);
        matureOne(lot);
        clock(2_161, 4_809);
        vm.expectRevert(StakeCustody.TimeGateNotMet.selector);
        matureOne(lot);
        clock(2_161, 4_810);
        matureOne(lot);
    }

    function test_theEvidenceGateIsIndependentOfTheHoldGates() public {
        // An unbounded policy whose hold is shorter than its evidence window (impossible under the
        // development bounds) shows the evidence gate itself blocks maturity.
        Policy memory p = _defaultPolicy();
        p.evidenceWindow = 5_000;
        p.suffixEvidenceWindow = 5_000;
        p.holdNormal = 400;
        p.holdSuffix = 400;
        p.holdRetirement = 400;
        UncheckedPolicy source = new UncheckedPolicy(p);
        _deployManual(address(source), Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32}));
        reachMaturable(0);
        uint256 lot = lotOf(gid(0));
        // hold gate: max(160 + 400, 150 + 400) = 560; evidence gate: 150 + 5,000 = 5,150
        clock(5_150, 99_999);
        vm.expectRevert(StakeCustody.EvidenceGateNotMet.selector);
        matureOne(lot);
        clock(5_151, 99_999);
        matureOne(lot);
    }

    // --- non-reentrancy of maturity --------------------------------------------------------------

    function test_matureAndClaimShareOneReentrancyGuard() public {
        // claim() to a contract that tries to mature during the callback: the guard blocks it.
        reachMaturable(0);
        clock(3_000, 5_000);
        matureOne(lotOf(gid(0)));
        MatureOnReceive attacker = new MatureOnReceive(custody, lotOf(gid(1)));
        // route the credit to the attacker as withdrawal authority of identity 1
        vm.prank(vm.addr(wdPk(0)));
        custody.claim(GENESIS_BOND, address(attacker));
        assertTrue(attacker.triedAndFailed());
        assertEq(address(attacker).balance, GENESIS_BOND);
    }
}

contract MatureOnReceive {
    StakeCustody internal immutable CUSTODY;
    uint256 internal immutable LOT;
    bool public triedAndFailed;

    constructor(StakeCustody c, uint256 lot) {
        CUSTODY = c;
        LOT = lot;
    }

    receive() external payable {
        uint256[] memory ids = new uint256[](1);
        ids[0] = LOT;
        try CUSTODY.mature(ids) {}
        catch (bytes memory reason) {
            triedAndFailed = bytes4(reason) == bytes4(keccak256("ReentrancyGuardReentrantCall()"));
        }
    }
}
