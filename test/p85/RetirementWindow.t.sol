// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {MockRootRecords} from "./MockRootRecords.sol";
import {CustodyStorage} from "../../src/p85/CustodyStorage.sol";
import {GovernanceParams} from "../../src/p85/GovernanceParams.sol";
import {PolicyBounds} from "../../src/p85/PolicyBounds.sol";
import {Policy, RecordKind, RetirementData} from "../../src/p85/P85Types.sol";

/// @notice #1298 on the resettable-testnet profile (report window 1,800, settlement margin 1,800, time floor 3,600): the lock starts only
/// when it is authenticated that the stake backs no active or prepared assignment, and nothing else releases it early.
contract RetirementWindowTest is P85Flow {
    function _rotate(uint256 i, uint256 newPk) internal {
        bytes memory newKey = compressed(newPk);
        bytes32 digest = keccak256(
            abi.encode(
                keccak256("unicity.p85.pop.proposeRootKey"),
                NETWORK,
                block.chainid,
                address(custody),
                gid(i),
                uint64(1),
                keccak256(newKey),
                uint64(0)
            )
        );
        bytes memory pop = sign(newPk, digest);
        vm.prank(vm.addr(ownerPk(i)));
        custody.proposeRootKey(gid(i), newKey, pop);
    }

    function test_aRequestStartsNoClock() public {
        requestRetirement(0);
        uint256 lot = lotOf(gid(0));
        assertEq(lotv(lot).timeUntil, 0, "no floor from the request");
        handoffExcluding(0);
        vm.expectRevert(CustodyStorage.LotStillReferenced.selector); // G still holds it
        matureOne(lot);
        closeGenesisAt(1_000_000, 100_000_000);
        // referenced no more, every floor long past, but the retirement is not authenticated: still no exit
        clock(10_000_000, 200_000_000);
        vm.expectRevert(CustodyStorage.RetirementNotImported.selector);
        matureOne(lot);
    }

    function test_aKeyRotationStartsNoClock() public {
        _rotate(0, 0x9501);
        requestRetirement(0);
        uint256 lot = lotOf(gid(0));
        clock(1_000_000, 100_000_000);
        vm.expectRevert(CustodyStorage.LotStillReferenced.selector);
        matureOne(lot);
        assertEq(lotv(lot).timeUntil, 0, "rotation raises no floor and starts no clock");
    }

    function test_aPreparedAssignmentKeepsTheStakeLocked() public {
        // identity 0 is prepared into J, then asks to retire: the root cannot authenticate its retirement while J relies on it
        reserve(RES_J, ASG_J, allMembers(), 1);
        requestRetirement(0);
        (,,,, uint64 gen,,,,) = custody.positions(gid(0));
        clock(500, 2_000);
        pushRecord(
            RecordKind.Retirement,
            abi.encode(RetirementData(gid(0), gen, custody.exposureChain(gid(0), gen)))
        );
        vm.expectRevert(CustodyStorage.RefsStillLive.selector);
        custody.applyRootRecords(1);
        clock(1_000_000, 100_000_000);
        uint256 lot = lotOf(gid(0));
        vm.expectRevert(CustodyStorage.RecordsPending.selector);
        matureOne(lot);
    }

    function test_aFreeLotKeepsItsFloorsAcrossReuseAndCannotWithdraw() public {
        // identity 3 is dropped by J without retiring: its lot returns to Free carrying G's floors
        handoffExcluding(3);
        closeGenesisAt(150, 1_200);
        uint256 lot = lotOf(gid(3));
        LotV memory l = lotv(lot);
        assertEq(l.category, 1, "Free");
        assertEq(l.timeUntil, 1_200 + 3_600);
        assertEq(l.evidenceUntil, 150 + 1_000);
        assertEq(l.holdUntil, 150 + 2_000);
        clock(1_000_000, 100_000_000);
        vm.expectRevert(CustodyStorage.RetirementNotImported.selector);
        matureOne(lot);
        // reused by the next primary: the floors stay
        reserve(RES_J2, ASG_J2, allMembers(), 1);
        LotV memory r = lotv(lot);
        assertEq(r.category, 2, "Encumbered");
        assertEq(r.timeUntil, l.timeUntil);
        assertEq(r.evidenceUntil, l.evidenceUntil);
        assertEq(r.holdUntil, l.holdUntil);
    }

    function test_rapidRoundsWithLittleUcTimeCannotRelease() public {
        reachMaturable(0); // G closes at 150 / 1,200, the retirement lands at 160 / 1,210: t >= 4,810
        uint256 lot = lotOf(gid(0));
        clock(10_000_000, 4_809);
        vm.expectRevert(CustodyStorage.TimeGateNotMet.selector);
        matureOne(lot);
        clock(10_000_000, 4_810); // equality passes
        matureOne(lot);
    }

    function test_theTimeFloorCoversTheReportWindowAndTheSettlementMargin() public view {
        GovernanceParams gov = factory.POLICY();
        assertEq(gov.reportWindow(), 1_800);
        assertEq(gov.settlementMargin(), 1_800);
        assertEq(evidence.reportWindow(), 1_800);
        assertGe(gov.policy().timeFloor, gov.reportWindow() + gov.settlementMargin());
    }
}

/// @notice #1298 on the production profile: W = 7 days plus 12 h reporting/inclusion margin (648,000 s), 12 h settlement margin, the
/// 8-day floor (691,200 s = PolicyBounds.MAX_FLOOR).
contract RetirementWindowProductionTest is P85Flow {
    uint64 internal constant FLOOR = 691_200;

    function setUp() public override {
        roots = new MockRootRecords();
        Policy memory p = _defaultPolicy();
        p.timeFloor = FLOOR;
        _deploy(p);
    }

    function _reportWindow() internal pure override returns (uint64) {
        return 648_000;
    }

    function _settlementMargin() internal pure override returns (uint64) {
        return 43_200;
    }

    function test_theProductionProfileIsPinned() public view {
        GovernanceParams gov = factory.POLICY();
        assertEq(PolicyBounds.MAX_FLOOR, FLOOR);
        assertEq(gov.reportWindow(), 648_000);
        assertEq(gov.settlementMargin(), 43_200);
        assertEq(gov.policy().timeFloor, FLOOR);
        assertEq(evidence.reportWindow(), 648_000);
        assertEq(lotv(lotOf(gid(0))).timeFloor, FLOOR, "every genesis lot captured the full floor");
    }

    function test_releaseNeedsTheFullEightDaysAfterRetirementExactlyOnce() public {
        reachMaturable(0); // retirement at UC 1,210: t >= 1,210 + 691,200
        uint256 lot = lotOf(gid(0));
        (,,,,, uint64 timeUntil,) = evidence.releaseState(lot);
        assertEq(timeUntil, 1_210 + FLOOR);
        clock(50_000_000, 1_210 + FLOOR - 1); // fast rounds, one UC second short
        vm.expectRevert(CustodyStorage.TimeGateNotMet.selector);
        matureOne(lot);
        clock(50_000_000, 1_210 + FLOOR);
        matureOne(lot);
        address wd = vm.addr(wdPk(0));
        assertEq(creditOf(wd), GENESIS_BOND);
        vm.expectRevert(CustodyStorage.LotAlreadyReleased.selector);
        matureOne(lot);
        vm.prank(wd);
        custody.claim(GENESIS_BOND, wd);
        assertEq(wd.balance, GENESIS_BOND);
        vm.prank(wd);
        vm.expectRevert(CustodyStorage.InsufficientCredit.selector);
        custody.claim(1, wd);
    }

    function test_aGovernanceReductionBelowTheReportWindowIsRejected() public {
        GovernanceParams gov = factory.POLICY();
        Policy memory p = _defaultPolicy();
        p.timeFloor = 604_800; // the old 7-day ceiling: no settlement room after W
        bytes32 h = gov.currentPolicyHash();
        vm.prank(governanceAuthority);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("timeFloor<report+settlement")
            )
        );
        gov.queue(p, 1 ether, h, 1);
        p.timeFloor = FLOOR - 1;
        vm.prank(governanceAuthority);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("timeFloor<report+settlement")
            )
        );
        gov.queue(p, 1 ether, h, 1);
        p.timeFloor = FLOOR;
        vm.prank(governanceAuthority);
        gov.queue(p, 1 ether, h, 1);
    }
}
