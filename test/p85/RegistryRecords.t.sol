// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {RewardsBase} from "./Rewards.t.sol";
import {RewardPool} from "../../src/p85/RewardPool.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {CustodyStorage} from "../../src/p85/CustodyStorage.sol";
import {OutputView} from "../../src/vr/VRTypes.sol";
import {
    RecordKind,
    RecoveryAckData,
    BoundaryData,
    OutputRejectedData,
    HolderRetirementData,
    SessionClosedData
} from "../../src/p85/P85Types.sol";

/// @dev The two ValidatorRegistry views RewardPool's tail bound reads, etched at the canonical VR address: one open output and the
/// progress it was reserved at.
contract MockOpenOutput {
    bytes32 public openOutput;
    uint64 internal _reserved;

    function setOpen(bytes32 rid, uint64 reservedProgress) external {
        openOutput = rid;
        _reserved = reservedProgress;
    }

    function output(bytes32 rid) external view returns (OutputView memory v) {
        if (rid == openOutput) {
            v.state = 1;
            v.reservedProgress = _reserved;
        }
    }
}

/// @notice VT-15 (bft-core#1157), the consumer half of the shared acceptance contract AC-LR (validator-registry design sections 4.2 and
/// 4.4): P85 custody and the RewardPool read a validator-registry log. Kinds 6 and 7, HolderRetirements of other holders and records of
/// results or assignments custody never had advance both cursors and change nothing; a HolderRetirement of custody's own holder index
/// retires; reward accrual ends at the authoritative transition, NONE segments accrue nothing, and closeInterval skips an ended NONE
/// segment and is NothingToDo on an open NONE tail.
///
/// The records are pushed into the test registry (MockRootRecords) with result ids custody does or does not know; the payload words of
/// kinds 6 to 8 are the schema v1 widths, which the registry tests check against the frozen vectors. What this file does not cover, and
/// VT-04 owes for AC-LR: the PosElectionAdapter, the PoS output through VR and VR's own pointer switch, atomic loss and its interleavings,
/// VR-domain digests, the custody liability-holder layout (ERC-7201 facts), the 16-member and >8-fact-key liability cases, holders A and
/// B overlapping on one (id, generation), and the verifier refusals (stale cursor, lotReferences, code-hash mismatch, VT-05a).
contract RegistryRecordsTest is RewardsBase {
    bytes32 internal constant RES_NATIVE = keccak256("result/native");
    bytes32 internal constant RES_OTHER = keccak256("result/other-module");

    function _boundary(bytes32 resultID, uint64 epoch, bool recovered)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            BoundaryData(
                resultID, epoch, recovered ? epoch + 1 : epoch, epoch + 1, 1_234, recovered, 0
            )
        );
    }

    function _rejected(bytes32 resultID) internal pure returns (bytes memory) {
        return abi.encode(OutputRejectedData(resultID, 1, 0, 0x3));
    }

    function _holderRetirement(uint8 holder, uint64 id, uint64 gen, bytes32 ref)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(HolderRetirementData(holder, id, gen, ref));
    }

    // --- custody: cursor no-ops ----------------------------------------------------------------------

    function test_kinds6And7AndForeignRecordsAdvanceBothCursorsAndChangeNothing() public {
        clock(40, 10);
        // a reserved custody session, so a foreign record is not mistaken for "no session at all"
        reserve(RES_J, ASG_J, allExcept(3), 1);
        bytes32 lastAcked = custody.lastAckedAssignment();
        pushRecord(RecordKind.Boundary, _boundary(RES_OTHER, 2, false));
        pushRecord(RecordKind.OutputRejected, _rejected(RES_OTHER));
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_OTHER)));
        pushRecord(RecordKind.Ack, ackData(RES_NATIVE, H_ROUND, 100, 101));
        pushRecord(RecordKind.Boundary, _boundary(RES_NATIVE, 2, false));
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_NATIVE, ASG_K, 300, 301, 350, 400, 401, 3, 3))
        );
        pushRecord(RecordKind.Boundary, _boundary(RES_NATIVE, 2, true));
        pushRecord(
            RecordKind.Closure, closureData(keccak256("assignment/never-reserved"), H_ROUND, "x")
        );
        pushRecord(RecordKind.HolderRetirement, _holderRetirement(3, gid(0), 1, keccak256("ref")));
        pushRecord(RecordKind.HolderRetirement, _holderRetirement(7, gid(1), 1, bytes32(0)));
        uint64 n = roots.recordCount();
        applyAll();
        assertEq(custody.recordCursor(), n, "custody consumed every record");
        assertEq(custody.lastRecordID(), roots.recordAt(n - 1).recordID, "and kept the hash chain");
        assertEq(
            custody.lastAckedAssignment(), lastAcked, "no foreign acknowledgement moved custody"
        );
        assertEq(custody.session(RES_J).state, 1, "the reserved session is still open");
        (bool imported,,) = custody.retirements(gid(0), 1);
        assertFalse(imported, "another holder's retirement is not custody's");
        _advanceAll();
        assertEq(pool.recordCursor(), n, "the pool consumed every record");
        assertEq(pool.lastRecordID(), roots.recordAt(n - 1).recordID);
        // the foreign Ack ended the genesis segment and opened NONE; the foreign RecoveryAck while NONE is open moved nothing
        assertEq(pool.segmentCount(), 2);
        RewardPool.Segment memory none = pool.segmentAt(1);
        assertEq(none.assignmentID, bytes32(0));
        assertEq(none.start, 100);
        assertFalse(none.ended);
        assertEq(pool.segmentAt(0).end, 100);
    }

    function test_aRecordOfAKnownSessionStillAppliesOrRevertsAsBefore() public {
        handoffExcluding(3);
        // J is acknowledged: a SessionClosed of it is the impossible history it always was
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        vm.expectRevert(CustodyStorage.SessionNotOpen.selector);
        custody.applyRootRecords(1);
    }

    function test_aDetachedHolderCatchesUpPermissionlesslyOverForeignRecords() public {
        // a long foreign stretch: custody is never driven, then anyone applies it in bounded batches
        clock(40, 10);
        for (uint256 i; i < 40; ++i) {
            bytes32 r = keccak256(abi.encode("native", i));
            pushRecord(RecordKind.Ack, ackData(r, H_ROUND, uint64(100 + i), uint64(101 + i)));
            pushRecord(RecordKind.Boundary, _boundary(r, uint64(2 + i), false));
        }
        vm.prank(makeAddr("anyone"));
        custody.applyRootRecords(32);
        vm.prank(makeAddr("someone else"));
        custody.applyRootRecords(32);
        vm.prank(makeAddr("anyone"));
        custody.applyRootRecords(16);
        assertEq(custody.recordCursor(), 80);
        while (pool.recordCursor() < 80) {
            vm.prank(makeAddr("anyone"));
            pool.advanceRecords(2);
        }
        assertEq(pool.segmentCount(), 2, "one NONE segment for the whole foreign stretch");
    }

    // --- custody: kind 8 -----------------------------------------------------------------------------

    function test_aHolderRetirementOfCustodysHolderIndexRetires() public {
        assertEq(StakeCustody(address(custody)).HOLDER_INDEX(), 0);
        requestRetirement(0);
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        (,,,, uint64 gen,,,,) = custody.positions(gid(0));
        clock(160, 1_210);
        pushRecord(
            RecordKind.HolderRetirement,
            _holderRetirement(1, gid(0), gen, custody.exposureChain(gid(0), gen))
        );
        pushRecord(
            RecordKind.HolderRetirement,
            _holderRetirement(0, gid(0), gen, custody.exposureChain(gid(0), gen))
        );
        applyAll();
        (bool imported, uint64 pRet, uint64 tRet) = custody.retirements(gid(0), gen);
        assertTrue(imported);
        assertEq(pRet, 160);
        assertEq(tRet, 1_210);
    }

    function test_aHolderRetirementOfCustodysHolderIndexKeepsTheRetirementRules() public {
        requestRetirement(0);
        clock(160, 1_210);
        // identity 0 still has a live genesis exposure: the authorization is applied under custody's own protection rules
        pushRecord(
            RecordKind.HolderRetirement,
            _holderRetirement(0, gid(0), 1, custody.exposureChain(gid(0), 1))
        );
        vm.expectRevert(CustodyStorage.RefsStillLive.selector);
        custody.applyRootRecords(1);
        assertEq(custody.recordCursor(), 0);
    }

    // --- rewards: accrual end, NONE segments, the floor oracle ----------------------------------------

    struct Interval {
        bytes32 assignmentID;
        uint64 start;
        uint64 end;
    }

    /// @dev The oracle: interval credit floor(q * L / 1000), split floor(b * w_i / W) over the owning assignment's exposures, the dust
    /// returned to the pool. Adds each payee's expected credit to `expect` (indexed by genesis payee) and returns the distributed total.
    function _oracle(Interval memory iv, uint256[4] memory expect)
        internal
        view
        returns (uint256 distributed)
    {
        uint256 budget = uint256(DEFAULT_REWARD_RATE) * (iv.end - iv.start) / 1_000;
        bytes32[] memory ids = custody.assignmentExposures(iv.assignmentID);
        uint256 total;
        for (uint256 i; i < ids.length; ++i) {
            total += expo(ids[i]).weight;
        }
        for (uint256 i; i < ids.length; ++i) {
            uint256 share = budget * expo(ids[i]).weight / total;
            address p = expo(ids[i]).operatorPayee;
            for (uint256 k; k < 4; ++k) {
                if (payee(k) == p) expect[k] += share;
            }
            distributed += share;
        }
    }

    /// @dev AC-LR rewards: owned -> foreign -> foreign -> owned RecoveryAck -> foreign over half-open intervals, a fixed rate and no
    /// policy change, the pool funded with at least ten times the nominal emission of the whole span; nothing is paid in NONE spans or
    /// after the end, and earlier credits are kept.
    function test_ownedForeignForeignOwnedRecoveryForeign() public {
        uint64 horizon = 9_000;
        assertGe(
            pool.available(),
            10 * (uint256(DEFAULT_REWARD_RATE) * horizon / 1_000),
            "funded >= 10x nominal emission"
        );
        uint256 funded = pool.available();

        // owned: G over [0, 1300)
        clock(1_000, 100);
        assertEq(_drain(), 1, "[0,1000) G");
        uint256[4] memory early;
        for (uint256 k; k < 4; ++k) {
            early[k] = pool.credits(payee(k));
        }

        // foreign (a native output): G ends at 1300, NONE opens
        clock(1_400, 200);
        pushRecord(RecordKind.Ack, ackData(RES_NATIVE, H_ROUND, 1_300, 1_301));
        pushRecord(RecordKind.Boundary, _boundary(RES_NATIVE, 2, false));
        applyAll();
        _advanceAll();
        assertEq(_drain(), 1, "[1000,1300) G; the open NONE tail closes nothing");
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();

        // foreign again (another module's result): NONE is already open, nothing moves
        clock(1_700, 300);
        pushRecord(RecordKind.Ack, ackData(RES_OTHER, H_ROUND, 1_600, 1_601));
        pushRecord(RecordKind.Boundary, _boundary(RES_OTHER, 3, false));
        applyAll();
        _advanceAll();
        assertEq(pool.segmentCount(), 2);

        // owned RecoveryAck (reattachment): NONE ends at jOffset 1900, J owns [1900, 2300), K from 2300
        reserve(RES_J, ASG_J, allExcept(3), 1);
        clock(2_400, 400);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 1_900, 1_901, 1_950, 2_300, 2_301, 3, 3))
        );
        pushRecord(RecordKind.Boundary, _boundary(RES_J, 2, true));
        applyAll();
        _advanceAll();
        assertEq(pool.segmentAt(1).end, 1_900, "NONE ends at the owned record's offset");

        // foreign: K ends at 3500, NONE opens
        clock(3_600, 500);
        pushRecord(RecordKind.Ack, ackData(keccak256("result/native-2"), H_ROUND, 3_500, 3_501));
        pushRecord(RecordKind.Boundary, _boundary(keccak256("result/native-2"), 4, false));
        applyAll();
        _advanceAll();
        assertEq(pool.segmentCount(), 5, "G, NONE, J, K, NONE");

        clock(horizon, 900);
        uint256 closed = _drain();
        assertEq(closed, 4, "[1900,2000) J, [2000,2300) J, [2300,3000) K, [3000,3500) K");
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        clock(horizon * 2, 1_800);
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        assertEq(pool.nextStart(), 3_500, "nothing after the end of the last owned assignment");

        Interval[7] memory ivs = [
            Interval(GENESIS_ASSIGNMENT, 0, 1_000),
            Interval(GENESIS_ASSIGNMENT, 1_000, 1_300),
            Interval(ASG_J, 1_900, 2_000),
            Interval(ASG_J, 2_000, 2_300),
            Interval(ASG_K, 2_300, 3_000),
            Interval(ASG_K, 3_000, 3_500),
            Interval(bytes32(0), 0, 0)
        ];
        uint256[4] memory expect;
        uint256 distributed;
        for (uint256 i; i < 6; ++i) {
            distributed += _oracle(ivs[i], expect);
        }
        for (uint256 k; k < 4; ++k) {
            assertEq(pool.credits(payee(k)), expect[k], string.concat("payee ", vm.toString(k)));
            assertGe(pool.credits(payee(k)), early[k], "earlier credits are kept");
        }
        assertEq(pool.totalCredits(), distributed);
        assertEq(
            pool.available(), funded - distributed, "the dust returned; NONE spans paid nothing"
        );
        _conserved();
    }

    function test_anOwnedAckAfterNoneReattachesAtItsOffset() public {
        clock(400, 50);
        pushRecord(RecordKind.Ack, ackData(RES_NATIVE, H_ROUND, 300, 301));
        applyAll();
        _advanceAll();
        reserve(RES_J, ASG_J, allExcept(3), 1);
        clock(1_500, 100);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 700, 701));
        applyAll();
        _advanceAll();
        assertEq(pool.segmentCount(), 3);
        assertEq(pool.segmentAt(1).end, 700);
        assertEq(pool.segmentAt(2).assignmentID, ASG_J);
        assertEq(pool.segmentAt(2).start, 700);
        // [0,300) G, NONE [300,700) skipped, [700,1000) J
        assertEq(_drain(), 2);
        assertEq(pool.nextStart(), 1_000);
        assertEq(pool.credits(payee(3)), uint256(0.3 ether) / 4, "identity 3 is only in G");
        assertEq(pool.credits(payee(0)), uint256(0.3 ether) / 4 + uint256(0.3 ether) / 3);
        _conserved();
    }

    // --- the AC-LR mixed log (VT-15 half) --------------------------------------------------------------

    /// @dev genesis; a PoS output acknowledged (Ack + Boundary); another PoS result rejected (OutputRejected + SessionClosed); a native
    /// output acknowledged (the pointer switch: Ack + Boundary of a result custody never had); the Closure of the PoS assignments; the
    /// HolderRetirement of the identity the PoS output dropped; then mature and claim. Rewards stop at the end of the old assignment.
    function test_mixedLogModuleSwitchThenClosureRetirementAndWithdrawal() public {
        requestRetirement(3);
        // the PoS output J (identity 3 dropped), acknowledged at offset 100
        reserve(RES_J, ASG_J, allExcept(3), 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        pushRecord(RecordKind.Boundary, _boundary(RES_J, 2, false));
        applyAll();
        closeGenesisAt(150, 1_200);
        // another PoS result, rejected as expired
        reserve(RES_J2, ASG_J2, allExcept(3), 2);
        clock(400, 1_300);
        pushRecord(RecordKind.OutputRejected, _rejected(RES_J2));
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J2)));
        applyAll();
        assertEq(custody.session(RES_J2).state, 3, "the rejected session closed");
        // the native output: the pointer switch away from the PoS module, at offset 2000
        clock(2_100, 1_400);
        pushRecord(RecordKind.Ack, ackData(RES_NATIVE, 1_950, 2_000, 2_001));
        pushRecord(RecordKind.Boundary, _boundary(RES_NATIVE, 3, false));
        applyAll();
        assertEq(
            custody.lastAckedAssignment(),
            ASG_J,
            "custody's last acknowledged assignment is still the PoS one"
        );
        // the Closure of J's liability, its H being the native output's
        clock(2_200, 1_500);
        pushRecord(RecordKind.Closure, closureData(ASG_J, 1_950, "J"));
        applyAll();
        assertTrue(asg(ASG_J).closed);
        // the HolderRetirement of identity 3 (dropped by J, released by G's closure)
        (,,,, uint64 gen,,,,) = custody.positions(gid(3));
        clock(2_300, 1_600);
        pushRecord(
            RecordKind.HolderRetirement,
            _holderRetirement(0, gid(3), gen, custody.exposureChain(gid(3), gen))
        );
        applyAll();
        (bool imported,,) = custody.retirements(gid(3), gen);
        assertTrue(imported);
        // mature and claim: the withdrawal of the retired identity
        clock(9_000, 90_000);
        matureOne(lotOf(gid(3)));
        address wd = vm.addr(wdPk(3));
        assertEq(creditOf(wd), GENESIS_BOND);
        vm.prank(wd);
        custody.claim(GENESIS_BOND, wd);
        assertEq(wd.balance, GENESIS_BOND);

        // rewards: [0,100) G, [100,1000) J, [1000,2000) J, then NONE; nothing after 2000
        _advanceAll();
        assertEq(pool.recordCursor(), roots.recordCount());
        assertEq(_drain(), 3);
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        assertEq(pool.nextStart(), 2_000);
        assertEq(pool.totalCredits(), 0.1 ether + 1.9 ether - _dust());
        assertEq(
            pool.credits(payee(3)), uint256(0.1 ether) / 4, "the retired identity earned only in G"
        );
        assertConserved();
        _conserved();
    }

    /// @dev The rounding dust of J's two intervals (three equal weights), which the pool keeps available.
    function _dust() internal pure returns (uint256) {
        return (uint256(0.9 ether) - 3 * (uint256(0.9 ether) / 3))
            + (uint256(1 ether) - 3 * (uint256(1 ether) / 3));
    }

    // --- the tail bound: a handoff pending in VR (reviews of #88: astra HIGH, sol P1) ---------------------

    bytes32 internal constant RES_FOREIGN = keccak256("result/foreign-pending");

    function _registry() internal returns (MockOpenOutput vr) {
        address registryAt = pool.REGISTRY();
        vm.etch(registryAt, address(new MockOpenOutput()).code);
        vr = MockOpenOutput(registryAt);
    }

    /// @dev [0,1000) is settled and partly claimed; then VR reserves a foreign output at 1000, commits it, and the root closes G at
    /// H = 1900 while progress runs to 2100 before the foreign acknowledgement is projected.
    function _pendingForeignHandoff() internal returns (MockOpenOutput vr, uint256 claimed) {
        vr = _registry();
        clock(1_000, 100);
        assertEq(_drain(), 1, "[0,1000) settles while no output is open");
        claimed = pool.credits(payee(0)) / 2;
        vm.prank(payee(0));
        pool.claim(claimed, payable(payee(0)));
        vr.setOpen(RES_FOREIGN, 1_000);
        clock(1_950, 195);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, 1_900, "G"));
        applyAll();
        _advanceAll();
        assertTrue(asg(GENESIS_ASSIGNMENT).closed);
        clock(2_100, 210);
        // caught up with every imported record, yet the tail does not settle past the open output's reservation
        assertEq(pool.recordCursor(), roots.recordCount());
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        // a claim of what was earned before is unaffected
        vm.prank(payee(1));
        pool.claim(0.1 ether, payable(payee(1)));
        claimed += 0.1 ether;
    }

    function _assertGEndsAt(uint64 end, uint256 claimed) internal {
        assertEq(pool.segmentAt(0).end, end);
        assertTrue(pool.segmentAt(0).ended);
        assertEq(pool.segmentAt(1).assignmentID, bytes32(0), "NONE from the foreign offset");
        assertEq(pool.segmentAt(1).start, end);
        uint256 closed = _drain();
        assertEq(closed, 1, "[1000,end) G, then the open NONE tail");
        assertEq(pool.nextStart(), end);
        uint256[4] memory expect;
        uint256 distributed = _oracle(Interval(GENESIS_ASSIGNMENT, 0, 1_000), expect);
        distributed += _oracle(Interval(GENESIS_ASSIGNMENT, 1_000, end), expect);
        uint256 paid0 = claimed - 0.1 ether;
        assertEq(
            pool.credits(payee(0)), expect[0] - paid0, "earlier credit kept, less what was claimed"
        );
        assertEq(pool.credits(payee(1)), expect[1] - 0.1 ether);
        assertEq(pool.credits(payee(2)), expect[2]);
        assertEq(pool.credits(payee(3)), expect[3]);
        assertEq(pool.totalCredits(), distributed - claimed);
        assertEq(pool.available(), REWARD_FUNDING - distributed, "nothing past the end was paid");
        _conserved();
    }

    function test_aPendingForeignAckIsNotSettledPastAndEndsTheOwnerWhenItArrives() public {
        (MockOpenOutput vr, uint256 claimed) = _pendingForeignHandoff();
        // the acknowledgement arrives with offset 1900; VR imports its Boundary only later (a lagging VR cursor keeps the bound)
        pushRecord(RecordKind.Ack, ackData(RES_FOREIGN, 1_900, 1_900, 1_901));
        applyAll();
        _advanceAll();
        assertEq(
            pool.recordCursor(),
            roots.recordCount(),
            "the foreign Ack is consumed, no TimelineMismatch"
        );
        _assertGEndsAt(1_900, claimed);
        // VR releases the output (Boundary imported): the NONE tail still settles nothing
        pushRecord(RecordKind.Boundary, _boundary(RES_FOREIGN, 2, false));
        applyAll();
        _advanceAll();
        vr.setOpen(bytes32(0), 0);
        clock(9_000, 900);
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
    }

    function test_aPendingForeignRecoveryAckIsNotSettledPastAndEndsTheOwnerAtJOffset() public {
        (, uint256 claimed) = _pendingForeignHandoff();
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(
                RecoveryAckData(
                    RES_FOREIGN,
                    keccak256("assignment/foreign-K"),
                    1_900,
                    1_901,
                    1_950,
                    1_960,
                    1_961,
                    3,
                    3
                )
            )
        );
        pushRecord(RecordKind.Boundary, _boundary(RES_FOREIGN, 2, true));
        applyAll();
        _advanceAll();
        _assertGEndsAt(1_900, claimed);
    }

    function test_delayedImportsKeepTheTailBounded() public {
        (MockOpenOutput vr,) = _pendingForeignHandoff();
        // imported by the registry, not yet applied by custody: the pool cannot read it and the tail is NotCaughtUp
        pushRecord(RecordKind.Ack, ackData(RES_FOREIGN, 1_900, 1_900, 1_901));
        vm.expectRevert(RewardPool.NotCaughtUp.selector);
        pool.closeInterval();
        // applied by custody, not yet read by the pool: still NotCaughtUp
        applyAll();
        vm.expectRevert(RewardPool.NotCaughtUp.selector);
        pool.closeInterval();
        // VR released the output before this pool read the Ack (VR imported the Boundary): the caught-up check still comes first
        vr.setOpen(bytes32(0), 0);
        pushRecord(RecordKind.Boundary, _boundary(RES_FOREIGN, 2, false));
        applyAll();
        vm.expectRevert(RewardPool.NotCaughtUp.selector);
        pool.closeInterval();
        // once the pool has read the Ack, G's end is final: [1000,1900) settles even with the Boundary still unread, and no more
        pool.advanceRecords(1);
        assertEq(pool.segmentAt(0).end, 1_900);
        assertEq(_drain(), 1, "[1000,1900) G only");
        assertEq(pool.nextStart(), 1_900);
        pool.advanceRecords(1);
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
    }

    function test_theOpenOutputBoundAppliesToAnOwnedTailAndLiftsAtRelease() public {
        MockOpenOutput vr = _registry();
        // a native repair output reserved at 1500 while G owns the tail: settlement stops at the last grid point below it
        vr.setOpen(keccak256("result/native-repair"), 1_500);
        clock(3_200, 320);
        assertEq(_drain(), 1, "[0,1000) only: [1000,2000) ends above the reservation");
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        // the output is released without a handoff (SessionClosed): the tail settles to the current progress again
        pushRecord(RecordKind.OutputRejected, _rejected(keccak256("result/native-repair")));
        pushRecord(
            RecordKind.SessionClosed,
            abi.encode(SessionClosedData(keccak256("result/native-repair")))
        );
        applyAll();
        _advanceAll();
        vr.setOpen(bytes32(0), 0);
        assertEq(_drain(), 2, "[1000,2000) and [2000,3000)");
        assertEq(pool.totalCredits(), 3 ether);
        _conserved();
    }

    /// @dev The reviewers' timeline (astra on #88): G closes at H = 900 before the foreign Ack exists, settlement is attempted at 1000,
    /// and the Ack at offset 900 arrives at 1100. With the foreign output open in VR since 850 nothing past 850 settles, so the Ack is
    /// consumed and G is paid exactly [0,900).
    function test_theReviewersTimelineNoLongerOverCredits() public {
        MockOpenOutput vr = _registry();
        assertEq(
            election.openResult(),
            bytes32(0),
            "the other module's election is absent from this pool's ElectionPolicy"
        );
        vr.setOpen(RES_FOREIGN, 850);
        clock(900, 90);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, 900, "G"));
        applyAll();
        _advanceAll();
        clock(1_000, 100);
        vm.expectRevert(RewardPool.NothingToDo.selector);
        pool.closeInterval();
        assertEq(pool.totalCredits(), 0);
        clock(1_100, 200);
        pushRecord(RecordKind.Ack, ackData(RES_FOREIGN, 900, 900, 901));
        applyAll();
        _advanceAll();
        assertEq(pool.recordCursor(), 2, "the foreign transition is consumed");
        assertEq(_drain(), 1);
        assertEq(pool.totalCredits(), 0.9 ether, "G is paid [0,900) and nothing beyond");
        _conserved();
    }
}
