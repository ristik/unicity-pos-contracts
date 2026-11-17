// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {RewardsBase} from "./Rewards.t.sol";
import {RewardPool} from "../../src/p85/RewardPool.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {CustodyStorage} from "../../src/p85/CustodyStorage.sol";
import {
    RecordKind,
    RecoveryAckData,
    BoundaryData,
    OutputRejectedData,
    HolderRetirementData,
    SessionClosedData
} from "../../src/p85/P85Types.sol";

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
}
