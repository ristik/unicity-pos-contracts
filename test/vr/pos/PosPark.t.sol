// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";
import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {ElectionStorage} from "../../../src/p85/ElectionPolicy.sol";
import {
    ElectionParams,
    RecordKind,
    OutputRejectedData,
    HolderRetirementData
} from "../../../src/p85/P85Types.sol";

/// @notice #1303: design 3.7.4 parking on the PoS stack. An ordered Expired OutputRejected of a P85 result parks, for 2 x LIFETIME of root
/// progress, the members that are not incumbents (the committed predecessor's members) and did not prove: a clear ready bit when the
/// result was published, a missing on-chain assignment PoP when it was not. Each result is applied once, from VR's own record segment,
/// whatever custody's cursor. Parking only delays future eligibility.
contract PosParkTest is PosBase {
    uint64 internal constant PARK = 2 * VRC.LIFETIME;
    bytes32 internal constant PARKED_SIG = keccak256("Parked(bytes32,uint64,uint64)");

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

    function _join() internal returns (Joiner memory j) {
        j = _joinPos(1_000 * UCT);
        evmPkOf[j.id] = j.evmPk;
    }

    function _expired(bytes32 rid, uint16 bitmap) internal {
        pushRecord(RecordKind.OutputRejected, abi.encode(OutputRejectedData(rid, 1, 0, bitmap)));
    }

    /// @dev The root's rejection of an expired output: OutputRejected(Expired, bitmap) and SessionClosed, applied through VR.
    function _expire(bytes32 rid, uint16 bitmap) internal returns (uint64 p) {
        _advance(10, 10);
        p = progress;
        _expired(rid, bitmap);
        _closedRecord(rid);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_CLOSED);
        assertEq(election.openResult(), bytes32(0));
    }

    function _ids(bytes32 rid) internal view returns (uint64[] memory ids) {
        ElectionStorage.Frozen[] memory f = election.frozenMembers(rid);
        ids = new uint64[](f.length);
        for (uint256 i; i < f.length; ++i) {
            ids[i] = f[i].id;
        }
    }

    function _has(bytes32 rid, uint64 id) internal view returns (bool) {
        uint64[] memory ids = _ids(rid);
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i] == id) return true;
        }
        return false;
    }

    /// @dev An election at exactly root progress `p` (past the cadence in UC time).
    function _electAt(uint64 p) internal returns (bytes32 rid) {
        progress = p;
        ucTime += 1_000;
        roots.setClock(progress, ucTime);
        vm.roll(block.number + 1);
        assertEq(_vrElect(ORIGIN), VRC.ELECT_RESERVED, "an election from stake");
        rid = vr.openOutput();
    }

    function _parkedEvents(Vm.Log[] memory logs) internal view returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(election) && logs[i].topics[0] == PARKED_SIG) ++n;
        }
    }

    // ---- published: the ordered bitmap ----

    function test_aPublishedExpiryParksTheClearBitJoinerAndNoIncumbent() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_ids(r1).length, 5);
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        // bits 0 and 3 (incumbents 1 and 4) and bit 4 (the joiner) are clear: a clear bit alone never parks an incumbent
        vm.recordLogs();
        uint64 p = _expire(r1, 0x06);
        assertEq(_parkedEvents(vm.getRecordedLogs()), 1, "one identity parked");
        assertEq(election.parkedUntil(j.id), p + PARK, "the joiner is parked for 2 x LIFETIME");
        for (uint64 id = 1; id <= N_GENESIS; ++id) {
            assertEq(election.parkedUntil(id), 0, "an incumbent is never parked");
        }
        // the next election excludes the parked joiner and finalizes with the incumbents
        bytes32 r2 = _electFromStake();
        uint64[] memory ids = _ids(r2);
        assertEq(ids.length, 4, "the parked joiner is not elected");
        for (uint256 i; i < 4; ++i) {
            assertEq(ids[i], i + 1);
        }
        assertEq(_publishResult2(r2), VRC.PUB_PUBLISHED);
        _ackNext(r2);
        assertEq(vr.committee().length, 4);
        // the parked identity is still bonded, delegated and in the live index
        assertTrue(election.isIndexed(j.id));
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_aSetBitSparesThePublishedJoiner() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        _expire(r1, 0x10); // only the joiner's bit (the fifth frozen member)
        assertEq(election.parkedUntil(j.id), 0);
        assertTrue(_has(_electFromStake(), j.id), "an unparked joiner is elected again");
    }

    function test_aPublishedExpiryUsesFrozenMemberOrder() public {
        // continuity admits one joiner per election here: a joins first, then b is elected beside it
        Joiner memory a = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        _ackNext(r1);
        Joiner memory b = _join();
        bytes32 r2 = _electFromStake();
        uint64[] memory ids = _ids(r2);
        assertEq(ids.length, 6);
        assertEq(ids[4], a.id);
        assertEq(ids[5], b.id);
        assertEq(_publishResult2(r2), VRC.PUB_PUBLISHED);
        uint256 snap = vm.snapshotState();
        uint64 p = _expire(r2, 0x1f); // bit 5 (b) clear
        assertEq(election.parkedUntil(a.id), 0, "a is an incumbent now");
        assertEq(election.parkedUntil(b.id), p + PARK, "bit 5 clear");
        vm.revertToState(snap);
        _expire(r2, 0x20); // only bit 5 set: b is spared, the incumbents' clear bits park nobody
        for (uint64 id = 1; id <= b.id; ++id) {
            assertEq(election.parkedUntil(id), 0);
        }
    }

    // ---- unpublished: the on-chain assignment PoPs ----

    function test_anUnpublishedExpiryParksTheMembersWithoutAPoP() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_ids(r1).length, 5);
        // incumbents 1 and 2 never prove; 3 and 4 do; nobody finalizes, so VR never publishes
        uint256[] memory idx = new uint256[](2);
        idx[0] = 2;
        idx[1] = 3;
        election.submitAssignmentPoPs(r1, _pops(r1, idx));
        uint256 snap = vm.snapshotState();

        // the joiner proved: nobody is parked, although incumbents lack proofs
        ElectionStorage.PoPInput[] memory pj = new ElectionStorage.PoPInput[](1);
        bytes memory key = compressed(j.evmPk);
        pj[0] = ElectionStorage.PoPInput(
            j.id, key, sign(j.evmPk, election.popDigest(r1, j.id, keccak256(key)))
        );
        election.submitAssignmentPoPs(r1, pj);
        assertEq(_state(r1), VRC.OUT_RESERVED);
        assertFalse(election.publication(r1).published);
        _expire(r1, 0);
        for (uint64 id = 1; id <= j.id; ++id) {
            assertEq(election.parkedUntil(id), 0, "every non-incumbent proved");
        }
        assertTrue(_has(_electFromStake(), j.id));

        // the joiner did not prove: it alone is parked
        vm.revertToState(snap);
        uint64 p = _expire(r1, 0);
        assertEq(election.parkedUntil(j.id), p + PARK, "no PoP");
        for (uint64 id = 1; id <= N_GENESIS; ++id) {
            assertEq(election.parkedUntil(id), 0, "an incumbent without a PoP is never parked");
        }
        assertFalse(_has(_electFromStake(), j.id));
    }

    function test_anUnpublishedExpiryIgnoresTheBitmap() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        uint64 p = _expire(r1, 0x1f); // a set bit does not stand in for a missing PoP
        assertEq(election.parkedUntil(j.id), p + PARK);
    }

    // ---- once, from VR's segment ----

    function test_theSameRecordTwiceParksOnce() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        _advance(10, 10);
        uint64 p = progress;
        uint64 first = roots.recordCount();
        _expired(r1, 0);
        _closedRecord(r1);
        vm.recordLogs();
        _vrApplyAll();
        // the segment again (a redelivery), and a second Expired record of the same result at a later progress
        vm.prank(VR_ADDR);
        adapter.onRecords(first, 2);
        _advance(500, 10);
        _expired(r1, 0);
        _vrApplyAll();
        assertEq(_parkedEvents(vm.getRecordedLogs()), 1, "parked once");
        assertEq(election.parkedUntil(j.id), p + PARK, "the first application stands");
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_aFrontRunCustodyCursorStillParks() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        _advance(10, 10);
        uint64 p = progress;
        _expired(r1, 0x0f);
        _closedRecord(r1);
        // anyone pulls custody past both records before VR imports them
        custody.applyRootRecords(2);
        assertEq(custody.recordCursor(), roots.recordCount());
        assertEq(uint8(election.result(r1).state), uint8(ElectionStorage.ResultState.Closed));
        assertEq(election.parkedUntil(j.id), 0, "nothing parked by custody");
        _vrApplyAll();
        assertEq(election.parkedUntil(j.id), p + PARK, "VR's segment parks");
        assertFalse(_has(_electFromStake(), j.id));
    }

    // ---- the park period ----

    function test_eligibilityResumesAfterTwoLifetimes() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        uint64 until = _expire(r1, 0x0f) + PARK;
        assertEq(election.parkedUntil(j.id), until);
        bytes32 r2 = _electFromStake();
        assertFalse(_has(r2, j.id));
        assertEq(_publishResult2(r2), VRC.PUB_PUBLISHED);
        _ackNext(r2);

        uint256 snap = vm.snapshotState();
        assertFalse(_has(_electAt(until - 1), j.id), "still parked one round before the end");
        vm.revertToState(snap);
        bytes32 r3 = _electAt(until);
        assertTrue(_has(r3, j.id), "eligible again when the period ends");
        assertEq(_publishResult2(r3), VRC.PUB_PUBLISHED);
        _ackNext(r3);
        assertEq(vr.committee().length, 5, "the joiner joins after its park");
    }

    function test_aSecondExpiryDoesNotEscalate() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        uint64 p1 = _expire(r1, 0);
        assertEq(election.parkedUntil(j.id), p1 + PARK);
        bytes32 r2 = _electAt(p1 + PARK);
        assertTrue(_has(r2, j.id));
        uint64 p2 = _expire(r2, 0);
        assertEq(election.parkedUntil(j.id), p2 + PARK, "the same fixed period again");
    }

    // ---- what parking does not touch ----

    function test_aParkedJoinerStillRetiresAndClaims() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        _expire(r1, 0x0f);
        assertGt(election.parkedUntil(j.id), progress);
        assertEq(custody.liveExposures(j.id, 1), 0, "the expired reservation released the joiner");

        vm.prank(vm.addr(j.ownerPk));
        custody.requestRetirement(j.id);
        requestedSeen[j.id][1] = true;
        _assertFacts(j.id, 1);
        _advance(400, 400);
        pushRecord(
            RecordKind.HolderRetirement,
            abi.encode(HolderRetirementData(0, j.id, 1, custody.exposureChain(j.id, 1)))
        );
        _vrApplyAll();
        (bool imported,,) = custody.retirements(j.id, 1);
        assertTrue(imported, "a parked identity retires");
        _advance(100_000, 100_000);
        uint256[] memory lots = new uint256[](1);
        lots[0] = lotOf(j.id);
        custody.mature(lots);
        address wd = vm.addr(j.ownerPk);
        uint256 credit = custody.credit(wd);
        assertEq(credit, 1_000 * UCT);
        vm.prank(wd);
        custody.claim(credit, wd);
        assertEq(wd.balance, 1_000 * UCT, "and claims");
    }

    function test_anInvalidatedRejectionParksNothing() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        _advance(10, 10);
        pushRecord(RecordKind.OutputRejected, abi.encode(OutputRejectedData(r1, 2, 0, 0)));
        _closedRecord(r1);
        _vrApplyAll();
        assertEq(election.parkedUntil(j.id), 0);
    }

    function test_aForeignResultParksNothing() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        vm.prank(ADAPTER);
        election.parkExpired(keccak256("foreign"), 0, progress);
        assertEq(election.parkedUntil(j.id), 0);
        // the real record still parks: the foreign id consumed nothing
        _expire(r1, 0);
        assertGt(election.parkedUntil(j.id), 0);
    }

    /// @dev review P3-1: a park call that fails is reported (`ParkSkipped`), leaves the identity unparked, and does not hold the records
    /// back from custody or fault the module.
    function test_aFailedParkIsReportedAndTheRecordsStillReachCustody() public {
        Joiner memory j = _join();
        bytes32 r1 = _electFromStake();
        assertEq(_publishResult2(r1), VRC.PUB_PUBLISHED);
        vm.mockCallRevert(
            address(election), abi.encodeWithSelector(election.parkExpired.selector), "boom"
        );
        vm.recordLogs();
        _expire(r1, 0);
        vm.clearMockedCalls();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 skipped;
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == ADAPTER && logs[i].topics[0] == keccak256("ParkSkipped(bytes32)")
                    && logs[i].topics[1] == r1
            ) ++skipped;
        }
        assertEq(skipped, 1, "the skip is reported once");
        assertEq(election.parkedUntil(j.id), 0, "skipped: not parked");
        assertEq(custody.recordCursor(), roots.recordCount());
        assertEq(vr.health(), VRC.HEALTHY);
    }

    function test_onlyTheAdapterParks() public {
        _join();
        bytes32 r1 = _electFromStake();
        vm.expectRevert(ElectionStorage.NotSystem.selector);
        election.parkExpired(r1, 0, progress);
        vm.prank(SYS);
        vm.expectRevert(ElectionStorage.NotSystem.selector);
        election.parkExpired(r1, 0, progress);
    }
}
