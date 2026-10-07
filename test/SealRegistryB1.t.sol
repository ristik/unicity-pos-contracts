// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {SealRegistry} from "../src/SealRegistry.sol";
import {
    B1Entry,
    B1Member,
    B1Update,
    B1StateInvalid,
    PriorTipMismatch,
    OldTipEndMismatch,
    InvalidInterval,
    TooManyEntries,
    RingFull,
    NonContiguousEpochs,
    ExpiredEntry,
    StartAfterOrigin,
    OriginEpochMismatch,
    EntryAlreadyPresent,
    BadMemberCount,
    BadNodeID,
    NodeIDsNotSorted,
    BadCompressedKey,
    BadWeight,
    ZeroIdentity
} from "../src/B1Layout.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";

/// @notice B1 #62 registry history: deterministic pruning, closure, insertion and the ring, against
/// slot formulas written independently in SealRegistryBase. Every refusal test first shows that the
/// unmodified update succeeds, then applies exactly one mutation and requires the exact custom-error
/// selector and that no tracked operational or B1 word changed.
///
/// Fixture profile: W_cert = 3, so K_max = 4 and L = max(0, O - 3). The genesis entry is epoch 1,
/// open, starting at root round 1, with three members.
abstract contract SealRegistryB1Helpers is SealRegistryBase {
    /// @dev An ordinary open at origin round O against the stored assignment, with no new entries.
    function plainAt(uint64 O) internal view returns (OpenArgs memory a) {
        a = firstPayload();
        a.n = uint64(uintWord("round.authorized")) + 1;
        a.rootRound = O;
        a.rootEpoch = uint64(uintWord("assignment.rootEpoch"));
        a.certEpoch = uint64(uintWord("assignment.epoch"));
        a.authEpoch = a.certEpoch;
        a.activeConfHash = word("assignment.activeConfHash");
        a.update = emptyUpdate(tipEpoch());
    }

    /// @dev An acknowledgement open that advances the root epoch by `delta` and carries update `u`.
    function ackWith(uint64 O, uint64 delta, B1Update memory u)
        internal
        view
        returns (OpenArgs memory a)
    {
        a = plainAt(O);
        uint64 oldRoot = a.rootEpoch;
        uint64 oldShard = a.certEpoch;
        bytes32 oldHash = a.activeConfHash;
        bytes32 newHash = keccak256(abi.encode("conf", oldRoot, delta));
        a.rootEpoch = oldRoot + delta;
        a.authEpoch = oldShard + delta;
        a.hasBlockHash = true;
        a.blockHash = keccak256("parent block");
        a.transitionCount = 1;
        a.bodyID = keccak256("ack body");
        a.genesisID = keccak256("ack genesis");
        a.frozenID = keccak256("ack frozen");
        a.commitID = keccak256("ack commit");
        a.frozenParent = keccak256("ack frozen parent");
        a.successorTR = keccak256("ack successor TR");
        a.activeConfHash = newHash;
        a.assignment = assignmentProjection(
            oldRoot,
            oldShard,
            oldHash,
            oldRoot + delta,
            oldShard + delta,
            newHash,
            delta > 1 ? delta : 0,
            delta > 1 ? keccak256("verified span") : bytes32(0)
        );
        a.update = u;
    }

    /// @dev The honest acknowledgement: `delta` consecutive new epochs ending at origin round O.
    function ackAt(uint64 O, uint64 delta, uint256 m) internal view returns (OpenArgs memory a) {
        a = ackWith(O, delta, advanceUpdate(tipEpoch(), O, delta, m));
    }

    function step(OpenArgs memory a) internal {
        openAsSystem(a);
        finalizeAsSystem(a.n, keccak256(abi.encode("R", a.n)));
    }

    /// @dev Writes one entry's words with vm.store, independent of the registry code.
    function storeEntry(B1Entry memory en) internal {
        uint256 e = en.epoch;
        vm.store(A_SR, eSlot(e, 0), bytes32(uint256(1)));
        vm.store(A_SR, eSlot(e, 1), bytes32(uint256(en.bodyKind)));
        vm.store(A_SR, eSlot(e, 2), en.bodyID);
        vm.store(A_SR, eSlot(e, 3), en.activationCommitID);
        vm.store(A_SR, eSlot(e, 4), bytes32(uint256(en.start)));
        vm.store(A_SR, eSlot(e, 5), bytes32(uint256(en.end)));
        vm.store(A_SR, eSlot(e, 6), bytes32(uint256(en.hasEnd ? 1 : 0)));
        vm.store(A_SR, eSlot(e, 7), bytes32(uint256(en.signingScheme)));
        vm.store(A_SR, eSlot(e, 8), en.signingConfigHash);
        vm.store(A_SR, eSlot(e, 9), bytes32(en.members.length));
        vm.store(A_SR, eSlot(e, 10), bytes32(totalWeight(en.members)));
        for (uint256 j = 0; j < en.members.length; j++) {
            B1Member memory x = en.members[j];
            vm.store(A_SR, mSlot(e, j, 0), bytes32(uint256(x.nodeIDLength)));
            for (uint256 w = 0; w < 4; w++) {
                vm.store(A_SR, mSlot(e, j, 1 + w), x.nodeID[w]);
            }
            vm.store(A_SR, mSlot(e, j, 5), x.key[0]);
            vm.store(A_SR, mSlot(e, j, 6), x.key[1]);
            vm.store(A_SR, mSlot(e, j, 7), bytes32(uint256(x.weight)));
        }
    }

    function clearEntry(uint256 e, uint256 maxMembers) internal {
        for (uint256 f = 0; f < 11; f++) {
            vm.store(A_SR, eSlot(e, f), bytes32(0));
        }
        for (uint256 j = 0; j < maxMembers; j++) {
            for (uint256 f = 0; f < 8; f++) {
                vm.store(A_SR, mSlot(e, j, f), bytes32(0));
            }
        }
    }

    /// @dev Replaces the genesis live set by `es` laid out from ring index `headIdx`, and sets the
    /// assignment and origin to the tail epoch with the clock at `originRound`. This builds states
    /// (full rings, epoch zero, an impossible-by-honest-history ring) that honest updates cannot reach
    /// quickly; entries are written by the independent storeEntry.
    function seedRing(B1Entry[] memory es, uint256 headIdx, uint64 originRound) internal {
        clearEntry(ROOT_EPOCH, 8);
        for (uint256 i = 0; i < kMax(); i++) {
            vm.store(A_SR, qSlot(i), bytes32(0));
        }
        for (uint256 i = 0; i < es.length; i++) {
            storeEntry(es[i]);
            vm.store(A_SR, qSlot((headIdx + i) % kMax()), bytes32(uint256(es[i].epoch)));
        }
        vm.store(A_SR, fixedSlot("b1.head"), bytes32(headIdx));
        vm.store(A_SR, fixedSlot("b1.count"), bytes32(es.length));
        uint64 tip = es[es.length - 1].epoch;
        setWord("assignment.rootEpoch", bytes32(uint256(tip)));
        setWord("origin.rootEpoch", bytes32(uint256(tip)));
        setWord("clock.rootRound", bytes32(uint256(originRound)));
    }

    /// @dev Four contiguous live entries e1..e4 over [10,11) [11,12) [12,13) [13,open), origin 13.
    function fullRing() internal pure returns (B1Entry[] memory es) {
        es = new B1Entry[](4);
        es[0] = entry(1, 10, 11, 3);
        es[1] = entry(2, 11, 12, 3);
        es[2] = entry(3, 12, 13, 3);
        es[3] = entry(4, 13, 0, 3);
    }

    function epochsEq(uint256[] memory got, uint256[] memory want) internal pure returns (bool) {
        if (got.length != want.length) return false;
        for (uint256 i = 0; i < got.length; i++) {
            if (got[i] != want[i]) return false;
        }
        return true;
    }

    function epochs(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function epochs(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        r[0] = a;
        r[1] = b;
    }

    function epochs(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory r) {
        r = new uint256[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }

    function epochs(uint256 a, uint256 b, uint256 c, uint256 d)
        internal
        pure
        returns (uint256[] memory r)
    {
        r = new uint256[](4);
        r[0] = a;
        r[1] = b;
        r[2] = c;
        r[3] = d;
    }

    function assertLive(uint256[] memory want) internal view {
        assertTrue(epochsEq(liveEpochs(), want), "live epochs in queue order");
        assertEq(b1Word("b1.count"), want.length, "count");
    }

    function refuse(OpenArgs memory a, bytes4 selector) internal {
        assertRefused(A_SYS, openCalldata(a), selector);
    }

    function premiseOpenSucceeds(OpenArgs memory a) internal {
        uint256 snap = vm.snapshotState();
        (bool ok, bytes memory ret) = callAs(A_SYS, openCalldata(a));
        if (!ok) emit log_named_bytes("premise open reverted", ret);
        assertTrue(ok, "premise: the unmodified open succeeds");
        vm.revertToState(snap);
    }
}

contract SealRegistryB1Test is SealRegistryB1Helpers {
    // ---------------------------------------------------------------- insertion and closure

    function test_ackInsertsTheEntryAndClosesTheFormerTipOnce() public {
        OpenArgs memory a = ackAt(6, 1, 3);
        bytes32 digestBefore = b1Digest();
        openAsSystem(a);
        assertTrue(digestBefore != b1Digest());

        assertLive(epochs(1, 2));
        assertEq(b1Word("b1.head"), 0);
        // Former tip: closed exactly where the successor starts; no other word changed.
        B1Entry memory tip = genesisEntry();
        tip.hasEnd = true;
        tip.end = 6;
        assertEntryStored(tip, 8);
        assertEntryStored(a.update.newEntries[0], 8);
        assertEq(ent(2, 4), bytes32(uint256(6)), "successor starts at the closure");
        assertEq(ent(2, 6), bytes32(0), "the new tail is open");
        assertEq(queueAt(0), 1);
        assertEq(queueAt(1), 2);
        assertEq(queueAt(2), 0);
        finalizeAsSystem(a.n, keccak256("R"));
        assertEq(uintWord("phase"), 2);
    }

    /// Retained supersession epochs that never produced an EVM block are inserted, with exact starts
    /// and ends, because they still intersect [L, O].
    function test_supersessionEpochsWithNoEvmBlockAreInsertedWithExactBounds() public {
        OpenArgs memory a = ackAt(6, 3, 3); // epochs 2,3,4 starting 4,5,6; the tip closes at 4
        step(a);
        assertLive(epochs(1, 2, 3, 4));
        B1Entry memory tip = genesisEntry();
        tip.hasEnd = true;
        tip.end = 4;
        assertEntryStored(tip, 8);
        assertEq(ent(2, 4), bytes32(uint256(4)));
        assertEq(ent(2, 5), bytes32(uint256(5)));
        assertEq(ent(3, 4), bytes32(uint256(5)));
        assertEq(ent(3, 5), bytes32(uint256(6)));
        assertEq(ent(4, 4), bytes32(uint256(6)));
        assertEq(ent(4, 6), bytes32(0));
        for (uint256 i = 0; i < 3; i++) {
            assertEntryStored(a.update.newEntries[i], 8);
        }
    }

    /// Epochs 2 and 3 expired inside the skipped span: authenticated by Go but never materialized.
    /// The former tip is deleted outright, with no closure written first.
    function test_expiredIntermediateEpochsAreNeverMaterializedAndTheOldTipIsNotClosed() public {
        // O = 20, L = 17. Real intervals: e1 [1,5), e2 [5,8), e3 [8,12), e4 [12,open).
        B1Update memory u = B1Update({
            priorTipEpoch: ROOT_EPOCH,
            hasOldTipEnd: true,
            oldTipEnd: 5,
            newEntries: new B1Entry[](1)
        });
        u.newEntries[0] = entry(4, 12, 0, 3);
        OpenArgs memory a = ackWith(20, 3, u);
        step(a);
        assertLive(epochs(4));
        assertEq(b1Word("b1.head"), 0);
        assertEntryAbsent(1, 8);
        assertEntryAbsent(2, 8);
        assertEntryAbsent(3, 8);
        assertEntryStored(u.newEntries[0], 8);
        assertEq(queueAt(0), 4);
    }

    // ---------------------------------------------------------------- pruning boundary

    /// An entry with end = L is removed and end = L + 1 is retained (half-open [start, end)).
    function test_pruningBoundaryEndEqualToLIsRemovedAndEndAboveLIsRetained() public {
        step(ackAt(4, 1, 3)); // e1 [1,4), e2 [4,open); L = 1
        assertLive(epochs(1, 2));
        uint256 snap = vm.snapshotState();

        // O = 6: L = 3 < 4 = end(e1): retained.
        step(plainAt(6));
        assertLive(epochs(1, 2));
        assertEntryStored(_closedGenesis(4), 8);

        // O = 7: L = 4 = end(e1): removed, with every metadata and member word.
        vm.revertToState(snap);
        step(plainAt(7));
        assertLive(epochs(2));
        assertEq(b1Word("b1.head"), 1);
        assertEntryAbsent(1, 8);
        assertEq(queueAt(0), 0, "queue word of the removed entry is cleared");
        assertEq(queueAt(1), 2);
    }

    function test_removedEntryLeavesNoStaleWordsAnywhere() public {
        B1Entry[] memory es = fullRing();
        seedRing(es, 0, 13);
        step(plainAt(16)); // L = 13: e1, e2, e3 end at or before 13
        assertLive(epochs(4));
        for (uint256 e = 1; e <= 3; e++) {
            assertEntryAbsent(e, 8);
        }
        assertEntryStored(es[3], 8);
        assertEq(b1Word("b1.head"), 3);
    }

    /// The boundary-crossing predecessor is retained however ancient its start; here the open tail.
    function test_theOpenTailIsNeverPrunedHoweverOldItsStart() public {
        step(plainAt(1000));
        assertLive(epochs(1));
        assertEntryStored(genesisEntry(), 8);
    }

    function test_originBelowTheWindowPrunesNothing() public {
        // O = 2 < W_cert = 3: L = 0, so even an entry ending at 2 is retained.
        step(ackAt(2, 1, 3));
        assertLive(epochs(1, 2));
        assertEntryStored(_closedGenesis(2), 8);
    }

    /// A repeated origin advances nothing: the intervals stay and later-tip knowledge is irrelevant.
    function test_repeatedOriginLeavesIntervalsUnchanged() public {
        step(ackAt(6, 1, 3));
        bytes32 before = b1Digest();
        step(plainAt(6));
        assertEq(before, b1Digest(), "no interval word changed");
        step(plainAt(6));
        assertEq(before, b1Digest());
    }

    // ---------------------------------------------------------------- acknowledgement clock

    /// An acknowledgement is an ordinary open for the monotone origin clock: a lower root round is
    /// refused even though every interval rule would accept it (design v4, "monotone origin"; a lower
    /// origin would move L backward after earlier pruning discarded history). The ordinary open at
    /// round 10 leaves the tail at epoch 1 starting at round 1, so the acknowledgement's entry (start
    /// 9) is valid at round 9 and at round 10: the two payloads differ only in the root round.
    function test_anAcknowledgementBelowTheClockIsRefusedByTheClockGuardAlone() public {
        step(plainAt(10));
        assertEq(uintWord("clock.rootRound"), 10);
        assertLive(epochs(1));

        B1Update memory u = advanceUpdate(tipEpoch(), 9, 1, 3);
        premiseOpenSucceeds(ackWith(10, 1, u)); // the same update at the clock's own round
        refuse(ackWith(9, 1, u), SealRegistry.StaleRootRound.selector); // exact error, nothing written
        refuse(ackWith(0, 1, u), SealRegistry.StaleRootRound.selector);

        // Nothing was lost by the refusal: the unchanged update still opens at round 10 afterwards.
        step(ackWith(10, 1, u));
        assertLive(epochs(1, 2));
    }

    /// The guard is strict: an acknowledgement at exactly the clock's round is accepted and the clock
    /// does not move.
    function test_anAcknowledgementAtTheClockRoundIsAcceptedAndKeepsTheClock() public {
        step(plainAt(10));
        step(ackWith(10, 1, advanceUpdate(tipEpoch(), 9, 1, 3)));
        assertEq(uintWord("clock.rootRound"), 10);
        assertEq(uintWord("origin.rootEpoch"), 2);
        assertLive(epochs(1, 2));
        assertEq(ent(1, 5), bytes32(uint256(9)), "the former tip closed where the successor starts");
    }

    function test_everyOriginAdvancePerformsThePruneCheck() public {
        step(ackAt(4, 1, 3)); // e1 [1,4), e2 [4,open)
        step(plainAt(6)); // L = 3: nothing to prune
        assertLive(epochs(1, 2));
        step(plainAt(7)); // L = 4: e1 pruned with no update entries at all
        assertLive(epochs(2));
    }

    // ---------------------------------------------------------------- ring: wrap, eviction, epoch zero

    function test_ringFillsThenWrapsAndOldEntriesLeaveFirst() public {
        step(ackAt(2, 1, 3)); // e1 [1,2) e2 [2,)
        step(ackAt(3, 1, 3)); // e3 [3,)
        step(ackAt(4, 1, 3)); // e4 [4,): the ring is full, L = 1 retains e1 (end 2)
        assertLive(epochs(1, 2, 3, 4));
        assertEq(b1Word("b1.count"), kMax());

        // O = 5, L = 2: e1 (end 2) is removed first, then e5 reuses the freed slot 0.
        step(ackAt(5, 1, 3));
        assertLive(epochs(2, 3, 4, 5));
        assertEq(b1Word("b1.head"), 1);
        assertEq(queueAt(0), 5, "wrapped into the freed slot");
        assertEq(queueAt(1), 2);
        assertEntryAbsent(1, 8);

        step(ackAt(6, 1, 3));
        assertLive(epochs(3, 4, 5, 6));
        assertEq(b1Word("b1.head"), 2);
        assertEq(queueAt(1), 6);
        assertEntryAbsent(2, 8);

        step(ackAt(7, 1, 3));
        step(ackAt(8, 1, 3));
        assertLive(epochs(5, 6, 7, 8));
        assertEq(b1Word("b1.head"), 0, "head wrapped back to zero");
        assertEq(queueAt(0), 5);
        assertEq(queueAt(3), 8);
    }

    function test_multipleEvictionsWithAnInsertionAtTheWrap() public {
        seedRing(fullRing(), 0, 13);
        // O = 15, L = 12: e1 (end 11) and e2 (end 12) are removed; e3 (end 13) and e4 stay.
        OpenArgs memory a = ackAt(15, 1, 3);
        step(a);
        assertLive(epochs(3, 4, 5));
        assertEq(b1Word("b1.head"), 2);
        assertEq(queueAt(0), 5, "e5 landed in the freed slot 0, wrapping past slot 3");
        assertEq(queueAt(1), 0, "removed head words are cleared");
        assertEntryAbsent(1, 8);
        assertEntryAbsent(2, 8);
        B1Entry memory e4 = entry(4, 13, 15, 3);
        assertEntryStored(e4, 8); // closed where e5 starts
        assertEntryStored(a.update.newEntries[0], 8);
    }

    /// p = K_max evictions with a = K_max simultaneous insertions: the whole live set is replaced.
    function test_fullReplacementDeletesEveryOldEntryAndInsertsK() public {
        seedRing(fullRing(), 0, 13);
        // O = 20, L = 17. The old tip closes at 14 <= L. New intervals: e5 [14,18), e6 [18,19),
        // e7 [19,20), e8 [20,open): starts are 14 then distinct integers in (L, O].
        B1Update memory u = B1Update({
            priorTipEpoch: 4, hasOldTipEnd: true, oldTipEnd: 14, newEntries: new B1Entry[](4)
        });
        u.newEntries[0] = entry(5, 14, 18, 3);
        u.newEntries[1] = entry(6, 18, 19, 3);
        u.newEntries[2] = entry(7, 19, 20, 3);
        u.newEntries[3] = entry(8, 20, 0, 3);
        step(ackWith(20, 4, u));
        assertLive(epochs(5, 6, 7, 8));
        assertEq(b1Word("b1.head"), 0, "an emptied ring restarts at slot zero");
        for (uint256 e = 1; e <= 4; e++) {
            assertEntryAbsent(e, 8);
        }
        for (uint256 i = 0; i < 4; i++) {
            assertEntryStored(u.newEntries[i], 8);
            assertEq(queueAt(i), 5 + i);
        }
    }

    function test_epochZeroIsAnOccupiedWordNotAnEmptyOne() public {
        // e0 [1,5), e1 [5,open) with the origin at 6: removing e0 must leave count = 1, head = 1.
        B1Entry[] memory es = new B1Entry[](2);
        es[0] = entry(0, 1, 5, 3);
        es[1] = entry(1, 5, 0, 3);
        seedRing(es, 0, 6);
        step(plainAt(9)); // L = 6
        assertLive(epochs(1));
        assertEq(b1Word("b1.head"), 1);
        assertEntryAbsent(0, 8);
        assertEntryStored(es[1], 8);
    }

    function test_aLoneEpochZeroTailIsALiveRingOfOne() public {
        B1Entry[] memory es = new B1Entry[](1);
        es[0] = entry(0, 1, 0, 3);
        seedRing(es, 0, 5);
        assertEq(queueAt(0), 0, "the queue word is zero");
        step(plainAt(6));
        assertLive(epochs(0));
        assertEntryStored(es[0], 8);
    }

    function test_countZeroIsARefusedEmptyRingEvenThoughTheQueueWordIsZero() public {
        B1Entry[] memory es = new B1Entry[](1);
        es[0] = entry(0, 1, 0, 3);
        seedRing(es, 0, 5);
        OpenArgs memory a = plainAt(6);
        a.update = emptyUpdate(0);
        premiseOpenSucceeds(a);
        vm.store(A_SR, fixedSlot("b1.count"), bytes32(0));
        refuse(a, B1StateInvalid.selector);
    }

    // ---------------------------------------------------------------- refusals: update binding

    function test_priorTipMustBeTheStoredTail() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);
        a.update.priorTipEpoch = 2;
        refuse(a, PriorTipMismatch.selector);
    }

    function test_oldTipEndMustAccompanyNewEntriesAndOnlyThem() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory missing = ackAt(6, 1, 3);
        missing.update.hasOldTipEnd = false;
        refuse(missing, OldTipEndMismatch.selector);

        OpenArgs memory extra = plainAt(6);
        extra.update.hasOldTipEnd = true;
        extra.update.oldTipEnd = 6;
        premiseOpenSucceeds(plainAt(6));
        refuse(extra, OldTipEndMismatch.selector);

        OpenArgs memory dirty = plainAt(6);
        dirty.update.oldTipEnd = 6; // present flag clear but a value supplied
        refuse(dirty, OldTipEndMismatch.selector);
    }

    function test_theClosureMustFollowTheFormerTipsStart() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);
        a.update.oldTipEnd = GENESIS_START; // an empty former-tip interval
        a.update.newEntries[0].start = GENESIS_START;
        refuse(a, InvalidInterval.selector);
    }

    function test_theFirstNewEntryMustBeTheFormerTipsSuccessor() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        // The supersession link: epoch tip+1 starting exactly at the closure.
        OpenArgs memory epochGap = ackAt(6, 1, 3);
        epochGap.update.newEntries[0].epoch = 3;
        refuse(epochGap, NonContiguousEpochs.selector);

        OpenArgs memory startGap = ackAt(6, 1, 3);
        startGap.update.newEntries[0].start = 5;
        refuse(startGap, NonContiguousEpochs.selector);
    }

    function test_newEntriesMustBeConsecutiveEpochsWithEndEqualToTheNextStart() public {
        premiseOpenSucceeds(ackAt(6, 2, 3));
        OpenArgs memory epochGap = ackAt(6, 2, 3);
        epochGap.update.newEntries[1].epoch = 4;
        refuse(epochGap, NonContiguousEpochs.selector);

        OpenArgs memory startGap = ackAt(6, 2, 3);
        startGap.update.newEntries[1].start = 7; // != end of the previous entry (6)
        refuse(startGap, NonContiguousEpochs.selector);
    }

    function test_onlyTheLastEntryIsOpen() public {
        premiseOpenSucceeds(ackAt(6, 2, 3));
        OpenArgs memory openMiddle = ackAt(6, 2, 3);
        openMiddle.update.newEntries[0].hasEnd = false;
        openMiddle.update.newEntries[0].end = 0;
        refuse(openMiddle, InvalidInterval.selector);

        OpenArgs memory closedLast = ackAt(6, 2, 3);
        closedLast.update.newEntries[1].hasEnd = true;
        closedLast.update.newEntries[1].end = 9;
        refuse(closedLast, InvalidInterval.selector);
    }

    function test_endAndHasEndMustBeCanonical() public {
        premiseOpenSucceeds(ackAt(6, 2, 3));
        OpenArgs memory empty = ackAt(6, 2, 3);
        empty.update.newEntries[0].end = empty.update.newEntries[0].start; // empty [s,s)
        refuse(empty, InvalidInterval.selector);

        // ackAt(6,1,..) makes a single open tail: a stray non-zero end with hasEnd clear.
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory stray = ackAt(6, 1, 3);
        stray.update.newEntries[0].end = 9;
        refuse(stray, InvalidInterval.selector);
    }

    function test_theFinalTailMustNameTheOriginEpoch() public {
        premiseOpenSucceeds(ackAt(6, 2, 3));
        // Two entries (epochs 2 and 3) while the operational projection names root epoch 2.
        OpenArgs memory a = ackAt(6, 2, 3);
        a.rootEpoch = 2;
        a.authEpoch = 1;
        a.assignment = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH + 1,
            a.activeConfHash,
            0,
            bytes32(0)
        );
        refuse(a, OriginEpochMismatch.selector);
    }

    function test_noEntryMayStartAfterTheOrigin() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);
        a.update.oldTipEnd = 7;
        a.update.newEntries[0].start = 7; // origin round is 6
        refuse(a, StartAfterOrigin.selector);
    }

    function test_aNewClosedEntryAtOrBelowLIsExpiredNotInsertable() public {
        // O = 20, L = 17, the tip closes at 5 <= L so it is removed; e2 [5,10) is expired.
        B1Update memory good = _skipUpdate(12, 4);
        premiseOpenSucceeds(ackWith(20, 3, good));
        B1Update memory u = B1Update({
            priorTipEpoch: ROOT_EPOCH,
            hasOldTipEnd: true,
            oldTipEnd: 5,
            newEntries: new B1Entry[](2)
        });
        u.newEntries[0] = entry(2, 5, 10, 3); // end 10 <= 17
        u.newEntries[1] = entry(3, 10, 0, 3);
        refuse(ackWith(20, 2, u), ExpiredEntry.selector);
    }

    function test_whenEverythingExpiresTheFirstNewEntryMustCrossL() public {
        // The first surviving entry starts at 18 > L = 17 while the old tip is deleted: a gap in
        // coverage at L.
        premiseOpenSucceeds(ackWith(20, 3, _skipUpdate(12, 4)));
        refuse(ackWith(20, 3, _skipUpdate(18, 4)), StartAfterOrigin.selector);
    }

    function test_afterTotalExpiryTheFirstNewEpochMustFollowTheOldTip() public {
        premiseOpenSucceeds(ackWith(20, 3, _skipUpdate(12, 4)));
        B1Update memory u = _skipUpdate(12, 1); // epoch 1 again: not newer than the former tip
        refuse(ackWith(20, 3, u), NonContiguousEpochs.selector);
    }

    function test_moreNewEntriesThanRingSlotsAreRefused() public {
        premiseOpenSucceeds(ackAt(6, 4, 3));
        OpenArgs memory a = ackAt(6, 4, 3);
        B1Entry[] memory five = new B1Entry[](5);
        for (uint256 i = 0; i < 4; i++) {
            five[i] = a.update.newEntries[i];
        }
        five[4] = entry(6, 7, 0, 3);
        a.update.newEntries = five;
        refuse(a, TooManyEntries.selector);
    }

    /// The full-ring guard: survivors plus new entries may not exceed K_max. Honest histories cannot
    /// reach it (K_max = W_cert + 1 is the pigeonhole bound); a ring that is full of live entries
    /// plus one more must be refused rather than overwrite a live queue slot.
    function test_aFullRingOfLiveEntriesRefusesAnInsertion() public {
        // Stored ends far above L = O - W_cert keep every entry live (a state honest histories
        // cannot produce, which is why it is seeded). The guard fires before any write.
        B1Entry[] memory es = new B1Entry[](4);
        es[0] = entry(1, 1, 2000, 3);
        es[1] = entry(2, 2000, 2001, 3);
        es[2] = entry(3, 2001, 2002, 3);
        es[3] = entry(4, 2002, 0, 3);
        seedRing(es, 0, 5);
        B1Update memory u = B1Update({
            priorTipEpoch: 4, hasOldTipEnd: true, oldTipEnd: 2003, newEntries: new B1Entry[](1)
        });
        u.newEntries[0] = entry(5, 2003, 0, 3);
        refuse(ackWith(10, 1, u), RingFull.selector);
    }

    function test_aRingWithOneFreeSlotAcceptsTheSameInsertion() public {
        B1Entry[] memory es = new B1Entry[](3);
        es[0] = entry(2, 90, 91, 3);
        es[1] = entry(3, 91, 92, 3);
        es[2] = entry(4, 92, 0, 3);
        seedRing(es, 0, 92);
        B1Update memory u = B1Update({
            priorTipEpoch: 4, hasOldTipEnd: true, oldTipEnd: 93, newEntries: new B1Entry[](1)
        });
        u.newEntries[0] = entry(5, 93, 0, 3);
        step(ackWith(93, 1, u));
        assertLive(epochs(2, 3, 4, 5));
    }

    function test_aStaleEntryForTheNewEpochRefusesInsertion() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        vm.store(A_SR, eSlot(2, 0), bytes32(uint256(1)));
        refuse(ackAt(6, 1, 3), EntryAlreadyPresent.selector);
    }

    // ---------------------------------------------------------------- refusals: entry shape

    function test_memberCountMustBeBetweenOneAndSixtyFour() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory none = ackAt(6, 1, 3);
        none.update.newEntries[0].members = new B1Member[](0);
        refuse(none, BadMemberCount.selector);
        OpenArgs memory many = ackAt(6, 1, 65);
        refuse(many, BadMemberCount.selector);
        OpenArgs memory max = ackAt(6, 1, 64);
        premiseOpenSucceeds(max);
    }

    function test_nodeIDLengthAndPaddingAreChecked() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory zeroLen = ackAt(6, 1, 3);
        zeroLen.update.newEntries[0].members[0].nodeIDLength = 0;
        refuse(zeroLen, BadNodeID.selector);

        OpenArgs memory tooLong = ackAt(6, 1, 3);
        tooLong.update.newEntries[0].members[0].nodeIDLength = 129;
        refuse(tooLong, BadNodeID.selector);

        // Length 3 with a non-zero byte after the third in word 0.
        OpenArgs memory padded = ackAt(6, 1, 3);
        padded.update.newEntries[0].members[0].nodeID[0] |= bytes32(uint256(1));
        refuse(padded, BadNodeID.selector);

        // Length 40 uses all of word 0 and the first 8 bytes of word 1; the rest is padding.
        B1Update memory good40 = advanceUpdate(1, 6, 1, 3);
        _longIDs(good40.newEntries[0]);
        premiseOpenSucceeds(ackWith(6, 1, good40));

        B1Update memory dirtyWord1 = advanceUpdate(1, 6, 1, 3);
        _longIDs(dirtyWord1.newEntries[0]);
        dirtyWord1.newEntries[0].members[0].nodeID[1] |= bytes32(uint256(1) << 184); // byte 8
        refuse(ackWith(6, 1, dirtyWord1), BadNodeID.selector);

        B1Update memory dirtyWord2 = advanceUpdate(1, 6, 1, 3);
        _longIDs(dirtyWord2.newEntries[0]);
        dirtyWord2.newEntries[0].members[0].nodeID[2] = bytes32(uint256(1) << 255);
        refuse(ackWith(6, 1, dirtyWord2), BadNodeID.selector);
    }

    function test_membersMustBeInStrictlyIncreasingRawNodeIDOrder() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory dup = ackAt(6, 1, 3);
        dup.update.newEntries[0].members[1].nodeID = dup.update.newEntries[0].members[0].nodeID;
        refuse(dup, NodeIDsNotSorted.selector);

        OpenArgs memory desc = ackAt(6, 1, 3);
        (desc.update.newEntries[0].members[0], desc.update.newEntries[0].members[1]) =
        (desc.update.newEntries[0].members[1], desc.update.newEntries[0].members[0]);
        refuse(desc, NodeIDsNotSorted.selector);

        // A proper prefix sorts first: [76 A0 00] then [76 A0 00 00] is ascending, the reverse is not.
        OpenArgs memory prefix = ackAt(6, 1, 2);
        B1Member memory a = prefix.update.newEntries[0].members[0];
        B1Member memory b = prefix.update.newEntries[0].members[1];
        b.nodeID = a.nodeID;
        b.nodeIDLength = a.nodeIDLength + 1; // same padded word, one more (zero) byte
        premiseOpenSucceeds(prefix);
        (prefix.update.newEntries[0].members[0], prefix.update.newEntries[0].members[1]) = (b, a);
        refuse(prefix, NodeIDsNotSorted.selector);
    }

    function test_compressedKeysMustHavePrefix02Or03AndZeroPadding() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        uint8[3] memory badPrefix = [0, 1, 4];
        for (uint256 i = 0; i < badPrefix.length; i++) {
            OpenArgs memory a = ackAt(6, 1, 3);
            bytes32 k = a.update.newEntries[0].members[0].key[0];
            a.update.newEntries[0].members[0].key[0] =
                bytes32(abi.encodePacked(bytes1(badPrefix[i]), bytes31(k << 8)));
            refuse(a, BadCompressedKey.selector);
        }
        OpenArgs memory pad = ackAt(6, 1, 3);
        pad.update.newEntries[0].members[0].key[1] |= bytes32(uint256(1) << 240); // byte 33
        refuse(pad, BadCompressedKey.selector);
    }

    function test_weightsMustBePositiveAndTheirTotalMustFitU64() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory zero = ackAt(6, 1, 3);
        zero.update.newEntries[0].members[0].weight = 0;
        refuse(zero, BadWeight.selector);

        OpenArgs memory overflow = ackAt(6, 1, 3);
        overflow.update.newEntries[0].members[0].weight = uint64(1) << 63;
        overflow.update.newEntries[0].members[1].weight = uint64(1) << 63;
        refuse(overflow, BadWeight.selector);

        // Exactly 2^64 - 1 is a valid total.
        OpenArgs memory edge = ackAt(6, 1, 2);
        edge.update.newEntries[0].members[0].weight = type(uint64).max - 1;
        edge.update.newEntries[0].members[1].weight = 1;
        premiseOpenSucceeds(edge);
        assertEq(totalWeight(edge.update.newEntries[0].members), type(uint64).max);
    }

    function test_bodySigningConfigAndActivationIdentitiesMustBeNonZero() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory body = ackAt(6, 1, 3);
        body.update.newEntries[0].bodyID = bytes32(0);
        refuse(body, ZeroIdentity.selector);
        OpenArgs memory config = ackAt(6, 1, 3);
        config.update.newEntries[0].signingConfigHash = bytes32(0);
        refuse(config, ZeroIdentity.selector);
        OpenArgs memory activation = ackAt(6, 1, 3);
        activation.update.newEntries[0].activationCommitID = bytes32(0);
        refuse(activation, ZeroIdentity.selector);
    }

    // ---------------------------------------------------------------- impossible stored state

    function test_aCorruptRingIsAnExecutionErrorNotAZeroFilledAuthority() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);

        vm.store(A_SR, fixedSlot("b1.count"), bytes32(uint256(5))); // > K_max
        refuse(a, B1StateInvalid.selector);
        vm.store(A_SR, fixedSlot("b1.count"), bytes32(uint256(1)));

        vm.store(A_SR, fixedSlot("b1.head"), bytes32(uint256(4))); // head >= K_max
        refuse(a, B1StateInvalid.selector);
        vm.store(A_SR, fixedSlot("b1.head"), bytes32(0));

        vm.store(A_SR, eSlot(1, 6), bytes32(uint256(1))); // the tail is closed
        refuse(a, B1StateInvalid.selector);
    }

    function test_finalizeReassertsTheOpenTailOfTheOriginEpoch() public {
        OpenArgs memory a = ackAt(6, 1, 3);
        openAsSystem(a);
        uint256 snap = vm.snapshotState();
        finalizeAsSystem(a.n, keccak256("R")); // premise: a good ring finalizes
        vm.revertToState(snap);

        bytes memory fin = finalizeCalldata(a.n, keccak256("R"));
        vm.store(A_SR, fixedSlot("b1.count"), bytes32(0));
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
        vm.store(A_SR, fixedSlot("b1.count"), bytes32(uint256(2)));

        vm.store(A_SR, qSlot(1), bytes32(uint256(7))); // tail epoch != origin.rootEpoch
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
        vm.store(A_SR, qSlot(1), bytes32(uint256(2)));

        vm.store(A_SR, eSlot(2, 6), bytes32(uint256(1))); // tail closed
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
        vm.store(A_SR, eSlot(2, 6), bytes32(0));

        vm.store(A_SR, eSlot(2, 0), bytes32(0)); // tail not present
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
    }

    // ---------------------------------------------------------------- atomicity

    /// A failure after deletions have been applied discards the whole candidate: here the last
    /// inserted entry is bad after every old entry was pruned and three new entries written.
    function test_prefixFailureAfterPruningAndInsertionRollsBackEverything() public {
        seedRing(fullRing(), 0, 13);
        B1Update memory u = B1Update({
            priorTipEpoch: 4, hasOldTipEnd: true, oldTipEnd: 14, newEntries: new B1Entry[](4)
        });
        u.newEntries[0] = entry(5, 14, 18, 3);
        u.newEntries[1] = entry(6, 18, 19, 3);
        u.newEntries[2] = entry(7, 19, 20, 3);
        u.newEntries[3] = entry(8, 20, 0, 3);
        premiseOpenSucceeds(ackWith(20, 4, u));

        u.newEntries[3].members[2].weight = 0; // the failure arrives last
        refuse(ackWith(20, 4, u), BadWeight.selector);
        assertLive(epochs(1, 2, 3, 4));
        assertEntryStored(fullRing()[0], 8);
    }

    // ---------------------------------------------------------------- authorization

    function test_onlyTheSystemCallerCanChangeTheRing() public {
        OpenArgs memory a = ackAt(6, 1, 3);
        premiseOpenSucceeds(a);
        address[3] memory strangers = [
            address(0xBEEF),
            0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE, // the EIP-4788 system caller
            A_SR
        ];
        for (uint256 i = 0; i < strangers.length; i++) {
            assertRefused(strangers[i], openCalldata(a), SealRegistry.NotSystemCaller.selector);
        }
        openAsSystem(a);
        assertRefused(
            address(0xBEEF),
            finalizeCalldata(a.n, keccak256("R")),
            SealRegistry.NotSystemCaller.selector
        );
    }

    /// The only state-changing entry points are open and finalize: the registry cannot be told to
    /// write a queue, entry, member or profile word, or to initialize or destroy itself.
    function test_noOtherEntryPointCanWriteB1State() public {
        string[8] memory sigs = [
            "initialize()",
            "setHead(uint256)",
            "setCount(uint256)",
            "writeEntry(uint256,uint256,bytes32)",
            "setWCert(uint64)",
            "setProfileHash(bytes32)",
            "selfdestruct()",
            "upgradeTo(address)"
        ];
        for (uint256 i = 0; i < sigs.length; i++) {
            assertRefusedWithoutReason(A_SYS, abi.encodeWithSignature(sigs[i], uint256(1)), 0);
            assertRefusedWithoutReason(
                address(0xBEEF), abi.encodeWithSignature(sigs[i], uint256(1)), 0
            );
        }
    }

    function testFuzz_aStrangerWithAnyUpdateChangesNothing(address caller, uint256 seed) public {
        vm.assume(caller != A_SYS);
        OpenArgs memory a = randomArgs(seed);
        assertRefused(caller, openCalldata(a), SealRegistry.NotSystemCaller.selector);
    }

    /// Whatever an update does, a success preserves the ring shape: within K_max, contiguous, one open
    /// tail on the origin epoch, and no live entry for an expired epoch.
    function testFuzz_systemUpdatesKeepTheRingAContiguousLiveSet(uint256 seed) public {
        OpenArgs memory a = randomArgs(seed);
        (bool ok,) = callAs(A_SYS, openCalldata(a));
        if (!ok) return;
        uint256[] memory es = liveEpochs();
        assertGe(es.length, 1);
        assertLe(es.length, kMax());
        for (uint256 i = 0; i < es.length; i++) {
            assertEq(ent(es[i], 0), bytes32(uint256(1)));
            bool last = i == es.length - 1;
            assertEq(uint256(ent(es[i], 6)), last ? 0 : 1);
            if (!last) {
                assertEq(es[i + 1], es[i] + 1);
                assertEq(ent(es[i], 5), ent(es[i + 1], 4));
            }
        }
        assertEq(es[es.length - 1], uintWord("origin.rootEpoch"));
    }

    /// A model of the rule written independently of the contract: starts are remembered per epoch, an
    /// entry is live iff it is the tail or its successor's start exceeds L, and the registry's live
    /// set, closures and absent words must match it after every honest step.
    function testFuzz_honestHistoriesMatchTheIndependentModel(uint256 seed) public {
        uint256[] memory starts = new uint256[](64); // starts[e] for e >= 1
        starts[1] = GENESIS_START;
        uint64 tip = 1;
        uint64 O = 5;
        step(plainAt(O));
        for (uint256 i = 0; i < 14; i++) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            uint64 delta = uint64(seed % 4); // 0 = no epoch change
            uint64 move = uint64((seed >> 8) % 3);
            // The new intervals start at O' - delta + 1 .. O', all after the previous origin.
            O = O + (delta == 0 ? move : delta + move);
            if (delta == 0) {
                step(plainAt(O));
            } else {
                for (uint64 k = 1; k <= delta; k++) {
                    starts[tip + k] = O - delta + k;
                }
                step(ackAt(O, delta, 1 + (seed >> 16) % 4));
                tip += delta;
            }
            _assertMatchesModel(starts, tip, O);
        }
    }

    function _assertMatchesModel(uint256[] memory starts, uint64 tip, uint64 O) internal view {
        uint256 low = O > W_CERT ? O - W_CERT : 0;
        uint256[] memory live = liveEpochs();
        uint256 n;
        for (uint256 e = 1; e <= tip; e++) {
            bool isTail = e == tip;
            bool alive = isTail || starts[e + 1] > low;
            if (alive) {
                assertEq(live[n], e, "model: live epoch");
                n++;
                assertEq(ent(e, 0), bytes32(uint256(1)));
                assertEq(ent(e, 4), bytes32(starts[e]), "model: start");
                assertEq(ent(e, 6), bytes32(uint256(isTail ? 0 : 1)));
                assertEq(ent(e, 5), bytes32(isTail ? 0 : starts[e + 1]), "model: closure");
            } else {
                assertEntryAbsent(e, 4);
            }
        }
        assertEq(n, live.length, "model: live count");
        assertLe(live.length, kMax());
    }

    // ---------------------------------------------------------------- helpers

    function _closedGenesis(uint64 end) internal pure returns (B1Entry memory en) {
        en = genesisEntry();
        en.hasEnd = true;
        en.end = end;
    }

    /// @dev An update for the skipped span O = 20: the former tip (epoch 1) closes at 5, so it is
    /// removed, and only `firstEpoch` starting at `start` is supplied; epochs between were expired.
    function _skipUpdate(uint64 start, uint64 firstEpoch)
        internal
        pure
        returns (B1Update memory u)
    {
        u = B1Update({
            priorTipEpoch: ROOT_EPOCH,
            hasOldTipEnd: true,
            oldTipEnd: 5,
            newEntries: new B1Entry[](1)
        });
        u.newEntries[0] = entry(firstEpoch, start, 0, 3);
    }

    /// @dev Gives every member of `en` a 40-byte node ID in increasing order (word 0 = 0x80 + j).
    function _longIDs(B1Entry memory en) internal pure {
        for (uint256 j = 0; j < en.members.length; j++) {
            en.members[j].nodeIDLength = 40;
            en.members[j].nodeID[0] = bytes32(uint256(0x80 + j) << 248);
            en.members[j].nodeID[1] = bytes32(uint256(0xab) << 248);
            en.members[j].nodeID[2] = bytes32(0);
            en.members[j].nodeID[3] = bytes32(0);
        }
    }
}

/// @notice W_cert = 0: K_max = 1, and exactly the origin interval is retained.
contract SealRegistryB1W0Test is SealRegistryB1Helpers {
    function setUp() public override {
        wCertFixture = 0;
        super.setUp();
    }

    function test_theQueueHasOneSlotAndTheGenesisEntryFillsIt() public view {
        assertEq(kMax(), 1);
        assertEq(b1Word("b1.wCert"), 0);
        assertLive(epochs(1));
    }

    function test_anEpochAdvanceReplacesTheOnlyIntervalWithNoClosureWritten() public {
        // O = 6, L = 6: the tip closes at 6 <= L and is deleted; the new tail reuses slot 0.
        OpenArgs memory a = ackAt(6, 1, 3);
        step(a);
        assertLive(epochs(2));
        assertEq(b1Word("b1.head"), 0);
        assertEq(queueAt(0), 2);
        assertEntryAbsent(1, 8);
        assertEntryStored(a.update.newEntries[0], 8);
    }

    function test_theOriginIntervalIsRetainedWhateverItsAge() public {
        step(plainAt(500));
        assertLive(epochs(1));
        assertEntryStored(genesisEntry(), 8);
    }

    function test_twoNewEntriesCannotFitOneSlot() public {
        premiseOpenSucceeds(ackAt(7, 1, 3));
        refuse(ackAt(7, 2, 3), TooManyEntries.selector);
    }
}
