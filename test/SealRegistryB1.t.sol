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
    AppendGap,
    BadAppend,
    NonContiguousEpochs,
    AppendStartNotIncreasing,
    AppendClosesUsableOrigin,
    StartAfterOrigin,
    OriginEpochMismatch,
    EntryAlreadyPresent,
    OriginBeforeStart,
    BadMemberCount,
    BadNodeID,
    NodeIDsNotSorted,
    BadCompressedKey,
    BadWeight,
    ZeroIdentity
} from "../src/B1Layout.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";

/// @notice The permanent B1 registry: append, close, origin advance and the cursors, against slot formulas written independently in
/// SealRegistryBase. Every refusal test first shows that the unmodified update succeeds, then applies exactly one mutation and requires
/// the exact custom-error selector and that no tracked operational or B1 word changed. The reference is bft-core `b1state.Registry.Apply`.
///
/// The genesis entry is epoch 1, open, starting at root round 1, with three members; the fixture profile imports at most B = 2 epochs.
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
    // ---------------------------------------------------------------- genesis and the first origin

    function test_genesisIsTheOnlyEntryAndNoOriginIsUsableYet() public view {
        assertEq(b1Word("b1.format"), 2);
        assertEq(b1Word("b1.initialized"), 1);
        assertEq(b1Word("b1.genesisEpoch"), ROOT_EPOCH);
        assertEq(b1Word("b1.importedTipEpoch"), ROOT_EPOCH);
        assertEq(b1Word("b1.originReady"), 0);
        assertEq(uintWord("origin.rootEpoch"), 0);
        assertEq(uintWord("clock.rootRound"), 0);
        assertEntryStored(genesisEntry(), 8);
        // none of the windowed layout's words exists
        assertEq(b1Word("b1.wCert"), 0);
        assertEq(b1Word("b1.head"), 0);
        assertEq(b1Word("b1.count"), 0);
    }

    function test_theFirstOpenMakesTheOriginUsableWithoutMovingTheTip() public {
        step(plainAt(5));
        assertEq(b1Word("b1.originReady"), 1);
        assertEq(uintWord("origin.rootEpoch"), ROOT_EPOCH);
        assertEq(uintWord("clock.rootRound"), 5);
        assertEq(tipEpoch(), ROOT_EPOCH);
        assertEntryStored(genesisEntry(), 8);
    }

    function test_aFirstOriginBeforeTheTipsStartIsRefused() public {
        premiseOpenSucceeds(plainAt(GENESIS_START));
        refuse(plainAt(GENESIS_START - 1), OriginBeforeStart.selector);
    }

    function test_repeatedAndAdvancingOriginsLeaveTheIntervalsUnchanged() public {
        step(plainAt(5));
        step(plainAt(5));
        step(plainAt(9));
        assertEq(uintWord("clock.rootRound"), 9);
        assertEntryStored(genesisEntry(), 8);
        assertEq(tipEpoch(), ROOT_EPOCH);
    }

    // ---------------------------------------------------------------- append and close

    function test_ackInstallsTheEntryAndClosesTheFormerTipOnce() public {
        OpenArgs memory a = ackAt(6, 1, 3);
        step(a);
        assertEntryStored(_closedGenesis(6), 8);
        assertEntryStored(entry(2, 6, 0, 3), 8);
        assertEq(tipEpoch(), 2);
        assertEq(genesisEpoch(), ROOT_EPOCH);
        assertEq(b1Word("b1.originReady"), 1);
        assertEq(uintWord("origin.rootEpoch"), 2);
        assertEq(uintWord("clock.rootRound"), 6);
    }

    function test_twoEpochsInOneBlockAreBothInstalled() public {
        step(ackAt(7, 2, 3));
        assertEntryStored(_closedGenesis(6), 8);
        assertEntryStored(entry(2, 6, 7, 3), 8);
        assertEntryStored(entry(3, 7, 0, 3), 8);
        assertEq(tipEpoch(), 3);
        assertEq(uintWord("origin.rootEpoch"), 3);
    }

    function test_nothingIsEverRemoved() public {
        uint64 tip = 1;
        uint64 O = 5;
        step(plainAt(O));
        uint256[] memory starts = new uint256[](9);
        starts[1] = GENESIS_START;
        for (uint256 i = 0; i < 6; i++) {
            O += 3;
            starts[tip + 1] = O;
            step(ackAt(O, 1, 1 + i));
            tip += 1;
        }
        assertEq(tipEpoch(), 7);
        for (uint256 e = 1; e <= tip; e++) {
            assertEq(ent(e, 0), bytes32(uint256(1)), "present");
            assertEq(ent(e, 4), bytes32(starts[e]), "start");
            assertEq(ent(e, 6), bytes32(uint256(e == tip ? 0 : 1)), "closed below the tip");
            assertEq(
                ent(e, 5), bytes32(e == tip ? 0 : starts[e + 1]), "end is the successor's start"
            );
            assertEq(ent(e, 9), bytes32(e == 1 ? 3 : 1 + ((e - 2) % 6)), "members kept");
        }
    }

    // ---------------------------------------------------------------- the update's own shape and the append rules

    function test_priorTipMustBeTheImportedTip() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);
        a.update.priorTipEpoch = 2;
        refuse(a, PriorTipMismatch.selector);
    }

    function test_oldTipEndMustAccompanyNewEntriesAndOnlyThem() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory missing = ackAt(6, 1, 3);
        missing.update.hasOldTipEnd = false;
        missing.update.oldTipEnd = 0;
        refuse(missing, OldTipEndMismatch.selector);
        OpenArgs memory stray = plainAt(5);
        stray.update.hasOldTipEnd = true;
        stray.update.oldTipEnd = 5;
        refuse(stray, OldTipEndMismatch.selector);
        OpenArgs memory notTheStart = ackAt(6, 1, 3);
        notTheStart.update.oldTipEnd = 5;
        refuse(notTheStart, OldTipEndMismatch.selector);
    }

    function test_theFirstNewEntryMustBeTheTipsSuccessor() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);
        a.update.newEntries[0].epoch = 3;
        refuse(a, AppendGap.selector);
        OpenArgs memory behind = ackAt(6, 1, 3);
        behind.update.newEntries[0].epoch = 1;
        refuse(behind, AppendGap.selector);
    }

    function test_newEntriesMustBeConsecutiveEpochsWithEndEqualToTheNextStart() public {
        premiseOpenSucceeds(ackAt(7, 2, 3));
        OpenArgs memory gap = ackAt(7, 2, 3);
        gap.update.newEntries[1].epoch = 4;
        refuse(gap, AppendGap.selector);
        OpenArgs memory seam = ackAt(7, 2, 3);
        seam.update.newEntries[1].start = 8; // the first entry ends at 7
        refuse(seam, NonContiguousEpochs.selector);
        OpenArgs memory open = ackAt(7, 2, 3);
        open.update.newEntries[0].hasEnd = false;
        open.update.newEntries[0].end = 0;
        refuse(open, InvalidInterval.selector); // a non-last entry that is open: only the last may be
    }

    function test_onlyTheLastEntryIsOpen() public {
        premiseOpenSucceeds(ackAt(7, 2, 3));
        OpenArgs memory closedTail = ackAt(7, 2, 3);
        closedTail.update.newEntries[1].hasEnd = true;
        closedTail.update.newEntries[1].end = 7;
        refuse(closedTail, InvalidInterval.selector);
    }

    function test_endAndHasEndMustBeCanonical() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory stray = ackAt(6, 1, 3);
        stray.update.newEntries[0].end = 5; // an end without hasEnd
        refuse(stray, InvalidInterval.selector);
        OpenArgs memory empty = ackAt(7, 2, 3);
        empty.update.newEntries[0].end = 6; // end == start: an empty interval (and the seam breaks, but the interval is refused first)
        empty.update.newEntries[1].start = 6;
        refuse(empty, InvalidInterval.selector);
    }

    function test_theFinalTailMustNameTheOriginEpoch() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        // the root epoch advances by two but the update installs one epoch
        refuse(ackWith(6, 2, advanceUpdate(1, 6, 1, 3)), OriginEpochMismatch.selector);
        // and a plain open must be on the tip
        OpenArgs memory plain = plainAt(5);
        plain.rootEpoch = 1;
        premiseOpenSucceeds(plain);
    }

    function test_noEntryMayStartAfterTheOriginOrEndAfterIt() public {
        premiseOpenSucceeds(ackAt(7, 2, 3));
        OpenArgs memory late = ackAt(6, 1, 3);
        late.update.newEntries[0].start = 7;
        late.update.oldTipEnd = 7;
        refuse(late, StartAfterOrigin.selector);
        OpenArgs memory longEnd = ackAt(7, 2, 3);
        longEnd.update.newEntries[0].end = 8;
        longEnd.update.newEntries[1].start = 8;
        refuse(longEnd, StartAfterOrigin.selector);
    }

    function test_theSuccessorMustStartAfterTheTip() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);
        a.update.newEntries[0].start = GENESIS_START;
        a.update.oldTipEnd = GENESIS_START;
        refuse(a, AppendStartNotIncreasing.selector);
    }

    function test_theSuccessorMayNotCloseTheUsableEpochAtOrBelowTheOrigin() public {
        step(plainAt(8));
        premiseOpenSucceeds(ackAt(9, 1, 3));
        refuse(ackAt(8, 1, 3), AppendClosesUsableOrigin.selector); // would start at 8, the usable epoch's origin round
    }

    function test_aGenesisBodyCannotBeAppended() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);
        a.update.newEntries[0].bodyKind = 1;
        a.update.newEntries[0].activationCommitID = bytes32(0);
        refuse(a, BadAppend.selector);
    }

    function test_aStaleEntryForTheNewEpochRefusesInsertion() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        storeEntry(entry(2, 6, 0, 3));
        refuse(ackAt(6, 1, 3), EntryAlreadyPresent.selector);
    }

    // ---------------------------------------------------------------- entry shape

    function test_memberCountMustBeBetweenOneAndSixteen() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory none = ackAt(6, 1, 3);
        none.update.newEntries[0].members = new B1Member[](0);
        refuse(none, BadMemberCount.selector);
        OpenArgs memory many = ackAt(6, 1, 17);
        refuse(many, BadMemberCount.selector);
        OpenArgs memory max = ackAt(6, 1, 16);
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

    function test_aCorruptTipIsAnExecutionErrorNotAZeroFilledAuthority() public {
        premiseOpenSucceeds(ackAt(6, 1, 3));
        OpenArgs memory a = ackAt(6, 1, 3);
        vm.store(A_SR, eSlot(1, 6), bytes32(uint256(1))); // the tip is closed
        refuse(a, B1StateInvalid.selector);
        vm.store(A_SR, eSlot(1, 6), bytes32(0));
        vm.store(A_SR, eSlot(1, 0), bytes32(0)); // the tip is not present
        refuse(a, B1StateInvalid.selector);
        vm.store(A_SR, eSlot(1, 0), bytes32(uint256(1)));
        vm.store(A_SR, fixedSlot("b1.importedTipEpoch"), bytes32(uint256(40))); // a tip with no entry
        refuse(a, B1StateInvalid.selector);
    }

    function test_finalizeReassertsTheCursorsAndTheOpenTip() public {
        OpenArgs memory a = ackAt(6, 1, 3);
        openAsSystem(a);
        uint256 snap = vm.snapshotState();
        finalizeAsSystem(a.n, keccak256("R")); // premise: good state finalizes
        vm.revertToState(snap);

        importEmptyAsSystem(a.n);
        bytes memory fin = finalizeCalldata(a.n, keccak256("R"));
        vm.store(A_SR, fixedSlot("b1.originReady"), bytes32(0));
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
        vm.store(A_SR, fixedSlot("b1.originReady"), bytes32(uint256(1)));

        vm.store(A_SR, fixedSlot("b1.format"), bytes32(uint256(1)));
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
        vm.store(A_SR, fixedSlot("b1.format"), bytes32(uint256(2)));

        vm.store(A_SR, fixedSlot("b1.importedTipEpoch"), bytes32(uint256(3))); // tip != usable epoch
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
        vm.store(A_SR, fixedSlot("b1.importedTipEpoch"), bytes32(uint256(2)));

        vm.store(A_SR, eSlot(2, 6), bytes32(uint256(1))); // tip closed
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
        vm.store(A_SR, eSlot(2, 6), bytes32(0));

        vm.store(A_SR, eSlot(2, 0), bytes32(0)); // tip not present
        assertRefused(A_SYS, fin, B1StateInvalid.selector);
    }

    // ---------------------------------------------------------------- atomicity

    /// A failure after entries were written discards the whole candidate: here the last of two new entries is bad.
    function test_aLaterFailureRollsBackEveryEarlierWrite() public {
        premiseOpenSucceeds(ackAt(7, 2, 3));
        OpenArgs memory a = ackAt(7, 2, 3);
        a.update.newEntries[1].members[2].weight = 0; // the failure arrives last
        bytes32 before = b1Digest();
        refuse(a, BadWeight.selector);
        assertEq(b1Digest(), before);
        assertEq(tipEpoch(), ROOT_EPOCH);
        assertEntryStored(genesisEntry(), 8);
        assertEq(ent(2, 0), bytes32(0));
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
    /// write a cursor, entry, member or profile word, or to initialize or destroy itself.
    function test_noOtherEntryPointCanWriteB1State() public {
        string[8] memory sigs = [
            "initialize()",
            "setImportedTip(uint256)",
            "setFormat(uint256)",
            "writeEntry(uint256,uint256,bytes32)",
            "setGenesisEpoch(uint64)",
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

    /// Whatever the update is, a success keeps the registry a permanent contiguous history: every epoch from g to I present, all below the
    /// tip closed at the successor's start, only the tip open, and the usable epoch is the tip.
    function testFuzz_systemUpdatesKeepAContiguousPermanentHistory(uint256 seed) public {
        OpenArgs memory a = randomArgs(seed);
        (bool ok,) = callAs(A_SYS, openCalldata(a));
        if (!ok) return;
        uint256 tip = tipEpoch();
        assertEq(uintWord("origin.rootEpoch"), tip);
        for (uint256 e = genesisEpoch(); e <= tip; e++) {
            assertEq(ent(e, 0), bytes32(uint256(1)));
            assertEq(uint256(ent(e, 6)), e == tip ? 0 : 1);
            if (e != tip) assertEq(ent(e, 5), ent(e + 1, 4));
        }
    }

    /// A model of the rule written independently of the contract: starts are remembered per epoch; the registry's entries, closures and
    /// cursors must match it after every honest step, and no entry is ever absent.
    function testFuzz_honestHistoriesMatchTheIndependentModel(uint256 seed) public {
        uint256[] memory starts = new uint256[](64);
        starts[1] = GENESIS_START;
        uint64 tip = 1;
        uint64 O = 5;
        step(plainAt(O));
        for (uint256 i = 0; i < 14; i++) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            uint64 delta = uint64(seed % 3); // 0 = no epoch change; at most B = 2 epochs
            uint64 move = uint64((seed >> 8) % 3);
            O = O + (delta == 0 ? move : delta + move);
            if (delta == 0) {
                step(plainAt(O));
            } else {
                for (uint64 k = 1; k <= delta; k++) {
                    starts[tip + k] = O - delta + k;
                }
                step(ackAt(O, delta, 1 + (seed >> 16) % 16));
                tip += delta;
            }
            _assertMatchesModel(starts, tip, O);
        }
    }

    function _assertMatchesModel(uint256[] memory starts, uint64 tip, uint64 O) internal view {
        assertEq(tipEpoch(), tip, "model: imported tip");
        assertEq(uintWord("origin.rootEpoch"), tip, "model: usable epoch");
        assertEq(uintWord("clock.rootRound"), O, "model: origin round");
        assertEq(b1Word("b1.originReady"), 1);
        for (uint256 e = 1; e <= tip; e++) {
            bool isTail = e == tip;
            assertEq(ent(e, 0), bytes32(uint256(1)), "model: present");
            assertEq(ent(e, 4), bytes32(starts[e]), "model: start");
            assertEq(ent(e, 6), bytes32(uint256(isTail ? 0 : 1)));
            assertEq(ent(e, 5), bytes32(isTail ? 0 : starts[e + 1]), "model: closure");
        }
        assertEq(ent(uint256(tip) + 1, 0), bytes32(0), "model: nothing beyond the tip");
    }

    // ---------------------------------------------------------------- helpers

    function _closedGenesis(uint64 end) internal pure returns (B1Entry memory en) {
        en = genesisEntry();
        en.hasEnd = true;
        en.end = end;
    }

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
