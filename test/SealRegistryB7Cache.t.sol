// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {SealRegistry} from "../src/SealRegistry.sol";
import {B1Entry, B1Update} from "../src/B1Layout.sol";
import {SealRegistryB1Helpers} from "./SealRegistryB1.t.sol";

/// @notice The B7 trust cache (#68 step 2): every entry caches C_e at E(e, 11) when it is written (at genesis by the builder, on
/// append by open), closing an epoch never changes it, and epochCommitments reads at most 64 named epochs by direct lookup. The
/// expected value comes from B7Relation over the stored words (bft-core b7rel vectors pin that formula), not from B1Layout.
contract SealRegistryB7CacheTest is SealRegistryB1Helpers {
    SealRegistry internal reg = SealRegistry(A_SR);

    function _one(uint64 e) internal pure returns (uint64[] memory es) {
        es = new uint64[](1);
        es[0] = e;
    }

    function test_theGenesisBuilderCachesTheGenesisCommitment() public view {
        bytes32 c = ent(ROOT_EPOCH, 11);
        assertTrue(c != 0, "cached");
        assertEq(c, storedWordsCommitment(ROOT_EPOCH), "C_e over the stored words");
        assertEq(c, expectedCommitment(genesisEntry()), "C_e over the genesis entry");
    }

    function test_aSpanTwoImportCachesBothEpochsAndClosureLeavesTheCacheUnchanged() public {
        bytes32 genesisBefore = ent(ROOT_EPOCH, 11);
        step(ackAt(7, 2, 3)); // installs epochs 2 and 3, closes the genesis epoch at 6
        assertEq(ent(ROOT_EPOCH, 11), genesisBefore, "closing the genesis epoch keeps its C_e");
        assertEq(ent(ROOT_EPOCH, 6), bytes32(uint256(1)), "premise: the genesis epoch is closed");
        for (uint64 e = 1; e <= 3; e++) {
            assertEq(ent(e, 11), storedWordsCommitment(e), "C_e over the stored words");
        }

        uint64[] memory es = new uint64[](3);
        (es[0], es[1], es[2]) = (3, 1, 2); // the caller's order, not sorted
        (bytes32[] memory c, uint64[] memory ends, bool[] memory hasEnd) = reg.epochCommitments(es);
        assertEq(c[0], ent(3, 11));
        assertEq(c[1], genesisBefore);
        assertEq(c[2], ent(2, 11));
        assertEq(ends[0], 0);
        assertFalse(hasEnd[0], "the tip is open");
        assertEq(ends[1], 6);
        assertTrue(hasEnd[1]);
        assertEq(ends[2], 7);
        assertTrue(hasEnd[2]);
    }

    function test_aFullWidthEntryIsCachedOverEverySixteenMembers() public {
        step(ackAt(6, 1, 16));
        assertEq(uint256(ent(2, 9)), 16, "premise: 16 members");
        assertEq(ent(2, 11), storedWordsCommitment(2));
        assertEq(ent(2, 11), expectedCommitment(entry(2, 6, 0, 16)));
    }

    function test_theCacheBindsTheDeploymentWords() public {
        step(ackAt(6, 1, 3));
        bytes32 c = ent(2, 11);
        // The same entry under another genesisCommitment or profileHash is another C_e: rewriting either word and re-deriving the
        // stored-words commitment no longer matches the cache written under the original deployment.
        vm.store(A_SR, fixedSlot("genesisCommitment"), keccak256("another genesis"));
        assertTrue(storedWordsCommitment(2) != c, "genesisCommitment is bound");
        vm.store(A_SR, fixedSlot("genesisCommitment"), GENESIS_COMMITMENT);
        vm.store(A_SR, fixedSlot("b1.profileHash"), keccak256("another profile"));
        assertTrue(storedWordsCommitment(2) != c, "profileHash is bound");
    }

    function test_theViewRefusesNoEpochsAndMoreThanSixtyFour() public {
        vm.expectRevert(SealRegistry.CommitmentViewBounds.selector);
        reg.epochCommitments(new uint64[](0));

        uint64[] memory es = new uint64[](64);
        for (uint256 i = 0; i < 64; i++) {
            es[i] = ROOT_EPOCH;
        }
        (bytes32[] memory c,,) = reg.epochCommitments(es); // exactly the bound is served
        assertEq(c.length, 64);

        es = new uint64[](65);
        for (uint256 i = 0; i < 65; i++) {
            es[i] = ROOT_EPOCH;
        }
        vm.expectRevert(SealRegistry.CommitmentViewBounds.selector);
        reg.epochCommitments(es);
    }

    function test_theViewRefusesAMissingEpochAZeroCacheAndAnAbsentEntry() public {
        vm.expectRevert(
            abi.encodeWithSelector(SealRegistry.EpochCommitmentMissing.selector, ROOT_EPOCH + 1)
        );
        reg.epochCommitments(_one(ROOT_EPOCH + 1)); // never installed

        reg.epochCommitments(_one(ROOT_EPOCH)); // premise: the genesis epoch is served
        bytes32 c = ent(ROOT_EPOCH, 11);
        vm.store(A_SR, eSlot(ROOT_EPOCH, 11), bytes32(0)); // a missing cache is never read as a zero commitment
        vm.expectRevert(
            abi.encodeWithSelector(SealRegistry.EpochCommitmentMissing.selector, ROOT_EPOCH)
        );
        reg.epochCommitments(_one(ROOT_EPOCH));

        vm.store(A_SR, eSlot(ROOT_EPOCH, 11), c);
        vm.store(A_SR, eSlot(ROOT_EPOCH, 0), bytes32(0)); // a cache word without a present entry is not served
        vm.expectRevert(
            abi.encodeWithSelector(SealRegistry.EpochCommitmentMissing.selector, ROOT_EPOCH)
        );
        reg.epochCommitments(_one(ROOT_EPOCH));
    }

    function test_aRefusedImportLeavesNoCacheWord() public {
        OpenArgs memory a = ackAt(7, 2, 3);
        a.update.newEntries[1].members[0].weight = 0; // the second entry is malformed: the whole call reverts
        (bool ok,) = callAs(A_SYS, openCalldata(a));
        assertFalse(ok);
        assertEq(ent(2, 11), bytes32(0), "the first entry's cache rolled back");
        assertEq(ent(3, 11), bytes32(0));
    }

    /// The members are hashed straight from calldata, which is sound only because the ABI decoder has already refused a uint64
    /// member word with dirty high bits: such an open reverts and leaves no entry and no cache.
    function test_aDirtyMemberWordIsRefusedBeforeAnythingIsHashedOrWritten() public {
        OpenArgs memory a = ackAt(6, 1, 3);
        premiseOpenSucceeds(a);
        bytes memory data = openCalldata(a);
        bytes32 id0 = a.update.newEntries[0].members[0].nodeID[0];
        uint256 pos = type(uint256).max;
        for (uint256 i = 4; i + 32 <= data.length; i += 32) {
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(data, 0x20), i))
            }
            if (w == id0) {
                pos = i - 32; // the member's nodeIDLength word precedes nodeID word 0
                break;
            }
        }
        assertTrue(pos != type(uint256).max, "premise: the member is in the calldata");
        data[pos] = 0x01; // nodeIDLength keeps its value in the low 8 bytes but is no longer a clean uint64
        (bool ok,) = callAs(A_SYS, data);
        assertFalse(ok, "a dirty uint64 member word is refused");
        assertEntryAbsent(2, 3);
    }

    /// No path scans the history: the view reads exactly four words of the registry per named epoch (present, C_e, end,
    /// hasEnd), the same before and after eight more epochs are installed.
    function test_theViewReadsFourWordsPerEpochWhateverTheHistory() public {
        assertEq(_viewReads(), 4, "genesis only");
        uint64 O = 6;
        for (uint256 i = 0; i < 8; i++) {
            step(ackAt(O, 1, 3));
            O += 2;
        }
        assertEq(tipEpoch(), ROOT_EPOCH + 8, "premise: eight more epochs installed");
        assertEq(_viewReads(), 4, "nine epochs installed");
    }

    function _viewReads() internal returns (uint256) {
        vm.record();
        reg.epochCommitments(_one(ROOT_EPOCH));
        (bytes32[] memory reads,) = vm.accesses(A_SR);
        return reads.length;
    }
}
