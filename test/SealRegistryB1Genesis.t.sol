// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {
    B1Entry,
    B1Member,
    BadMemberCount,
    BadNodeID,
    NodeIDsNotSorted,
    BadCompressedKey,
    BadWeight,
    ZeroIdentity,
    InvalidInterval
} from "../src/B1Layout.sol";
import {
    B1GenesisBuilder,
    B1GenesisParams,
    B1Word,
    ProfileBounds,
    UnmeasuredB,
    GasEnvelopeShort,
    GenesisEntryInvalid
} from "../src/B1GenesisBuilder.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";

/// @notice The genesis builder applies the runtime's bounds and entry rules to the genesis entry and
/// refuses a profile whose g_sys does not cover the registry envelope. Its output is checked against
/// the independent slot derivation in SealRegistryBase and a pinned digest for the fixture.
contract SealRegistryB1GenesisTest is SealRegistryBase {
    /// @dev Words of a member that are non-zero: length, nodeID word 0 (IDs here are 3 bytes), key
    /// word 0, key word 1 if its byte is non-zero, and weight.
    function nonZeroMemberWords(B1Member[] memory ms) internal pure returns (uint256 n) {
        for (uint256 j = 0; j < ms.length; j++) {
            n += 4 + (ms[j].key[1] != bytes32(0) ? 1 : 0);
        }
    }

    function _build(B1GenesisParams memory p) internal view returns (B1Word[] memory) {
        return builder.words(p);
    }

    function _expectRefusal(B1GenesisParams memory p, bytes4 selector) internal {
        _build(genesisParams()); // premise: the unmodified profile builds
        vm.expectRevert(selector);
        builder.words(p);
    }

    // ---------------------------------------------------------------- the genesis allocation

    function test_thereAreExactlyTheNonZeroGenesisWords() public view {
        B1Word[] memory ws = _build(genesisParams());
        // 6 operational (genesisCommitment, config, rootEpoch, activeConf, records.ucTime, phase; shard epoch 0 is
        // absent) + 6 profile and cursors (network, format, profileHash, initialized, genesisEpoch, importedTipEpoch;
        // originReady is 0) + 8 entry metadata (activationCommitID, end, hasEnd are zero) + the non-zero member words.
        assertEq(ws.length, 6 + 6 + 8 + nonZeroMemberWords(genesisEntry().members));
        for (uint256 i = 0; i < ws.length; i++) {
            assertTrue(ws[i].value != bytes32(0), "zero words are omitted");
            for (uint256 j = 0; j < i; j++) {
                assertTrue(ws[i].slot != ws[j].slot, "no slot is written twice");
            }
        }
    }

    function test_noLayoutVersionWordIsEverWritten() public view {
        B1Word[] memory ws = _build(genesisParams());
        for (uint256 i = 0; i < ws.length; i++) {
            assertTrue(ws[i].slot != fixedSlot("layoutVersion"));
            assertTrue(ws[i].slot != keccak256("unicity.seal-registry.v1/layoutVersion"));
        }
    }

    /// The pinned digest of the fixture's genesis storage: every (slot, value) pair in builder order.
    /// An independent genesis builder (the Go construction) must reproduce these words.
    function test_fixtureGenesisStorageDigestIsPinned() public view {
        B1Word[] memory ws = _build(genesisParams());
        bytes memory all;
        for (uint256 i = 0; i < ws.length; i++) {
            all = bytes.concat(all, ws[i].slot, ws[i].value);
        }
        assertEq(keccak256(all), GENESIS_STORAGE_DIGEST);
    }

    bytes32 internal constant GENESIS_STORAGE_DIGEST =
        0x8c9f35d7df00fd660f826cb340b4adc651c90cf0d6a6ff4ee9ab9d9f36e26c76;

    function test_theInstalledGenesisRoundTripsThroughTheIndependentReaders() public view {
        assertEntryStored(genesisEntry(), 8);
        assertEq(b1Word("b1.network"), NETWORK);
        assertEq(b1Word("b1.format"), 2);
        assertEq(b1Word("b1.genesisEpoch"), ROOT_EPOCH);
        assertEq(b1Word("b1.importedTipEpoch"), ROOT_EPOCH);
        assertEq(b1Word("b1.originReady"), 0);
        assertEq(uintWord("phase"), 2);
        assertEq(word("assignment.activeConfHash"), FULL_SHARD_CONF_HASH);
    }

    /// Epoch zero is a valid, occupied genesis epoch: g and I are zero words (absent), and only the entry's present word says it exists.
    function test_aZeroGenesisEpochIsOccupiedByItsPresentWord() public view {
        B1GenesisParams memory p = genesisParams();
        p.rootEpoch = 0;
        p.entry.epoch = 0;
        B1Word[] memory ws = _build(p);
        bool present;
        for (uint256 i = 0; i < ws.length; i++) {
            assertTrue(ws[i].slot != fixedSlot("b1.genesisEpoch"), "g = 0 is an absent word");
            assertTrue(ws[i].slot != fixedSlot("b1.importedTipEpoch"), "I = 0 is an absent word");
            if (ws[i].slot == eSlot(0, 0)) present = ws[i].value == bytes32(uint256(1));
        }
        assertTrue(present, "the entry for epoch 0 says it is present");
    }

    function test_aGenesisEntryOfSixteenMaximalMembersIsAccepted() public {
        B1GenesisParams memory p = genesisParams();
        p.entry.members = new B1Member[](16);
        for (uint256 j = 0; j < 16; j++) {
            p.entry.members[j] = member(0xA0, uint8(j));
        }
        assertEq(_build(p).length, 6 + 6 + 8 + nonZeroMemberWords(p.entry.members));
        // and it installs, and the registry's own storage view agrees
        B1Word[] memory ws = _build(p);
        for (uint256 i = 0; i < ws.length; i++) {
            vm.store(A_SR, ws[i].slot, ws[i].value);
        }
        assertEq(memW(ROOT_EPOCH, 15, 7), bytes32(uint256(member(0xA0, 15).weight)));
    }

    // ---------------------------------------------------------------- profile bounds

    function test_deltaEvMustBeBelowDeltaHoldAndBMustBePositive() public {
        B1GenesisParams memory hold = genesisParams();
        hold.deltaHold = hold.deltaEv; // delta_ev < delta_hold is strict
        _expectRefusal(hold, ProfileBounds.selector);

        B1GenesisParams memory inverted = genesisParams();
        inverted.deltaHold = inverted.deltaEv - 1;
        _expectRefusal(inverted, ProfileBounds.selector);

        B1GenesisParams memory zero = genesisParams();
        zero.maxEpochsPerUpdate = 0;
        _expectRefusal(zero, ProfileBounds.selector);
    }

    function test_measuredBCapIsAcceptedAndNextBIsRefusedDespiteAmpleGas() public {
        // The largest actual-call fixture is explicitly B = 2, not a budget-derived limit.
        assertEq(builder.MAX_MEASURED_B(), 2);
        B1GenesisParams memory p = genesisParams();
        p.maxEpochsPerUpdate = 2;
        p.gRest = builder.gRestBound(2);
        p.gSys = builder.minGSys(2, p.gRest);
        _build(p);

        p.maxEpochsPerUpdate = 3; // every other profile and entry check still passes
        p.gRest = 10 ** 30;
        p.gSys = 10 ** 40;
        _expectRefusal(p, UnmeasuredB.selector);
    }

    function testFuzz_unmeasuredBIsRefusedDespiteAmpleGas(uint64 b) public {
        B1GenesisParams memory p = genesisParams();
        p.maxEpochsPerUpdate = uint64(bound(b, 3, type(uint64).max));
        p.gRest = 10 ** 30;
        p.gSys = 10 ** 40;
        _expectRefusal(p, UnmeasuredB.selector);
    }

    // ---------------------------------------------------------------- gas envelope

    function test_minGSysIsTheSpecifiedEnvelope() public view {
        // B = 1: 155936 + (505244 + 177800*16) = 3,505,980, the contract's planning cross-check at N = 16
        assertEq(builder.minGSys(1, 0), 3_505_980);
        assertEq(builder.minGSys(1, 12_345), 3_505_980 + 12_345);
        // B = 2: 155936 + 2*(505244 + 177800*16)
        assertEq(builder.minGSys(2, 0), 155_936 + 2 * (505_244 + 177_800 * 16));
    }

    function test_gSysBelowTheEnvelopeIsRefusedAndAtTheEnvelopeAccepted() public {
        B1GenesisParams memory p = genesisParams();
        _build(p); // gSys == minGSys is accepted
        p.gSys -= 1;
        _expectRefusal(p, GasEnvelopeShort.selector);
    }

    function test_gRestBelowTheFrozenBoundIsRefused() public {
        B1GenesisParams memory p = genesisParams();
        p.gRest -= 1; // below the measured-plus-margin allowance
        p.gSys = builder.minGSys(maxEpochsFixture, p.gRest); // consistent g_sys for the lower G_rest
        _expectRefusal(p, GasEnvelopeShort.selector);
    }

    // ---------------------------------------------------------------- the genesis entry

    function test_theGenesisEntryMustBeTheOpenIntervalOfTheRootGenesisEpoch() public {
        B1GenesisParams memory epoch = genesisParams();
        epoch.entry.epoch = ROOT_EPOCH + 1;
        _expectRefusal(epoch, GenesisEntryInvalid.selector);

        B1GenesisParams memory closed = genesisParams();
        closed.entry.hasEnd = true;
        closed.entry.end = 9;
        _expectRefusal(closed, GenesisEntryInvalid.selector);
    }

    function test_theGenesisEntryObeysTheRuntimeShapeRules() public {
        B1GenesisParams memory active = genesisParams();
        active.entry.activationCommitID = keccak256("not genesis");
        _expectRefusal(active, ZeroIdentity.selector);

        B1GenesisParams memory body = genesisParams();
        body.entry.bodyID = bytes32(0);
        _expectRefusal(body, ZeroIdentity.selector);

        B1GenesisParams memory config = genesisParams();
        config.entry.signingConfigHash = bytes32(0);
        _expectRefusal(config, ZeroIdentity.selector);

        B1GenesisParams memory none = genesisParams();
        none.entry.members = new B1Member[](0);
        _expectRefusal(none, BadMemberCount.selector);

        B1GenesisParams memory many = genesisParams();
        many.entry.members = members(17, 0xA0);
        _expectRefusal(many, BadMemberCount.selector);

        B1GenesisParams memory id = genesisParams();
        id.entry.members[0].nodeIDLength = 0;
        _expectRefusal(id, BadNodeID.selector);

        B1GenesisParams memory order = genesisParams();
        order.entry.members[1] = order.entry.members[0];
        _expectRefusal(order, NodeIDsNotSorted.selector);

        B1GenesisParams memory key = genesisParams();
        key.entry.members[0].key[0] = bytes32(uint256(0x04) << 248);
        _expectRefusal(key, BadCompressedKey.selector);

        B1GenesisParams memory weight = genesisParams();
        weight.entry.members[0].weight = 0;
        _expectRefusal(weight, BadWeight.selector);
    }
}
