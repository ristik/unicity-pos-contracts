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
    UnmeasuredKMax,
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
        // absent) + 6 profile/queue (network, wCert, profileHash, initialized, count, queue[0] = 1)
        // + 8 entry metadata (activationCommitID, end, hasEnd are zero) + the non-zero member words.
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
        0x7f69338f0f9ebc1140fb3c43c3f21ea570c8c61f8abe3038f53a3ee5033cb065;

    function test_theInstalledGenesisRoundTripsThroughTheIndependentReaders() public view {
        assertEntryStored(genesisEntry(), 8);
        assertEq(b1Word("b1.network"), NETWORK);
        assertEq(b1Word("b1.count"), 1);
        assertEq(queueAt(0), ROOT_EPOCH);
        assertEq(uintWord("phase"), 2);
        assertEq(word("assignment.activeConfHash"), FULL_SHARD_CONF_HASH);
    }

    function test_aGenesisEntryOfSixtyFourMaximalMembersIsAccepted() public {
        B1GenesisParams memory p = genesisParams();
        p.entry.members = new B1Member[](64);
        for (uint256 j = 0; j < 64; j++) {
            p.entry.members[j] = member(0xA0, uint8(j));
        }
        assertEq(_build(p).length, 6 + 6 + 8 + nonZeroMemberWords(p.entry.members));
        // and it installs, and the registry's own storage view agrees
        B1Word[] memory ws = _build(p);
        for (uint256 i = 0; i < ws.length; i++) {
            vm.store(A_SR, ws[i].slot, ws[i].value);
        }
        assertEq(memW(ROOT_EPOCH, 63, 7), bytes32(uint256(member(0xA0, 63).weight)));
    }

    // ---------------------------------------------------------------- profile bounds

    function test_wCertMustNotExceedDeltaEvAndDeltaEvMustBeBelowDeltaHold() public {
        B1GenesisParams memory p = genesisParams();
        p.wCert = p.deltaEv; // equality is allowed: W_cert <= delta_ev
        p.gRest = builder.gRestBound(uint256(p.wCert) + 1);
        p.gSys = builder.minGSys(uint256(p.wCert) + 1, p.gRest);
        _build(p);

        B1GenesisParams memory over = genesisParams();
        over.wCert = over.deltaEv + 1;
        _expectRefusal(over, ProfileBounds.selector);

        B1GenesisParams memory hold = genesisParams();
        hold.deltaHold = hold.deltaEv; // delta_ev < delta_hold is strict
        _expectRefusal(hold, ProfileBounds.selector);

        B1GenesisParams memory inverted = genesisParams();
        inverted.deltaHold = inverted.deltaEv - 1;
        _expectRefusal(inverted, ProfileBounds.selector);
    }

    function test_kMaxMustNotOverflow() public {
        B1GenesisParams memory p = genesisParams();
        p.wCert = type(uint64).max;
        p.deltaEv = type(uint64).max;
        p.deltaHold = type(uint64).max;
        _expectRefusal(p, ProfileBounds.selector);
    }

    function test_measuredKCapIsAcceptedAndNextKIsRefusedDespiteAmpleGas() public {
        // The largest actual-call fixture is explicitly K = 16, not a budget-derived limit.
        assertEq(builder.MAX_MEASURED_K(), 16);
        B1GenesisParams memory p = genesisParams();
        p.wCert = 15;
        p.deltaEv = 16;
        p.deltaHold = 17;
        p.gRest = builder.gRestBound(16);
        p.gSys = builder.minGSys(16, p.gRest);
        _build(p);

        p.wCert = 16; // K = 17; every other profile and entry check still passes
        p.gRest = 10 ** 30;
        p.gSys = 10 ** 40;
        _expectRefusal(p, UnmeasuredKMax.selector);
    }

    function testFuzz_unmeasuredKIsRefusedDespiteAmpleGas(uint64 wCert) public {
        B1GenesisParams memory p = genesisParams();
        p.wCert = uint64(bound(wCert, 16, type(uint64).max - 1));
        p.deltaEv = p.wCert;
        p.deltaHold = p.wCert + 1;
        p.gRest = 10 ** 30;
        p.gSys = 10 ** 40;
        _expectRefusal(p, UnmeasuredKMax.selector);
    }

    // ---------------------------------------------------------------- gas envelope

    function test_minGSysIsTheSpecifiedEnvelope() public view {
        // K = 1: 67536 + 326144 + 22100*528 + 7100*524 + G_rest
        assertEq(builder.minGSys(1, 0), 15_782_880);
        assertEq(builder.minGSys(1, 12_345), 15_782_880 + 12_345);
        // K = 4: 67536 + 4*326144 + 22100*(524*4+4) + 7100*524*4 + G_rest
        assertEq(builder.minGSys(4, 0), 67_536 + 1_304_576 + 22_100 * 2100 + 7100 * 2096);
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
        p.gSys = builder.minGSys(kMax(), p.gRest); // consistent g_sys for the lower G_rest
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
        many.entry.members = members(65, 0xA0);
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
