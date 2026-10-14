// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: contract licensing is an explicit owner decision (bft-core #1), not a default.
pragma solidity 0.8.37;

import {B1Layout, B1Entry} from "./B1Layout.sol";

/// delta_ev < delta_hold does not hold, or B is zero.
error ProfileBounds();
/// B (epochs imported per block) exceeds the largest maximal actual-call gas fixture; a larger budget does not admit it.
error UnmeasuredB();
/// The profile's g_sys does not cover the conservative registry envelope for its B.
error GasEnvelopeShort();
/// The genesis entry is not the open interval of the root genesis epoch.
error GenesisEntryInvalid();

struct B1GenesisParams {
    bytes32 genesisCommitment;
    bytes32 shardConfHash;
    uint64 shardEpoch;
    uint64 rootEpoch;
    // The pinned genesis UC time: records.ucTime before any import.
    uint64 genesisUcTime;
    uint16 network;
    // B: the most validator epochs one block imports (the profile's MaxEpochsPerUpdate). Not a registry word: the paired verifier and
    // the system-call gas enforce it. Used here only for the gas envelope.
    uint64 maxEpochsPerUpdate;
    uint64 deltaEv;
    uint64 deltaHold;
    bytes32 profileHash;
    uint256 gSys;
    uint256 gRest;
    B1Entry entry;
}

struct B1Word {
    bytes32 slot;
    bytes32 value;
}

/// @notice Builds the registry's genesis storage under the same bounds as a runtime update. It is a
/// build-time helper for genesis tooling and tests; it is not part of the registry runtime code and
/// is never deployed on chain. It takes calldata so that the genesis entry passes through the very
/// function (B1Layout.checkEntry) that checks runtime entries. Zero words are absent from a genesis
/// allocation, so only non-zero words are returned.
contract B1GenesisBuilder {
    /// Largest B exercised by maximal actual-call fixtures; raising it requires re-measurement.
    uint256 public constant MAX_MEASURED_B = 2;

    /// Measured-plus-margin allowance for the pinned runtime (docs/b1-registry-gas.md): every cost of a maximal open+finalize other
    /// than the history SSTOREs the rectangle covers, for B imported epochs of the 16-member ceiling. Coefficients are fitted from the
    /// maximal actual-call fixtures at B = 1 and 2 with a 1.5x safety factor, not a proof.
    uint256 public constant G_REST_BASE = 1_150_000;
    uint256 public constant G_REST_PER_EPOCH = 250_000;

    function gRestBound(uint256 b) public pure returns (uint256) {
        return G_REST_BASE + G_REST_PER_EPOCH * b;
    }

    /// g_sys >= 155936 + (505244 + 177800*16)*B + G_rest(B): the full-entry write rectangle for B epochs at the 16-member ceiling (11 + 8N
    /// words per entry, one predecessor closure, cursors) plus the measured rest. A conservative rectangle, not an attainable cost.
    function minGSys(uint256 b, uint256 gRest) public pure returns (uint256) {
        return 155_936 + (505_244 + 177_800 * 16) * b + gRest;
    }

    function words(B1GenesisParams calldata p) external pure returns (B1Word[] memory out) {
        if (p.maxEpochsPerUpdate == 0 || p.deltaEv >= p.deltaHold) revert ProfileBounds();
        uint256 b = p.maxEpochsPerUpdate;
        if (b > MAX_MEASURED_B) revert UnmeasuredB();
        if (p.gRest < gRestBound(b) || p.gSys < minGSys(b, p.gRest)) revert GasEnvelopeShort();
        B1Entry calldata en = p.entry;
        if (en.epoch != p.rootEpoch || en.hasEnd) revert GenesisEntryInvalid();
        uint64 total = B1Layout.checkEntry(en, true);

        uint256 m = en.members.length;
        out = new B1Word[](16 + 11 + 8 * m);
        uint256 n = 0;
        // Operational words, re-exported under the single layout (no layoutVersion word).
        n = _put(out, n, _name("genesisCommitment"), p.genesisCommitment);
        n = _put(out, n, _name("config.shardConfHash"), p.shardConfHash);
        n = _put(out, n, _name("assignment.epoch"), bytes32(uint256(p.shardEpoch)));
        n = _put(out, n, _name("assignment.rootEpoch"), bytes32(uint256(p.rootEpoch)));
        n = _put(out, n, _name("assignment.activeConfHash"), p.shardConfHash);
        n = _put(out, n, _name("records.ucTime"), bytes32(uint256(p.genesisUcTime)));
        n = _put(out, n, _name("phase"), bytes32(uint256(2)));
        // B1 immutable and mutable words.
        n = _put(out, n, B1Layout.F_NETWORK, bytes32(uint256(p.network)));
        n = _put(out, n, B1Layout.F_FORMAT, bytes32(B1Layout.FORMAT));
        n = _put(out, n, B1Layout.F_PROFILE_HASH, p.profileHash);
        n = _put(out, n, B1Layout.F_INITIALIZED, bytes32(uint256(1)));
        // g and I are both the genesis epoch (a zero epoch is an absent word, and a valid occupied epoch: the entry's present word, not
        // these, distinguishes it); originReady is 0 and so absent, and the operational origin epoch and round are 0 until the first origin.
        n = _put(out, n, B1Layout.F_GENESIS_EPOCH, bytes32(uint256(en.epoch)));
        n = _put(out, n, B1Layout.F_IMPORTED_TIP, bytes32(uint256(en.epoch)));
        uint256 e = en.epoch;
        n = _put(out, n, B1Layout.entrySlot(e, 0), bytes32(uint256(1)));
        n = _put(out, n, B1Layout.entrySlot(e, 1), bytes32(uint256(en.bodyKind)));
        n = _put(out, n, B1Layout.entrySlot(e, 2), en.bodyID);
        // f=3 activationCommitID, f=5 end and f=6 hasEnd are zero at genesis.
        n = _put(out, n, B1Layout.entrySlot(e, 4), bytes32(uint256(en.start)));
        n = _put(out, n, B1Layout.entrySlot(e, 7), bytes32(uint256(en.signingScheme)));
        n = _put(out, n, B1Layout.entrySlot(e, 8), en.signingConfigHash);
        n = _put(out, n, B1Layout.entrySlot(e, 9), bytes32(m));
        n = _put(out, n, B1Layout.entrySlot(e, 10), bytes32(uint256(total)));
        for (uint256 j = 0; j < m; j++) {
            n = _put(
                out, n, B1Layout.memberSlot(e, j, 0), bytes32(uint256(en.members[j].nodeIDLength))
            );
            for (uint256 w = 0; w < 4; w++) {
                n = _put(out, n, B1Layout.memberSlot(e, j, 1 + w), en.members[j].nodeID[w]);
            }
            n = _put(out, n, B1Layout.memberSlot(e, j, 5), en.members[j].key[0]);
            n = _put(out, n, B1Layout.memberSlot(e, j, 6), en.members[j].key[1]);
            n = _put(out, n, B1Layout.memberSlot(e, j, 7), bytes32(uint256(en.members[j].weight)));
        }
        assembly ("memory-safe") {
            mstore(out, n) // trim the unused tail: zero words are not allocated
        }
    }

    function _name(string memory name) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("unicity.seal-registry/", name));
    }

    function _put(B1Word[] memory out, uint256 n, bytes32 slot, bytes32 value)
        private
        pure
        returns (uint256)
    {
        if (value == 0) return n;
        out[n] = B1Word(slot, value);
        return n + 1;
    }
}
