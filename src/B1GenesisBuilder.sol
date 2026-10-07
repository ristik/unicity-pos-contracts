// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: contract licensing is an explicit owner decision (bft-core #1), not a default.
pragma solidity 0.8.37;

import {B1Layout, B1Entry} from "./B1Layout.sol";

/// W_cert <= delta_ev < delta_hold does not hold, or W_cert + 1 overflows.
error ProfileBounds();
/// The profile's g_sys does not cover the conservative registry envelope for its K_max.
error GasEnvelopeShort();
/// The genesis entry is not the open interval of the root genesis epoch.
error GenesisEntryInvalid();

struct B1GenesisParams {
    bytes32 genesisCommitment;
    bytes32 shardConfHash;
    uint64 shardEpoch;
    uint64 rootEpoch;
    uint16 network;
    uint64 wCert;
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
    /// Frozen bound on G_rest(K_max, C_max) for the pinned runtime (docs/b1-registry-gas.md): every
    /// cost of a maximal open+finalize other than the history SSTOREs the rectangle covers. Linear in
    /// the entries inserted (a) and deleted (p); a <= K_max and p <= K_max, so the worst case is
    /// base + (perInsert + perDelete) * K_max.
    uint256 public constant G_REST_BASE = 1_000_000;
    uint256 public constant G_REST_PER_INSERT = 800_000;
    uint256 public constant G_REST_PER_DELETE = 200_000;
    uint256 public constant G_REST_PER_ENTRY = G_REST_PER_INSERT + G_REST_PER_DELETE;

    function gRestFor(uint256 inserted, uint256 deleted) public pure returns (uint256) {
        return G_REST_BASE + G_REST_PER_INSERT * inserted + G_REST_PER_DELETE * deleted;
    }

    function gRestBound(uint256 kMax) public pure returns (uint256) {
        return G_REST_BASE + G_REST_PER_ENTRY * kMax;
    }

    /// g_sys >= 67536 + 326144*K + 22100*(524*K+4) + 7100*524*K + G_rest (design v4, realizable
    /// system metering). A conservative rectangle, not an attainable cost.
    function minGSys(uint256 kMax, uint256 gRest) public pure returns (uint256) {
        return 67_536 + 326_144 * kMax + 22_100 * (524 * kMax + 4) + 7100 * 524 * kMax + gRest;
    }

    function words(B1GenesisParams calldata p) external pure returns (B1Word[] memory out) {
        if (p.wCert > p.deltaEv || p.deltaEv >= p.deltaHold || p.wCert == type(uint64).max) {
            revert ProfileBounds();
        }
        uint256 kMax = uint256(p.wCert) + 1;
        if (p.gRest < gRestBound(kMax) || p.gSys < minGSys(kMax, p.gRest)) {
            revert GasEnvelopeShort();
        }
        B1Entry calldata en = p.entry;
        if (en.epoch != p.rootEpoch || en.hasEnd) revert GenesisEntryInvalid();
        uint64 total = B1Layout.checkEntry(en, true);

        uint256 m = en.members.length;
        out = new B1Word[](14 + 11 + 8 * m);
        uint256 n = 0;
        // Operational words, re-exported under the single layout (no layoutVersion word).
        n = _put(out, n, _name("genesisCommitment"), p.genesisCommitment);
        n = _put(out, n, _name("config.shardConfHash"), p.shardConfHash);
        n = _put(out, n, _name("assignment.epoch"), bytes32(uint256(p.shardEpoch)));
        n = _put(out, n, _name("assignment.rootEpoch"), bytes32(uint256(p.rootEpoch)));
        n = _put(out, n, _name("assignment.activeConfHash"), p.shardConfHash);
        n = _put(out, n, _name("phase"), bytes32(uint256(2)));
        // B1 immutable and mutable words.
        n = _put(out, n, B1Layout.F_NETWORK, bytes32(uint256(p.network)));
        n = _put(out, n, B1Layout.F_W_CERT, bytes32(uint256(p.wCert)));
        n = _put(out, n, B1Layout.F_PROFILE_HASH, p.profileHash);
        n = _put(out, n, B1Layout.F_INITIALIZED, bytes32(uint256(1)));
        n = _put(out, n, B1Layout.F_COUNT, bytes32(uint256(1)));
        // head = 0 is absent. Queue slot 0 holds the genesis epoch (a zero epoch is a present word:
        // count, not the word, distinguishes it from emptiness).
        n = _put(out, n, B1Layout.queueSlot(0), bytes32(uint256(en.epoch)));
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
