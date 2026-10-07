// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: contract licensing is an explicit owner decision (bft-core #1), not a default.
pragma solidity 0.8.37;

// B1 #62 pruned authenticated registry history (design: briefs/b1-design-v4.md, "A'"). Shared by
// the SealRegistry runtime and the genesis builder so that both apply identical shape rules.

/// The parent queue, count or tail is not a well-formed live set (an impossible admitted state, or an
/// update that would leave no open tail).
error B1StateInvalid();
/// The update's prior tip epoch is not the stored tail epoch.
error PriorTipMismatch();
/// oldTipEnd is present without new entries, absent with them, or non-canonically zero.
error OldTipEndMismatch();
/// An interval is empty, or an end/hasEnd pair is non-canonical.
error InvalidInterval();
/// More new entries than the ring has slots (K_max = W_cert + 1).
error TooManyEntries();
/// The survivors plus the new entries exceed K_max.
error RingFull();
/// Epochs are not consecutive, or an end is not the next start.
error NonContiguousEpochs();
/// A new entry would be expired at insertion (closed with end <= L).
error ExpiredEntry();
/// An entry starts after the origin round, or the first new entry leaves a gap at L.
error StartAfterOrigin();
/// The final open tail does not name the block's origin epoch.
error OriginEpochMismatch();
/// A new epoch is already present in storage.
error EntryAlreadyPresent();
/// An entry has no members or more than 64.
error BadMemberCount();
/// A node ID is empty, longer than 128 bytes or has non-zero padding.
error BadNodeID();
/// Members are not in strictly increasing raw node-ID order (this also refuses duplicates).
error NodeIDsNotSorted();
/// A compressed key is not a 33-byte value with prefix 02 or 03, or has non-zero padding.
error BadCompressedKey();
/// A member weight is zero or the weight total overflows u64.
error BadWeight();
/// A body, activation or signing-configuration identity that must be non-zero is zero, or a genesis
/// activation identity is not zero.
error ZeroIdentity();

struct B1Member {
    uint64 nodeIDLength;
    bytes32[4] nodeID; // wire order, left-aligned, zero right padding
    bytes32[2] key; // key[0] bytes 0..31, key[1] byte 0 is wire byte 32, remaining bytes zero
    uint64 weight;
}

struct B1Entry {
    uint64 epoch;
    uint64 bodyKind;
    bytes32 bodyID;
    bytes32 activationCommitID;
    uint64 start;
    bool hasEnd;
    uint64 end;
    uint64 signingScheme;
    bytes32 signingConfigHash;
    B1Member[] members;
}

/// The projection of the authenticated Update that is not already an operational open() argument:
/// the origin round, epoch, identity and block number are the open() arguments themselves.
struct B1Update {
    uint64 priorTipEpoch;
    bool hasOldTipEnd;
    uint64 oldTipEnd;
    B1Entry[] newEntries;
}

library B1Layout {
    uint256 internal constant ENTRY_FIELDS = 11;
    uint256 internal constant MEMBER_FIELDS = 8;
    uint256 internal constant MAX_MEMBERS = 64;
    uint256 internal constant MAX_NODE_ID = 128;

    // Fixed words, F(name) = keccak256(UTF8("unicity.seal-registry/" || name)).
    bytes32 internal constant F_NETWORK = keccak256("unicity.seal-registry/b1.network");
    bytes32 internal constant F_W_CERT = keccak256("unicity.seal-registry/b1.wCert");
    bytes32 internal constant F_PROFILE_HASH = keccak256("unicity.seal-registry/b1.profileHash");
    bytes32 internal constant F_INITIALIZED = keccak256("unicity.seal-registry/b1.initialized");
    bytes32 internal constant F_HEAD = keccak256("unicity.seal-registry/b1.head");
    bytes32 internal constant F_COUNT = keccak256("unicity.seal-registry/b1.count");
    bytes32 internal constant F_QUEUE = keccak256("unicity.seal-registry/b1.queue");
    bytes32 internal constant F_ENTRY = keccak256("unicity.seal-registry/b1.entry");
    bytes32 internal constant F_MEMBER = keccak256("unicity.seal-registry/b1.member");

    /// Q(i) = keccak256(abi.encode(F("b1.queue"), uint256(i))): the epoch stored at ring index i.
    function queueSlot(uint256 i) internal pure returns (bytes32 slot) {
        bytes32 f = F_QUEUE;
        assembly ("memory-safe") {
            mstore(0x00, f) // scratch space: no allocation, so no memory growth over a long update
            mstore(0x20, i)
            slot := keccak256(0x00, 0x40)
        }
    }

    /// E(e,f) = keccak256(abi.encode(F("b1.entry"), uint256(e), uint256(f))), f = 0..10:
    /// present, bodyKind, bodyID, activationCommitID, start, end, hasEnd, signingScheme,
    /// signingConfigHash, memberCount, totalWeight.
    function entrySlot(uint256 e, uint256 f) internal pure returns (bytes32 slot) {
        bytes32 prefix = F_ENTRY;
        assembly ("memory-safe") {
            // Temporary words above the free pointer, never kept: the free pointer is not moved, so
            // memory does not grow with the number of slots an update touches.
            let p := mload(0x40)
            mstore(p, prefix)
            mstore(add(p, 0x20), e)
            mstore(add(p, 0x40), f)
            slot := keccak256(p, 0x60)
        }
    }

    /// M(e,j,f) = keccak256(abi.encode(F("b1.member"), uint256(e), uint256(j), uint256(f))), f = 0..7:
    /// nodeIDLength, nodeID words 0..3, key words 0..1, weight.
    function memberSlot(uint256 e, uint256 j, uint256 f) internal pure returns (bytes32 slot) {
        bytes32 prefix = F_MEMBER;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, prefix)
            mstore(add(p, 0x20), e)
            mstore(add(p, 0x40), j)
            mstore(add(p, 0x60), f)
            slot := keccak256(p, 0x80)
        }
    }

    /// The shape rules shared by every entry, whether it enters at genesis or through an update.
    /// Returns the checked total weight. Signature, key-point and lineage semantics are verified by
    /// the paired Go node and the Rust execution client, not here.
    function checkEntry(B1Entry calldata en, bool genesis) internal pure returns (uint64 total) {
        if (en.bodyID == 0 || en.signingConfigHash == 0) revert ZeroIdentity();
        if (genesis != (en.activationCommitID == 0)) revert ZeroIdentity();
        if (en.hasEnd) {
            if (en.end <= en.start) revert InvalidInterval();
        } else if (en.end != 0) {
            revert InvalidInterval();
        }
        uint256 m = en.members.length;
        if (m == 0 || m > MAX_MEMBERS) revert BadMemberCount();
        for (uint256 j = 0; j < m; j++) {
            B1Member calldata mem = en.members[j];
            _checkNodeID(mem);
            // Prefix 02 or 03; wire byte 32 is the top byte of key[1] and the rest of it is padding.
            if ((uint8(mem.key[0][0]) | 1) != 3 || uint256(mem.key[1]) << 8 != 0) {
                revert BadCompressedKey();
            }
            uint256 sum = uint256(total) + mem.weight;
            if (mem.weight == 0 || sum > type(uint64).max) revert BadWeight();
            // forge-lint: disable-next-line(unsafe-typecast)
            total = uint64(sum); // sum <= type(uint64).max was just checked
            if (j != 0 && !_lessThan(en.members[j - 1], mem)) revert NodeIDsNotSorted();
        }
    }

    function _checkNodeID(B1Member calldata mem) private pure {
        uint256 len = mem.nodeIDLength;
        if (len == 0 || len > MAX_NODE_ID) revert BadNodeID();
        for (uint256 w = 0; w < 4; w++) {
            uint256 used = len > 32 * w ? len - 32 * w : 0;
            if (used > 32) used = 32;
            // Bytes at and beyond `used` in this word must be zero.
            if (uint256(mem.nodeID[w]) & (type(uint256).max >> (8 * used)) != 0) {
                revert BadNodeID();
            }
        }
    }

    /// Lexicographic order on raw node-ID bytes: zero-padded words compare as big-endian integers,
    /// and equal padded words are ordered by length (a proper prefix sorts first).
    function _lessThan(B1Member calldata a, B1Member calldata b) private pure returns (bool) {
        for (uint256 w = 0; w < 4; w++) {
            if (a.nodeID[w] != b.nodeID[w]) return a.nodeID[w] < b.nodeID[w];
        }
        return a.nodeIDLength < b.nodeIDLength;
    }
}
