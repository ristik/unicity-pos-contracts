// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: contract licensing is an explicit owner decision (bft-core #1), not a default.
pragma solidity 0.8.37;

// B1 permanent registry (design: briefs/b1-any-age-by-signatures.md, contract: briefs/b1-any-age-contract.md section 1). Every installed
// validator epoch is kept forever: no window, no ring, no pruning, no deletion. Shared by the SealRegistry runtime and the genesis builder
// so that both apply identical shape rules. The state machine mirrors bft-core b1state.Registry.Apply, one error per Go sentinel.

/// The stored cursors or tip are not a well-formed permanent registry (an impossible admitted state), or an update that would leave no
/// open tip.
error B1StateInvalid();
/// The update's prior tip epoch is not the imported tip I.
error PriorTipMismatch();
/// oldTipEnd is present without new entries, absent with them, or not the first new entry's start.
error OldTipEndMismatch();
/// An interval is empty, or an end/hasEnd pair is non-canonical.
error InvalidInterval();
/// An append is not the successor of the imported tip (ErrAppendGap).
error AppendGap();
/// Epochs inside the update are not consecutive, or an end is not the next start.
error NonContiguousEpochs();
/// A new entry is a genesis body, or its epoch would overflow (ErrHistory / ErrOverflow).
error BadAppend();
/// An installed entry cannot change: a replay differs in an immutable field (ErrImmutable).
error ImmutableEntry();
/// The successor's start does not exceed the tip's start (ErrAppendStartNotIncreasing).
error AppendStartNotIncreasing();
/// The successor's start would close the usable epoch at or below the origin round (ErrAppendClosesUsableOrigin).
error AppendClosesUsableOrigin();
/// An entry starts after the origin round, or ends after it.
error StartAfterOrigin();
/// The final open tip does not name the block's origin epoch.
error OriginEpochMismatch();
/// A new epoch is already present in storage.
error EntryAlreadyPresent();
/// The usable origin epoch moves backwards (ErrOriginEpochRegression).
error OriginEpochRegression();
/// The origin round moves backwards (ErrOriginRoundRegression).
error OriginRoundRegression();
/// The usable origin epoch is beyond the imported tip (ErrOriginBeyondImportedTip).
error OriginBeyondImportedTip();
/// The first usable origin epoch precedes the genesis epoch (ErrFirstOriginBeforeGenesis).
error FirstOriginBeforeGenesis();
/// The origin round precedes the usable epoch's start (ErrOriginBeforeStart).
error OriginBeforeStart();
/// The origin round is at or past the usable epoch's end (ErrOriginAtOrAfterEnd).
error OriginAtOrAfterEnd();
/// While a usable origin exists the usable epoch is the imported tip after every update (ErrImportedUsableMismatch).
error ImportedUsableMismatch();
/// An entry has no members or more than 16.
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
    uint256 internal constant MAX_MEMBERS = 16; // N_admit = N_verify = 16 (contract section 4): a populated entry above it is impossible state
    uint256 internal constant MAX_NODE_ID = 128;

    // Fixed words, F(name) = keccak256(UTF8("unicity.seal-registry/" || name)).
    bytes32 internal constant F_NETWORK = keccak256("unicity.seal-registry/b1.network");
    bytes32 internal constant F_FORMAT = keccak256("unicity.seal-registry/b1.format");
    bytes32 internal constant F_PROFILE_HASH = keccak256("unicity.seal-registry/b1.profileHash");
    bytes32 internal constant F_INITIALIZED = keccak256("unicity.seal-registry/b1.initialized");
    /// g: the first epoch admitted in this deployment (zero is a valid, occupied epoch).
    bytes32 internal constant F_GENESIS_EPOCH = keccak256("unicity.seal-registry/b1.genesisEpoch");
    /// I: the greatest contiguously installed epoch, the durable import cursor.
    bytes32 internal constant F_IMPORTED_TIP =
        keccak256("unicity.seal-registry/b1.importedTipEpoch");
    /// 0 before the first usable root origin, 1 thereafter.
    bytes32 internal constant F_ORIGIN_READY = keccak256("unicity.seal-registry/b1.originReady");
    bytes32 internal constant F_ENTRY = keccak256("unicity.seal-registry/b1.entry");
    bytes32 internal constant F_MEMBER = keccak256("unicity.seal-registry/b1.member");
    /// The registry format word: 2 is the permanent layout.
    uint256 internal constant FORMAT = 2;
    /// E(e, 11) caches C_e, the entry's trust commitment (B7 design §3): written with the entry, never rewritten.
    uint256 internal constant COMMITMENT_FIELD = 11;
    bytes32 internal constant COMMITMENT_DOMAIN =
        keccak256("unicity.seal-registry.v2/epoch-commitment");

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

    /// C_e = keccak256(COMMITMENT_DOMAIN || genesisCommitment || profileHash || epoch || the stored metadata words 0-4 and 7-10 ||
    /// the 8 stored words of every member, in order): bft-core `b1state.Deployment.EpochCommitment`. The closure words 5 and 6 are
    /// excluded, so closing the epoch does not change it. `total` is the checked total weight (stored word 10).
    ///
    /// A static B1Member is ABI-encoded as exactly its 8 stored words in stored order, so the members are hashed straight from
    /// calldata. Precondition: `checkEntry(en, ...)` has run, which reads every member field through the ABI decoder and so refuses a
    /// uint64 word with dirty high bits before this raw copy could hash it.
    function epochCommitment(
        bytes32 genesisCommitment,
        bytes32 profileHash,
        B1Entry calldata en,
        uint256 total
    ) internal pure returns (bytes32 c) {
        B1Member[] calldata ms = en.members;
        bytes32 domain = COMMITMENT_DOMAIN;
        uint256 epoch = en.epoch;
        uint256 bodyKind = en.bodyKind;
        bytes32 bodyID = en.bodyID;
        bytes32 activation = en.activationCommitID;
        uint256 start = en.start;
        uint256 scheme = en.signingScheme;
        bytes32 signing = en.signingConfigHash;
        assembly ("memory-safe") {
            // Temporary words above the free pointer, never kept (as in entrySlot).
            let p := mload(0x40)
            mstore(p, domain)
            mstore(add(p, 0x20), genesisCommitment)
            mstore(add(p, 0x40), profileHash)
            mstore(add(p, 0x60), epoch)
            mstore(add(p, 0x80), 1) // present
            mstore(add(p, 0xa0), bodyKind)
            mstore(add(p, 0xc0), bodyID)
            mstore(add(p, 0xe0), activation)
            mstore(add(p, 0x100), start)
            mstore(add(p, 0x120), scheme)
            mstore(add(p, 0x140), signing)
            mstore(add(p, 0x160), ms.length)
            mstore(add(p, 0x180), total)
            let n := mul(ms.length, 0x100)
            calldatacopy(add(p, 0x1a0), ms.offset, n)
            c := keccak256(p, add(0x1a0, n))
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
