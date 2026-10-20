// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: contract licensing is an explicit owner decision (bft-core #1), not a default.
pragma solidity 0.8.37;

/// @title B7Relation
/// @notice The proof-system-independent interface of the B7 succinct redemption fallback (bft-core `b7rel`, design
///         briefs/b7-succinct-fallback-design.md steps 1 and 2): the candidate limits and the relation ID, the per-epoch registry
///         commitment C_e, and the canonical public journal. The Go reference produces `test/b7/fixtures/b7-relation-vectors-v1.json`.
///         Nothing here verifies a proof or redeems; the succinct adapter (step 4) builds on it.
library B7Relation {
    error JournalMalformed();
    /// The member words are not 8 per member.
    error MemberWordsMalformed();

    // ---- candidate limits (design §5): benchmark targets, not measured capacity; they define the relation ID ---------------
    uint256 internal constant MAX_LEAVES = 1024;
    uint256 internal constant MAX_TRANSFERS = 1023;
    uint256 internal constant MAX_EPOCHS = 64;
    uint256 internal constant MAX_ANCHORS = 1024;
    uint256 internal constant MAX_SEMANTIC_BYTES = 1 << 20;
    uint256 internal constant MAX_WITNESS_BYTES = 16 << 20;
    uint256 internal constant MAX_MEMBERS_PER_EPOCH = 16;
    uint256 internal constant MAX_RSMT_SIBLINGS = 32;

    bytes32 internal constant RELATION_DOMAIN = keccak256("unicity.b7.relation.v1");
    bytes32 internal constant COMMITMENT_DOMAIN =
        keccak256("unicity.seal-registry.v2/epoch-commitment");
    bytes32 internal constant JOURNAL_DOMAIN = keccak256("unicity.b7.journal.v1");

    uint256 private constant HEADER_WORDS = 16;
    uint256 private constant EPOCH_USE_WORDS = 4;

    /// @notice keccak256(RELATION_DOMAIN || the limits as words, in declaration order).
    function relationId() internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                RELATION_DOMAIN,
                MAX_LEAVES,
                MAX_TRANSFERS,
                MAX_EPOCHS,
                MAX_ANCHORS,
                MAX_SEMANTIC_BYTES,
                MAX_WITNESS_BYTES,
                MAX_MEMBERS_PER_EPOCH,
                MAX_RSMT_SIBLINGS
            )
        );
    }

    /// @notice C_e over an entry's stored words: keccak256(COMMITMENT_DOMAIN || genesisCommitment || profileHash || epoch ||
    ///         metadata words 0-4 and 7-10 || every member's 8 words in order). The closure words 5 and 6 (end, hasEnd) are
    ///         excluded, so C_e does not change when the epoch closes. `members` is the flat list of 8 words per member.
    function epochCommitment(
        bytes32 genesisCommitment,
        bytes32 profileHash,
        uint64 epoch,
        bytes32[11] memory metadata,
        bytes32[] memory members
    ) internal pure returns (bytes32) {
        if (members.length % 8 != 0) revert MemberWordsMalformed();
        bytes memory head = abi.encode(
            COMMITMENT_DOMAIN,
            genesisCommitment,
            profileHash,
            uint256(epoch),
            metadata[0],
            metadata[1],
            metadata[2],
            metadata[3],
            metadata[4],
            metadata[7],
            metadata[8],
            metadata[9],
            metadata[10]
        );
        return keccak256(bytes.concat(head, abi.encodePacked(members)));
    }

    /// @notice The kernel result fields the vault consumes (the direct path's KernelResult without its leaves).
    struct Release {
        bytes32 cfg;
        uint256 nonce;
        uint256 amount;
        bytes32 tokenId;
        bytes32 salt;
        bytes32 firstPredicateHash;
        bytes32 lockDigest;
        address releaseTo;
        bytes32 nullifier;
    }

    struct EpochUse {
        uint64 epoch;
        bytes32 commitment;
        uint64 minRound;
        uint64 maxRound;
    }

    struct Journal {
        bytes32 relationId;
        uint256 chainId;
        bytes32 genesisCommitment;
        bytes32 profileHash;
        bytes32 witnessCommitment;
        Release release;
        EpochUse[] epochs;
    }

    function _word(bytes calldata b, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := calldataload(add(b.offset, mul(i, 32)))
        }
    }

    function _u64(bytes calldata b, uint256 i) private pure returns (uint64) {
        uint256 v = uint256(_word(b, i));
        if (v > type(uint64).max) revert JournalMalformed();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(v);
    }

    /// @notice Decodes the canonical journal and refuses anything else (JournalMalformed): the domain word; an epoch count in
    ///         1..MAX_EPOCHS that matches the length exactly; zero high bytes in the address and every uint64 field; epochs
    ///         strictly ascending; minRound <= maxRound.
    function decodeJournal(bytes calldata b) internal pure returns (Journal memory j) {
        if (b.length < 32 * HEADER_WORDS || b.length % 32 != 0) revert JournalMalformed();
        if (_word(b, 0) != JOURNAL_DOMAIN) revert JournalMalformed();
        uint256 n = _u64(b, 15);
        if (n == 0 || n > MAX_EPOCHS || b.length != 32 * (HEADER_WORDS + EPOCH_USE_WORDS * n)) {
            revert JournalMalformed();
        }
        uint256 to = uint256(_word(b, 13));
        if (to >> 160 != 0) revert JournalMalformed();
        j.relationId = _word(b, 1);
        j.chainId = uint256(_word(b, 2));
        j.genesisCommitment = _word(b, 3);
        j.profileHash = _word(b, 4);
        j.witnessCommitment = _word(b, 5);
        j.release = Release({
            cfg: _word(b, 6),
            nonce: uint256(_word(b, 7)),
            amount: uint256(_word(b, 8)),
            tokenId: _word(b, 9),
            salt: _word(b, 10),
            firstPredicateHash: _word(b, 11),
            lockDigest: _word(b, 12),
            // forge-lint: disable-next-line(unsafe-typecast)
            releaseTo: address(uint160(to)),
            nullifier: _word(b, 14)
        });
        j.epochs = new EpochUse[](n);
        for (uint256 i = 0; i < n; ++i) {
            uint256 base = HEADER_WORDS + i * EPOCH_USE_WORDS;
            EpochUse memory u = EpochUse({
                epoch: _u64(b, base),
                commitment: _word(b, base + 1),
                minRound: _u64(b, base + 2),
                maxRound: _u64(b, base + 3)
            });
            if (u.minRound > u.maxRound) revert JournalMalformed();
            if (i > 0 && u.epoch <= j.epochs[i - 1].epoch) revert JournalMalformed();
            j.epochs[i] = u;
        }
    }
}
