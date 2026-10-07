// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: contract licensing is an explicit owner decision (bft-core #1), not a default.
pragma solidity 0.8.37;

import {
    B1Layout,
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
    EntryAlreadyPresent
} from "./B1Layout.sol";

/// @title SealRegistry, profile sealRegistry/v2
/// @notice Fixed-profile registry of the imported root origin and certified round clock for the
/// enshrined EVM. Specification: bft-core docs/design/f4a-seal-registry-contract.md, as accepted in
/// #153 (last changed by 9545881e). Section numbers below refer to that document.
///
/// Profile: immutable genesis configuration identity plus an authenticated active EVM assignment.
/// The paired BFT/Ureth verifier supplies the canonical acknowledgement projection; this contract
/// checks its stored old context, target context and bounded epoch/span arithmetic.
///
/// Layout (§4): no Solidity state variables. Every field lives at the fixed key
/// keccak256("unicity.seal-registry/" || name) and is read and written with sload and sstore, so
/// the compiler cannot move a field. Scalars are uint64 values in a 32-byte word.
///
/// Genesis: there is no constructor. The genesis allocation places this runtime code at the
/// registry address and writes seven words, adding assignment.activeConfHash (initialized to the
/// immutable config.shardConfHash). The old config slot remains immutable after genesis.
///
/// Compiler (foundry.toml): solc 0.8.37 with the IR pipeline for the expanded static open projection.
/// The only inline assembly is the sload and sstore in _load and _store,
/// which read and write whole words at constant keys and touch no memory.
///
/// What this contract enforces is local: the caller (O1, F1), its own state machine (O2 to O5, F2,
/// F3) and bounded invariants on its arguments (O6 to O10). It cannot enforce, and does not claim,
/// the execution-client rules of §6.4 and §12: that a reverted or out-of-gas call invalidates the
/// block, that open runs first and finalize after the forced prefix exactly once each, the post-block
/// phase check, g_sys accounting, the header extraData check, rejection of any other transaction from
/// a_sys, and that the calldata is a faithful projection of the authenticated rootInput.
contract SealRegistry {
    /// @notice a_sys, the only caller of open and finalize (§2.1).
    address internal constant A_SYS = 0xff00000000000000000000000000000000000001;

    uint256 internal constant PHASE_OPEN = 1;
    uint256 internal constant PHASE_FINALIZED = 2;

    // §4.1 slot keys, one per §4.2 field.
    bytes32 internal constant SLOT_GENESIS_COMMITMENT =
        keccak256("unicity.seal-registry/genesisCommitment");
    bytes32 internal constant SLOT_CONFIG_SHARD_CONF_HASH =
        keccak256("unicity.seal-registry/config.shardConfHash");
    bytes32 internal constant SLOT_ASSIGNMENT_EPOCH =
        keccak256("unicity.seal-registry/assignment.epoch");
    bytes32 internal constant SLOT_ASSIGNMENT_ROOT_EPOCH =
        keccak256("unicity.seal-registry/assignment.rootEpoch");
    bytes32 internal constant SLOT_ASSIGNMENT_ACTIVE_CONF_HASH =
        keccak256("unicity.seal-registry/assignment.activeConfHash");
    bytes32 internal constant SLOT_ASSIGNMENT_SPAN_COMMITMENT =
        keccak256("unicity.seal-registry/assignment.spanCommitment");
    bytes32 internal constant ASSIGNMENT_PROJECTION_DOMAIN =
        keccak256("unicity.seal-registry.v2/assignment-ack-projection");
    bytes32 internal constant SLOT_CLOCK_ROOT_ROUND =
        keccak256("unicity.seal-registry/clock.rootRound");
    bytes32 internal constant SLOT_ORIGIN_ROOT_EPOCH =
        keccak256("unicity.seal-registry/origin.rootEpoch");
    bytes32 internal constant SLOT_ORIGIN_TIMESTAMP =
        keccak256("unicity.seal-registry/origin.timestamp");
    bytes32 internal constant SLOT_ORIGIN_TREE_ROOT =
        keccak256("unicity.seal-registry/origin.treeRoot");
    bytes32 internal constant SLOT_ORIGIN_IDENTITY =
        keccak256("unicity.seal-registry/origin.identity");
    bytes32 internal constant SLOT_ORIGIN_TR_HASH =
        keccak256("unicity.seal-registry/origin.trHash");
    bytes32 internal constant SLOT_ROUND_AUTHORIZED =
        keccak256("unicity.seal-registry/round.authorized");
    bytes32 internal constant SLOT_INPUT_COMMITMENT =
        keccak256("unicity.seal-registry/input.commitment");
    bytes32 internal constant SLOT_CERTIFIED_ROUND =
        keccak256("unicity.seal-registry/certified.round");
    bytes32 internal constant SLOT_CERTIFIED_STATE_HASH =
        keccak256("unicity.seal-registry/certified.stateHash");
    bytes32 internal constant SLOT_CERTIFIED_HAS_BLOCK_HASH =
        keccak256("unicity.seal-registry/certified.hasBlockHash");
    bytes32 internal constant SLOT_CERTIFIED_BLOCK_HASH =
        keccak256("unicity.seal-registry/certified.blockHash");
    bytes32 internal constant SLOT_PHASE = keccak256("unicity.seal-registry/phase");
    bytes32 internal constant SLOT_OUTCOMES_ROUND =
        keccak256("unicity.seal-registry/outcomes.round");
    bytes32 internal constant SLOT_OUTCOMES_COMMITMENT =
        keccak256("unicity.seal-registry/outcomes.commitment");
    bytes32 internal constant SLOT_TRANSITION_CURSOR =
        keccak256("unicity.seal-registry/transition.cursor");
    bytes32 internal constant SLOT_TRANSITION_BODY_ID =
        keccak256("unicity.seal-registry/transition.bodyID");
    bytes32 internal constant SLOT_TRANSITION_GENESIS_ID =
        keccak256("unicity.seal-registry/transition.genesisID");
    bytes32 internal constant SLOT_TRANSITION_FROZEN_ID =
        keccak256("unicity.seal-registry/transition.frozenID");
    bytes32 internal constant SLOT_TRANSITION_COMMIT_ID =
        keccak256("unicity.seal-registry/transition.commitID");
    bytes32 internal constant SLOT_TRANSITION_FROZEN_PARENT =
        keccak256("unicity.seal-registry/transition.frozenParent");
    bytes32 internal constant SLOT_TRANSITION_SUCCESSOR_TR =
        keccak256("unicity.seal-registry/transition.successorTR");
    // inbox.consumed remains genesis-only. transition.cursor advances on each accepted acknowledgement.

    /// O1, F1: the caller is not a_sys.
    error NotSystemCaller();
    /// O2: b1.initialized is not 1, or genesisCommitment is zero.
    error NotInitialized();
    /// O3: the previous block's finalize has not run.
    error PreviousNotFinalized();
    /// O4: the shard round does not exceed round.authorized.
    error RoundNotAhead();
    /// O5: the root round is behind clock.rootRound.
    error StaleRootRound();
    /// O6: the origin names another shard configuration.
    error ConfigurationMismatch();
    /// O7: the certified or authorized epoch is not the assignment epoch.
    error ShardEpochMismatch();
    /// O8: the root epoch is not the assignment root epoch.
    error RootEpochMismatch();
    /// O9: more than one transition is unsupported in this profile.
    error TransitionsUnsupported();
    error InvalidTransition();
    /// A supplied assignment context does not match the stored or projected transition context.
    error AssignmentContextMismatch();
    /// An assignment acknowledgement carries a malformed or unverified supersession span.
    error InvalidSupersessionSpan();
    /// This assignment acknowledgement was already imported.
    error DuplicateAcknowledgement();
    /// O10: a null block hash is not encoded as the zero word.
    error NonCanonicalNullBlockHash();
    /// F2: no open round to finalize.
    error NotOpen();
    /// F3: the round is not the one that was opened.
    error WrongOutcomeRound();

    event EpochAcknowledged(
        uint64 indexed rootEpoch,
        uint64 indexed shardEpoch,
        bytes32 indexed activeConfHash,
        uint64 supersessionSpan,
        bytes32 supersessionCommitment,
        bytes32 bodyID,
        bytes32 genesisID,
        bytes32 frozenID,
        bytes32 commitID,
        bytes32 frozenParent,
        bytes32 successorTR
    );

    /// @notice Canonical context authenticated by the paired verifier for one root acknowledgement.
    /// `supersessionCommitment` commits to the consecutive committed handoffs when span > 1. BFT
    /// verifies those records and Ureth verifies the projected span before this system call; the
    /// registry enforces that the projection is bound to its old state and exact new assignment.
    struct AssignmentProjection {
        uint64 oldRootEpoch;
        uint64 oldShardEpoch;
        bytes32 oldActiveConfHash;
        uint64 newRootEpoch;
        uint64 newShardEpoch;
        bytes32 newActiveConfHash;
        uint64 supersessionSpan;
        bytes32 supersessionCommitment;
        bytes32 projectionHash;
    }

    /// @notice The privileged open step (§6.1, §6.2). Arguments are the projection of the verified
    /// rootInput; the contract checks only what §6.2 lists. The ABI decoder refuses any uint64 or bool
    /// word outside its type's range before this body runs.
    function open(
        uint64 n,
        uint64 rootRound,
        uint64 rootEpoch,
        uint64 timestamp,
        bytes32 treeRoot,
        bytes32 originIdentity,
        bytes32 trHash,
        bytes32 shardConfHash,
        uint64 certifiedRound,
        uint64 certEpoch,
        uint64 authEpoch,
        bytes32 stateHash,
        bool hasBlockHash,
        bytes32 blockHash,
        bytes32 inputCommitment,
        uint64 transitionCount,
        bytes32 bodyID,
        bytes32 genesisID,
        bytes32 frozenID,
        bytes32 commitID,
        bytes32 frozenParent,
        bytes32 successorTR,
        bytes32 activeConfHash,
        AssignmentProjection calldata assignment,
        B1Update calldata update
    ) external {
        if (msg.sender != A_SYS) revert NotSystemCaller(); // O1
        if (_load(B1Layout.F_INITIALIZED) != 1 || _load(SLOT_GENESIS_COMMITMENT) == 0) {
            revert NotInitialized(); // O2
        }
        if (_load(SLOT_PHASE) != PHASE_FINALIZED) revert PreviousNotFinalized(); // O3
        if (n <= _load(SLOT_ROUND_AUTHORIZED)) revert RoundNotAhead(); // O4
        // `config.shardConfHash` is the immutable genesis identity. The active assignment hash is
        // separately checked below and changes only on a privileged acknowledgement.
        if (uint256(shardConfHash) != _load(SLOT_CONFIG_SHARD_CONF_HASH)) {
            revert ConfigurationMismatch(); // O6
        }
        uint256 epoch = _load(SLOT_ASSIGNMENT_EPOCH);
        uint256 assignedRootEpoch = _load(SLOT_ASSIGNMENT_ROOT_EPOCH);
        bytes32 assignedConfHash = bytes32(_load(SLOT_ASSIGNMENT_ACTIVE_CONF_HASH));
        if (transitionCount == 0) {
            if (rootEpoch != assignedRootEpoch) revert RootEpochMismatch(); // O8
            if (certEpoch != epoch || authEpoch != epoch) revert ShardEpochMismatch(); // O7
            if (activeConfHash != assignedConfHash) revert ConfigurationMismatch();
            if (rootRound < _load(SLOT_CLOCK_ROOT_ROUND)) revert StaleRootRound(); // O5
            if (
                bodyID != 0 || genesisID != 0 || frozenID != 0 || commitID != 0 || frozenParent != 0
                    || successorTR != 0 || !_isZeroProjection(assignment)
            ) revert InvalidTransition();
        } else if (transitionCount == 1) {
            if (rootRound < _load(SLOT_CLOCK_ROOT_ROUND)) revert StaleRootRound(); // O5
            if (
                bodyID == 0 || genesisID == 0 || frozenID == 0 || commitID == 0 || frozenParent == 0
                    || successorTR == 0
            ) revert InvalidTransition();
            if (assignment.newRootEpoch <= assignedRootEpoch) revert DuplicateAcknowledgement();
            if (
                assignment.oldRootEpoch != assignedRootEpoch || assignment.oldShardEpoch != epoch
                    || assignment.oldActiveConfHash != assignedConfHash
                    || assignment.newRootEpoch != rootEpoch || assignment.newShardEpoch != authEpoch
                    || assignment.newActiveConfHash != activeConfHash
                    || certEpoch != assignment.oldShardEpoch
            ) revert AssignmentContextMismatch();
            if (
                activeConfHash == 0
                    || _assignmentProjectionHash(assignment) != assignment.projectionHash
            ) {
                revert AssignmentContextMismatch();
            }
            _validateAssignmentAdvance(assignment);
            if (_load(SLOT_TRANSITION_CURSOR) == type(uint64).max) revert InvalidTransition();
            _store(SLOT_TRANSITION_CURSOR, _load(SLOT_TRANSITION_CURSOR) + 1);
            _store(SLOT_TRANSITION_BODY_ID, uint256(bodyID));
            _store(SLOT_TRANSITION_GENESIS_ID, uint256(genesisID));
            _store(SLOT_TRANSITION_FROZEN_ID, uint256(frozenID));
            _store(SLOT_TRANSITION_COMMIT_ID, uint256(commitID));
            _store(SLOT_TRANSITION_FROZEN_PARENT, uint256(frozenParent));
            _store(SLOT_TRANSITION_SUCCESSOR_TR, uint256(successorTR));
            _store(SLOT_ASSIGNMENT_EPOCH, assignment.newShardEpoch);
            _store(SLOT_ASSIGNMENT_ROOT_EPOCH, assignment.newRootEpoch);
            _store(SLOT_ASSIGNMENT_ACTIVE_CONF_HASH, uint256(assignment.newActiveConfHash));
            _store(SLOT_ASSIGNMENT_SPAN_COMMITMENT, uint256(assignment.supersessionCommitment));
            emit EpochAcknowledged(
                assignment.newRootEpoch,
                assignment.newShardEpoch,
                assignment.newActiveConfHash,
                assignment.supersessionSpan,
                assignment.supersessionCommitment,
                bodyID,
                genesisID,
                frozenID,
                commitID,
                frozenParent,
                successorTR
            );
        } else {
            revert TransitionsUnsupported(); // O9
        }
        if (!hasBlockHash && blockHash != 0) revert NonCanonicalNullBlockHash(); // O10

        // B1: prune expired intervals, close the former tip and insert the new live ones. Any error
        // above or below reverts the whole call, so no partial deletion or insertion is published.
        _applyB1(update, rootRound, rootEpoch);

        // §6.2 effects, in order.
        _store(SLOT_ORIGIN_ROOT_EPOCH, rootEpoch);
        _store(SLOT_ORIGIN_TIMESTAMP, timestamp);
        _store(SLOT_ORIGIN_TREE_ROOT, uint256(treeRoot));
        _store(SLOT_ORIGIN_IDENTITY, uint256(originIdentity));
        _store(SLOT_ORIGIN_TR_HASH, uint256(trHash));
        _store(SLOT_CERTIFIED_ROUND, certifiedRound);
        _store(SLOT_CERTIFIED_STATE_HASH, uint256(stateHash));
        _store(SLOT_CERTIFIED_HAS_BLOCK_HASH, hasBlockHash ? 1 : 0);
        _store(SLOT_CERTIFIED_BLOCK_HASH, uint256(blockHash));
        _store(SLOT_CLOCK_ROOT_ROUND, rootRound);
        _store(SLOT_ROUND_AUTHORIZED, n);
        _store(SLOT_INPUT_COMMITMENT, uint256(inputCommitment));
        _store(SLOT_OUTCOMES_ROUND, n);
        _store(SLOT_OUTCOMES_COMMITMENT, 0);
        _store(SLOT_PHASE, PHASE_OPEN);
    }

    /// @notice Reproducible, domain-separated hash for the acknowledgement projection carried in
    /// open(). Chain validity itself is established by the paired verifier before the system call.
    function assignmentProjectionHash(AssignmentProjection calldata assignment)
        external
        pure
        returns (bytes32)
    {
        return _assignmentProjectionHash(assignment);
    }

    function _assignmentProjectionHash(AssignmentProjection calldata assignment)
        private
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                ASSIGNMENT_PROJECTION_DOMAIN,
                assignment.oldRootEpoch,
                assignment.oldShardEpoch,
                assignment.oldActiveConfHash,
                assignment.newRootEpoch,
                assignment.newShardEpoch,
                assignment.newActiveConfHash,
                assignment.supersessionSpan,
                assignment.supersessionCommitment
            )
        );
    }

    function _validateAssignmentAdvance(AssignmentProjection calldata assignment) private pure {
        uint64 rootDelta = assignment.newRootEpoch - assignment.oldRootEpoch;
        uint64 shardDelta = assignment.newShardEpoch >= assignment.oldShardEpoch
            ? assignment.newShardEpoch - assignment.oldShardEpoch
            : 0;
        bool sameAssignment = assignment.newShardEpoch == assignment.oldShardEpoch
            && assignment.newActiveConfHash == assignment.oldActiveConfHash;

        if (rootDelta == 1) {
            if (assignment.supersessionSpan != 0 || assignment.supersessionCommitment != 0) {
                revert InvalidSupersessionSpan();
            }
            if (sameAssignment) return; // unchanged root-only handoff
            if (
                shardDelta != 1 || assignment.newActiveConfHash == assignment.oldActiveConfHash
                    || assignment.oldShardEpoch == type(uint64).max
            ) revert AssignmentContextMismatch();
            return; // ordinary EVM assignment change: both epochs advance exactly once
        }

        if (
            rootDelta <= 1 || shardDelta != rootDelta
                || assignment.newActiveConfHash == assignment.oldActiveConfHash
                || assignment.supersessionSpan != rootDelta
                || assignment.supersessionCommitment == 0
        ) revert InvalidSupersessionSpan();
    }

    function _isZeroProjection(AssignmentProjection calldata assignment)
        private
        pure
        returns (bool)
    {
        return assignment.oldRootEpoch == 0 && assignment.oldShardEpoch == 0
            && assignment.oldActiveConfHash == 0 && assignment.newRootEpoch == 0
            && assignment.newShardEpoch == 0 && assignment.newActiveConfHash == 0
            && assignment.supersessionSpan == 0 && assignment.supersessionCommitment == 0
            && assignment.projectionHash == 0;
    }

    /// @notice The privileged finalize step (§6.1, §6.3).
    function finalize(uint64 n, bytes32 sealRegistryCommitment) external {
        if (msg.sender != A_SYS) revert NotSystemCaller(); // F1
        if (_load(SLOT_PHASE) != PHASE_OPEN) revert NotOpen(); // F2
        if (n != _load(SLOT_OUTCOMES_ROUND)) revert WrongOutcomeRound(); // F3

        _checkB1Invariants();
        _store(SLOT_OUTCOMES_COMMITMENT, uint256(sealRegistryCommitment));
        _store(SLOT_PHASE, PHASE_FINALIZED);
    }

    // ------------------------------------------------------------------ B1 pruned history

    /// @dev Applies the committed update to the circular queue of live root-epoch intervals, in the
    /// order of the design: bind and check the parent tip, prune before inserting (so occupancy never
    /// exceeds K_max), write the former tip's closure once if it survives, append the new entries and
    /// check the final live set. O is the origin round and L = max(0, O - W_cert); an entry is live
    /// iff it is open or its exclusive end exceeds L.
    function _applyB1(B1Update calldata update, uint64 originRound, uint64 originEpoch) private {
        uint256 k = _load(B1Layout.F_W_CERT) + 1;
        uint256 origin = originRound;
        uint256 low = origin > k - 1 ? origin - (k - 1) : 0;
        uint256 head = _load(B1Layout.F_HEAD);
        uint256 count = _load(B1Layout.F_COUNT);
        if (count == 0 || count > k || head >= k) revert B1StateInvalid();

        uint256 tail = _load(B1Layout.queueSlot((head + count - 1) % k));
        if (_load(B1Layout.entrySlot(tail, 6)) != 0) revert B1StateInvalid(); // the tail is open
        if (update.priorTipEpoch != tail) revert PriorTipMismatch();

        B1Entry[] calldata news = update.newEntries;
        uint256 a = news.length;
        if (a > k) revert TooManyEntries();
        if (update.hasOldTipEnd != (a != 0)) revert OldTipEndMismatch();
        if (!update.hasOldTipEnd && update.oldTipEnd != 0) revert OldTipEndMismatch();
        if (update.hasOldTipEnd && update.oldTipEnd <= _load(B1Layout.entrySlot(tail, 4))) {
            revert InvalidInterval();
        }

        // Prune from the head while the entry's effective end is at or below L. The former tip's
        // effective end is the supplied oldTipEnd, so a tip that is deleted is never closed first.
        while (count != 0) {
            uint256 e = _load(B1Layout.queueSlot(head));
            bool ended;
            uint256 end;
            if (count == 1) {
                ended = update.hasOldTipEnd;
                end = update.oldTipEnd;
            } else {
                ended = _load(B1Layout.entrySlot(e, 6)) != 0;
                end = _load(B1Layout.entrySlot(e, 5));
            }
            if (!ended || end > low) break; // survivor (the boundary-crossing entry is retained)
            _deleteEntry(e, head);
            head = (head + 1) % k;
            count--;
        }
        if (count == 0) head = 0;

        if (a != 0) {
            if (count + a > k) revert RingFull();
            if (count != 0) {
                // The former tip survives: it closes exactly where its successor starts.
                if (news[0].epoch != uint256(tail) + 1 || news[0].start != update.oldTipEnd) {
                    revert NonContiguousEpochs();
                }
                _store(B1Layout.entrySlot(tail, 5), update.oldTipEnd);
                _store(B1Layout.entrySlot(tail, 6), 1);
            } else {
                // Everything expired: the first new entry must be the one that crosses L.
                if (news[0].epoch <= tail) revert NonContiguousEpochs();
                if (news[0].start > low) revert StartAfterOrigin();
            }
            for (uint256 i = 0; i < a; i++) {
                B1Entry calldata en = news[i];
                if (i != 0) {
                    B1Entry calldata prev = news[i - 1];
                    if (en.epoch != uint256(prev.epoch) + 1 || en.start != prev.end) {
                        revert NonContiguousEpochs();
                    }
                }
                if (en.hasEnd == (i == a - 1)) revert InvalidInterval(); // only the last is open
                if (en.hasEnd && en.end <= low) revert ExpiredEntry();
                if (en.start > origin) revert StartAfterOrigin();
                if (_load(B1Layout.entrySlot(en.epoch, 0)) != 0) revert EntryAlreadyPresent();
                B1Layout.checkEntry(en, false);
                _writeEntry(en);
                _store(B1Layout.queueSlot((head + count) % k), en.epoch);
                count++;
            }
            tail = news[a - 1].epoch;
        }

        if (count == 0) revert B1StateInvalid();
        if (tail != originEpoch) revert OriginEpochMismatch();
        _store(B1Layout.F_HEAD, head);
        _store(B1Layout.F_COUNT, count);
    }

    /// @dev Writes the 11 metadata words and 8 words per member of one entry.
    function _writeEntry(B1Entry calldata en) private {
        uint256 e = en.epoch;
        uint256 m = en.members.length;
        uint256 total = 0;
        for (uint256 j = 0; j < m; j++) {
            total += en.members[j].weight;
        }
        _store(B1Layout.entrySlot(e, 0), 1);
        _store(B1Layout.entrySlot(e, 1), en.bodyKind);
        _store(B1Layout.entrySlot(e, 2), uint256(en.bodyID));
        _store(B1Layout.entrySlot(e, 3), uint256(en.activationCommitID));
        _store(B1Layout.entrySlot(e, 4), en.start);
        _store(B1Layout.entrySlot(e, 5), en.end);
        _store(B1Layout.entrySlot(e, 6), en.hasEnd ? 1 : 0);
        _store(B1Layout.entrySlot(e, 7), en.signingScheme);
        _store(B1Layout.entrySlot(e, 8), uint256(en.signingConfigHash));
        _store(B1Layout.entrySlot(e, 9), m);
        _store(B1Layout.entrySlot(e, 10), total);
        for (uint256 j = 0; j < m; j++) {
            B1Member calldata mem = en.members[j];
            _store(B1Layout.memberSlot(e, j, 0), mem.nodeIDLength);
            for (uint256 w = 0; w < 4; w++) {
                _store(B1Layout.memberSlot(e, j, 1 + w), uint256(mem.nodeID[w]));
            }
            _store(B1Layout.memberSlot(e, j, 5), uint256(mem.key[0]));
            _store(B1Layout.memberSlot(e, j, 6), uint256(mem.key[1]));
            _store(B1Layout.memberSlot(e, j, 7), mem.weight);
        }
    }

    /// @dev Clears every metadata word, every member word and the queue word of one entry.
    function _deleteEntry(uint256 e, uint256 queueIndex) private {
        uint256 m = _load(B1Layout.entrySlot(e, 9));
        for (uint256 j = 0; j < m; j++) {
            for (uint256 f = 0; f < B1Layout.MEMBER_FIELDS; f++) {
                _store(B1Layout.memberSlot(e, j, f), 0);
            }
        }
        for (uint256 f = 0; f < B1Layout.ENTRY_FIELDS; f++) {
            _store(B1Layout.entrySlot(e, f), 0);
        }
        _store(B1Layout.queueSlot(queueIndex), 0);
    }

    /// @dev Finalize re-asserts what the last open established: a non-empty ring within K_max whose
    /// tail is the open interval of the origin epoch.
    function _checkB1Invariants() private view {
        uint256 k = _load(B1Layout.F_W_CERT) + 1;
        uint256 head = _load(B1Layout.F_HEAD);
        uint256 count = _load(B1Layout.F_COUNT);
        if (count == 0 || count > k || head >= k) revert B1StateInvalid();
        uint256 tail = _load(B1Layout.queueSlot((head + count - 1) % k));
        if (
            _load(B1Layout.entrySlot(tail, 0)) != 1 || _load(B1Layout.entrySlot(tail, 6)) != 0
                || tail != _load(SLOT_ORIGIN_ROOT_EPOCH)
        ) revert B1StateInvalid();
    }

    /// @dev Reads one whole word at a constant key. No memory is used.
    function _load(bytes32 slot) private view returns (uint256 value) {
        assembly ("memory-safe") {
            value := sload(slot)
        }
    }

    /// @dev Writes one whole word at a constant key. No memory is used.
    function _store(bytes32 slot, uint256 value) private {
        assembly ("memory-safe") {
            sstore(slot, value)
        }
    }
}
