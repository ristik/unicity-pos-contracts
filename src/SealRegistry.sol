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
    AppendGap,
    BadAppend,
    NonContiguousEpochs,
    AppendStartNotIncreasing,
    AppendClosesUsableOrigin,
    StartAfterOrigin,
    OriginEpochMismatch,
    EntryAlreadyPresent,
    OriginEpochRegression,
    OriginRoundRegression,
    OriginBeyondImportedTip,
    FirstOriginBeforeGenesis,
    OriginBeforeStart,
    OriginAtOrAfterEnd,
    ImportedUsableMismatch
} from "./B1Layout.sol";

import {IRootRecords} from "./p85/IP85.sol";
import {RootRecord, RecordKind} from "./p85/P85Types.sol";

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
contract SealRegistry is IRootRecords {
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
    // P85 root records (PR1c control-records spec, section 6): the linked log custody applies, with the progress and UC time the paired
    // verifier supplied. Whole-word slots like every other field; entries are keyed by RECORDS_ENTRY.
    bytes32 internal constant SLOT_RECORDS_COUNT = keccak256("unicity.seal-registry/records.count");
    bytes32 internal constant SLOT_RECORDS_TIP = keccak256("unicity.seal-registry/records.tip");
    bytes32 internal constant SLOT_RECORDS_PROGRESS =
        keccak256("unicity.seal-registry/records.progress");
    bytes32 internal constant SLOT_RECORDS_UC_TIME =
        keccak256("unicity.seal-registry/records.ucTime");
    bytes32 internal constant SLOT_RECORDS_TARGET_COUNT =
        keccak256("unicity.seal-registry/records.targetCount");
    bytes32 internal constant SLOT_RECORDS_TARGET_TIP =
        keccak256("unicity.seal-registry/records.targetTip");
    bytes32 internal constant SLOT_RECORDS_IMPORTED_ROUND =
        keccak256("unicity.seal-registry/records.importedRound");
    bytes32 internal constant RECORDS_ENTRY = keccak256("unicity.seal-registry/records.entry");
    bytes32 internal constant RECORDS_CLOSURE = keccak256("unicity.seal-registry/records.closure");
    bytes32 internal constant RECORDS_RETIREMENT =
        keccak256("unicity.seal-registry/records.retirement");
    uint256 internal constant MAX_IMPORT = 32;
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
    /// finalize found no importRootRecords call for this round.
    error RecordImportMissing();
    /// importRootRecords was already applied for this round.
    error RecordImportDuplicate();
    /// The batch is not exactly the next required prefix of the authenticated source log.
    error RecordPrefixInvalid();
    /// A record's index, predecessor, identifier, kind or payload shape is invalid.
    error RecordInvalid();
    /// Current progress, UC time or the target count would decrease, or a record anchor is out of order or above the current value.
    error RecordAnchorInvalid();
    /// The target tip contradicts the target count or the imported tail.
    error RecordTargetInvalid();
    /// A closure or retirement is already logged under its key.
    error RecordDuplicateKey();
    /// recordAt outside the imported count.
    error RecordIndexOutOfRange();
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

    // ------------------------------------------------------------------ root records import

    /// @notice One projected record plus the closed root epoch of a Closure (zero for every other kind).
    struct ImportedRecord {
        RootRecord record;
        uint64 closedEpoch;
    }

    /// @notice The privileged import step, run exactly once per EVM block after open() and before finalize(). `p` and `t` are the
    /// authenticated current canonical progress and UC time, `targetCount` and `targetTip` the length and tip of the complete source
    /// log the paired verifier reconstructed. The batch must be the next min(32, targetCount - count) records, so a relayer can
    /// neither omit, select, reorder nor look ahead. Root signatures, terminal proofs and lifecycle validity are checked by the paired
    /// verifier before this call; the registry checks provenance, log identity, content identity and anchors.
    function importRootRecords(
        uint64 n,
        uint64 p,
        uint64 t,
        uint64 targetCount,
        bytes32 targetTip,
        ImportedRecord[] calldata entries
    ) external {
        if (msg.sender != A_SYS) revert NotSystemCaller();
        if (_load(SLOT_PHASE) != PHASE_OPEN) revert NotOpen();
        if (n != _load(SLOT_OUTCOMES_ROUND)) revert WrongOutcomeRound();
        if (_load(SLOT_RECORDS_IMPORTED_ROUND) == n) revert RecordImportDuplicate();

        uint256 count = _load(SLOT_RECORDS_COUNT);
        uint256 batch = entries.length;
        if (
            p < _load(SLOT_RECORDS_PROGRESS) || t < _load(SLOT_RECORDS_UC_TIME)
                || targetCount < _load(SLOT_RECORDS_TARGET_COUNT)
        ) revert RecordAnchorInvalid();
        if (targetCount < count + batch) revert RecordPrefixInvalid();
        uint256 required = targetCount - count;
        if (required > MAX_IMPORT) required = MAX_IMPORT;
        if (batch != required) revert RecordPrefixInvalid();
        if (
            (targetCount == _load(SLOT_RECORDS_TARGET_COUNT)
                    && targetTip != bytes32(_load(SLOT_RECORDS_TARGET_TIP)))
                // a zero target forces count zero and a zero tail, so the tail rule below refuses a non-zero tip too; kept as the
                // explicit statement of the spec's rule
                || (targetCount == 0 && targetTip != bytes32(0))
        ) {
            revert RecordTargetInvalid();
        }

        bytes32 tip = bytes32(_load(SLOT_RECORDS_TIP));
        uint256 lastProgress = 0;
        uint256 lastTime = 0;
        if (count != 0) {
            lastProgress = _load(_entrySlot(count - 1, 3));
            lastTime = _load(_entrySlot(count - 1, 4));
        }
        for (uint256 i = 0; i < batch; ++i) {
            RootRecord calldata r = entries[i].record;
            if (r.index != count + i || r.predecessor != tip) revert RecordInvalid();
            if (r.progress < lastProgress || r.ucTime < lastTime || r.progress > p || r.ucTime > t)
            {
                revert RecordAnchorInvalid();
            }
            if (
                r.recordID
                    != keccak256(
                        abi.encode(r.index, r.predecessor, r.kind, r.progress, r.ucTime, r.data)
                    )
            ) revert RecordInvalid();
            _acceptRecord(r, entries[i].closedEpoch);
            lastProgress = r.progress;
            lastTime = r.ucTime;
            tip = r.recordID;
        }
        if (count + batch == targetCount && tip != targetTip) revert RecordTargetInvalid();

        _store(SLOT_RECORDS_COUNT, count + batch);
        _store(SLOT_RECORDS_TIP, uint256(tip));
        _store(SLOT_RECORDS_PROGRESS, p);
        _store(SLOT_RECORDS_UC_TIME, t);
        _store(SLOT_RECORDS_TARGET_COUNT, targetCount);
        _store(SLOT_RECORDS_TARGET_TIP, uint256(targetTip));
        _store(SLOT_RECORDS_IMPORTED_ROUND, n);
    }

    /// @dev Checks the exact payload width and uint64-word shape of one record (P85Types structs: all static words), fixes the
    /// closure or retirement key to this index, and stores every word. The first record of a key is the only one.
    function _acceptRecord(RootRecord calldata r, uint64 closedEpoch) private {
        uint256 kind = uint8(r.kind);
        uint256 words;
        uint256 u64Mask = 0; // bit j set: payload word j is a uint64
        if (kind == uint8(RecordKind.SessionClosed)) {
            words = 1;
        } else if (kind == uint8(RecordKind.Ack)) {
            (words, u64Mask) = (4, 0xe);
        } else if (kind == uint8(RecordKind.RecoveryAck)) {
            (words, u64Mask) = (9, 0x1fc);
        } else if (kind == uint8(RecordKind.Closure)) {
            (words, u64Mask) = (6, 0x2);
        } else if (kind == uint8(RecordKind.Retirement)) {
            (words, u64Mask) = (3, 0x3);
        } else {
            revert RecordInvalid();
        }
        bytes calldata d = r.data;
        if (d.length != words * 32) revert RecordInvalid();
        if (kind != uint8(RecordKind.Closure) && closedEpoch != 0) revert RecordInvalid();

        bytes32 key = bytes32(0);
        if (kind == uint8(RecordKind.Closure)) {
            key = keccak256(
                abi.encode(RECORDS_CLOSURE, closedEpoch, bytes32(d[64:96]), _u64(d[32:64]))
            );
        } else if (kind == uint8(RecordKind.Retirement)) {
            key = keccak256(abi.encode(RECORDS_RETIREMENT, _u64(d[0:32]), _u64(d[32:64])));
        }
        if (key != 0) {
            if (_load(key) != 0) revert RecordDuplicateKey();
            _store(key, r.index + 1);
        }

        uint64 i = r.index;
        _store(_entrySlot(i, 0), uint256(r.recordID));
        _store(_entrySlot(i, 1), uint256(r.predecessor));
        _store(_entrySlot(i, 2), kind);
        _store(_entrySlot(i, 3), r.progress);
        _store(_entrySlot(i, 4), r.ucTime);
        _store(_entrySlot(i, 5), d.length);
        for (uint256 j = 0; j < words; ++j) {
            uint256 w = uint256(bytes32(d[32 * j:32 * j + 32]));
            if (u64Mask & (1 << j) != 0 && w > type(uint64).max) revert RecordInvalid();
            _store(_entrySlot(i, 6 + j), w);
        }
        _store(_entrySlot(i, 15), closedEpoch);
    }

    function _u64(bytes calldata word) private pure returns (uint64) {
        uint256 w = abi.decode(word, (uint256));
        if (w > type(uint64).max) revert RecordInvalid();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(w);
    }

    function _entrySlot(uint256 index, uint256 field) private pure returns (bytes32) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return keccak256(abi.encode(RECORDS_ENTRY, uint64(index), uint64(field)));
    }

    /// @notice Number of imported records.
    function recordCount() external view returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(_load(SLOT_RECORDS_COUNT));
    }

    /// @notice Length of the authenticated source log as of the last import, for complete-prefix gates.
    function recordTargetCount() external view returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(_load(SLOT_RECORDS_TARGET_COUNT));
    }

    /// @notice Record `index` of the imported log.
    function recordAt(uint64 index) external view returns (RootRecord memory r) {
        if (index >= _load(SLOT_RECORDS_COUNT)) revert RecordIndexOutOfRange();
        r.index = index;
        r.recordID = bytes32(_load(_entrySlot(index, 0)));
        r.predecessor = bytes32(_load(_entrySlot(index, 1)));
        // forge-lint: disable-next-line(unsafe-typecast)
        r.kind = RecordKind(uint8(_load(_entrySlot(index, 2))));
        // forge-lint: disable-start(unsafe-typecast)
        r.progress = uint64(_load(_entrySlot(index, 3)));
        r.ucTime = uint64(_load(_entrySlot(index, 4)));
        // forge-lint: disable-end(unsafe-typecast)
        bytes memory d = new bytes(_load(_entrySlot(index, 5)));
        for (uint256 j = 0; j < d.length / 32; ++j) {
            uint256 w = _load(_entrySlot(index, 6 + j));
            assembly ("memory-safe") {
                mstore(add(add(d, 0x20), mul(j, 0x20)), w)
            }
        }
        r.data = d;
    }

    /// @notice Canonical ordinary progress p as of the last import (supplied by the paired verifier).
    function progress() external view returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(_load(SLOT_RECORDS_PROGRESS));
    }

    /// @notice Quorum-approved UC time as of the last import; the pinned genesis UC time before any.
    function ucTime() external view returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(_load(SLOT_RECORDS_UC_TIME));
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
        if (_load(SLOT_RECORDS_IMPORTED_ROUND) != n) revert RecordImportMissing();

        _checkB1Invariants();
        _store(SLOT_OUTCOMES_COMMITMENT, uint256(sealRegistryCommitment));
        _store(SLOT_PHASE, PHASE_FINALIZED);
    }

    // ------------------------------------------------------------------ B1 permanent history

    /// @dev Applies the committed update to the permanent registry, mirroring bft-core `b1state.Registry.Apply`: bind the parent tip, check
    /// the update's own shape, append the new epochs after the imported tip (closing the former tip once), then move the usable origin to
    /// (originEpoch, originRound) under the write-side guards. Nothing is pruned or deleted. Any error reverts the whole call, so no
    /// partial import is published. How many epochs one block may import (B) is the profile's admission rule at the paired verifier and
    /// the system-call gas, not a word of this registry.
    function _applyB1(B1Update calldata update, uint64 originRound, uint64 originEpoch) private {
        uint256 tip = _load(B1Layout.F_IMPORTED_TIP);
        if (_load(B1Layout.entrySlot(tip, 0)) != 1 || _load(B1Layout.entrySlot(tip, 6)) != 0) {
            revert B1StateInvalid(); // the imported tip is the one open entry
        }
        if (update.priorTipEpoch != tip) revert PriorTipMismatch();

        B1Entry[] calldata news = update.newEntries;
        uint256 a = news.length;
        if (a == 0) {
            if (update.hasOldTipEnd || update.oldTipEnd != 0) revert OldTipEndMismatch();
            if (tip != originEpoch) revert OriginEpochMismatch();
        } else {
            if (!update.hasOldTipEnd || update.oldTipEnd != news[0].start) {
                revert OldTipEndMismatch();
            }
            _appendAll(news, tip, originRound, originEpoch);
            tip = news[a - 1].epoch;
            _store(B1Layout.F_IMPORTED_TIP, tip);
        }
        _advanceOrigin(originEpoch, originRound);
        if (originEpoch != tip) revert ImportedUsableMismatch(); // no preload mode: the usable epoch is the imported tip
    }

    /// @dev The update's shape (bft-core `b1state` update validation) and `Registry.append` for each new epoch, in order.
    function _appendAll(
        B1Entry[] calldata news,
        uint256 tip,
        uint64 originRound,
        uint64 originEpoch
    ) private {
        uint256 a = news.length;
        if (tip == type(uint64).max) revert BadAppend();
        bool ready = _load(B1Layout.F_ORIGIN_READY) == 1;
        uint256 prevStart = _load(B1Layout.entrySlot(tip, 4));
        for (uint256 i = 0; i < a; i++) {
            B1Entry calldata en = news[i];
            if (en.bodyKind == 1) revert BadAppend(); // the genesis body is installed at genesis only
            if (en.epoch != tip + 1 + i) revert AppendGap();
            if (i != 0 && (!news[i - 1].hasEnd || news[i - 1].end != en.start)) {
                revert NonContiguousEpochs();
            }
            if (en.start > originRound || (en.hasEnd && en.end > originRound)) {
                revert StartAfterOrigin();
            }
            if (en.hasEnd == (i == a - 1)) revert InvalidInterval(); // only the last is open
            if (i == a - 1 && en.epoch != originEpoch) revert OriginEpochMismatch();
            B1Layout.checkEntry(en, false);
            if (en.start <= prevStart) revert AppendStartNotIncreasing();
            if (
                i == 0 && ready && tip == _load(SLOT_ORIGIN_ROOT_EPOCH)
                    && en.start <= _load(SLOT_CLOCK_ROOT_ROUND)
            ) {
                revert AppendClosesUsableOrigin();
            }
            if (_load(B1Layout.entrySlot(en.epoch, 0)) != 0) revert EntryAlreadyPresent();
            if (i == 0) {
                // The former tip closes exactly where its successor starts, once.
                _store(B1Layout.entrySlot(tip, 5), en.start);
                _store(B1Layout.entrySlot(tip, 6), 1);
            }
            _writeEntry(en);
            prevStart = en.start;
        }
    }

    /// @dev `Registry.advance`: the usable origin moves forward onto an installed epoch whose interval holds the origin round.
    function _advanceOrigin(uint64 epoch, uint64 round) private {
        bool ready = _load(B1Layout.F_ORIGIN_READY) == 1;
        if (ready) {
            if (epoch < _load(SLOT_ORIGIN_ROOT_EPOCH)) revert OriginEpochRegression();
            if (round < _load(SLOT_CLOCK_ROOT_ROUND)) revert OriginRoundRegression();
        } else if (epoch < _load(B1Layout.F_GENESIS_EPOCH)) {
            revert FirstOriginBeforeGenesis();
        }
        if (epoch > _load(B1Layout.F_IMPORTED_TIP) || _load(B1Layout.entrySlot(epoch, 0)) != 1) {
            revert OriginBeyondImportedTip();
        }
        if (round < _load(B1Layout.entrySlot(epoch, 4))) revert OriginBeforeStart();
        if (
            _load(B1Layout.entrySlot(epoch, 6)) != 0 && round >= _load(B1Layout.entrySlot(epoch, 5))
        ) {
            revert OriginAtOrAfterEnd();
        }
        if (!ready) _store(B1Layout.F_ORIGIN_READY, 1);
    }

    /// @dev Writes the 11 metadata words and 8 words per member of one entry, and its commitment C_e at field 11 (never rewritten:
    /// closing the epoch writes only fields 5 and 6, which C_e excludes).
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
        _store(
            B1Layout.entrySlot(e, B1Layout.COMMITMENT_FIELD),
            uint256(
                B1Layout.epochCommitment(
                    bytes32(_load(SLOT_GENESIS_COMMITMENT)),
                    bytes32(_load(B1Layout.F_PROFILE_HASH)),
                    en,
                    total
                )
            )
        );
    }

    // ------------------------------------------------------------------ B7 trust cache

    /// @notice The most epochs one epochCommitments call reads: the most root epochs one B7 journal names.
    uint256 public constant MAX_COMMITMENT_VIEW = 64;

    /// The view names no epoch or more than MAX_COMMITMENT_VIEW.
    error CommitmentViewBounds();
    /// A named epoch is not installed, or its cached commitment is zero.
    error EpochCommitmentMissing(uint64 epoch);

    /// @notice The cached C_e of each named epoch with its closure words (end, hasEnd), which C_e excludes. One direct lookup per
    ///         epoch, in the caller's order; it never enumerates the history.
    function epochCommitments(uint64[] calldata epochs)
        external
        view
        returns (bytes32[] memory commitments, uint64[] memory ends, bool[] memory hasEnd)
    {
        uint256 n = epochs.length;
        if (n == 0 || n > MAX_COMMITMENT_VIEW) revert CommitmentViewBounds();
        commitments = new bytes32[](n);
        ends = new uint64[](n);
        hasEnd = new bool[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 e = epochs[i];
            bytes32 c = bytes32(_load(B1Layout.entrySlot(e, B1Layout.COMMITMENT_FIELD)));
            if (_load(B1Layout.entrySlot(e, 0)) != 1 || c == 0) {
                revert EpochCommitmentMissing(epochs[i]);
            }
            commitments[i] = c;
            // forge-lint: disable-next-line(unsafe-typecast)
            ends[i] = uint64(_load(B1Layout.entrySlot(e, 5))); // written only from a uint64 start
            hasEnd[i] = _load(B1Layout.entrySlot(e, 6)) == 1;
        }
    }

    /// @dev Finalize re-asserts what the last open established: format 2, a usable origin that is the imported tip, and the tip is the one
    /// open present entry at or after the genesis epoch.
    function _checkB1Invariants() private view {
        uint256 tip = _load(B1Layout.F_IMPORTED_TIP);
        if (
            _load(B1Layout.F_FORMAT) != B1Layout.FORMAT || _load(B1Layout.F_ORIGIN_READY) != 1
                || tip < _load(B1Layout.F_GENESIS_EPOCH) || tip != _load(SLOT_ORIGIN_ROOT_EPOCH)
                || _load(B1Layout.entrySlot(tip, 0)) != 1 || _load(B1Layout.entrySlot(tip, 6)) != 0
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
