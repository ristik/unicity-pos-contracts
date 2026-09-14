// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: contract licensing is an explicit owner decision (bft-core #1), not a default.
pragma solidity 0.8.37;

/// @title SealRegistry, profile sealRegistry/v1
/// @notice Fixed-profile registry of the imported root origin and certified round clock for the
/// enshrined EVM. Specification: bft-core docs/design/f4a-seal-registry-contract.md, as accepted in
/// #153 (last changed by 9545881e). Section numbers below refer to that document.
///
/// Profile (§0): one shard configuration, one shard configuration epoch, one root epoch, an empty
/// transition list and an empty forced-inclusion prefix. Every other input is refused.
///
/// Layout (§4): no Solidity state variables. Every field lives at the fixed key
/// keccak256("unicity.seal-registry.v1/" || name) and is read and written with sload and sstore, so
/// the compiler cannot move a field. Scalars are uint64 values in a 32-byte word.
///
/// Genesis (§5.4): there is no constructor. The genesis allocation places this runtime code at the
/// registry address and writes exactly six words: layoutVersion, genesisCommitment,
/// config.shardConfHash, assignment.epoch, assignment.rootEpoch and phase = 2. The code does not
/// depend on the address it is placed at.
///
/// Compiler (foundry.toml): solc 0.8.37 with the IR pipeline, so the sixteen-argument open signature of
/// §6.1 decodes as specified. The only inline assembly is the sload and sstore in _load and _store,
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

    uint256 internal constant LAYOUT_VERSION = 1;
    uint256 internal constant PHASE_OPEN = 1;
    uint256 internal constant PHASE_FINALIZED = 2;

    // §4.1 slot keys, one per §4.2 field.
    bytes32 internal constant SLOT_LAYOUT_VERSION =
        keccak256("unicity.seal-registry.v1/layoutVersion");
    bytes32 internal constant SLOT_GENESIS_COMMITMENT =
        keccak256("unicity.seal-registry.v1/genesisCommitment");
    bytes32 internal constant SLOT_CONFIG_SHARD_CONF_HASH =
        keccak256("unicity.seal-registry.v1/config.shardConfHash");
    bytes32 internal constant SLOT_ASSIGNMENT_EPOCH =
        keccak256("unicity.seal-registry.v1/assignment.epoch");
    bytes32 internal constant SLOT_ASSIGNMENT_ROOT_EPOCH =
        keccak256("unicity.seal-registry.v1/assignment.rootEpoch");
    bytes32 internal constant SLOT_CLOCK_ROOT_ROUND =
        keccak256("unicity.seal-registry.v1/clock.rootRound");
    bytes32 internal constant SLOT_ORIGIN_ROOT_EPOCH =
        keccak256("unicity.seal-registry.v1/origin.rootEpoch");
    bytes32 internal constant SLOT_ORIGIN_TIMESTAMP =
        keccak256("unicity.seal-registry.v1/origin.timestamp");
    bytes32 internal constant SLOT_ORIGIN_TREE_ROOT =
        keccak256("unicity.seal-registry.v1/origin.treeRoot");
    bytes32 internal constant SLOT_ORIGIN_IDENTITY =
        keccak256("unicity.seal-registry.v1/origin.identity");
    bytes32 internal constant SLOT_ORIGIN_TR_HASH =
        keccak256("unicity.seal-registry.v1/origin.trHash");
    bytes32 internal constant SLOT_ROUND_AUTHORIZED =
        keccak256("unicity.seal-registry.v1/round.authorized");
    bytes32 internal constant SLOT_INPUT_COMMITMENT =
        keccak256("unicity.seal-registry.v1/input.commitment");
    bytes32 internal constant SLOT_CERTIFIED_ROUND =
        keccak256("unicity.seal-registry.v1/certified.round");
    bytes32 internal constant SLOT_CERTIFIED_STATE_HASH =
        keccak256("unicity.seal-registry.v1/certified.stateHash");
    bytes32 internal constant SLOT_CERTIFIED_HAS_BLOCK_HASH =
        keccak256("unicity.seal-registry.v1/certified.hasBlockHash");
    bytes32 internal constant SLOT_CERTIFIED_BLOCK_HASH =
        keccak256("unicity.seal-registry.v1/certified.blockHash");
    bytes32 internal constant SLOT_PHASE = keccak256("unicity.seal-registry.v1/phase");
    bytes32 internal constant SLOT_OUTCOMES_ROUND =
        keccak256("unicity.seal-registry.v1/outcomes.round");
    bytes32 internal constant SLOT_OUTCOMES_COMMITMENT =
        keccak256("unicity.seal-registry.v1/outcomes.commitment");
    // transition.cursor and inbox.consumed (§4.2) are written by genesis only and never by this code.

    /// O1, F1: the caller is not a_sys.
    error NotSystemCaller();
    /// O2: layoutVersion is not 1, or genesisCommitment is zero.
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
    /// O9: pending transitions are not supported in v1.
    error TransitionsUnsupported();
    /// O10: a null block hash is not encoded as the zero word.
    error NonCanonicalNullBlockHash();
    /// F2: no open round to finalize.
    error NotOpen();
    /// F3: the round is not the one that was opened.
    error WrongOutcomeRound();

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
        uint64 transitionCount
    ) external {
        if (msg.sender != A_SYS) revert NotSystemCaller(); // O1
        if (_load(SLOT_LAYOUT_VERSION) != LAYOUT_VERSION || _load(SLOT_GENESIS_COMMITMENT) == 0) {
            revert NotInitialized(); // O2
        }
        if (_load(SLOT_PHASE) != PHASE_FINALIZED) revert PreviousNotFinalized(); // O3
        if (n <= _load(SLOT_ROUND_AUTHORIZED)) revert RoundNotAhead(); // O4
        if (rootRound < _load(SLOT_CLOCK_ROOT_ROUND)) revert StaleRootRound(); // O5
        if (uint256(shardConfHash) != _load(SLOT_CONFIG_SHARD_CONF_HASH)) {
            revert ConfigurationMismatch(); // O6
        }
        uint256 epoch = _load(SLOT_ASSIGNMENT_EPOCH);
        if (certEpoch != epoch || authEpoch != epoch) revert ShardEpochMismatch(); // O7
        if (rootEpoch != _load(SLOT_ASSIGNMENT_ROOT_EPOCH)) revert RootEpochMismatch(); // O8
        if (transitionCount != 0) revert TransitionsUnsupported(); // O9
        if (!hasBlockHash && blockHash != 0) revert NonCanonicalNullBlockHash(); // O10

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

    /// @notice The privileged finalize step (§6.1, §6.3).
    function finalize(uint64 n, bytes32 sealRegistryCommitment) external {
        if (msg.sender != A_SYS) revert NotSystemCaller(); // F1
        if (_load(SLOT_PHASE) != PHASE_OPEN) revert NotOpen(); // F2
        if (n != _load(SLOT_OUTCOMES_ROUND)) revert WrongOutcomeRound(); // F3

        _store(SLOT_OUTCOMES_COMMITMENT, uint256(sealRegistryCommitment));
        _store(SLOT_PHASE, PHASE_FINALIZED);
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
