// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Policy} from "./P85Types.sol";
import {IPolicySource, IRootRecords, IGovernance, GovernanceSnapshot} from "./IP85.sol";
import {PolicyBounds} from "./PolicyBounds.sol";

/// @title GovernanceParams
/// @notice The policy source of a governed deployment (T8 #47 / P7 #54, briefs/t8-p7-design.md): the ten economic and protection policy
/// fields plus the operator reward rate, changed prospectively and only through one pending proposal.
///
/// A fixed development authority queues a complete proposed snapshot. After BOTH captured delays (progress rounds and UC seconds) anyone
/// may `execute` it, which only SCHEDULES it. The snapshot becomes the policy in force when the election entry point (`ElectionPolicy.elect`)
/// calls `activateDue` at its next eligible boundary: records reconciled, no unresolved election, the threshold due under the old
/// parameters. Nothing else activates a snapshot, so every builder, follower and replay sees the same policy ID at the same block.
///
/// A snapshot never changes and an ID is never reused: an obligation that captured an ID keeps its terms and its maximum for ever. Governance
/// cannot edit cases, exclusions, K authorization, payees, credits or candidates, and it has no setter for the knobs this deployment keeps
/// immutable (bond unit and minimum, election cadence and cardinality, turnover, module addresses, resource and gas limits, checkpoint and
/// clock policy). The only state-changing functions are `queue`, `execute`, `cancel` and `activateDue`.
// forge-lint: disable-next-line(locked-ether)
contract GovernanceParams is IPolicySource, IGovernance {
    error UnknownPolicy();
    error NotAuthority();
    error NotElection();
    error ZeroAddress();
    error ProposalPending();
    error NoProposal();
    error StaleNonce(uint64 expected);
    error StalePredecessor();
    error RewardRateOutOfBounds();
    error DelayNotElapsed();
    error WrongState();
    error PolicyIDExhausted();

    enum State {
        None,
        Queued,
        Scheduled
    }

    /// @dev The proposal slot. Only one exists at a time; a second `queue` is refused, not queued behind it.
    struct Proposal {
        State state;
        uint64 nonce;
        bytes32 predecessor; // the hash of the snapshot in force when it was queued
        Policy policy;
        uint128 rewardRate;
        uint64 notBeforeProgress; // absolute: the progress at queue plus the captured round delay
        uint64 notBeforeTime; // absolute: the UC time at queue plus the captured second delay
    }

    event Queued(
        uint64 indexed nonce,
        bytes32 predecessor,
        bytes32 proposalHash,
        uint64 notBeforeProgress,
        uint64 notBeforeTime
    );
    event Executed(uint64 indexed nonce);
    event Cancelled(uint64 indexed nonce);
    event Activated(
        uint32 indexed policyID, uint64 indexed nonce, bytes32 snapshotHash, uint64 progress
    );

    bytes32 internal constant SNAPSHOT_DOMAIN = keccak256("unicity.p85.governance.snapshot");
    bytes32 internal constant PROPOSAL_DOMAIN = keccak256("unicity.p85.governance.proposal");
    /// @dev The governance delay (design section 3): both must have passed. Fixed, captured at queue, never shortened for a queued proposal.
    uint64 public constant DELAY_ROUNDS = 2_000;
    uint64 public constant DELAY_SECONDS = 3_600;
    /// @dev The immutable rate bound: at most 10 UCT per 1,000 progress units (1 UCT = 10^18 base units).
    uint128 public constant MAX_REWARD_RATE = 10 ether;

    address public immutable AUTHORITY;
    address public immutable ELECTION;
    IRootRecords public immutable ROOTS;

    mapping(uint32 => GovernanceSnapshot) private _snapshots;
    uint32 private _current;
    uint64 public nextNonce = 1;
    Proposal private _pending;

    /// @param initial the genesis snapshot (policy ID 1, effective from progress 0).
    constructor(
        Policy memory initial,
        uint128 initialRewardRate,
        address authority,
        address election,
        address roots
    ) {
        if (authority == address(0) || election == address(0) || roots == address(0)) {
            revert ZeroAddress();
        }
        _validate(initial, initialRewardRate);
        AUTHORITY = authority;
        ELECTION = election;
        ROOTS = IRootRecords(roots);
        _current = 1;
        _snapshots[1] = GovernanceSnapshot({
            policy: initial,
            rewardRate: initialRewardRate,
            hash: _snapshotHash(1, bytes32(0), initial, initialRewardRate),
            effectiveProgress: 0,
            effectiveTime: 0
        });
    }

    // --- the policy source API custody and evidence read --------------------------------------

    function currentPolicyID() external view returns (uint32) {
        return _current;
    }

    function policy() external view returns (Policy memory) {
        return _snapshots[_current].policy;
    }

    function policyAt(uint32 policyID) external view returns (Policy memory) {
        return _snapshot(policyID).policy;
    }

    // --- snapshots ------------------------------------------------------------------------------

    function snapshotAt(uint32 policyID) external view returns (GovernanceSnapshot memory) {
        return _snapshot(policyID);
    }

    function rewardRateAt(uint32 policyID) external view returns (uint128) {
        return _snapshot(policyID).rewardRate;
    }

    function currentRewardRate() external view returns (uint128) {
        return _snapshots[_current].rewardRate;
    }

    function currentPolicyHash() external view returns (bytes32) {
        return _snapshots[_current].hash;
    }

    function pending() external view returns (Proposal memory) {
        return _pending;
    }

    // --- the proposal state machine -------------------------------------------------------------

    /// @notice Queue a complete proposed snapshot. `expectedPolicyHash` is the hash of the snapshot in force (a stale view is refused) and
    /// `nonce` the next unused one. Refused while another proposal is pending or scheduled.
    function queue(
        Policy calldata proposed,
        uint128 rewardRate,
        bytes32 expectedPolicyHash,
        uint64 nonce
    ) external returns (uint64) {
        if (msg.sender != AUTHORITY) revert NotAuthority();
        if (_pending.state != State.None) revert ProposalPending();
        if (nonce != nextNonce) revert StaleNonce(nextNonce);
        bytes32 inForce = _snapshots[_current].hash;
        if (expectedPolicyHash != inForce) revert StalePredecessor();
        _validate(proposed, rewardRate);
        uint64 nbp = ROOTS.progress() + DELAY_ROUNDS;
        uint64 nbt = ROOTS.ucTime() + DELAY_SECONDS;
        nextNonce = nonce + 1;
        _pending = Proposal({
            state: State.Queued,
            nonce: nonce,
            predecessor: inForce,
            policy: proposed,
            rewardRate: rewardRate,
            notBeforeProgress: nbp,
            notBeforeTime: nbt
        });
        emit Queued(
            nonce, inForce, keccak256(abi.encode(PROPOSAL_DOMAIN, proposed, rewardRate)), nbp, nbt
        );
        return nonce;
    }

    /// @notice Schedule a queued proposal once both delays have passed. Permissionless; it activates nothing.
    function execute(uint64 nonce) external {
        Proposal storage p = _pending;
        if (p.state == State.None || p.nonce != nonce) revert NoProposal();
        if (p.state != State.Queued) revert WrongState();
        if (ROOTS.progress() < p.notBeforeProgress || ROOTS.ucTime() < p.notBeforeTime) {
            revert DelayNotElapsed();
        }
        if (p.predecessor != _snapshots[_current].hash) revert StalePredecessor();
        _validate(p.policy, p.rewardRate);
        p.state = State.Scheduled;
        emit Executed(nonce);
    }

    /// @notice Withdraw the pending proposal, queued or scheduled. The nonce stays consumed, and an activated snapshot cannot be undone.
    function cancel(uint64 nonce) external {
        if (msg.sender != AUTHORITY) revert NotAuthority();
        Proposal storage p = _pending;
        if (p.state == State.None || p.nonce != nonce) revert NoProposal();
        delete _pending;
        emit Cancelled(nonce);
    }

    /// @notice Election-only: make a scheduled snapshot the policy in force, at the progress `p` of the election block. Returns whether one
    /// was activated. Called by `ElectionPolicy.elect` after its eligibility checks and before the election captures the policy ID.
    function activateDue(uint64 p, uint64 t) external returns (bool) {
        if (msg.sender != ELECTION) revert NotElection();
        Proposal storage s = _pending;
        if (s.state != State.Scheduled) return false;
        GovernanceSnapshot storage old = _snapshots[_current];
        if (s.predecessor != old.hash) revert StalePredecessor();
        _validate(s.policy, s.rewardRate);
        if (_current == type(uint32).max) revert PolicyIDExhausted();
        uint32 id = _current + 1;
        bytes32 h = _snapshotHash(id, old.hash, s.policy, s.rewardRate);
        _snapshots[id] = GovernanceSnapshot({
            policy: s.policy,
            rewardRate: s.rewardRate,
            hash: h,
            effectiveProgress: p,
            effectiveTime: t
        });
        _current = id;
        uint64 nonce = s.nonce;
        delete _pending;
        emit Activated(id, nonce, h, p);
        return true;
    }

    // --- internals ------------------------------------------------------------------------------

    function _snapshot(uint32 policyID) private view returns (GovernanceSnapshot storage s) {
        if (policyID == 0 || policyID > _current) revert UnknownPolicy();
        s = _snapshots[policyID];
    }

    function _validate(Policy memory p, uint128 rate) private pure {
        PolicyBounds.validate(p);
        if (rate > MAX_REWARD_RATE) revert RewardRateOutOfBounds();
    }

    function _snapshotHash(uint32 id, bytes32 predecessor, Policy memory p, uint128 rate)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(SNAPSHOT_DOMAIN, block.chainid, address(this), id, predecessor, p, rate)
        );
    }
}
