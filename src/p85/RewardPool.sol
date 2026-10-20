// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded: at most MAX_MEMBERS committee members, the policy snapshots since the last interval, and two records per call. The
// getters of custody and the session return more fields than this module needs, so the unused ones are dropped on purpose.
// forge-lint: disable-start(calls-loop, unused-return, uninitialized-local)

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IRootRecords, GovernanceSnapshot} from "./IP85.sol";
import {RecordKind, RootRecord, AckData, RecoveryAckData} from "./P85Types.sol";

interface IRewardCustody {
    function recordCursor() external view returns (uint64);
    function session(bytes32 resultID)
        external
        view
        returns (
            uint8 state,
            bytes32 assignmentID,
            bytes32 lineage,
            uint64 attempt,
            bytes32 incumbentAssignmentID
        );
    function assignmentExposures(bytes32 assignmentID) external view returns (bytes32[] memory);
    function exposures(bytes32 exposureID)
        external
        view
        returns (
            bytes32 assignmentID,
            uint64 id,
            uint64 generation,
            uint64 weight,
            uint64 rawWeight,
            bytes32 rootKeyHash,
            bytes32 evmKeyHash,
            address operatorPayee,
            bool referencesReleased,
            uint32 sessionLocks
        );
    function assignments(bytes32 assignmentID)
        external
        view
        returns (
            uint8 state,
            bytes32 lineage,
            uint64 rootEpoch,
            uint64 evmEpoch,
            uint64 offset,
            uint64 firstRound,
            bool offsetSet,
            bool hKnown,
            uint64 hRound,
            bool closed,
            uint64 pClose,
            uint64 tClose,
            bytes32 closureKey,
            bytes32 exposureDigest,
            bytes32 keyDigest,
            uint32 policyID
        );
}

interface IRewardElection {
    function openResult() external view returns (bytes32);
}

interface IRewardGovernance {
    function currentPolicyID() external view returns (uint32);
    function rewardRateAt(uint32 policyID) external view returns (uint128);
    function snapshotAt(uint32 policyID) external view returns (GovernanceSnapshot memory);
}

/// @title RewardPool
/// @notice Funded operator rewards (T8 #47 / P7 #54, briefs/t8-p7-design.md sections 4 and 5). Rewards are paid from an explicitly funded
/// pool, per authenticated assignment interval, to the operator payees frozen in that assignment's exposures, by pull claim. Nothing is
/// minted; custody, treasury credits, fees and bridge backing are never touched; `FeeCollector.rewardPot` is not counted (design section 6).
///
/// The timeline is derived from the authenticated root records alone (read from the pinned registry, only once custody has applied
/// them), never from caller-supplied finality, weights or current mutable payees:
///   - the genesis assignment owns [start, ...);
///   - an Ack ends the incumbent at its `offset` and starts the successor there;
///   - a RecoveryAck ends the incumbent at `jOffset`, gives J [jOffset, kOffset) (a zero-length interval when they coincide) and starts K
///     at `kOffset`;
///   - SessionClosed, Closure and Retirement records move no boundary, so an aborted candidate earns nothing.
/// Intervals are half-open [a, b). `b` is the earliest of: the owner's end, the next point of the fixed grid (every GRID progress units
/// from the start), and the progress a later policy snapshot (a new reward rate) took effect. A caller chooses no endpoint and no length.
/// An interval is closed only up to the current canonical progress (`b <= progress`), and the tail of the latest assignment only while the
/// record prefix is fully applied and no election result is open, because an open result may still end the tail earlier.
///
/// For length L = b - a and the rate q in force at `a`: nominal = floor(q * L / 1000), budget = min(nominal, available). Each member of
/// the owning assignment, in the exposures' canonical order, is credited floor(budget * weight / totalWeight) (the committed, quantized
/// weight); the rounding dust returns to `available` in the same call, so no later budget depends on how work was split across calls. A
/// committee has at most MAX_MEMBERS members (the election's nMax), so one call closes one interval and settles all of it atomically.
/// Zero funding or a zero rate gives a zero budget and still advances the cursor; later funding never reopens a closed interval.
/// A failure of any reward step reverts only that call: it never blocks an election, a recovery, a penalty or an exit.
///
/// Conservation, after every call: balance = available + operatorCredits + surplus, with surplus >= 0 (forced value is surplus).
// forge-lint: disable-next-line(locked-ether)
contract RewardPool is ReentrancyGuard {
    error ZeroAddress();
    error NothingToDo();
    error NotCaughtUp();
    error TimelineMismatch();
    error RecordOutOfOrder();
    error CommitteeTooLarge();
    error ZeroTotalWeight();
    error InsufficientCredit();
    error TransferFailed();
    error TooManyRecords();
    error NoDirectPayment();

    struct Segment {
        bytes32 assignmentID;
        uint64 start;
        uint64 end; // exclusive; meaningful when `ended`
        bool ended;
    }

    event Funded(address indexed from, uint256 amount);
    event TimelineExtended(uint64 indexed recordIndex, uint256 segments);
    event IntervalClosed(
        uint256 indexed segment,
        uint64 start,
        uint64 end,
        uint128 rate,
        uint256 budget,
        uint256 distributed
    );
    event Credited(address indexed payee, uint256 amount);
    event Claimed(address indexed payee, address indexed to, uint256 amount);

    /// @dev The fixed closing grid (design section 3): 1,000 progress units, anchored at START.
    uint64 public constant GRID = 1_000;
    uint256 public constant MAX_MEMBERS = 16;
    uint32 public constant MAX_RECORDS_PER_CALL = 2;
    uint256 internal constant RATE_UNITS = 1_000;

    IRootRecords public immutable ROOTS;
    IRewardCustody public immutable CUSTODY;
    IRewardElection public immutable ELECTION;
    IRewardGovernance public immutable GOVERNANCE;
    /// @notice The progress at which rewards start: the genesis assignment's offset.
    uint64 public immutable START;

    Segment[] private _segments;
    uint256 public segmentCursor; // the segment the next interval belongs to
    uint64 public nextStart; // where the next interval begins
    uint32 public rateCursor; // the policy snapshot whose rate is in force at nextStart
    uint64 public recordCursor; // this pool's own cursor over the authenticated records
    bytes32 public lastRecordID;

    uint256 public available;
    uint256 public totalCredits;
    mapping(address => uint256) public credits;

    /// @param genesisAssignmentID the genesis assignment of the manifest; its offset is the reward start.
    constructor(
        address roots,
        address custody,
        address election,
        address governance,
        bytes32 genesisAssignmentID
    ) payable {
        if (
            roots == address(0) || custody == address(0) || election == address(0)
                || governance == address(0)
        ) revert ZeroAddress();
        ROOTS = IRootRecords(roots);
        CUSTODY = IRewardCustody(custody);
        ELECTION = IRewardElection(election);
        GOVERNANCE = IRewardGovernance(governance);
        (,,,, uint64 offset,, bool offsetSet,,,,,,,,,) = CUSTODY.assignments(genesisAssignmentID);
        if (!offsetSet) revert TimelineMismatch();
        // a genesis committee over the settlement bound could never be settled: refuse it at deployment, not at the first interval
        if (CUSTODY.assignmentExposures(genesisAssignmentID).length > MAX_MEMBERS) {
            revert CommitteeTooLarge();
        }
        START = offset;
        _segments.push(Segment(genesisAssignmentID, offset, 0, false));
        nextStart = offset;
        rateCursor = 1;
        available = msg.value;
        if (msg.value != 0) emit Funded(msg.sender, msg.value);
    }

    receive() external payable {
        revert NoDirectPayment();
    }

    /// @notice Add funding. Only value sent here is allocated; forced or unexpected value is surplus.
    function fund() external payable {
        available += msg.value;
        emit Funded(msg.sender, msg.value);
    }

    // --- views -----------------------------------------------------------------------------------

    function segmentCount() external view returns (uint256) {
        return _segments.length;
    }

    function segmentAt(uint256 i) external view returns (Segment memory) {
        return _segments[i];
    }

    /// @notice Native currency the pool owes or has allocated: available funding plus unclaimed operator credits.
    function accounted() public view returns (uint256) {
        return available + totalCredits;
    }

    /// @notice Value held beyond what is allocated (forced transfers); never allocated to rewards.
    function surplus() external view returns (uint256) {
        return address(this).balance - accounted();
    }

    // --- the authenticated timeline --------------------------------------------------------------

    /// @notice Extend the timeline by up to `maxRecords` (at most two) authenticated records, in order, each only once custody has applied it.
    function advanceRecords(uint32 maxRecords) external returns (uint32 processed) {
        if (maxRecords > MAX_RECORDS_PER_CALL) revert TooManyRecords();
        uint64 count = ROOTS.recordCount();
        uint64 applied = CUSTODY.recordCursor();
        while (processed < maxRecords) {
            uint64 i = recordCursor;
            if (i >= count || i >= applied) break;
            RootRecord memory r = ROOTS.recordAt(i);
            if (r.index != i || r.predecessor != lastRecordID) revert RecordOutOfOrder();
            _apply(r);
            lastRecordID = r.recordID;
            recordCursor = i + 1;
            ++processed;
        }
        if (processed == 0) revert NothingToDo();
    }

    function _apply(RootRecord memory r) private {
        if (r.kind == RecordKind.Ack) {
            AckData memory d = abi.decode(r.data, (AckData));
            (, bytes32 successor,,, bytes32 incumbent) = CUSTODY.session(d.resultID);
            _endLast(incumbent, d.offset);
            _segments.push(Segment(successor, d.offset, 0, false));
            emit TimelineExtended(r.index, _segments.length);
        } else if (r.kind == RecordKind.RecoveryAck) {
            RecoveryAckData memory d = abi.decode(r.data, (RecoveryAckData));
            (, bytes32 j,,, bytes32 incumbent) = CUSTODY.session(d.resultID);
            if (d.kOffset < d.jOffset) revert TimelineMismatch();
            _endLast(incumbent, d.jOffset);
            _segments.push(Segment(j, d.jOffset, d.kOffset, true));
            _segments.push(Segment(d.recoveryAssignmentID, d.kOffset, 0, false));
            emit TimelineExtended(r.index, _segments.length);
        }
    }

    /// @dev The latest segment must be the incumbent and open; it ends at `boundary`, never before what was already rewarded.
    function _endLast(bytes32 incumbent, uint64 boundary) private {
        uint256 last = _segments.length - 1;
        Segment storage s = _segments[last];
        if (s.ended || s.assignmentID != incumbent || boundary < s.start) {
            revert TimelineMismatch();
        }
        if (last == segmentCursor && boundary < nextStart) revert TimelineMismatch();
        s.end = boundary;
        s.ended = true;
    }

    // --- closing and settling one interval -------------------------------------------------------

    /// @notice Close the next interval and settle all of it. Permissionless ordinary work: the caller chooses neither the endpoint nor the
    /// length. Reverts with `NothingToDo` when no interval can be closed yet.
    function closeInterval() external returns (uint64 start, uint64 end, uint256 budget) {
        Segment storage s = _segments[segmentCursor];
        start = nextStart;
        // a finished (or zero-length) segment hands over to the next one without an interval
        while (s.ended && start >= s.end) {
            if (segmentCursor + 1 >= _segments.length) revert TimelineMismatch();
            ++segmentCursor;
            s = _segments[segmentCursor];
            if (s.start != start) revert TimelineMismatch();
        }
        if (start < s.start) revert TimelineMismatch();
        if (!s.ended) {
            // the tail can still be ended by a record or an open election result
            if (
                recordCursor != ROOTS.recordCount() || CUSTODY.recordCursor() != recordCursor
                    || ELECTION.openResult() != bytes32(0)
            ) revert NotCaughtUp();
        }
        end = _intervalEnd(s, start);
        if (end <= start || end > ROOTS.progress()) revert NothingToDo();

        uint128 rate = GOVERNANCE.rewardRateAt(rateCursor);
        uint256 nominal = Math.mulDiv(rate, end - start, RATE_UNITS);
        budget = nominal < available ? nominal : available;
        available -= budget;
        nextStart = end;
        uint256 distributed = budget == 0 ? 0 : _settle(s.assignmentID, budget);
        available += budget - distributed; // the dust, in the same call
        emit IntervalClosed(segmentCursor, start, end, rate, budget, distributed);
    }

    /// @dev The earliest boundary after `start`: the owner's end, the next grid point, the next policy snapshot's effective progress.
    /// Also advances the rate cursor to the snapshot in force at `start`.
    function _intervalEnd(Segment storage s, uint64 start) private returns (uint64 end) {
        end = type(uint64).max;
        if (s.ended) end = s.end;
        uint64 grid = START + ((start - START) / GRID + 1) * GRID;
        if (grid < end) end = grid;
        uint32 count = GOVERNANCE.currentPolicyID();
        uint32 cursor = rateCursor;
        while (cursor < count && GOVERNANCE.snapshotAt(cursor + 1).effectiveProgress <= start) {
            ++cursor;
        }
        if (cursor != rateCursor) rateCursor = cursor;
        if (cursor < count) {
            uint64 effective = GOVERNANCE.snapshotAt(cursor + 1).effectiveProgress;
            if (effective < end) end = effective;
        }
    }

    function _settle(bytes32 assignmentID, uint256 budget) private returns (uint256 distributed) {
        bytes32[] memory ids = CUSTODY.assignmentExposures(assignmentID);
        uint256 n = ids.length;
        if (n > MAX_MEMBERS) revert CommitteeTooLarge();
        uint64[] memory weights = new uint64[](n);
        address[] memory payees = new address[](n);
        uint256 total;
        for (uint256 i = 0; i < n; ++i) {
            (,,, uint64 weight,,,, address payee,,) = CUSTODY.exposures(ids[i]);
            weights[i] = weight;
            payees[i] = payee;
            total += weight;
        }
        if (total == 0) revert ZeroTotalWeight();
        for (uint256 i = 0; i < n; ++i) {
            uint256 share = Math.mulDiv(budget, weights[i], total);
            if (share == 0) continue;
            credits[payees[i]] += share;
            distributed += share;
            emit Credited(payees[i], share);
        }
        totalCredits += distributed;
    }

    // --- claims ----------------------------------------------------------------------------------

    /// @notice Pay `amount` of the caller's credit to `to`. Effects before the call; a recipient that reverts fails only this claim.
    function claim(uint256 amount, address payable to) external nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        uint256 credit = credits[msg.sender];
        if (amount == 0 || amount > credit) revert InsufficientCredit();
        credits[msg.sender] = credit - amount;
        totalCredits -= amount;
        // The destination is the credit holder's own choice and the amount is bounded by its own credit (effects come first).
        // forge-lint: disable-next-line(unchecked-call, arbitrary-send-eth)
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Claimed(msg.sender, to, amount);
    }
}

// forge-lint: disable-end
