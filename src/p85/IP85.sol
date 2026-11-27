// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {
    AssignmentSeat,
    SeatBinding,
    Policy,
    Delegation,
    ReserveInput,
    RootRecord
} from "./P85Types.sol";

/// @notice A policy snapshot of the governed source: immutable once written. `effective*` is the election block that activated it (0 for genesis).
struct GovernanceSnapshot {
    Policy policy;
    uint128 rewardRate; // operator reward, base units per 1,000 progress units
    bytes32 hash; // chained to the predecessor snapshot's hash
    uint64 effectiveProgress;
    uint64 effectiveTime;
}

/// @notice The election entry point's hook into a governed policy source.
interface IGovernance {
    function activateDue(uint64 progress, uint64 ucTime) external returns (bool);
}

/// @notice Authenticated root-record source: the SealRegistry projection of verified control
/// records, canonical progress and quorum-approved UC time. PR2 consumes this interface; PR1
/// supplies the authenticated implementation. Relayers supply data, never finality.
interface IRootRecords {
    function recordCount() external view returns (uint64);
    function recordAt(uint64 index) external view returns (RootRecord memory);
    /// @notice Current canonical ordinary progress p.
    function progress() external view returns (uint64);
    /// @notice Current quorum-approved UC time in seconds, monotonic on one lineage.
    function ucTime() external view returns (uint64);
}

/// @notice One installed B1 epoch of the SealRegistry's permanent history, as the authenticated system writer stored it (the paired Go
/// node and the execution client verified its UTB lineage before the write). `present` is false for an epoch that is not installed, and
/// every other field is then zero. `end` is the successor's start once the successor is installed (`hasEnd`).
struct SealEpoch {
    bool present;
    uint64 start;
    bool hasEnd;
    uint64 end;
    uint64 signingScheme;
    bytes32 activationCommitID; // the H RecordID of the handoff that activated this epoch (zero for the genesis entry)
    uint64 memberCount;
    uint64 totalWeight;
}

/// @notice The bounded read-only view of the installed B1 history (SealRegistry). The ordinary B1 verifier (0x0100) is unchanged.
interface ISealHistory {
    function sealEpoch(uint64 epoch) external view returns (SealEpoch memory);
    /// @notice Member `index` of an installed epoch, in the stored order: its 33-byte compressed key and weight. Reverts out of range.
    function sealMember(uint64 epoch, uint256 index)
        external
        view
        returns (bytes memory key, uint64 weight);
}

/// @notice Source of immutable policy snapshots. `currentPolicyID` names the snapshot in force;
/// a snapshot never changes, so an obligation that captured an ID keeps its terms forever.
/// `reportWindow` (the wallet window W plus a reporting and inclusion margin) and `settlementMargin` are UC-second deployment
/// immutables: every snapshot the source accepts has `timeFloor >= reportWindow + settlementMargin`.
interface IPolicySource {
    function policy() external view returns (Policy memory);
    function currentPolicyID() external view returns (uint32);
    function policyAt(uint32 policyID) external view returns (Policy memory);
    function reportWindow() external view returns (uint64);
    function settlementMargin() external view returns (uint64);
}

interface IStakeCustody {
    function positions(uint64 id)
        external
        view
        returns (
            address owner,
            address withdrawal,
            bytes32 rootKeyHash,
            bytes32 stagedRootKeyHash,
            uint64 generation,
            uint64 roleNonce,
            uint32 openLots,
            uint32 lotCount,
            bool retirementRequested
        );
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
    function assignmentSeatCount(bytes32 assignmentID) external view returns (uint256);
    function assignmentSeat(bytes32 assignmentID, uint256 ordinal)
        external
        view
        returns (AssignmentSeat memory);
    function internSeatBinding(SeatBinding calldata binding) external;
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
    /// @notice A closed term's report anchors (#1297/#1298, `anchorTerm`): the applied Closure's terminal root R_H and H RecordID and
    /// the authenticated progress and UC time captured once the Closure, its attribution and the installed successor root epoch were
    /// jointly usable (`anchored`).
    function termAnchors(bytes32 assignmentID)
        external
        view
        returns (bytes32 terminalRoot, bytes32 hRecordID, uint64 p0, uint64 t0, bool anchored);
    function assignmentExposures(bytes32 assignmentID) external view returns (bytes32[] memory);
    function policyTerms(bytes32 assignmentID) external view returns (Policy memory);
    function lots(uint256 lotID)
        external
        view
        returns (
            uint64 id,
            uint64 generation,
            uint128 initial,
            uint128 remaining,
            uint128 penalized,
            uint8 category,
            uint16 capBps,
            uint32 refCount,
            uint64 holdRetirement,
            uint64 timeFloor,
            uint64 holdUntil,
            uint64 evidenceUntil,
            uint64 timeUntil
        );
    function lotUnanchoredTerms(uint256 lotID) external view returns (uint32);
    function retirements(uint64 id, uint64 generation)
        external
        view
        returns (bool imported, uint64 pRet, uint64 tRet);
    function generationLots(uint64 id, uint64 generation) external view returns (uint256[] memory);
    function exposureLots(bytes32 exposureID) external view returns (uint256[] memory);
    function keyOwner(bytes32 keyHash) external view returns (uint64 id, uint8 role);
    function lastAckedAssignment() external view returns (bytes32);
    function recordCursor() external view returns (uint64);
    function bondUnit() external view returns (uint128);
    function minBond() external view returns (uint128);
    function registerEvmKey(uint64 id, bytes32 evmKeyHash) external;
    function reserveCandidate(ReserveInput calldata input) external returns (bytes32 exposureDigest);
    function applyPenalty(bytes32 caseID, uint256 lotID)
        external
        returns (uint256 debit, uint256 bounty, uint256 treasuryCredit);
}

struct CaseView {
    bytes32 offenceID;
    bytes32 exposureID;
    uint64 id;
    address reporter;
    uint256 budget;
    uint256 debited;
    uint32 cursor;
    uint32 lotCount;
}

interface IEvidence {
    function caseInfo(bytes32 caseID) external view returns (CaseView memory);
    function caseLocation(bytes32 caseID)
        external
        view
        returns (bytes32 assignmentID, uint256 ordinal);
    function pendingHolds(uint256 lotID) external view returns (uint32);
    function excluded(uint64 id) external view returns (bool);
}

interface IElectionPolicy {
    function syncLiveIndex(uint64 id) external;
    /// @notice Evidence-only: an identity was excluded or had a penalty settled; the open result re-checks that member's coverage.
    function coverageChanged(uint64 id) external;
    /// @notice Custody-only: a reserved result reached its end (acknowledged, recovered or closed) at the record's anchors.
    function resultResolved(bytes32 resultID, uint8 outcome, uint64 progress, uint64 ucTime)
        external;
    function liveCount() external view returns (uint32);
    function isIndexed(uint64 id) external view returns (bool);
    function delegation(uint64 id, uint64 generation)
        external
        view
        returns (Delegation memory binding, bytes32 bindingHash, uint64 nextNonce);
}

/// @notice The adapter's side of the atomic loss (VT-04, design 3.8 change 2): `ElectionPolicy` calls it at the one place its `lost` bit is
/// first set, and it calls `VR.invalidate(resultID, LOST)`. Neither call is inside a `try/catch`.
interface IPosAdapter {
    function outputLost(bytes32 resultID) external;
}
