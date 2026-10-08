// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Policy, Delegation, ReserveInput, RootRecord} from "./P85Types.sol";

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

/// @notice Source of immutable policy snapshots. `currentPolicyID` names the snapshot in force;
/// a snapshot never changes, so an obligation that captured an ID keeps its terms forever.
interface IPolicySource {
    function policy() external view returns (Policy memory);
    function currentPolicyID() external view returns (uint32);
    function policyAt(uint32 policyID) external view returns (Policy memory);
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
            bytes32 rootKeyHash,
            bytes32 evmKeyHash,
            uint64 weight,
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
