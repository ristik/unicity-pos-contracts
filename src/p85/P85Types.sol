// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// @notice Economic and protection policy captured per lot (cap, retirement hold) and per
/// assignment (penalty, evidence windows, holds). DEV-DEFAULT values, design v5 section 6.
/// Round-valued fields count canonical ordinary progress; `timeFloor` counts UC seconds.
struct Policy {
    uint16 penaltyBps; // objective offence penalty, basis points of exposed initial principal
    uint16 lifetimeCapBps; // aggregate per-lot lifetime penalty cap, basis points of initial
    uint16 bountyBps; // reporter share of the actual penalty
    uint128 bountyCap; // per-case bounty ceiling in base units
    uint64 evidenceWindow; // ordinary evidence window
    uint64 suffixEvidenceWindow; // evidence window after closure for old suffix signing
    uint64 holdNormal; // round hold after the liability anchor, ordinary
    uint64 holdSuffix; // round hold after the liability anchor, suffix-capable
    uint64 holdRetirement; // round hold after the imported retirement anchor
    uint64 timeFloor; // UC seconds after closure or retirement
}

/// @notice Fixed resource ceilings of the development profile (design v5 section 6).
struct Limits {
    uint32 vMax; // live-index and committee ceiling
    uint32 lMax; // lots per identity generation
    uint32 rMax; // live exposure references per lot
    uint32 maxBatch; // records, lots or proofs per batch call
}

/// @notice The election profile (design v5 section 6): committee cardinality, the churn budget of the continuity rule and the election
/// cadence. DEV-DEFAULT: nMin 4, nTarget 10, nMax 32, maxM 4, D <= 1/4, 100,000 ordinary progress rounds and 604,800 UC seconds.
struct ElectionParams {
    uint32 nMin;
    uint32 nTarget;
    uint32 nMax;
    uint64 maxM; // membership budget M = removed + added
    uint64 distNum; // weight distance D <= distNum / distDen
    uint64 distDen;
    uint64 cadenceRounds; // ordinary progress rounds since the last acknowledged ordinary rotation
    uint64 cadenceSeconds; // and UC seconds since it
}

struct GenesisIdentity {
    address owner;
    address withdrawal;
    bytes rootKey; // 33-byte compressed secp256k1
    bytes evmKey; // 33-byte compressed secp256k1
    bytes32 rootNodeID;
    bytes32 evmNodeID;
    address operatorPayee;
    uint256 bond; // native base units bonded at genesis
}

struct GenesisAssignment {
    bytes32 assignmentID;
    bytes32 lineage;
    uint64 rootEpoch;
    uint64 evmEpoch;
    uint64 firstRound;
}

/// @notice The genesis manifest every module is initialized with. Its hash is pinned by the
/// deployment record; each module stores it and refuses a second initialization.
struct Manifest {
    bytes32 network;
    uint256 chainId;
    address custody;
    address election;
    address evidence;
    address policySource;
    address roots; // authenticated root-record source (SealRegistry projection, PR1 fixture)
    address treasury;
    uint128 bondUnit;
    uint128 minBond;
    Limits limits;
    GenesisAssignment genesis;
    ElectionParams electionParams;
    GenesisIdentity[] identities;
}

/// @notice A staged EVM binding with its operator payee. Owned by ElectionPolicy, keyed by
/// (StakingID, generation).
struct Delegation {
    bytes32 rootNodeID;
    bytes rootKey;
    bytes32 evmNodeID;
    bytes evmKey;
    address operatorPayee;
}

/// @notice Signed admitDelegation payload (design v5 section 2). The owner authorizes it and the
/// EVM key proves possession over the same digest.
struct DelegationRequest {
    uint64 id;
    uint64 generation;
    Delegation binding;
    uint64 roleNonce;
    uint64 delegationNonce;
    uint64 expiry; // UC seconds
}

/// @notice Fixed-width custody wiring written by the factory at genesis (all fields static).
struct CustodyConfig {
    bytes32 network;
    address election;
    address evidence;
    address policySource;
    address roots;
    address treasury;
    uint128 bondUnit;
    uint128 minBond;
    Limits limits;
    GenesisAssignment genesis;
}

struct ReserveMember {
    uint64 id;
    uint64 weight;
    bytes32 rootKeyHash;
    bytes32 evmKeyHash;
    address operatorPayee;
    uint256[] lotIDs; // every unreleased lot of the identity's open generation, ascending
}

/// @notice Primary candidate reservation, written by the fixed ElectionPolicy at election.
/// The incumbent (recovery slate K) exposures are the last acknowledged assignment's; they are
/// locked for the session, never re-collateralized.
struct ReserveInput {
    bytes32 resultID;
    bytes32 assignmentID;
    bytes32 lineage;
    uint64 attempt;
    uint64 rootEpoch;
    uint64 evmEpoch;
    bytes32 incumbentAssignmentID;
    ReserveMember[] members; // ascending StakingID
}

enum RecordKind {
    None,
    SessionClosed,
    Ack,
    RecoveryAck,
    Closure,
    Retirement
}

/// @notice One authenticated root control record as projected by the SealRegistry. `progress` and
/// `ucTime` are the canonical progress and quorum-approved UC time anchors of the record.
struct RootRecord {
    uint64 index;
    bytes32 recordID; // authenticated record identifier assigned by the registry
    bytes32 predecessor; // recordID of index-1, zero for the first record
    RecordKind kind;
    uint64 progress;
    uint64 ucTime;
    bytes data;
}

struct SessionClosedData {
    bytes32 resultID;
}

struct AckData {
    bytes32 resultID;
    uint64 replacedHRound; // round at which H replaced the incumbent assignment
    uint64 offset; // successor progress offset p(e,h)+1
    uint64 firstRound; // successor activation round A*
}

struct RecoveryAckData {
    bytes32 resultID;
    bytes32 recoveryAssignmentID;
    uint64 jOffset;
    uint64 jFirstRound;
    uint64 jHRound; // round in J's epoch at which K's H was ordered
    uint64 kOffset;
    uint64 kFirstRound;
    uint64 kRootEpoch;
    uint64 kEvmEpoch;
}

struct ClosureData {
    bytes32 assignmentID;
    uint64 hRound;
    bytes32 hRecordID;
    bytes32 terminalRoot;
    bytes32 exposureDigest;
    bytes32 keyHistoryDigest;
}

struct RetirementData {
    uint64 id;
    uint64 generation;
    bytes32 refDigest;
}

/// @notice Identity position (roles, current/staged root key, open generation). Custody storage.
struct Position {
    address owner;
    address withdrawal;
    bytes32 rootKeyHash;
    bytes32 stagedRootKeyHash;
    uint64 generation;
    uint64 roleNonce;
    uint32 openLots; // unreleased lots of the open generation
    uint32 lotCount; // lots created in the open generation
    bool retirementRequested;
}

/// @notice One identity's attribution of its lots to one assignment's signing liability. Immutable
/// apart from the reference-release bit and session lock count.
struct Exposure {
    bytes32 assignmentID;
    uint64 id;
    uint64 generation;
    bytes32 rootKeyHash;
    bytes32 evmKeyHash;
    uint64 weight;
    address operatorPayee;
    bool referencesReleased;
    uint32 sessionLocks;
    uint256[] lotIDs;
}

/// @notice Assignment-level liability record. state: 0 none, 1 Reserved, 2 Active, 3 Aborted.
struct Assignment {
    uint8 state;
    bytes32 lineage;
    uint64 rootEpoch;
    uint64 evmEpoch;
    uint64 offset;
    uint64 firstRound;
    bool offsetSet;
    bool hKnown;
    uint64 hRound;
    bool closed;
    uint64 pClose;
    uint64 tClose;
    bytes32 closureKey;
    bytes32 exposureDigest;
    bytes32 keyDigest;
    uint32 policyID; // index into the custody policy table (captured obligation terms)
    bytes32[] exposureIDs;
}
