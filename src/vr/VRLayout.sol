// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRC} from "./VRConstants.sol";

/// @title VRLayout
/// @notice The ValidatorRegistry storage: one ERC-7201 struct at V = `unicity.vr.registry.v1` whose natural Solidity packing is the
/// frozen layout of schema v1 section 2.1 (V+0 .. V+15 and V+32 .. V+37, which the roots prove), plus VR-internal state in the reserved
/// ranges V+16 .. V+31 and V+38 .. V+63 (no root, node or ureth reads them). `test/vr/VRLayout.t.sol` writes the frozen scenarios
/// through this struct and compares every slot with the shared vectors.
library VRLayout {
    struct CommitteeLimits {
        uint32 nMin;
        uint32 nTarget;
        uint32 nMax;
    }

    struct HookLimits {
        uint32 vMax;
        uint32 lMax;
        uint32 rMax;
        uint32 maxBatch;
    }

    struct Status {
        uint8 health;
        uint64 knownRootEpoch;
        uint64 recordCursor;
        uint32 activationCount;
        uint8 holderCount;
    }

    struct Counters {
        uint64 nextChangeId;
        uint64 identityCount;
        uint64 nativeAttempt;
    }

    struct Fees {
        uint64 baseFeeFloor;
        uint64 changeDenominator;
        address feeCollector;
    }

    /// @dev outputs[R], 11 words (schema 2.2).
    struct Output {
        uint8 state;
        uint64 attempt;
        uint64 reservedProgress;
        uint64 expiresAtProgress;
        bytes32 predecessor;
        address sourceModule;
        bool native;
        bytes32 moduleTag;
        bytes32 membersDigest;
        bytes32 kDigest;
        bytes32 changesDigest;
        bytes32 snapshotDigest;
        bytes32 policyDigest;
        bytes32 outputCommit;
        uint8 invalidReason;
        uint64 invalidAtProgress;
    }

    /// @dev changes[id], 4 words (schema 2.3).
    struct Change {
        uint8 kind;
        uint8 state;
        uint8 rejectReason;
        uint64 notBeforeProgress;
        uint64 notBeforeTime;
        uint64 activeRootEpoch;
        bytes32 payloadHash;
        bytes32 boundTo;
        uint64 scheduledAt;
        uint32 payloadLength;
    }

    struct Activation {
        bytes32 ruleId;
        bytes32 releaseDigest;
        uint64 rootEpoch;
        uint64 notBeforeUcTime;
        uint8 state;
        uint64 changeId;
    }

    struct Holder {
        address holder;
        uint64 registeredEpoch;
        bytes32 holderCodeHash;
        address module;
    }

    // ---- VR-internal ----

    /// @dev The cached metadata of the active module (V+16 .. V+21).
    struct ModuleCache {
        bytes32 moduleTag; // V+16
        uint32 capabilities; // V+17
        uint64 maxElectionInterval;
        uint64[8] gasBounds; // V+18, V+19
        address liabilityHolder; // V+20
        bytes32 liabilityHolderCodeHash; // V+21
    }

    /// @dev Watchdogs and the cached clock (V+22).
    struct Watch {
        uint64 workSince; // progress at which the current work began
        bool workPending; // Scheduled boundary work or an executed ModuleAction with no completed boundary since
        bool actionWork; // an executed ModuleAction is part of the pending work
        uint64 epochStartProgress; // progress at which VR applied the current epoch's Boundary (genesis: the pinned value)
        uint64 cachedProgress; // SealRegistry progress at the last hook (invalidate calls nothing)
    }

    /// @dev Counters of the pending change set (V+23).
    struct Pending {
        bool pairRecovered; // the staged pair is a RecoveryAck
        uint8 pendingCount; // changes not Active, Cancelled or Rejected
        uint8 pendingForce; // ForceRemove changes Queued, Scheduled or Bound
        uint8 pendingSchedules; // ScheduleActivation changes not yet terminal
    }

    /// @dev The generation's fixed parameters (V+24, V+25): the genesis EVM PDR continuity budget and the fee profile's fixed fields.
    struct GenerationParams {
        uint64 maxM; // V+24 (with the next three)
        uint64 distNum;
        uint64 distDen;
        uint64 maxGas;
        uint64 systemGas; // V+25
    }

    struct Identity {
        address owner;
        uint64 generation; // of the current binding (1 at registration)
        bytes32 currentRef; // binding store key of the current binding
        bytes32 stagedRef; // zero when nothing is staged
        uint64 bindingNonce;
        bytes endpoints;
    }

    /// @dev A write-once binding (schema FD-16): the five binding words and their preimages, keyed by the hash of the words.
    struct BindingRecord {
        bytes32 rootNodeWord;
        bytes32 rootKeyHash;
        bytes32 evmNodeWord;
        bytes32 evmKeyHash;
        address payee;
        string rootNodeID;
        bytes rootKey;
        string evmNodeID;
        bytes evmKey;
    }

    /// @dev A committee member or an output member, three words: the binding is referenced into the binding store.
    struct Seat {
        uint64 id;
        uint64 generation;
        uint64 weight;
        uint64 rawWeight;
        bytes32 bindingRef;
        bytes32 exposureDigest;
    }

    /// @custom:storage-location erc7201:unicity.vr.registry.v1
    struct VRStorage {
        bytes32 network; // V+0
        bytes32 openOutput; // V+1
        bytes32 lastAcked; // V+2
        bytes32 pendingPair; // V+3
        CommitteeLimits committeeLimits; // V+4
        HookLimits hookLimits; // V+5
        Status status; // V+6
        address activeModule; // V+7
        bytes32 activeModuleCodeHash; // V+8
        address governor; // V+9
        Counters counters; // V+10
        Fees feesPrevious; // V+11, V+12
        Fees feesCurrent; // V+13, V+14
        uint64 feesEffectiveBlock; // V+15
        // ---- V+16 .. V+31: VR-internal ----
        ModuleCache module; // V+16 .. V+21
        Watch watch; // V+22
        Pending pending; // V+23
        GenerationParams params; // V+24, V+25
        bytes32 committeeDigest; // V+26: membersDigest of committee()
        uint256[5] reservedInternal; // V+27 .. V+31
        // ---- V+32 .. V+37: proven mappings ----
        mapping(bytes32 => Output) outputs; // V+32
        mapping(uint64 => Change) changes; // V+33
        mapping(uint64 => bytes) changePayload; // V+34
        mapping(uint32 => Activation) activations; // V+35
        mapping(uint8 => Holder) holders; // V+36
        mapping(uint8 => mapping(uint64 => mapping(uint64 => bool))) retired; // V+37
        // ---- V+38 .. V+63: VR-internal ----
        mapping(uint64 => Identity) identities; // V+38
        mapping(bytes32 => uint256) keyOwner; // V+39: keyHash => id << 8 | role (1 root, 2 evm)
        mapping(address => uint64) registrationNonce; // V+40
        mapping(bytes32 => BindingRecord) bindings; // V+41
        Seat[] committee; // V+42: the committee in force, ascending id
        mapping(bytes32 => Seat[]) outputSeats; // V+43
        mapping(bytes32 => uint64[]) outputChanges; // V+44: bound change ids, ascending
        uint64[] pendingIds; // V+45: changes not Active, Cancelled or Rejected, ascending
        mapping(uint64 => bytes32) changeScope; // V+46
        mapping(uint64 => ModuleCache) changeModule; // V+47: SetModule metadata cached at queue
        mapping(address => bool) detached; // V+48
        mapping(address => uint8) holderIndexPlusOne; // V+49
    }

    function load() internal pure returns (VRStorage storage $) {
        bytes32 ns = VRC.NAMESPACE;
        assembly ("memory-safe") {
            $.slot := ns
        }
    }
}
