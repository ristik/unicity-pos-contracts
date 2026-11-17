// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// @notice A registration or binding proposal (design section 3.1). Both keys sign its digest (schema section 4.6).
struct Registration {
    string rootNodeID; // libp2p peer id, 1..128 bytes
    bytes rootKey; // 33-byte compressed secp256k1
    string evmNodeID; // 1..128 bytes
    bytes evmKey; // 33 bytes, != rootKey
    address payee; // nonzero plain EVM address
    uint64 nonce; // register: registrationNonce[msg.sender]; proposeBinding: bindingNonce[id]
}

/// @notice A committee member as an output and the committee in force carry it: ten ABI words (schema section 4.1).
struct Member {
    uint64 id;
    uint64 generation;
    uint64 weight;
    uint64 rawWeight;
    bytes32 rootNodeWord; // keccak256(utf8(rootNodeID))
    bytes32 rootKeyHash; // keccak256(rootKey)
    bytes32 evmNodeWord;
    bytes32 evmKeyHash;
    address payee;
    bytes32 exposureDigest;
}

/// @notice One binding with its preimages, as the write-once binding store keeps it (schema FD-16).
struct Binding {
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

struct IdentityView {
    address owner;
    uint64 generation; // of the current binding; zero for an unknown id
    bytes32 currentRef; // binding store key of the current binding
    bytes32 stagedRef; // zero when nothing is staged
    uint64 bindingNonce;
    uint64 registrationNonce; // the owner's next registration nonce
    Binding current;
    Binding staged;
    bytes endpoints; // advisory, never consensus input
}

struct OutputView {
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
    Member[] members; // empty until the output is Published
    uint64[] changes; // bound change ids, ascending
}

struct ChangeView {
    uint8 kind;
    uint8 state;
    uint8 rejectReason;
    uint64 notBeforeProgress;
    uint64 notBeforeTime;
    uint64 activeRootEpoch;
    uint64 scheduledAt;
    bytes32 payloadHash;
    bytes32 boundTo;
    bytes payload;
}

/// @notice A module's cached metadata (design section 3.3.3), read at SetModule queue time and never on a hook path.
struct ModuleMeta {
    bytes32 moduleTag;
    uint32 capabilities;
    uint64 maxElectionInterval;
    uint64[8] gasBounds; // electGas, outputGas, recordGas, resolvedGas, attachGas, detachGas, govGas, adoptGas
    address liabilityHolder;
    bytes32 liabilityHolderCodeHash;
}

struct ModuleView {
    address module;
    bytes32 codeHash;
    ModuleMeta meta;
    uint8 health;
    bool workPending;
    uint64 workSince;
    uint64 stallDeadline; // maxElectionInterval + 2 * LIFETIME
}

struct FeeSet {
    uint64 baseFeeFloor;
    uint64 changeDenominator;
    address feeCollector;
}

struct ConfigView {
    bytes32 network;
    address governor;
    uint32 nMin;
    uint32 nTarget;
    uint32 nMax;
    uint32 vMax;
    uint32 lMax;
    uint32 rMax;
    uint32 maxBatch;
    FeeSet feesPrevious;
    FeeSet feesCurrent;
    uint64 feesEffectiveBlock;
    uint64 delayRounds;
    uint64 delaySeconds;
    uint64 knownRootEpoch;
    uint64 epochStartProgress;
    uint64 maxGas; // the generation's fixed fee-profile fields
    uint64 systemGas;
    uint64 continuityMaxM;
    uint64 continuityDistNum;
    uint64 continuityDistDen;
}

struct Activation {
    bytes32 ruleId;
    bytes32 releaseDigest;
    uint64 rootEpoch;
    uint64 notBeforeUcTime;
    uint8 state; // 1 Active, 2 Superseded, 3 Latched
    uint64 changeId;
}

struct HolderView {
    address holder;
    bytes32 holderCodeHash;
    address module;
    uint64 registeredEpoch;
}

/// @notice One imported root record as the SealRegistry returns it (`recordAt`). ABI-identical to the P85 `RootRecord`; the kind is
/// read as a plain uint8 so record kinds 6 to 8 decode without an enum range check.
struct VRRecord {
    uint64 index;
    bytes32 recordID;
    bytes32 predecessor;
    uint8 kind;
    uint64 progress;
    uint64 ucTime;
    bytes data;
}

/// @notice The authenticated root-record source and clock (the SealRegistry at 0xff..02).
interface IVRRecordSource {
    function recordCount() external view returns (uint64);
    function recordAt(uint64 index) external view returns (VRRecord memory);
    function progress() external view returns (uint64);
    function ucTime() external view returns (uint64);
}

/// @notice The election-module interface (design section 3.2). Every call VR makes into it is a contained step (section 3.3).
interface IElectionModule {
    function moduleTag() external view returns (bytes32);
    function capabilities() external view returns (uint32);
    function gasBounds()
        external
        view
        returns (
            uint64 electGas,
            uint64 outputGas,
            uint64 recordGas,
            uint64 resolvedGas,
            uint64 attachGas,
            uint64 detachGas,
            uint64 govGas,
            uint64 adoptGas
        );
    function maxElectionInterval() external view returns (uint64);
    function liabilityHolder() external view returns (address holder, bytes32 codeHash);

    function adoptionReady(bytes calldata attachContext)
        external
        view
        returns (bytes memory packedStatus);
    function attach(bytes calldata attachContext) external;
    function detach() external;
    function onRecords(uint64 fromIndex, uint32 count) external;
    function onResolved(bytes32 resultId, uint8 resolution) external;
    function onGovernance(bytes calldata action) external;
    function elect(bytes calldata context) external returns (bytes memory packedElect);
    function outputOf(bytes32 resultId) external view returns (bytes memory packedOutput);
}

/// @notice The ValidatorRegistry (design section 3.1).
interface IValidatorRegistry {
    function recordCursor() external view returns (uint64);
    function limits() external view returns (uint32 vMax, uint32 lMax, uint32 rMax, uint32 maxBatch);
    function applyRootRecords(uint32 maxRecords) external;
    function elect(bytes32 origin) external returns (uint8 outcome);

    function register(Registration calldata r, bytes calldata rootPoP, bytes calldata evmPoP)
        external
        returns (uint64 id);
    function proposeBinding(
        uint64 id,
        Registration calldata r,
        bytes calldata rootPoP,
        bytes calldata evmPoP
    ) external;
    function setEndpoints(uint64 id, bytes calldata multiaddrs) external;
    function identity(uint64 id) external view returns (IdentityView memory);
    function ownerOf(uint64 id) external view returns (address);
    function binding(bytes32 ref) external view returns (Binding memory);

    function queue(uint8 kind, bytes calldata payload) external returns (uint64 changeId);
    function cancel(uint64 changeId) external;
    function execute(uint64 changeId) external;
    function change(uint64 changeId) external view returns (ChangeView memory);

    function publish(bytes32 resultId) external returns (uint8 status);
    function invalidate(bytes32 resultId, uint8 reason) external returns (bool changed);
    function output(bytes32 resultId) external view returns (OutputView memory);
    function openOutput() external view returns (bytes32);
    function lastAcked() external view returns (bytes32);
    function committee() external view returns (Member[] memory);
    function activeModule() external view returns (ModuleView memory);
    function config() external view returns (ConfigView memory);
    function activationCount() external view returns (uint32);
    function activationAt(uint32 i) external view returns (Activation memory);
    function holderCount() external view returns (uint8);
    function holderAt(uint8 h) external view returns (HolderView memory);
    function retired(uint8 holder, uint64 id, uint64 generation) external view returns (bool);
}

/// @notice VR's contained-step entry points: callable only by VR itself while it holds its lock.
interface IVRSteps {
    function stepVoid(address module, uint256 cap, bytes calldata data) external;
    function stepAdoption(address module, uint256 cap, bytes calldata ctx) external;
    function stepElect(bytes calldata ctx) external;
    function stepPublish(bytes32 rid) external;
}

/// @notice The complete external ABI of the VR account (core plus facets).
interface IVR is IValidatorRegistry, IVRSteps {
    function registrationNonce(address owner) external view returns (uint64);
    function pendingChanges() external view returns (uint64[] memory);
    function pendingPair() external view returns (bytes32);
    function health() external view returns (uint8);
    function feesFor(uint64 n) external view returns (FeeSet memory);
    function committeeIds() external view returns (uint64[] memory);
    function scheduledForceRemoves()
        external
        view
        returns (uint64[] memory changeIds, uint64[] memory targets, uint64[] memory scheduledAt);
    function bindingOf(uint64 id, bool staged) external view returns (Member memory);
}
