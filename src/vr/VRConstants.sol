// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// @title VRConstants
/// @notice The frozen constants and codes of the ValidatorRegistry schema v1 (bft-core docs/design/validator-registry/schema-v1.md
/// sections 1 and 3, vrschema/constants.go and codes.go). Every value here is schema or rule; changing one is a new schema version.
library VRC {
    // ---- addresses (schema 1) ----
    address internal constant SYSTEM_CALLER = 0xff00000000000000000000000000000000000001;
    address internal constant SEAL_REGISTRY = 0xff00000000000000000000000000000000000002;

    // ---- namespaces and domains (schema 1, 2.1, 4) ----
    /// @dev ERC-7201 `unicity.vr.registry.v1`.
    bytes32 internal constant NAMESPACE =
        0x2015195c564edf8b5942ad7bb1fe48e96d190815eb762db2ddff1d85ce73f900;
    /// @dev ERC-7201 `unicity.vr.liability.v1`, the generic holder layout every liability holder writes in its own storage.
    bytes32 internal constant LIABILITY_NAMESPACE =
        0xb2905100cfe7c1af5dee2b1b6726fdfd755820e0f51ef675ed653be4f1102d00;
    bytes32 internal constant GENESIS_RESULT = keccak256("unicity.vr.genesis-result.v1");
    bytes32 internal constant REGISTRY_NATIVE = keccak256("unicity.vr.registry-native.v1");
    bytes32 internal constant MEMBERS_DOMAIN = keccak256("unicity.vr.members.v1");
    bytes32 internal constant CHANGES_DOMAIN = keccak256("unicity.vr.changes.v1");
    bytes32 internal constant OUTPUT_DOMAIN = keccak256("unicity.vr.output.v1");
    bytes32 internal constant NATIVE_RESULT_DOMAIN = keccak256("unicity.vr.native-result.v1");
    bytes32 internal constant REGISTER_DOMAIN = keccak256("unicity.vr.register");
    bytes32 internal constant BINDING_DOMAIN = keccak256("unicity.vr.binding");
    bytes32 internal constant EXPOSURE_DOMAIN = keccak256("unicity.p85.exposure");

    // ---- rules (schema 1) ----
    uint64 internal constant LIFETIME = 16_384; // provisional (design section 13)
    uint64 internal constant DELAY_ROUNDS = 2_000;
    uint64 internal constant DELAY_SECONDS = 3_600;
    uint256 internal constant MAX_PENDING_CHANGES = 32;
    uint256 internal constant MAX_BOUND_ROOT_SIDE = 8;
    uint256 internal constant MAX_BOUND_TOTAL = 16;
    uint256 internal constant MAX_BOUND_PAYLOAD = 64 * 1024;
    uint256 internal constant MAX_CHANGE_PAYLOAD = 16 * 1024;
    uint256 internal constant MAX_PENDING_FORCE = 4;
    uint256 internal constant MAX_COMMITTEE = 16;
    uint64 internal constant MIN_EPOCH_GAP = 100;
    uint8 internal constant MAX_HOLDERS = 8;
    uint32 internal constant MAX_ACTIVATIONS = 64;
    uint64 internal constant MAX_BASE_FEE = uint64(1) << 62;
    uint256 internal constant ELASTICITY = 2;
    uint8 internal constant NO_HOLDER = 0xff;
    uint256 internal constant ATTACH_CONTEXT_VERSION = 1;

    // ---- return caps, ABI envelope included (schema 1, 5) ----
    uint256 internal constant MAX_RET_ELECT = 160;
    uint256 internal constant MAX_RET_READY = 5408;
    uint256 internal constant MAX_RET_PENDING = 96;
    uint256 internal constant MAX_RET_ADOPTION = 96;
    uint256 internal constant MAX_RET_METADATA = 256;
    uint256 internal constant METADATA_GAS = 50_000;

    // ---- output states (schema 3.1) ----
    uint8 internal constant OUT_NONE = 0;
    uint8 internal constant OUT_RESERVED = 1;
    uint8 internal constant OUT_PUBLISHED = 2;
    uint8 internal constant OUT_INVALIDATED = 3;
    uint8 internal constant OUT_REJECTED = 4;
    uint8 internal constant OUT_ACKNOWLEDGED = 5;
    uint8 internal constant OUT_RECOVERED = 6;
    uint8 internal constant OUT_CLOSED = 7;

    // ---- other codes (schema 3.2) ----
    uint8 internal constant INVALID_LOST = 1;
    uint8 internal constant INVALID_WITHDRAWN = 2;
    uint8 internal constant REJ_EXPIRED = 1;
    uint8 internal constant REJ_INVALIDATED = 2;
    uint8 internal constant REJ_INVALID = 3;
    uint8 internal constant RES_ACKNOWLEDGED = 1;
    uint8 internal constant RES_RECOVERED = 2;
    uint8 internal constant RES_CLOSED = 3;
    uint8 internal constant HEALTHY = 0;
    uint8 internal constant FAULTED = 1;
    uint8 internal constant STALLED = 2;
    uint8 internal constant INCONSISTENT = 3;
    uint8 internal constant ELECT_DISABLED = 0;
    uint8 internal constant ELECT_NOT_DUE = 1;
    uint8 internal constant ELECT_RESERVED = 2;
    uint8 internal constant ELECT_NO_CANDIDATE = 3;
    uint8 internal constant PUB_PUBLISHED = 0;
    uint8 internal constant PUB_PENDING = 1;
    uint8 internal constant PUB_NOT_MINE = 2;
    uint8 internal constant PUB_PRECONDITION_FAILED = 3;
    uint8 internal constant STATUS_READY = 0;
    uint8 internal constant STATUS_PENDING = 1;
    uint8 internal constant STATUS_NOT_MINE = 2;
    uint8 internal constant STATUS_NOT_READY = 3;
    uint32 internal constant CAP_LIABILITY_HOLDER = 1;
    uint32 internal constant CAP_ADOPTION_CHECK = 2;

    // ---- change kinds and states (schema 3.2) ----
    uint8 internal constant K_SET_MODULE = 1;
    uint8 internal constant K_MODULE_ACTION = 2;
    uint8 internal constant K_SET_GOVERNOR = 3;
    uint8 internal constant K_COMMITTEE_LIMITS = 4;
    uint8 internal constant K_FEE_PARAMS = 5;
    uint8 internal constant K_REPLACE_AGGREGATOR = 6;
    uint8 internal constant K_ADD_PARTITION = 7;
    uint8 internal constant K_UPDATE_PARTITION = 8;
    uint8 internal constant K_SCHEDULE_ACTIVATION = 9;
    uint8 internal constant K_FORCE_REMOVE = 10;
    uint8 internal constant CH_NONE = 0;
    uint8 internal constant CH_QUEUED = 1;
    uint8 internal constant CH_SCHEDULED = 2;
    uint8 internal constant CH_BOUND = 3;
    uint8 internal constant CH_ACTIVE = 4;
    uint8 internal constant CH_REJECTED = 5;
    uint8 internal constant CH_CANCELLED = 6;

    // ---- verdicts and EVM-side reject reasons (schema 3.3) ----
    uint8 internal constant V_CONFLICT = 1;
    uint8 internal constant R_CODE_MISMATCH = 16;
    uint8 internal constant R_HOLDER_MISMATCH = 17;
    uint8 internal constant R_ADOPTION_NOT_READY = 18;
    uint8 internal constant R_ACTION_FAILED = 19;
    uint8 internal constant R_NOT_ACTIVE = 20;
    uint8 internal constant R_HOLDER_CEILING = 21;

    // ---- activation states (schema 3.2) ----
    uint8 internal constant ACT_ACTIVE = 1;
    uint8 internal constant ACT_SUPERSEDED = 2;
    uint8 internal constant ACT_LATCHED = 3;

    // ---- root-record kinds (schema 7) ----
    uint8 internal constant REC_SESSION_CLOSED = 1;
    uint8 internal constant REC_ACK = 2;
    uint8 internal constant REC_RECOVERY_ACK = 3;
    uint8 internal constant REC_CLOSURE = 4;
    uint8 internal constant REC_RETIREMENT = 5;
    uint8 internal constant REC_BOUNDARY = 6;
    uint8 internal constant REC_OUTPUT_REJECTED = 7;
    uint8 internal constant REC_HOLDER_RETIREMENT = 8;

    function rootSide(uint8 kind) internal pure returns (bool) {
        return kind == K_REPLACE_AGGREGATOR || kind == K_ADD_PARTITION || kind == K_UPDATE_PARTITION
            || kind == K_FORCE_REMOVE;
    }
}
