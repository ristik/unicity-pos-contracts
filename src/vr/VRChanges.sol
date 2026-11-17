// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// The PDR head reader returns (ok, value, position) tuples with explicit defaults; `(l + 31) / 32 * 32` rounds up to whole words;
// payload fields are narrowed only after `checkAbi` proved their width.
// forge-lint: disable-start(boolean-cst, divide-before-multiply, unsafe-typecast)

import {VRC} from "./VRConstants.sol";

/// @title VRChanges
/// @notice Strict decoding and structural queue-time validation of governed change payloads (design section 3.5.3; schema v1 sections
/// 6.1 to 6.3; bft-core vrschema/changes.go, abi.go, fees.go and scope.go). A payload is accepted only when it is exactly the
/// `abi.encode` of its kind's fields: canonical offsets with the dynamic tails in field order directly after the head, zero padding,
/// narrow integers zero-extended and no trailing bytes. `abi.decode` accepts more than that, so it is never used on a payload.
///
/// Everything here is pure: VR adds the chain checks (code presence and metadata for SetModule) and the state it passes in `Env`.
library VRChanges {
    // Queue refusal codes, in the order the reference checks them. VR reverts `QueueRefused(code)`.
    uint8 internal constant OK = 0;
    uint8 internal constant UNKNOWN_KIND = 1;
    uint8 internal constant TOO_MANY_PENDING = 2;
    uint8 internal constant OVERSIZE = 3;
    uint8 internal constant LENGTH = 4;
    uint8 internal constant OFFSET = 5;
    uint8 internal constant PADDING = 6;
    uint8 internal constant NARROW = 7;
    uint8 internal constant RANGE = 8; // a value out of range (zero address or code hash, committee limits, zero ruleId)
    uint8 internal constant ZERO_PARAMETER = 9;
    uint8 internal constant NO_ORDINARY_CAPACITY = 10;
    uint8 internal constant INVALID_PARENT_BASE_FEE = 11;
    uint8 internal constant UNSUPPORTED_PROFILE = 12;
    uint8 internal constant ZERO_FEE_COLLECTOR = 13;
    uint8 internal constant SCHEDULE_TOO_EARLY = 14;
    uint8 internal constant SCHEDULE_TOO_SOON = 15;
    uint8 internal constant NOT_IN_COMMITTEE = 16;
    uint8 internal constant TOO_MANY_FORCE_REMOVES = 17;
    uint8 internal constant UNREADABLE_SCOPE = 18;
    // VR chain checks (not part of the pure reference check)
    uint8 internal constant NO_CODE = 20;
    uint8 internal constant CODE_HASH_MISMATCH = 21;
    uint8 internal constant BAD_METADATA = 22;
    uint8 internal constant TOO_MANY_ACTIVATIONS = 23;

    // Field type codes of the kind signatures.
    uint8 internal constant T_ADDRESS = 0xa0;
    uint8 internal constant T_BYTES32 = 0xb2;
    uint8 internal constant T_DYNAMIC = 0xd0; // bytes or string (byte canonicality only, no UTF-8 rule)
    uint8 internal constant T_UINT32 = 4;
    uint8 internal constant T_UINT64 = 8;

    uint256 internal constant PDR_TAG = 39008;

    /// @notice The VR state a queue-time check reads.
    struct Env {
        uint64 knownRootEpoch;
        uint64 ucTime;
        uint256 pending; // changes not Active, Cancelled or Rejected
        uint256 pendingForce; // ForceRemove changes Queued, Scheduled or Bound
        uint64[] committee; // ids of the committee in force
        uint64 maxGas; // the generation's fixed fee-profile fields
        uint64 systemGas;
    }

    /// @notice The frozen abi.encode field types of a kind (vrschema ChangePayloadTypes); empty for an unknown kind.
    function types(uint8 kind) internal pure returns (bytes memory) {
        if (kind == VRC.K_SET_MODULE) return abi.encodePacked(T_ADDRESS, T_BYTES32, T_DYNAMIC);
        if (kind == VRC.K_MODULE_ACTION) return abi.encodePacked(T_ADDRESS, T_DYNAMIC);
        if (kind == VRC.K_SET_GOVERNOR) return abi.encodePacked(T_ADDRESS, T_BYTES32);
        if (kind == VRC.K_COMMITTEE_LIMITS) return abi.encodePacked(T_UINT32, T_UINT32, T_UINT32);
        if (kind == VRC.K_FEE_PARAMS) return abi.encodePacked(T_UINT64, T_UINT64, T_ADDRESS);
        if (kind == VRC.K_REPLACE_AGGREGATOR) {
            return abi.encodePacked(T_UINT32, T_DYNAMIC, T_BYTES32, T_DYNAMIC, T_DYNAMIC);
        }
        if (kind == VRC.K_ADD_PARTITION) return abi.encodePacked(T_DYNAMIC, T_DYNAMIC);
        if (kind == VRC.K_UPDATE_PARTITION) {
            return abi.encodePacked(T_UINT32, T_DYNAMIC, T_BYTES32, T_DYNAMIC);
        }
        if (kind == VRC.K_SCHEDULE_ACTIVATION) {
            return abi.encodePacked(T_BYTES32, T_BYTES32, T_UINT64, T_UINT64, T_DYNAMIC);
        }
        if (kind == VRC.K_FORCE_REMOVE) return abi.encodePacked(T_UINT64);
        return "";
    }

    function _word(bytes memory b, uint256 offset) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), offset))
        }
    }

    /// @notice The strict decoder of `types` over `data` (vrschema DecodeABI): OK or the first refusal in head order.
    function checkAbi(bytes memory ts, bytes memory data) internal pure returns (uint8) {
        uint256 n = ts.length;
        if (data.length < 32 * n || data.length % 32 != 0) return LENGTH;
        uint256 next = 32 * n;
        for (uint256 i = 0; i < n; ++i) {
            uint8 t = uint8(ts[i]);
            uint256 w = _word(data, 32 * i);
            if (t == T_DYNAMIC) {
                if (w != next) return OFFSET;
                if (next + 32 > data.length) return LENGTH;
                uint256 l = _word(data, next);
                if (l > data.length - next - 32) return LENGTH;
                uint256 start = next + 32;
                uint256 padded = start + (l + 31) / 32 * 32;
                if (padded > data.length) return LENGTH;
                for (uint256 j = start + l; j < padded; ++j) {
                    if (data[j] != 0) return PADDING;
                }
                next = padded;
            } else if (t == T_ADDRESS) {
                if (w > type(uint160).max) return NARROW;
            } else if (t != T_BYTES32) {
                if (w >> (8 * uint256(t)) != 0) return NARROW;
            }
        }
        if (next != data.length) return LENGTH;
        return OK;
    }

    /// @notice Static field `i` of an already checked payload.
    function field(bytes memory data, uint256 i) internal pure returns (uint256) {
        return _word(data, 32 * i);
    }

    /// @notice Dynamic field `i` of an already checked payload, copied out.
    function dynField(bytes memory data, uint256 i) internal pure returns (bytes memory out) {
        uint256 off = _word(data, 32 * i);
        uint256 l = _word(data, off);
        out = new bytes(l);
        for (uint256 j = 0; j < l; ++j) {
            out[j] = data[off + 32 + j];
        }
    }

    /// @notice Strict payload decoding: the size bound first, then the exact ABI shape (vrschema DecodeChangePayload).
    function checkPayload(uint8 kind, bytes memory payload) internal pure returns (uint8) {
        bytes memory ts = types(kind);
        if (ts.length == 0) return UNKNOWN_KIND;
        if (payload.length > VRC.MAX_CHANGE_PAYLOAD) return OVERSIZE;
        return checkAbi(ts, payload);
    }

    /// @notice The fee-profile validity (vrschema ValidateProfile, the ureth `BlockProfile.validate` equivalent plus the collector).
    function validateFees(
        uint64 maxGas,
        uint64 systemGas,
        uint64 floor_,
        uint64 denominator,
        address collector
    ) internal pure returns (uint8) {
        if (maxGas == 0 || systemGas == 0 || floor_ == 0 || denominator == 0) {
            return ZERO_PARAMETER;
        }
        if (systemGas >= maxGas) return NO_ORDINARY_CAPACITY;
        if (floor_ > VRC.MAX_BASE_FEE) return INVALID_PARENT_BASE_FEE;
        if ((maxGas - systemGas) % VRC.ELASTICITY != 0) return UNSUPPORTED_PROFILE;
        if (collector == address(0)) return ZERO_FEE_COLLECTOR;
        return OK;
    }

    /// @notice The structural, state-light queue check (design section 3.5.3, schema 6.2; vrschema QueueCheck).
    function check(uint8 kind, bytes memory payload, Env memory env) internal pure returns (uint8) {
        if (kind == 0 || kind > VRC.K_FORCE_REMOVE) return UNKNOWN_KIND;
        if (env.pending >= VRC.MAX_PENDING_CHANGES) return TOO_MANY_PENDING;
        uint8 e = checkPayload(kind, payload);
        if (e != OK) return e;
        if (kind == VRC.K_SET_MODULE || kind == VRC.K_SET_GOVERNOR) {
            if (field(payload, 0) == 0 || field(payload, 1) == 0) return RANGE;
        } else if (kind == VRC.K_COMMITTEE_LIMITS) {
            uint256 nMin = field(payload, 0);
            uint256 nTarget = field(payload, 1);
            uint256 nMax = field(payload, 2);
            if (nMin < 1 || nMin > nTarget || nTarget > nMax || nMax > VRC.MAX_COMMITTEE) {
                return RANGE;
            }
        } else if (kind == VRC.K_FEE_PARAMS) {
            // forge-lint: disable-next-line(unsafe-typecast)
            return validateFees(
                env.maxGas,
                env.systemGas,
                uint64(field(payload, 0)),
                uint64(field(payload, 1)),
                address(uint160(field(payload, 2)))
            );
        } else if (kind == VRC.K_ADD_PARTITION) {
            (bool ok,) = pdrPartition(dynField(payload, 0));
            if (!ok) return UNREADABLE_SCOPE;
        } else if (kind == VRC.K_SCHEDULE_ACTIVATION) {
            if (field(payload, 0) == 0) return RANGE;
            uint256 epoch = field(payload, 2);
            if (
                env.knownRootEpoch > type(uint64).max - 3 || epoch < uint256(env.knownRootEpoch) + 3
            ) {
                return SCHEDULE_TOO_EARLY;
            }
            uint256 nb = field(payload, 3);
            if (
                env.ucTime > type(uint64).max - VRC.DELAY_SECONDS
                    || nb < uint256(env.ucTime) + VRC.DELAY_SECONDS
            ) return SCHEDULE_TOO_SOON;
        } else if (kind == VRC.K_FORCE_REMOVE) {
            uint256 id = field(payload, 0);
            bool member = false;
            for (uint256 i = 0; i < env.committee.length; ++i) {
                if (env.committee[i] == id) member = true;
            }
            if (!member) return NOT_IN_COMMITTEE;
            if (env.pendingForce >= VRC.MAX_PENDING_FORCE) return TOO_MANY_FORCE_REMOVES;
        }
        return OK;
    }

    /// @notice The running state of one output's binding selection (design 3.5.4, schema 6.3; vrschema SelectBinding).
    struct Selection {
        uint256 rootSide;
        uint256 total;
        uint256 payloadBytes;
        uint256 nScopes;
        bytes32[16] scopes;
    }

    /// @notice Whether a Scheduled change fits the selection: never a ModuleAction; a ForceRemove only if performed; at most 16 changes,
    /// 8 root-side and 64 KiB of payload; its scope (if any) not yet bound. A change that does not fit is deferred.
    function fits(Selection memory s, uint8 kind, uint256 size, bytes32 sc, bool performed)
        internal
        pure
        returns (bool)
    {
        if (kind == VRC.K_MODULE_ACTION) return false;
        if (kind == VRC.K_FORCE_REMOVE && !performed) return false;
        if (s.total >= VRC.MAX_BOUND_TOTAL || s.payloadBytes + size > VRC.MAX_BOUND_PAYLOAD) {
            return false;
        }
        if (VRC.rootSide(kind) && s.rootSide >= VRC.MAX_BOUND_ROOT_SIDE) return false;
        if (sc != 0) {
            for (uint256 i = 0; i < s.nScopes; ++i) {
                if (s.scopes[i] == sc) return false;
            }
        }
        return true;
    }

    function take(Selection memory s, uint8 kind, uint256 size, bytes32 sc) internal pure {
        ++s.total;
        s.payloadBytes += size;
        if (VRC.rootSide(kind)) ++s.rootSide;
        if (sc != 0) s.scopes[s.nScopes++] = sc;
    }

    /// @notice The binding scope of a checked payload (schema 6.3): its kind for 1, 3, 4 and 5; its shard for 6 and 8 (shared); its
    /// partition for 7; its rule for 9; none (zero) for 2 and 10.
    function scope(uint8 kind, bytes memory payload) internal pure returns (bytes32) {
        if (
            kind == VRC.K_SET_MODULE || kind == VRC.K_SET_GOVERNOR || kind == VRC.K_COMMITTEE_LIMITS
                || kind == VRC.K_FEE_PARAMS
        ) return keccak256(abi.encode("kind", uint256(kind)));
        if (kind == VRC.K_REPLACE_AGGREGATOR || kind == VRC.K_UPDATE_PARTITION) {
            return keccak256(abi.encode("shard", field(payload, 0), dynField(payload, 1)));
        }
        if (kind == VRC.K_ADD_PARTITION) {
            (, uint32 p) = pdrPartition(dynField(payload, 0));
            return keccak256(abi.encode("partition", uint256(p)));
        }
        if (kind == VRC.K_SCHEDULE_ACTIVATION) {
            return keccak256(abi.encode("rule", field(payload, 0)));
        }
        return bytes32(0);
    }

    /// @notice The partition id of a canonical CBOR PDR read from its leading bytes without a CBOR decoder (schema 6.3, FD-25): the
    /// tag head d9 98 60 (39008), a shortest-form array head of at least three items, then three shortest-form unsigned integers
    /// (version, network id, partition id <= 2^32 - 1).
    function pdrPartition(bytes memory pdr) internal pure returns (bool ok, uint32 partition) {
        uint256 pos = 0;
        uint256 v;
        (ok, v, pos) = _head(pdr, pos, 6);
        if (!ok || v != PDR_TAG) return (false, 0);
        (ok, v, pos) = _head(pdr, pos, 4);
        if (!ok || v < 3) return (false, 0);
        for (uint256 i = 0; i < 3; ++i) {
            (ok, v, pos) = _head(pdr, pos, 0);
            if (!ok) return (false, 0);
        }
        if (v > type(uint32).max) return (false, 0);
        // forge-lint: disable-next-line(unsafe-typecast)
        return (true, uint32(v));
    }

    /// @dev One shortest-form CBOR head of major type `major` at `pos`.
    function _head(bytes memory b, uint256 pos, uint8 major)
        private
        pure
        returns (bool, uint256, uint256)
    {
        if (pos >= b.length || uint8(b[pos]) >> 5 != major) return (false, 0, pos);
        uint8 ai = uint8(b[pos]) & 0x1f;
        ++pos;
        if (ai < 24) return (true, ai, pos);
        uint256 n;
        uint256 min;
        if (ai == 24) (n, min) = (1, 24);
        else if (ai == 25) (n, min) = (2, 1 << 8);
        else if (ai == 26) (n, min) = (4, 1 << 16);
        else if (ai == 27) (n, min) = (8, 1 << 32);
        else return (false, 0, pos);
        if (pos + n > b.length) return (false, 0, pos);
        uint256 v = 0;
        for (uint256 i = 0; i < n; ++i) {
            v = (v << 8) | uint8(b[pos + i]);
        }
        return (v >= min, v, pos + n);
    }
}
