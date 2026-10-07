// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Cbor} from "./Cbor.sol";
import {CfgMalformed, PolicyMalformed} from "./BridgeErrors.sol";
import {Cfg, Policy} from "./BridgeTypes.sol";

/// @notice Canonical encodings of the bridge profile: Cfg, the one-shard Policy and the type/asset
///         derivations. These are the exact bytes of the merged oracle (bft-core `bridgeprofile`,
///         SDK 3.0.1 profile, protocol v2); `test/bridge/golden.json` pins them.
library BridgeProfile {
    string internal constant CFG_DOMAIN = "UNICITY_BR_CFG";
    string internal constant POLICY_DOMAIN = "UNICITY_BR_AGG_ONE";

    uint256 internal constant MAX_CFG_BYTES = 1024;
    uint256 internal constant MAX_POLICY_BYTES = 128;
    uint256 internal constant MAX_SHARD_BYTES = 33;

    /// @dev The one-byte native encoding of the empty shard prefix.
    bytes1 internal constant EMPTY_PREFIX = 0x80;

    function encodeCfg(Cfg memory c) internal pure returns (bytes memory) {
        return bytes.concat(
            Cbor.arrayHead(16),
            Cbor.domain(CFG_DOMAIN),
            Cbor.uint_(c.network),
            Cbor.bstr32(c.rootGenesis),
            Cbor.uint_(c.chainId),
            Cbor.bstr32(c.executionGenesis),
            Cbor.uint_(c.evmPartition),
            Cbor.bstr(c.evmShard),
            Cbor.bstr20(c.vault),
            Cbor.bstr20(c.zeroAddress),
            Cbor.bstr32(c.ty),
            Cbor.bstr32(c.aid),
            Cbor.bstr32(c.semanticProfileHash),
            Cbor.bstr20(c.tokenVerifier),
            Cbor.bstr32(c.tokenVerifierCodeHash),
            Cbor.bstr32(c.b1ProfileHash),
            Cbor.bstr32(c.aggregatorPolicyHash)
        );
    }

    /// @dev `cfg = H(Cfg)`, raw SHA-256 of the exact Cfg bytes.
    function cfgHash(bytes memory cfgBytes) internal pure returns (bytes32) {
        return sha256(cfgBytes);
    }

    // forge-lint: disable-start(unsafe-typecast)
    /// @dev Strict decode. The reader only extracts the sixteen fields at their fixed widths; the
    ///      array head, domain string, field order and absence of trailing bytes are all enforced by
    ///      the final comparison with the canonical re-encoding of what was read. Every cast below
    ///      follows a `readUint` bound of the same width.
    function decodeCfg(bytes memory b) internal pure returns (Cfg memory c) {
        (,, uint256 pos) = Cbor.readHead(b, 0);
        (, pos) = Cbor.readBytesN(b, pos, bytes(CFG_DOMAIN).length);
        uint256 v;
        (v, pos) = Cbor.readUint(b, pos, type(uint16).max);
        c.network = uint16(v);
        (c.rootGenesis, pos) = Cbor.readBytes32(b, pos);
        (v, pos) = Cbor.readUint(b, pos, type(uint64).max);
        c.chainId = uint64(v);
        (c.executionGenesis, pos) = Cbor.readBytes32(b, pos);
        (v, pos) = Cbor.readUint(b, pos, type(uint32).max);
        c.evmPartition = uint32(v);
        (c.evmShard, pos) = Cbor.readBytes(b, pos, 1, MAX_SHARD_BYTES);
        (c.vault, pos) = Cbor.readAddress(b, pos);
        (c.zeroAddress, pos) = Cbor.readAddress(b, pos);
        (c.ty, pos) = Cbor.readBytes32(b, pos);
        (c.aid, pos) = Cbor.readBytes32(b, pos);
        (c.semanticProfileHash, pos) = Cbor.readBytes32(b, pos);
        (c.tokenVerifier, pos) = Cbor.readAddress(b, pos);
        (c.tokenVerifierCodeHash, pos) = Cbor.readBytes32(b, pos);
        (c.b1ProfileHash, pos) = Cbor.readBytes32(b, pos);
        (c.aggregatorPolicyHash, pos) = Cbor.readBytes32(b, pos);
        if (keccak256(encodeCfg(c)) != keccak256(b)) revert CfgMalformed();
    }
    // forge-lint: disable-end(unsafe-typecast)

    function encodePolicy(Policy memory p) internal pure returns (bytes memory) {
        return bytes.concat(
            Cbor.arrayHead(4),
            Cbor.domain(POLICY_DOMAIN),
            Cbor.uint_(p.partition),
            Cbor.bstr(abi.encodePacked(EMPTY_PREFIX)),
            Cbor.bstr32(p.shardConfHash)
        );
    }

    // forge-lint: disable-start(unsafe-typecast)
    /// @dev Strict decode of the policy body, by the same method as `decodeCfg`: extract the partition
    ///      and configuration hash, then require the canonical re-encoding to equal the input. That
    ///      comparison enforces the array head, the domain, the one-byte `80` shard (never the empty
    ///      string) and the absence of trailing bytes.
    function decodePolicy(bytes memory b) internal pure returns (Policy memory p) {
        (,, uint256 pos) = Cbor.readHead(b, 0);
        (, pos) = Cbor.readBytesN(b, pos, bytes(POLICY_DOMAIN).length);
        uint256 v;
        (v, pos) = Cbor.readUint(b, pos, type(uint32).max);
        p.partition = uint32(v);
        (, pos) = Cbor.readBytesN(b, pos, 1);
        (p.shardConfHash, pos) = Cbor.readBytes32(b, pos);
        if (keccak256(encodePolicy(p)) != keccak256(b)) revert PolicyMalformed();
    }

    // forge-lint: disable-end(unsafe-typecast)

    string internal constant TYPE_PREFIX = "unicity-bridge:unicity-native:";
    string internal constant ASSET_PREFIX = "unicity-bridge-coin:unicity-native:";

    /// @dev `D = networkDecimal:rootGenesisHex:executionGenesisHex:chainIdDecimal:zeroAddressHex`:
    ///      decimals without leading zeros, genesis hashes as 64 lowercase hex characters and the
    ///      zero address as 40 zero characters, none with a `0x` prefix. The vault is not part of it.
    function identityD(
        uint16 network,
        bytes32 rootGenesis,
        bytes32 executionGenesis,
        uint64 chainId
    ) internal pure returns (bytes memory) {
        return bytes.concat(
            bytes(Strings.toString(network)),
            ":",
            _hex32(rootGenesis),
            ":",
            _hex32(executionGenesis),
            ":",
            bytes(Strings.toString(chainId)),
            ":",
            "0000000000000000000000000000000000000000"
        );
    }

    /// @dev `ty = SHA256(UTF8("unicity-bridge:unicity-native:" + D))`. It excludes the vault: an
    ///      approved replacement vault represents the same asset under its own Cfg, salt and lock.
    function deriveType(
        uint16 network,
        bytes32 rootGenesis,
        bytes32 executionGenesis,
        uint64 chainId
    ) internal pure returns (bytes32) {
        return sha256(
            bytes.concat(
                bytes(TYPE_PREFIX), identityD(network, rootGenesis, executionGenesis, chainId)
            )
        );
    }

    /// @dev `aid = SHA256(UTF8("unicity-bridge-coin:unicity-native:" + D))`.
    function deriveAsset(
        uint16 network,
        bytes32 rootGenesis,
        bytes32 executionGenesis,
        uint64 chainId
    ) internal pure returns (bytes32) {
        return sha256(
            bytes.concat(
                bytes(ASSET_PREFIX), identityD(network, rootGenesis, executionGenesis, chainId)
            )
        );
    }

    /// @dev 64 lowercase hex characters, no prefix.
    function _hex32(bytes32 v) private pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(64);
        for (uint256 i = 0; i < 32; ++i) {
            uint8 b = uint8(v[i]);
            out[2 * i] = digits[b >> 4];
            out[2 * i + 1] = digits[b & 0x0f];
        }
    }

    /// @dev Kernel `prepareLock` payload `C(n, b(amount), P0)`; `p0` is the raw tagged predicate item.
    function preparePayload(uint256 n, uint256 amount, bytes memory p0)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(
            Cbor.arrayHead(3), Cbor.uint_(n), Cbor.bstr(Cbor.minimalBytes(amount)), p0
        );
    }
}
