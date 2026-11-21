// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// CBOR arguments are range checked before narrowing. Fixed byte casts select the decoded prefix.
// forge-lint: disable-start(unsafe-typecast)

import {Nb2Cbor as C} from "../Nb2Cbor.sol";
import {NB2Config} from "../../NB2Config.sol";
import {FlatNative} from "./FlatNative.sol";
import {FlatConfig, FlatHash, FlatWire as W, BadBinding} from "./FlatTypes.sol";

library FlatBindings {
    bytes32 private constant RELEASE = keccak256("UNICITY/NB2/CONT/1.1/RELEASE");
    bytes32 private constant PINS = keccak256("UNICITY/NB2/CONT/1.1/PINS");
    bytes32 private constant REGISTRY = keccak256("UNICITY/NB2/CONT/1.1/REGISTRY");
    bytes32 private constant GENERATION = keccak256("UNICITY/NB2/CONT/1.1/GEN");
    bytes32 private constant SESSION = keccak256("UNICITY/NB2/CONT/1.1/SESSION");

    struct ReleaseInputs {
        bytes32 certDescriptor;
        bytes32 memberDescriptor;
        bytes32 registryLayout;
        bytes32 executionDescriptor;
        bytes32 buildIndex;
        bytes32 primitiveVectors;
    }

    function pins(
        ReleaseInputs memory release,
        address ordinary,
        bytes32 ordinaryHash,
        address receipts,
        bytes32 receiptsHash,
        bytes32 registryHash,
        address lineage,
        bytes32 lineageHash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                PINS,
                keccak256(abi.encode(RELEASE, release)),
                uint16(6),
                uint16(1),
                ordinary,
                ordinaryHash,
                uint16(2),
                receipts,
                receiptsHash,
                uint16(3),
                FlatNative.CERT,
                release.certDescriptor,
                uint16(4),
                FlatNative.MEMBER,
                release.memberDescriptor,
                uint16(5),
                FlatNative.REGISTRY,
                keccak256(abi.encode(REGISTRY, registryHash, release.registryLayout)),
                uint16(256),
                lineage,
                lineageHash
            )
        );
    }

    function generation(bytes32 salt, bytes32 domain) internal pure returns (bytes32) {
        return keccak256(abi.encode(GENERATION, salt, domain));
    }

    function session(
        bytes32 gen,
        bytes32 domain,
        address vault,
        address recovery,
        bytes32 recoveryHash,
        bytes32 dependencyPins,
        uint64 size,
        bytes32 pageRoot
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                SESSION,
                W.VERSION,
                gen,
                domain,
                vault,
                recovery,
                recoveryHash,
                dependencyPins,
                size,
                pageRoot
            )
        );
    }

    struct ConfigBinding {
        FlatConfig cfg;
        uint64 chainId;
        address ordinary;
        bytes32 ordinaryHash;
        bytes32 profileHash;
    }

    function decode(bytes calldata gamma) internal pure returns (ConfigBinding memory b) {
        uint256 p = W.offset(gamma);
        if (gamma.length > 1024 || C.scan(p, p + gamma.length, false) != 0) revert BadBinding();
        p = C.array(p, 19);
        (uint256 literal, uint256 next) = C.fixedBytes(p, 15);
        if (bytes15(C.word(literal)) != bytes15("UNICITY_NB2_CFG")) revert BadBinding();
        p = C.version(next, 2);
        uint256 v;
        (v, p) = C.uintIn(p, 1, type(uint16).max);
        b.cfg.network = uint16(v);
        bytes32 rootGenesis;
        bytes32 executionGenesis;
        (rootGenesis, p) = C.bytes32At(p);
        (executionGenesis, p) = C.bytes32At(p);
        (v, p) = C.uintIn(p, 1, type(uint64).max);
        b.chainId = uint64(v);
        (v, p) = C.uintIn(p, 1, type(uint32).max);
        b.cfg.evmPartition = uint32(v);
        (uint256 shard, uint256 len, uint256 nextShard) = C.bstr(p);
        if (
            len == 0 || len > 33 || C.u8(shard + len - 1) == 0
                || (len == 33 && C.u8(shard + 32) != 0x80)
        ) revert BadBinding();
        b.cfg.evmShard = W.slice(shard, len);
        (v, p) = C.uintIn(nextShard, 1, type(uint32).max);
        if (v == b.cfg.evmPartition) revert BadBinding();
        b.cfg.aggPartition = uint32(v);
        (b.cfg.vault, p) = _address(p);
        bytes32 asset;
        (asset, p) = C.bytes32At(p);
        (b.cfg.tokenType, p) = C.bytes32At(p);
        (b.cfg.coin, p) = C.bytes32At(p);
        (b.profileHash, p) = C.bytes32At(p);
        (b.ordinary, p) = _address(p);
        (b.ordinaryHash, p) = C.bytes32At(p);
        (, p) = C.uintIn(p, 64, 64);
        (, p) = C.uintIn(p, 16, 16);
        (v, p) = C.amount(p);
        if (
            p != W.offset(gamma) + gamma.length || v >= 1 << 144 || asset != FlatHash.ASSET
                || b.cfg.vault == address(0) || b.ordinary == address(0)
        ) revert BadBinding();
        bytes memory stem =
            NB2Config.identityString(b.cfg.network, rootGenesis, executionGenesis, b.chainId);
        if (
            b.cfg.tokenType != sha256(bytes.concat("unicity-bridge:unicity-native-nb2-11:", stem))
                || b.cfg.coin
                    != sha256(bytes.concat("unicity-bridge-coin:unicity-native-nb2-11:", stem))
        ) revert BadBinding();
        b.cfg.domain = sha256(gamma);
    }

    function _address(uint256 p) private pure returns (address a, uint256 q) {
        uint256 dp;
        (dp, q) = C.fixedBytes(p, 20);
        a = address(bytes20(C.word(dp)));
    }
}
