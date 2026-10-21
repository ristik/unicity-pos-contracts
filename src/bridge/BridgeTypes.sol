// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice Immutable bridge configuration `Cfg` of the whole-token native profile (bft-core
///         docs/pos/specification/amendments/b2-whole-token-bridge-profile.md section C). Field
///         order is the CBOR array order; `cfg = sha256(encode(Cfg))`.
struct Cfg {
    uint16 network;
    bytes32 rootGenesis;
    uint64 chainId;
    bytes32 executionGenesis;
    uint32 evmPartition;
    bytes evmShard;
    address vault;
    address zeroAddress;
    bytes32 ty;
    bytes32 aid;
    bytes32 semanticProfileHash;
    address tokenVerifier;
    bytes32 tokenVerifierCodeHash;
    bytes32 b1ProfileHash;
    bytes32 aggregatorPolicyHash;
}

/// @notice The sole admitted aggregator policy (`AGG_PARTITION_V2`): ONE aggregation partition whose certified shard
///         configurations are authorized by the root quorum. No depth, shard list or configuration table: an anchor's depth is
///         derived from its own native shard id, its configuration hash is authenticated by its own UC, and a leaf's shard is
///         the first `d` bits of its raw 32-byte state ID for the depth `d` of the anchor that serves it.
struct Policy {
    uint32 partition;
}

/// @notice The relation result: the kernel `Result` without its leaf obligations (proven natively by 0x0105), and how many
///         leaves were proven. A prepare result has none.
struct KernelResult {
    bytes32 cfg;
    uint256 nonce;
    uint256 amount;
    bytes32 tokenId;
    bytes32 salt;
    bytes32 firstPredicateHash;
    bytes32 lockDigest;
    address releaseTo;
    bytes32 nullifier;
    uint256 leafCount;
}

/// @notice Aggregator claim of the proof envelope `abi.encode(bytes policyBody, bytes history, Anchor[], LeafProof[])`, which
///         0x0105 decodes; the claim fields are B1's view-free claim.
///         `inputRecord` is the exact canonical native InputRecord opening committed by
///         `expectedIRHash`: the only source of the anchor timestamp, meaningful only after B1 0x0100
///         has authenticated `(expectedStateRoot, expectedIRHash)`.
struct Anchor {
    uint32 partition;
    bytes shard;
    bytes32 shardConfHash;
    bytes32 expectedStateRoot;
    bytes32 expectedIRHash;
    bytes uc;
    bytes inputRecord;
}

/// @notice One RSMT path per exported leaf, in kernel leaf order.
struct LeafProof {
    uint16 anchorIndex;
    bytes32 bitmap;
    bytes32[] siblings;
}

/// @notice Constructor input of the vault. `chainId`, `vault` and `zeroAddress` are not inputs: the
///         vault takes them from its environment, and derives `ty` and `aid` (unicity-native family,
///         which excludes the vault) from the network, both genesis hashes and the chain ID.
struct Deployment {
    uint16 network;
    bytes32 rootGenesis;
    bytes32 executionGenesis;
    uint32 evmPartition;
    bytes evmShard;
    bytes32 semanticProfileHash;
    address tokenVerifier;
    bytes32 tokenVerifierCodeHash;
    bytes32 b1ProfileHash;
    bytes policyBody;
}
