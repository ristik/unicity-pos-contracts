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

/// @notice The sole admitted aggregator policy: one partition, the empty-prefix shard `80`, one
///         configuration hash.
struct Policy {
    uint32 partition;
    bytes32 shardConfHash;
}

/// @notice One inclusion obligation exported by the semantics kernel. It is not an assertion that
///         the leaf is included. `leafValue = H(C(b(txHash), referenceTime))` is the raw 32-byte RSMT
///         value (SDK 3.0.1); `referenceTime` is untrusted until the leaf is proven under an admitted
///         root and compared with the authenticated InputRecord timestamp.
struct Leaf {
    bytes32 sid;
    bytes32 txHash;
    uint64 referenceTime;
    bytes32 leafValue;
}

/// @notice Kernel `Result`, in the ABI order of the 0x0104 output.
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
    Leaf[] leaves;
}

/// @notice Aggregator claim of the proof envelope; the claim fields are B1's view-free claim.
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
