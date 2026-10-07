// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BudgetExceeded, PrecompileFailed, PrecompileBadReturn} from "./BridgeErrors.sol";
import {Anchor, LeafProof} from "./BridgeTypes.sol";

/// @notice Wrappers for the B1 A' native calls and the proposed B2 kernel. B1's framing is
///         `version:u8=1 | flags:u8=0 | count:u16` followed by view-free claims (bft-core
///         `docs/design/b1-aprime-spec.md`, "Caller oracle and vectors"). Authority comes from the
///         privileged registry projection that the native code reads from the selected block's
///         journal at `REGISTRY`; this library never reads or writes it, and carries no authority
///         body, trust base or committee.
// A refusal here must revert the whole call, including when reached from a bounded loop.
// forge-lint: disable-start(require-revert-in-loop)
library B1Calls {
    /// @dev UC_V1: one certified claim.
    address internal constant UC_VERIFIER = address(0x0100);
    /// @dev SHARED_SEAL_V1 (2..8 shards). Reserved for the disabled B3 extension; never called.
    address internal constant SHARED_VERIFIER = address(0x0101);
    /// @dev RSMT_MEMBER_V1: stateless membership of (key, value) under a caller-supplied root.
    address internal constant RSMT_VERIFIER = address(0x0102);
    /// @dev Proposed B2 whole-token semantics kernel (0x0103 stays reserved for S1).
    address internal constant KERNEL = address(0x0104);
    /// @dev Privileged B1 authority registry. Native-only: the precompiles read it through the
    ///      execution journal, so a bridge call needs no registry slot, proof or body from the caller.
    address internal constant REGISTRY = 0xff00000000000000000000000000000000000002;

    uint8 internal constant VERSION = 1;
    uint8 internal constant FLAGS = 0;

    uint256 internal constant MAX_SHARD_BYTES = 33;
    uint256 internal constant MAX_UC_BYTES = 24576;
    uint256 internal constant MAX_RSMT_VALUE_BYTES = 4096;

    /// @dev UC request with exactly one claim. The length bounds make the narrowing casts exact.
    // forge-lint: disable-start(unsafe-typecast)
    function ucRequest(Anchor memory a) internal pure returns (bytes memory) {
        if (a.shard.length > MAX_SHARD_BYTES || a.uc.length > MAX_UC_BYTES) {
            revert BudgetExceeded();
        }
        return bytes.concat(
            abi.encodePacked(VERSION, FLAGS, uint16(1), a.partition, uint16(a.shard.length)),
            a.shard,
            abi.encodePacked(
                a.shardConfHash, a.expectedStateRoot, a.expectedIRHash, uint32(a.uc.length)
            ),
            a.uc
        );
    }

    // forge-lint: disable-end(unsafe-typecast)

    /// @dev RSMT request: header | root | key | valueLength:u32 | value | bitmap | siblings. The value
    ///      is at most 4096 bytes (B1's bound); the bridge always passes the 32-byte raw leaf value
    ///      `H(C(b(txHash), t))` (SDK 3.0.1), never the txHash or an imprint.
    // forge-lint: disable-start(unsafe-typecast)
    function memberRequest(
        bytes32 root,
        bytes32 key,
        bytes memory value,
        bytes32 bitmap,
        bytes32[] memory siblings
    ) internal pure returns (bytes memory out) {
        if (value.length > MAX_RSMT_VALUE_BYTES) revert BudgetExceeded();
        out = bytes.concat(
            abi.encodePacked(VERSION, FLAGS, uint16(1), root, key, uint32(value.length)),
            value,
            abi.encodePacked(bitmap)
        );
        uint256 n = siblings.length;
        for (uint256 i = 0; i < n; ++i) {
            out = bytes.concat(out, siblings[i]);
        }
    }

    // forge-lint: disable-end(unsafe-typecast)

    /// @dev STATICCALL with the returndata size bounded before it is copied. A failed call (exceptional
    ///      halt, out of gas, host unavailable) reverts; B1 never reports failure as a verdict.
    function staticCall(address target, bytes memory input, uint256 maxReturn)
        internal
        view
        returns (bytes memory out)
    {
        bool ok;
        uint256 size;
        assembly ("memory-safe") {
            ok := staticcall(gas(), target, add(input, 32), mload(input), 0, 0)
            size := returndatasize()
        }
        if (!ok) revert PrecompileFailed(target);
        if (size > maxReturn) revert PrecompileBadReturn(target);
        out = new bytes(size);
        assembly ("memory-safe") {
            returndatacopy(add(out, 32), 0, size)
        }
    }

    /// @dev B1 verdict: exactly `abi.encode(uint256(1), bool)` (64 bytes). `(1,false)` is a verdict;
    ///      any other shape is rejected.
    function verdict(address target, bytes memory input) internal view returns (bool valid) {
        bytes memory out = staticCall(target, input, 64);
        if (out.length != 64) revert PrecompileBadReturn(target);
        uint256 version;
        uint256 flag;
        assembly ("memory-safe") {
            version := mload(add(out, 32))
            flag := mload(add(out, 64))
        }
        if (version != 1 || flag > 1) revert PrecompileBadReturn(target);
        valid = flag == 1;
    }
}
// forge-lint: disable-end(require-revert-in-loop)
