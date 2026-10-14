// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BudgetExceeded, PrecompileFailed, PrecompileBadReturn} from "./BridgeErrors.sol";
import {Anchor, LeafProof} from "./BridgeTypes.sol";

/// @notice Wrappers for the native calls of the any-age profile (briefs/b1-any-age-contract.md section 2): the
///         registry-backed certificate batch `CERT_BATCH_V2` at 0x0100, RSMT membership v1 at 0x0102 and the semantics
///         kernel at 0x0104. The batch is `version:u8=2 | flags:u8=0 | K:u16` followed by K packed claims and answers
///         exactly `abi.encode(uint256(2), bool)` for the whole batch. Authority comes from the privileged registry the
///         native code reads from the selected block's journal at `REGISTRY`; this library never reads or writes it, and
///         carries no authority body, trust base, epoch table or committee.
// A refusal here must revert the whole call, including when reached from a bounded loop.
// forge-lint: disable-start(require-revert-in-loop)
library B1Calls {
    /// @dev CERT_BATCH_V2: 1..16 claims, one verdict for the whole batch. There is no single-claim operation and 0x0101 is
    ///      reserved and inactive: a successful empty call to an unregistered address is never read as a verdict.
    address internal constant CERT_BATCH = address(0x0100);
    /// @dev RSMT_MEMBER_V1: stateless membership of (key, value) under a caller-supplied root.
    address internal constant RSMT_VERIFIER = address(0x0102);
    /// @dev Proposed B2 whole-token semantics kernel (0x0103 stays reserved for S1).
    address internal constant KERNEL = address(0x0104);
    /// @dev Privileged B1 authority registry. Native-only: the precompiles read it through the
    ///      execution journal, so a bridge call needs no registry slot, proof or body from the caller.
    address internal constant REGISTRY = 0xff00000000000000000000000000000000000002;

    uint8 internal constant BATCH_VERSION = 2;
    uint8 internal constant RSMT_VERSION = 1;
    uint8 internal constant FLAGS = 0;
    uint256 internal constant MAX_BATCH_CLAIMS = 16;

    uint256 internal constant MAX_SHARD_BYTES = 33;
    uint256 internal constant MAX_UC_BYTES = 24576;
    uint256 internal constant MAX_RSMT_VALUE_BYTES = 4096;

    /// @dev The CERT_BATCH_V2 request over the anchor table, in table order: `version | flags | K | Claim[K]`, a claim being
    ///      `partition:u32 | shardLen:u16 | shard | shardConfHash | stateRoot | irHash | ucLen:u32 | uc`. The length bounds make the
    ///      narrowing casts exact; no inputRecord opening is sent (it is checked here, after the verdict).
    // forge-lint: disable-start(unsafe-typecast)
    function batchRequest(Anchor[] memory anchors) internal pure returns (bytes memory out) {
        uint256 k = anchors.length;
        if (k == 0 || k > MAX_BATCH_CLAIMS) revert BudgetExceeded();
        out = abi.encodePacked(BATCH_VERSION, FLAGS, uint16(k));
        for (uint256 i = 0; i < k; ++i) {
            Anchor memory a = anchors[i];
            if (a.shard.length > MAX_SHARD_BYTES || a.uc.length > MAX_UC_BYTES) {
                revert BudgetExceeded();
            }
            out = bytes.concat(
                out,
                abi.encodePacked(a.partition, uint16(a.shard.length)),
                a.shard,
                abi.encodePacked(
                    a.shardConfHash, a.expectedStateRoot, a.expectedIRHash, uint32(a.uc.length)
                ),
                a.uc
            );
        }
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
        // One allocation: `abi.encodePacked` of a `bytes32[]` is the siblings back to back, 32 bytes each.
        out = bytes.concat(
            abi.encodePacked(RSMT_VERSION, FLAGS, uint16(1), root, key, uint32(value.length)),
            value,
            abi.encodePacked(bitmap),
            abi.encodePacked(siblings)
        );
    }

    // forge-lint: disable-end(unsafe-typecast)

    /// @dev STATICCALL forwarded exactly `gasCap` (the call's computed charge, `BridgeBounds`), with the
    ///      returndata size bounded before it is copied. A failed call (exceptional halt, out of gas,
    ///      host unavailable) reverts; B1 never reports failure as a verdict. Capping the forwarded
    ///      gas means a malformed late call cannot consume the rest of the transaction.
    function staticCall(address target, bytes memory input, uint256 maxReturn, uint256 gasCap)
        internal
        view
        returns (bytes memory out)
    {
        bool ok;
        uint256 size;
        assembly ("memory-safe") {
            ok := staticcall(gasCap, target, add(input, 32), mload(input), 0, 0)
            size := returndatasize()
        }
        if (!ok) revert PrecompileFailed(target);
        if (size > maxReturn) revert PrecompileBadReturn(target);
        out = new bytes(size);
        assembly ("memory-safe") {
            returndatacopy(add(out, 32), 0, size)
        }
    }

    /// @dev A verdict: exactly `abi.encode(uint256(version), bool)` (64 bytes). `(version, false)` is a verdict; any other shape is
    ///      rejected, and so is a version other than the one the call speaks.
    function verdict(address target, uint256 version, bytes memory input, uint256 gasCap)
        internal
        view
        returns (bool valid)
    {
        bytes memory out = staticCall(target, input, 64, gasCap);
        if (out.length != 64) revert PrecompileBadReturn(target);
        uint256 got;
        uint256 flag;
        assembly ("memory-safe") {
            got := mload(add(out, 32))
            flag := mload(add(out, 64))
        }
        if (got != version || flag > 1) revert PrecompileBadReturn(target);
        valid = flag == 1;
    }
}
// forge-lint: disable-end(require-revert-in-loop)
