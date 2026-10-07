// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IRBadOpening, IRMalformed, IRStateMismatch} from "./BridgeErrors.sol";

/// @notice Opening of the native InputRecord that an anchor carries beside `expectedIRHash`:
///         `tag(39002,[1,round,epoch,previousHash,stateHash,summary,timestamp,blockHash,fees,
///         executedTransactionsHash])`, arity 10, under B1's field, null, width and canonical rules
///         (bft-core `b1ref` `shapeIR`): unsigned integers in shortest form, `stateHash` a 32-byte
///         string, the other hash fields null or 32-byte strings, `summary` null or at most 256 bytes.
///
///         The opening carries no trust by itself. It is meaningful only after B1 0x0100 has
///         authenticated `(expectedStateRoot, expectedIRHash)`; the composing verifier calls it only
///         then. It never accepts a timestamp, or a hash, that the opening does not itself contain.
library InputRecord {
    uint256 internal constant MAX_BYTES = 512;
    uint256 internal constant MAX_SUMMARY_BYTES = 256;
    uint256 internal constant TAG = 39002;
    uint256 internal constant VERSION = 1;
    uint256 internal constant ARITY = 10;
    uint8 internal constant NULL = 0xf6;

    /// @dev Checks the opening against the anchor's hash and state root and returns its timestamp.
    ///      The length bound `MAX_BYTES` is enforced by the composing verifier on the envelope, before
    ///      anything is allocated; the scan below is exact and reads only what the opening declares.
    function open(bytes memory ir, bytes32 expectedIRHash, bytes32 expectedStateRoot)
        internal
        pure
        returns (uint64 timestamp)
    {
        if (sha256(ir) != expectedIRHash) revert IRBadOpening();
        bytes32 state;
        (timestamp, state) = _scan(ir);
        if (state != expectedStateRoot) revert IRStateMismatch(expectedStateRoot, state);
    }

    /// @dev Strict sequential scan: every head is shortest-form, every field has its exact type and
    ///      the last field ends the input. A single failure is `IRMalformed`.
    function _scan(bytes memory b) private pure returns (uint64 timestamp, bytes32 state) {
        uint256 pos = 0;
        uint256 v;
        // Tag 39002, array of ten, version 1.
        (v, pos) = _head(b, pos, 6);
        if (v != TAG) revert IRMalformed();
        (v, pos) = _head(b, pos, 4);
        if (v != ARITY) revert IRMalformed();
        (v, pos) = _head(b, pos, 0);
        if (v != VERSION) revert IRMalformed();
        // round, epoch
        (, pos) = _head(b, pos, 0);
        (, pos) = _head(b, pos, 0);
        // previousHash: null or 32 bytes
        pos = _hashOrNull(b, pos);
        // stateHash: exactly 32 bytes
        (state, pos) = _hash(b, pos);
        // summary: null or at most 256 bytes
        if (pos >= b.length) revert IRMalformed();
        if (uint8(b[pos]) == NULL) {
            ++pos;
        } else {
            (v, pos) = _head(b, pos, 2);
            if (v > MAX_SUMMARY_BYTES) revert IRMalformed();
            // A summary that runs past the end is caught by the next read, which is bounds-checked.
            pos += v;
        }
        // timestamp: u64
        (v, pos) = _head(b, pos, 0);
        // forge-lint: disable-next-line(unsafe-typecast)
        timestamp = uint64(v);
        // blockHash, fees, executedTransactionsHash
        pos = _hashOrNull(b, pos);
        (, pos) = _head(b, pos, 0);
        pos = _hashOrNull(b, pos);
        if (pos != b.length) revert IRMalformed();
    }

    /// @dev Reads one head of `major`, in shortest form. Every read is bounds-checked first, so a
    ///      truncated opening is `IRMalformed` and never reads beyond the buffer.
    function _head(bytes memory b, uint256 pos, uint8 major)
        private
        pure
        returns (uint256 arg, uint256 next)
    {
        if (pos >= b.length) revert IRMalformed();
        uint8 first = uint8(b[pos]);
        if (first >> 5 != major) revert IRMalformed();
        uint8 ai = first & 0x1f;
        next = pos + 1;
        if (ai < 24) return (ai, next);
        if (ai > 27) revert IRMalformed();
        uint256 width = uint256(1) << (ai - 24);
        if (next + width > b.length) revert IRMalformed();
        for (uint256 i = 0; i < width; ++i) {
            arg = (arg << 8) | uint8(b[next + i]);
        }
        next += width;
        // Shortest form: the argument needs more than the next narrower width.
        uint256 floor = ai == 24 ? 24 : (ai == 25 ? 1 << 8 : (ai == 26 ? 1 << 16 : 1 << 32));
        if (arg < floor) revert IRMalformed();
    }

    function _hash(bytes memory b, uint256 pos) private pure returns (bytes32 h, uint256 next) {
        // 0x58 0x20: byte string, one length byte, 32.
        if (pos + 34 > b.length || uint8(b[pos]) != 0x58 || uint8(b[pos + 1]) != 32) {
            revert IRMalformed();
        }
        assembly ("memory-safe") {
            h := mload(add(add(b, 34), pos))
        }
        next = pos + 34;
    }

    function _hashOrNull(bytes memory b, uint256 pos) private pure returns (uint256 next) {
        if (pos >= b.length) revert IRMalformed();
        if (uint8(b[pos]) == NULL) return pos + 1;
        (, next) = _hash(b, pos);
    }
}
