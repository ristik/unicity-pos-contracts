// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Cbor} from "./Cbor.sol";
import {BudgetExceeded, UCScanRejected} from "./BridgeErrors.sol";
import {BridgeBounds} from "./BridgeBounds.sol";

/// @notice Bounded scan of an anchor's UnicityCertificate for the two quantities the gas gate prices:
///         the seal's signature count `S` and the path steps `P` (shard-tree siblings plus unicity tree
///         steps). It reads only what those need and skips the rest by head arithmetic; it does no
///         cryptography and accepts a superset of what B1 accepts. B1 stays the sole authority on the
///         certificate: a UC this scan reads more cheaply than the native scan simply runs out of gas
///         inside its forwarded charge and reverts the whole call, never succeeds.
///         Shape (bft-core `b1ref` `decodeUC`): `tag(39001,[1, IR, h, h, tag(39003,[1, shard, [sib*]]),
///         tag(39004,[1, partition, [step*]]), tag(39005,[1, ..., sigs map])])`.
library UcScan {
    uint256 internal constant TAG_UC = 39001;
    uint256 internal constant TAG_SHARD_TREE = 39003;
    uint256 internal constant TAG_UNICITY_TREE = 39004;
    uint256 internal constant TAG_SEAL = 39005;

    uint8 internal constant MAJOR_BYTES = 2;
    uint8 internal constant MAJOR_ARRAY = 4;
    uint8 internal constant MAJOR_MAP = 5;
    uint8 internal constant MAJOR_TAG = 6;
    uint8 internal constant NULL = 0xf6;

    /// @param shard the claim's shard bytes; the UC's shard tree certificate must name it
    /// @param depth the policy depth; the certificate must carry exactly this many shard siblings
    /// @return sigs the signature entries of the seal (`S`)
    /// @return steps shard-tree siblings plus unicity tree steps (`P`)
    function scan(bytes memory uc, bytes memory shard, uint256 depth)
        internal
        pure
        returns (uint256 sigs, uint256 steps)
    {
        uint256 pos = _tagged(uc, 0, TAG_UC, 7);
        pos = _skip(uc, pos); // version
        pos = _skip(uc, pos); // input record
        pos = _skip(uc, pos); // technical record hash
        pos = _skip(uc, pos); // shard configuration hash

        pos = _tagged(uc, pos, TAG_SHARD_TREE, 3);
        pos = _skip(uc, pos); // version
        pos = _shardEquals(uc, pos, shard);
        uint256 n;
        (n, pos) = _count(uc, pos, MAJOR_ARRAY);
        if (n != depth) revert UCScanRejected();
        steps = n;
        pos = _skipN(uc, pos, n);

        pos = _tagged(uc, pos, TAG_UNICITY_TREE, 3);
        pos = _skip(uc, pos); // version
        pos = _skip(uc, pos); // partition
        (n, pos) = _count(uc, pos, MAJOR_ARRAY);
        if (n > BridgeBounds.MAX_UNICITY_STEPS) revert BudgetExceeded();
        steps += n;
        pos = _skipN(uc, pos, n);

        pos = _tagged(uc, pos, TAG_SEAL, 8);
        for (uint256 i = 0; i < 7; ++i) {
            pos = _skip(uc, pos);
        }
        (sigs,) = _count(uc, pos, MAJOR_MAP);
        if (sigs > BridgeBounds.MAX_SIGNATURES) revert BudgetExceeded();
    }

    /// @dev `tag(t, array(n))` head at `pos`; returns the position of the first element.
    function _tagged(bytes memory b, uint256 pos, uint256 tag, uint256 n)
        private
        pure
        returns (uint256)
    {
        (uint8 major, uint256 arg, uint256 p) = Cbor.readHead(b, pos);
        if (major != MAJOR_TAG || arg != tag) revert UCScanRejected();
        (major, arg, p) = Cbor.readHead(b, p);
        if (major != MAJOR_ARRAY || arg != n) revert UCScanRejected();
        return p;
    }

    function _shardEquals(bytes memory b, uint256 pos, bytes memory shard)
        private
        pure
        returns (uint256)
    {
        (uint8 major, uint256 len, uint256 p) = Cbor.readHead(b, pos);
        if (major != MAJOR_BYTES || len != shard.length || len > b.length - p) {
            revert UCScanRejected();
        }
        for (uint256 i = 0; i < len; ++i) {
            if (b[p + i] != shard[i]) revert UCScanRejected();
        }
        return p + len;
    }

    /// @dev Element count of an array or map at `pos` (null is empty) and the position after its head.
    function _count(bytes memory b, uint256 pos, uint8 want)
        private
        pure
        returns (uint256 n, uint256 next)
    {
        if (pos < b.length && uint8(b[pos]) == NULL) return (0, pos + 1);
        uint8 major;
        (major, n, next) = Cbor.readHead(b, pos);
        if (major != want || n > b.length) revert UCScanRejected();
    }

    function _skipN(bytes memory b, uint256 pos, uint256 n) private pure returns (uint256) {
        for (uint256 i = 0; i < n; ++i) {
            pos = _skip(b, pos);
        }
        return pos;
    }

    /// @dev Skips one complete item. Every iteration consumes at least one byte, so the loop is bounded
    ///      by the input length (itself bounded by `MAX_ANCHOR_UC_BYTES` before the scan).
    function _skip(bytes memory b, uint256 pos) private pure returns (uint256) {
        uint256 pending = 1;
        while (pending != 0) {
            (uint8 major, uint256 arg, uint256 next) = Cbor.readHead(b, pos);
            pos = next;
            --pending;
            if (major == 2 || major == 3) {
                if (arg > b.length - pos) revert UCScanRejected();
                pos += arg;
            } else if (major == MAJOR_ARRAY || major == MAJOR_MAP) {
                if (arg > b.length) revert UCScanRejected();
                pending += major == MAJOR_MAP ? 2 * arg : arg;
            } else if (major == MAJOR_TAG) {
                ++pending;
            }
        }
        return pos;
    }
}
