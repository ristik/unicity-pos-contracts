// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// Default leaves, the bitmaps and loop indices start at zero.
// forge-lint: disable-start(uninitialized-local)

import {FlatClaim, FlatHash, FlatWire as W, BadStep} from "./FlatTypes.sol";
import {FlatNative} from "./FlatNative.sol";

library FlatSparse {
    struct Cache {
        bytes32[17] keys;
        bytes32[17] values;
        uint256 used;
    }

    function defaults(bytes32 label) internal pure returns (bytes32[257] memory nodes) {
        for (uint256 i; i < 256; ++i) {
            nodes[i + 1] = FlatHash.node(label, nodes[i], nodes[i]);
        }
    }

    function sid(bytes calldata b, uint256 p, bytes32 key, bytes32 root, bytes32[257] memory empty)
        internal
        pure
        returns (bytes32, uint256)
    {
        bytes32 leaf = keccak256(abi.encode(FlatHash.SID, key));
        return _open(b, p, key, root, 0, leaf, FlatHash.SID_NODE, empty);
    }

    function claim(
        bytes calldata b,
        uint256 p,
        FlatClaim memory c,
        bytes32 root,
        bytes32[257] memory empty,
        Cache memory cache,
        FlatNative.Batch memory pending
    ) internal view returns (bytes32, uint256) {
        uint256 mode = W.number(b, p++, 1);
        for (uint256 i; i < cache.used; ++i) {
            if (cache.keys[i] == c.key) {
                if (mode != 1 || cache.values[i] != c.value) revert BadStep();
                return (root, p);
            }
        }
        if (mode != 0) revert BadStep();
        uint256 present = W.number(b, p++, 1);
        bytes32 leaf = FlatHash.node(FlatHash.CLAIM, c.key, c.value);
        if (present != 0) {
            if (W.word(b, p) != c.value) revert BadStep();
            p += 32;
        }
        (bytes32 newRoot, uint256 next) = _open(
            b, p, c.key, root, present == 0 ? bytes32(0) : leaf, leaf, FlatHash.CLAIM_NODE, empty
        );
        cache.keys[cache.used] = c.key;
        cache.values[cache.used++] = c.value;
        FlatNative.append(pending, c);
        return (newRoot, next);
    }

    function _open(
        bytes calldata b,
        uint256 p,
        bytes32 key,
        bytes32 expected,
        bytes32 oldNode,
        bytes32 newNode,
        bytes32 label,
        bytes32[257] memory empty
    ) private pure returns (bytes32, uint256) {
        uint256 bits = uint256(W.word(b, p));
        p += 32;
        uint256 index = uint256(key);
        for (uint256 h; h < 256; ++h) {
            bytes32 sibling = empty[h];
            if (bits & 1 != 0) {
                sibling = W.word(b, p);
                p += 32;
                if (sibling == empty[h]) revert BadStep();
            }
            if (index & 1 == 0) {
                oldNode = FlatHash.node(label, oldNode, sibling);
                newNode = FlatHash.node(label, newNode, sibling);
            } else {
                oldNode = FlatHash.node(label, sibling, oldNode);
                newNode = FlatHash.node(label, sibling, newNode);
            }
            bits >>= 1;
            index >>= 1;
        }
        if (oldNode != expected) revert BadStep();
        return (newNode, p);
    }
}
