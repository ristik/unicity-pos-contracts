// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The linter's boolean-cst and uninitialized-local flag every `return (false, ...)` and zero-initialised accumulator; the
// precompile calls in loops are bounded by the input; typecasts are range-checked before narrowing; CBOR encodings are
// self-delimiting, so packed concatenation does not collide.
// forge-lint: disable-start(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)

/// @notice The sorted circular-gap tree and the archive chain (section 10), as the wallet's seal-receipt check uses them
///         (section 12.2; bft-core nb2ref segment.go). The vault (NB2-04) carries its own implementation.
library Nb2Segment {
    bytes32 internal constant ARCHIVE_GENESIS = keccak256("UNICITY_NB2_ARCHIVE_GENESIS");
    bytes32 internal constant ARCHIVE_STEP = keccak256("UNICITY_NB2_ARCHIVE_STEP");

    function leaf(bytes32 l, bytes32 u) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore8(m, 0)
            mstore(add(m, 1), l)
            mstore(add(m, 33), u)
            h := keccak256(m, 65)
        }
    }

    function node(bytes32 l, bytes32 r) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore8(m, 1)
            mstore(add(m, 1), l)
            mstore(add(m, 33), r)
            h := keccak256(m, 65)
        }
    }

    /// @dev M over K strictly increasing identifiers (K a power of two >= 2), or false when they are not strictly increasing.
    function root(bytes32[] memory z) internal pure returns (bool, bytes32) {
        uint256 k = z.length;
        if (k < 2 || k & (k - 1) != 0) return (false, 0);
        for (uint256 i = 1; i < k; ++i) {
            if (z[i - 1] >= z[i]) return (false, 0);
        }
        bytes32[] memory row = new bytes32[](k);
        for (uint256 i; i < k; ++i) {
            row[i] = leaf(z[i], z[(i + 1) % k]);
        }
        for (uint256 w = k; w > 1; w /= 2) {
            for (uint256 i; i < w / 2; ++i) {
                row[i] = node(row[2 * i], row[2 * i + 1]);
            }
        }
        return (true, row[0]);
    }

    /// @dev The root a gap proof u8(i) || l || u || s_0 .. s_{h-1} derives for eta, or false (section 10.2).
    function gapRoot(uint256 k, bytes32 eta, bytes memory proof)
        internal
        pure
        returns (bool, bytes32)
    {
        uint256 h;
        while ((uint256(1) << h) < k) ++h;
        if (proof.length != 65 + 32 * h) return (false, 0);
        uint256 i = uint8(proof[0]);
        bytes32 l;
        bytes32 u;
        assembly ("memory-safe") {
            l := mload(add(proof, 33))
            u := mload(add(proof, 65))
        }
        if (i >= k) return (false, 0);
        if (i < k - 1) {
            if (!(l < u && l < eta && eta < u)) return (false, 0);
        } else if (!(u < l && (l < eta || eta < u))) {
            return (false, 0);
        }
        bytes32 x = leaf(l, u);
        for (uint256 s; s < h; ++s) {
            bytes32 sib;
            assembly ("memory-safe") {
                sib := mload(add(proof, add(97, mul(32, s))))
            }
            x = (i >> s) & 1 == 0 ? node(x, sib) : node(sib, x);
        }
        return (true, x);
    }

    function genesisHead(bytes32 d, uint256 k) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ARCHIVE_GENESIS, d, uint16(k)));
    }

    function nextHead(bytes32 d, uint64 j, bytes32 hj, bytes32 mj) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ARCHIVE_STEP, d, j, hj, mj));
    }
}
// forge-lint: disable-end(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)
