// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {CborMalformed} from "./BridgeErrors.sol";

/// @notice The two CBOR operations the bridge needs on chain: shortest-form encoding of unsigned
///         integers, byte strings and array heads, and a head reader for the fixed-shape Cfg and
///         Policy. Every decoder re-encodes and compares, so canonicality does not rest on this
///         reader being strict.
library Cbor {
    uint8 internal constant UINT = 0;
    uint8 internal constant BYTES = 2;
    uint8 internal constant ARRAY = 4;

    // forge-lint: disable-start(unsafe-typecast)
    /// @dev Shortest-form head of `major` with argument `v`.
    function head(uint8 major, uint256 v) internal pure returns (bytes memory) {
        uint256 m = uint256(major) << 5;
        if (v < 24) return abi.encodePacked(uint8(m | v));
        if (v <= type(uint8).max) return abi.encodePacked(uint8(m | 24), uint8(v));
        if (v <= type(uint16).max) return abi.encodePacked(uint8(m | 25), uint16(v));
        if (v <= type(uint32).max) return abi.encodePacked(uint8(m | 26), uint32(v));
        if (v <= type(uint64).max) return abi.encodePacked(uint8(m | 27), uint64(v));
        revert CborMalformed();
    }
    // forge-lint: disable-end(unsafe-typecast)

    function uint_(uint256 v) internal pure returns (bytes memory) {
        return head(UINT, v);
    }

    function bstr(bytes memory b) internal pure returns (bytes memory) {
        return bytes.concat(head(BYTES, b.length), b);
    }

    function bstr32(bytes32 b) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x58), uint8(32), b);
    }

    function bstr20(address a) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x54), a);
    }

    function arrayHead(uint256 n) internal pure returns (bytes memory) {
        return head(ARRAY, n);
    }

    /// @dev ASCII domain string as a byte string.
    function domain(string memory s) internal pure returns (bytes memory) {
        return bstr(bytes(s));
    }

    /// @dev Minimal unsigned big-endian bytes of `v` (empty for zero).
    function minimalBytes(uint256 v) internal pure returns (bytes memory out) {
        uint256 n = 0;
        for (uint256 t = v; t != 0; t >>= 8) {
            ++n;
        }
        out = new bytes(n);
        for (uint256 i = n; i != 0; --i) {
            out[i - 1] = bytes1(uint8(v & 0xff));
            v >>= 8;
        }
    }

    /// @dev Reads one head at `pos`. Additional-information values 28..31 (reserved, indefinite)
    ///      revert; a non-shortest argument is caught by the caller's re-encode comparison.
    function readHead(bytes memory b, uint256 pos)
        internal
        pure
        returns (uint8 major, uint256 arg, uint256 next)
    {
        if (pos >= b.length) revert CborMalformed();
        uint8 first = uint8(b[pos]);
        major = first >> 5;
        uint8 ai = first & 0x1f;
        next = pos + 1;
        if (ai < 24) return (major, ai, next);
        if (ai > 27) revert CborMalformed();
        uint256 width = uint256(1) << (ai - 24);
        if (next + width > b.length) revert CborMalformed();
        for (uint256 i = 0; i < width; ++i) {
            arg = (arg << 8) | uint8(b[next + i]);
        }
        next += width;
    }

    /// @dev Reads a byte string of `min..max` bytes at `pos`.
    function readBytes(bytes memory b, uint256 pos, uint256 min, uint256 max)
        internal
        pure
        returns (bytes memory out, uint256 next)
    {
        (uint8 major, uint256 len, uint256 p) = readHead(b, pos);
        if (major != BYTES || len < min || len > max || p + len > b.length) revert CborMalformed();
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) {
            out[i] = b[p + i];
        }
        next = p + len;
    }

    /// @dev Reads a byte string of exactly `len` bytes at `pos`.
    function readBytesN(bytes memory b, uint256 pos, uint256 len)
        internal
        pure
        returns (bytes memory, uint256)
    {
        return readBytes(b, pos, len, len);
    }

    function readBytes32(bytes memory b, uint256 pos)
        internal
        pure
        returns (bytes32 v, uint256 next)
    {
        bytes memory t;
        (t, next) = readBytesN(b, pos, 32);
        assembly ("memory-safe") {
            v := mload(add(t, 32))
        }
    }

    function readAddress(bytes memory b, uint256 pos)
        internal
        pure
        returns (address a, uint256 next)
    {
        bytes memory t;
        (t, next) = readBytesN(b, pos, 20);
        assembly ("memory-safe") {
            a := shr(96, mload(add(t, 32)))
        }
    }

    /// @dev Reads an unsigned integer bounded by `max`.
    function readUint(bytes memory b, uint256 pos, uint256 max)
        internal
        pure
        returns (uint256 v, uint256 next)
    {
        uint8 major;
        (major, v, next) = readHead(b, pos);
        if (major != UINT || v > max) revert CborMalformed();
    }
}
