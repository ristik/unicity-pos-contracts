// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The linter's boolean-cst and uninitialized-local flag every `return (false, ...)` and zero-initialised accumulator; the
// precompile calls in loops are bounded by the input; typecasts are range-checked before narrowing; CBOR encodings are
// self-delimiting, so packed concatenation does not collide.
// forge-lint: disable-start(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)

import {Nb2Rules as R} from "./Nb2Rules.sol";

/// @notice Canonical CBOR over calldata (docs/design/native-bridge-v2.md section 3; bft-core nb2ref/cbor.go). Every position is
///         an absolute calldata offset. `scan` is the strict scanner of one decoding unit and returns the first violation in
///         stream order. The readers below it assume a unit `scan` accepted and raise the 14.1 rules in the reference's order.
library Nb2Cbor {
    /// @dev The profile's cborDepth.
    uint256 internal constant MAX_DEPTH = 16;

    function fail(bytes4 rule) internal pure {
        assembly ("memory-safe") {
            mstore(0, rule)
            revert(0, 4)
        }
    }

    function u8(uint256 p) internal pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(248, calldataload(p))
        }
    }

    function word(uint256 p) internal pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := calldataload(p)
        }
    }

    /// @dev Strict scan of exactly one item spanning [p, end). `native` admits text strings and maps (an embedded native
    ///      certificate); negative integers, floats and simple values other than null are always refused. Returns 0 or the
    ///      first rule violated: Truncated, NonCanonical, InputTooLarge (depth), Trailing.
    function scan(uint256 p, uint256 end, bool native) internal pure returns (bytes4 err) {
        bytes4 eTruncated = R.TRUNCATED;
        bytes4 eNonCanonical = R.NON_CANONICAL;
        bytes4 eTooLarge = R.INPUT_TOO_LARGE;
        bytes4 eTrailing = R.TRAILING;
        assembly ("memory-safe") {
            // rem[d], the items left at depth d, in scratch memory past the free pointer (17 words).
            let rem := mload(0x40)
            let d := 0
            mstore(rem, 1)
            // bit b set: initial byte b is forbidden (negative integers, simple values other than null; text and maps outside
            // a native certificate)
            let forbidden := 0xffbfffff0000000000000000000000000000000000000000ffffffff00000000
            if iszero(native) {
                forbidden := 0xffbfffff00000000ffffffff00000000ffffffff00000000ffffffff00000000
            }
            let done := 0
            for {} iszero(done) {} {
                if iszero(lt(p, end)) {
                    err := eTruncated
                    break
                }
                let b := byte(0, calldataload(p))
                let mj := shr(5, b)
                if and(shr(b, forbidden), 1) {
                    err := eNonCanonical
                    break
                }
                let ai := and(b, 31)
                let arg := ai
                p := add(p, 1)
                if gt(ai, 23) {
                    if gt(ai, 27) {
                        err := eNonCanonical
                        break
                    }
                    let n := shl(sub(ai, 24), 1)
                    if lt(sub(end, p), n) {
                        err := eTruncated
                        break
                    }
                    arg := shr(sub(256, shl(3, n)), calldataload(p))
                    p := add(p, n)
                    let lo := 24
                    if gt(n, 1) { lo := shl(shl(2, n), 1) }
                    if lt(arg, lo) {
                        err := eNonCanonical
                        break
                    }
                }
                let rest := sub(end, p)
                let slot := add(rem, shl(5, d))
                mstore(slot, sub(mload(slot), 1))
                let push := 0
                switch mj
                case 2 {
                    if gt(arg, rest) {
                        err := eTruncated
                        break
                    }
                    p := add(p, arg)
                }
                case 3 {
                    if gt(arg, rest) {
                        err := eTruncated
                        break
                    }
                    p := add(p, arg)
                }
                case 4 {
                    if gt(add(d, 1), 16) {
                        err := eTooLarge
                        break
                    }
                    if gt(arg, rest) {
                        err := eTruncated
                        break
                    }
                    push := arg
                }
                case 5 {
                    if gt(add(d, 1), 16) {
                        err := eTooLarge
                        break
                    }
                    if gt(arg, rest) {
                        err := eTruncated
                        break
                    }
                    push := shl(1, arg)
                    if gt(push, rest) {
                        err := eTruncated
                        break
                    }
                }
                case 6 {
                    if gt(add(d, 1), 16) {
                        err := eTooLarge
                        break
                    }
                    push := 1
                }
                if push {
                    d := add(d, 1)
                    mstore(add(rem, shl(5, d)), push)
                    continue
                }
                for {} iszero(mload(add(rem, shl(5, d)))) {} {
                    if iszero(d) {
                        done := 1
                        break
                    }
                    d := sub(d, 1)
                }
            }
            if and(done, iszero(eq(p, end))) { err := eTrailing }
        }
    }

    /// @dev Head of a scanned item: major type, argument, position after the head.
    function hd(uint256 p) internal pure returns (uint256 mj, uint256 arg, uint256 q) {
        assembly ("memory-safe") {
            let b := shr(248, calldataload(p))
            mj := shr(5, b)
            let ai := and(b, 31)
            switch lt(ai, 24)
            case 1 {
                arg := ai
                q := add(p, 1)
            }
            default {
                let n := shl(sub(ai, 24), 1)
                arg := shr(sub(256, shl(3, n)), calldataload(add(p, 1)))
                q := add(add(p, 1), n)
            }
        }
    }

    /// @dev End of a scanned item.
    function skip(uint256 p) internal pure returns (uint256 q) {
        assembly ("memory-safe") {
            let pending := 1
            q := p
            for {} pending {} {
                let b := shr(248, calldataload(q))
                let mj := shr(5, b)
                let ai := and(b, 31)
                let arg := ai
                q := add(q, 1)
                if gt(ai, 23) {
                    let n := shl(sub(ai, 24), 1)
                    arg := shr(sub(256, shl(3, n)), calldataload(q))
                    q := add(q, n)
                }
                pending := sub(pending, 1)
                switch mj
                case 2 { q := add(q, arg) }
                case 3 { q := add(q, arg) }
                case 4 { pending := add(pending, arg) }
                case 5 { pending := add(pending, shl(1, arg)) }
                case 6 { pending := add(pending, 1) }
            }
        }
    }

    function isNull(uint256 p) internal pure returns (bool) {
        return u8(p) == 0xf6;
    }

    /// @dev Content position of tag `tag` at p (Shape, Tag).
    function tagged(uint256 p, uint256 tag) internal pure returns (uint256 q) {
        uint256 mj;
        uint256 arg;
        (mj, arg, q) = hd(p);
        if (mj != 6) fail(R.SHAPE);
        if (arg != tag) fail(R.TAG);
    }

    /// @dev First element of an array of exactly n items (Shape).
    function array(uint256 p, uint256 n) internal pure returns (uint256 q) {
        uint256 mj;
        uint256 arg;
        (mj, arg, q) = hd(p);
        if (mj != 4 || arg != n) fail(R.SHAPE);
    }

    /// @dev Any array: (count, first element).
    function anyArray(uint256 p) internal pure returns (uint256 n, uint256 q) {
        uint256 mj;
        (mj, n, q) = hd(p);
        if (mj != 4) fail(R.SHAPE);
    }

    function version(uint256 p, uint256 want) internal pure returns (uint256 q) {
        uint256 mj;
        uint256 arg;
        (mj, arg, q) = hd(p);
        if (mj != 0) fail(R.SHAPE);
        if (arg != want) fail(R.VERSION);
    }

    function uintIn(uint256 p, uint256 lo, uint256 hi)
        internal
        pure
        returns (uint256 v, uint256 q)
    {
        uint256 mj;
        (mj, v, q) = hd(p);
        if (mj != 0) fail(R.SHAPE);
        if (v < lo || v > hi) fail(R.INT_RANGE);
    }

    /// @dev Byte string of exactly n bytes: (payload position, next) (Shape, Length).
    function fixedBytes(uint256 p, uint256 n) internal pure returns (uint256 dp, uint256 q) {
        uint256 mj;
        uint256 len;
        (mj, len, dp) = hd(p);
        if (mj != 2) fail(R.SHAPE);
        if (len != n) fail(R.LENGTH);
        q = dp + len;
    }

    function bytes32At(uint256 p) internal pure returns (bytes32 v, uint256 q) {
        uint256 dp;
        (dp, q) = fixedBytes(p, 32);
        v = word(dp);
    }

    /// @dev Any byte string: (payload position, length, next) (Shape).
    function bstr(uint256 p) internal pure returns (uint256 dp, uint256 len, uint256 q) {
        uint256 mj;
        (mj, len, dp) = hd(p);
        if (mj != 2) fail(R.SHAPE);
        q = dp + len;
    }

    /// @dev null or a byte string: (null, payload position, length, next).
    function nullable(uint256 p)
        internal
        pure
        returns (bool nul, uint256 dp, uint256 len, uint256 q)
    {
        if (isNull(p)) return (true, 0, 0, p + 1);
        (dp, len, q) = bstr(p);
    }

    /// @dev An Amount: a minimal positive big-endian byte string of 1 to 32 bytes (Shape, IntRange, Length, NonCanonical).
    function amount(uint256 p) internal pure returns (uint256 v, uint256 q) {
        (uint256 dp, uint256 len, uint256 q2) = bstr(p);
        if (len == 0) fail(R.INT_RANGE);
        if (len > 32) fail(R.LENGTH);
        if (u8(dp) == 0) fail(R.NON_CANONICAL);
        assembly ("memory-safe") {
            v := shr(sub(256, shl(3, len)), calldataload(dp))
        }
        q = q2;
    }

    /// @dev The SDK deadline: null (unset) or a uint in [1, 2^64 - 1].
    function deadline(uint256 p) internal pure returns (bool set, uint256 when, uint256 q) {
        if (isNull(p)) return (false, 0, p + 1);
        (when, q) = uintIn(p, 1, type(uint64).max);
        set = true;
    }

    /// @dev Amount check without reverting (post-certificate parsers map every failure to one rule).
    function amountOk(uint256 p) internal pure returns (bool ok, uint256 v, uint256 q) {
        (uint256 mj, uint256 len, uint256 dp) = hd(p);
        if (mj != 2 || len == 0 || len > 32 || u8(dp) == 0) return (false, 0, 0);
        assembly ("memory-safe") {
            v := shr(sub(256, shl(3, len)), calldataload(dp))
        }
        return (true, v, dp + len);
    }
}
// forge-lint: disable-end(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)
