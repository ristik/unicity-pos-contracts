// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The linter's boolean-cst and uninitialized-local flag every `return (false, ...)` and zero-initialised accumulator; the
// precompile calls in loops are bounded by the input; typecasts are range-checked before narrowing; CBOR encodings are
// self-delimiting, so packed concatenation does not collide.
// forge-lint: disable-start(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)

/// @notice Hashing and secp256k1 helpers of the token verifier, over the standard precompiles only: SHA-256 (0x02) is H_U,
///         ecrecover (0x01) recovers unlock signers and derives the universal minter's key, modexp (0x05) decompresses keys.
library Nb2Crypto {
    /// @dev secp256k1 field prime, group order, n/2 and the generator's x coordinate (its y is even).
    uint256 internal constant P =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
    uint256 internal constant N =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 internal constant HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 internal constant GX =
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
    /// @dev (P + 1) / 4: the square-root exponent (P = 3 mod 4).
    uint256 internal constant SQRT_EXP =
        0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c;

    /// @dev A failed call to a standard precompile (out of gas): no rule, the call reverts.
    error PrecompileFailed(uint256 target);

    /// @dev SHA-256 of calldata [p, p + len).
    function sha256Cd(uint256 p, uint256 len) internal view returns (bytes32 h) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, p, len)
            if iszero(staticcall(gas(), 2, m, len, 0, 32)) {
                mstore(0, 0x00a4859300000000000000000000000000000000000000000000000000000000)
                mstore(4, 2)
                revert(0, 36)
            }
            h := mload(0)
        }
    }

    /// @dev SHA-256 of memory [m, m + len).
    function sha256Mem(uint256 m, uint256 len) internal view returns (bytes32 h) {
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 2, m, len, 0, 32)) {
                mstore(0, 0x00a4859300000000000000000000000000000000000000000000000000000000)
                mstore(4, 2)
                revert(0, 36)
            }
            h := mload(0)
        }
    }

    function sha256Bytes(bytes memory b) internal view returns (bytes32) {
        uint256 m;
        assembly ("memory-safe") {
            m := add(b, 32)
        }
        return sha256Mem(m, b.length);
    }

    function keccakCd(uint256 p, uint256 len) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, p, len)
            h := keccak256(m, len)
        }
    }

    /// @dev Address of a compressed key at calldata p (33 bytes), or zero when the key is not a valid secp256k1 point
    ///      (prefix other than 02/03, x >= P, or x^3 + 7 not a square): the reference's ParseKey.
    function keyAddress(uint256 p) internal view returns (address a) {
        uint256 prefix;
        uint256 x;
        assembly ("memory-safe") {
            prefix := shr(248, calldataload(p))
            x := calldataload(add(p, 1))
        }
        if ((prefix != 2 && prefix != 3) || x >= P) return address(0);
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        uint256 y = _modexp(rhs, SQRT_EXP, P);
        if (mulmod(y, y, P) != rhs) return address(0);
        if ((y & 1) != (prefix & 1)) y = P - y;
        assembly ("memory-safe") {
            mstore(0, x)
            mstore(32, y)
            a := and(keccak256(0, 64), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    function _modexp(uint256 b, uint256 e, uint256 m) private view returns (uint256 r) {
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, 32)
            mstore(add(f, 32), 32)
            mstore(add(f, 64), 32)
            mstore(add(f, 96), b)
            mstore(add(f, 128), e)
            mstore(add(f, 160), m)
            if iszero(staticcall(gas(), 5, f, 192, f, 32)) {
                mstore(0, 0x00a4859300000000000000000000000000000000000000000000000000000000)
                mstore(4, 5)
                revert(0, 36)
            }
            r := mload(f)
        }
    }

    /// @dev The signer of `digest` under r || s with recovery parity v in {0, 1}, or zero.
    function recover(bytes32 digest, uint256 v, bytes32 r, bytes32 s)
        internal
        view
        returns (address a)
    {
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, digest)
            mstore(add(f, 32), add(v, 27))
            mstore(add(f, 64), r)
            mstore(add(f, 96), s)
            mstore(0, 0)
            if iszero(staticcall(gas(), 1, f, 128, 0, 32)) {
                mstore(0, 0x00a4859300000000000000000000000000000000000000000000000000000000)
                mstore(4, 1)
                revert(0, 36)
            }
            a := mload(0)
        }
    }

    /// @dev Address of k * G for a valid secret 1 <= k < N, through ecrecover: with digest 0, r = Gx, v selecting the even
    ///      generator and s = k * Gx mod N, the recovered point is Gx^-1 * (s * G) = k * G.
    function scalarAddress(uint256 k) internal view returns (address) {
        return recover(bytes32(0), 0, bytes32(GX), bytes32(mulmod(k, GX, N)));
    }
}
// forge-lint: disable-end(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)
