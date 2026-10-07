// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// @title KeyLib
/// @notice Proof-of-possession primitives over 33-byte compressed secp256k1 verification keys.
/// A signature is r || s || v (65 bytes, v in {27, 28}) over a 32-byte digest; s must be in the
/// lower half order. The key is decompressed with the modexp precompile and the recovered signer
/// must equal the address of that exact public key, so possession is bound to the stored key.
library KeyLib {
    error BadKeyLength();
    error BadKeyPrefix();
    error KeyNotOnCurve();

    uint256 internal constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 internal constant KEY_LENGTH = 33;

    function hash(bytes memory key) internal pure returns (bytes32) {
        return keccak256(key);
    }

    /// @notice The EVM address of the decompressed public key.
    function toAddress(bytes memory key) internal view returns (address) {
        if (key.length != KEY_LENGTH) revert BadKeyLength();
        uint8 prefix = uint8(key[0]);
        if (prefix != 2 && prefix != 3) revert BadKeyPrefix();
        uint256 x;
        assembly ("memory-safe") {
            x := mload(add(key, 0x21))
        }
        if (x >= P) revert KeyNotOnCurve();
        uint256 y2 = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        uint256 y = _modexp(y2, (P + 1) / 4);
        if (mulmod(y, y, P) != y2) revert KeyNotOnCurve();
        if ((y & 1) != (prefix & 1)) y = P - y;
        return address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
    }

    /// @notice True iff `signature` over `digest` was produced by the private key of `key`.
    /// Malformed keys revert; malformed signatures return false.
    function verify(bytes memory key, bytes32 digest, bytes memory signature)
        internal
        view
        returns (bool)
    {
        address expected = toAddress(key);
        address signer = recover(digest, signature);
        return signer != address(0) && signer == expected;
    }

    /// @notice The signer of a 65-byte low-s signature, or the zero address if malformed.
    function recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (uint256(s) > HALF_N || (v != 27 && v != 28)) return address(0);
        return ecrecover(digest, v, r, s);
    }

    function _modexp(uint256 base, uint256 exponent) private view returns (uint256 result) {
        bytes memory input = abi.encode(uint256(32), uint256(32), uint256(32), base, exponent, P);
        assembly ("memory-safe") {
            let out := mload(0x40)
            // The modexp precompile is part of the pinned cancun profile and cannot fail on these
            // inputs; an (impossible) failure would be caught by the caller's curve check.
            pop(staticcall(gas(), 0x05, add(input, 0x20), mload(input), out, 0x20))
            result := mload(out)
        }
    }
}
