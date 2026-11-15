// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice The circular-gap proof of native bridge v2 (bft-core docs/design/native-bridge-v2.md section 10.2).
library NB2Gap {
    /// @notice Checks the gap proof `proof` = u8(i) || l || u || s_0 .. s_{h-1} (exactly 65 + 32h bytes) for `eta` in a segment
    ///         of K = 2^h identifiers and returns the root M it folds to. `ok` is false for a wrong length, i >= K, or eta not
    ///         strictly inside the gap: l < eta < u with l < u for i < K - 1, and l > u with (eta > l or eta < u) for the
    ///         exterior gap i = K - 1. The caller compares `root` with the expected one; no root is carried.
    function root(uint256 eta, bytes calldata proof, uint256 h)
        internal
        pure
        returns (bool ok, bytes32 r)
    {
        // forge-lint: disable-next-line(boolean-cst)
        if (proof.length != 65 + (h << 5)) return (false, bytes32(0));
        uint256 o;
        uint256 s;
        assembly ("memory-safe") {
            o := proof.offset
            s := mload(0x40)
        }
        return rootAt(eta, o, h, s);
    }

    /// @notice `root` for the proof at calldata offset `o` (its length checked by the caller), with 65 bytes of scratch
    ///         memory at `s` (at or above the free memory pointer).
    function rootAt(uint256 eta, uint256 o, uint256 h, uint256 s)
        internal
        pure
        returns (bool ok, bytes32 r)
    {
        assembly ("memory-safe") {
            // shl(shift, value): 2^h - 1
            // forge-lint: disable-next-line(incorrect-shift)
            let km1 := sub(shl(h, 1), 1)
            let i := byte(0, calldataload(o))
            let l := calldataload(add(o, 1))
            let u := calldataload(add(o, 33))
            switch lt(i, km1)
            case 1 { ok := and(lt(l, u), and(lt(l, eta), lt(eta, u))) }
            default { ok := and(eq(i, km1), and(gt(l, u), or(gt(eta, l), lt(eta, u)))) }
            if ok {
                // leaf = H_E(0x00 || l || u); step k: H_E(0x01 || x || s_k) if bit k of i is 0, else H_E(0x01 || s_k || x)
                mstore8(s, 0)
                mstore(add(s, 1), l)
                mstore(add(s, 33), u)
                let x := keccak256(s, 65)
                mstore8(s, 1)
                let sp := add(o, 65)
                for { let j := 0 } lt(j, h) { j := add(j, 1) } {
                    let sib := calldataload(sp)
                    switch and(shr(j, i), 1)
                    case 0 {
                        mstore(add(s, 1), x)
                        mstore(add(s, 33), sib)
                    }
                    default {
                        mstore(add(s, 1), sib)
                        mstore(add(s, 33), x)
                    }
                    x := keccak256(s, 65)
                    sp := add(sp, 32)
                }
                r := x
            }
        }
    }
}
