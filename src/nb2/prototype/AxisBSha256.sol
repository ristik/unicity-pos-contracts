// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice Portable SHA-256 compression for signed messages split across calls.
contract AxisBSha256 {
    bytes32 public constant IV = 0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;
    bytes private constant K =
        hex"428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca63511429296727b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa07019a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2";

    error InvalidHashChunk();

    function advance(bytes32 state, uint64 consumed, bytes calldata chunk, bool finalChunk)
        external
        pure
        returns (bytes32)
    {
        if (
            chunk.length == 0 || chunk.length > 4096 || consumed % 64 != 0
                || uint256(consumed) + chunk.length > type(uint64).max / 8 || !finalChunk
                && chunk.length % 64 != 0
        ) revert InvalidHashChunk();
        uint256 full = chunk.length & ~uint256(63);
        if (full != 0) state = _blocks(state, chunk[:full]);
        if (!finalChunk) return state;
        uint256 rem = chunk.length - full;
        uint256 zeroes = rem < 56 ? 55 - rem : 119 - rem;
        // The message suffix and zero padding are separated by the SHA-256 delimiter
        // and their lengths follow from the authenticated message length.
        // forge-lint: disable-next-line(encode-packed-collision,unsafe-typecast)
        bytes memory padded = abi.encodePacked(
            chunk[full:], bytes1(0x80), new bytes(zeroes), uint64((consumed + chunk.length) * 8)
        );
        return _blocks(state, padded);
    }

    function _blocks(bytes32 state, bytes memory input) private pure returns (bytes32 result) {
        bytes memory constants = K;
        assembly ("memory-safe") {
            function ror(x, n) -> y {
                y := or(shr(n, x), and(shl(sub(32, n), x), 0xffffffff))
            }
            function sig0(x) -> y { y := xor(xor(ror(x, 7), ror(x, 18)), shr(3, x)) }
            function sig1(x) -> y { y := xor(xor(ror(x, 17), ror(x, 19)), shr(10, x)) }
            let w := mload(0x40)
            mstore(0x40, add(w, 0x800))
            let end := add(add(input, 32), mload(input))
            let kp := add(constants, 32)
            for { let p := add(input, 32) } lt(p, end) { p := add(p, 64) } {
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    mstore(add(w, shl(5, i)), shr(224, mload(add(p, shl(2, i)))))
                }
                for { let i := 16 } lt(i, 64) { i := add(i, 1) } {
                    let off := add(w, shl(5, i))
                    let x := add(sig1(mload(sub(off, 64))), mload(sub(off, 224)))
                    let y := add(sig0(mload(sub(off, 480))), mload(sub(off, 512)))
                    mstore(off, and(add(x, y), 0xffffffff))
                }
                let a := shr(224, state)
                let b := and(shr(192, state), 0xffffffff)
                let c := and(shr(160, state), 0xffffffff)
                let d := and(shr(128, state), 0xffffffff)
                let e := and(shr(96, state), 0xffffffff)
                let f := and(shr(64, state), 0xffffffff)
                let g := and(shr(32, state), 0xffffffff)
                let h := and(state, 0xffffffff)
                for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                    let ch := xor(and(e, f), and(not(e), g))
                    let s1 := xor(xor(ror(e, 6), ror(e, 11)), ror(e, 25))
                    let t1 :=
                        add(
                            add(add(h, s1), ch),
                            add(shr(224, mload(add(kp, shl(2, i)))), mload(add(w, shl(5, i))))
                        )
                    let s0 := xor(xor(ror(a, 2), ror(a, 13)), ror(a, 22))
                    let maj := xor(xor(and(a, b), and(a, c)), and(b, c))
                    h := g
                    g := f
                    f := e
                    e := and(add(d, t1), 0xffffffff)
                    d := c
                    c := b
                    b := a
                    a := and(add(t1, add(s0, maj)), 0xffffffff)
                }
                let next := shl(224, add(a, shr(224, state)))
                next := or(next, shl(192, and(add(b, shr(192, state)), 0xffffffff)))
                next := or(next, shl(160, and(add(c, shr(160, state)), 0xffffffff)))
                next := or(next, shl(128, and(add(d, shr(128, state)), 0xffffffff)))
                next := or(next, shl(96, and(add(e, shr(96, state)), 0xffffffff)))
                next := or(next, shl(64, and(add(f, shr(64, state)), 0xffffffff)))
                next := or(next, shl(32, and(add(g, shr(32, state)), 0xffffffff)))
                state := or(next, and(add(h, state), 0xffffffff))
            }
            result := state
        }
    }
}
