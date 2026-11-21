// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Nb2Cbor as C} from "../verifier/Nb2Cbor.sol";
import {Nb2Rules as R} from "../verifier/Nb2Rules.sol";

// Offsets are bounded by the non-empty uint64 evidence, including the final short page.
// forge-lint: disable-start(unsafe-typecast)
uint64 constant AXIS_B_PAGE_BYTES = 4096;
uint256 constant AXIS_B_MAX_WINDOW_BYTES = 128 << 10;

contract AxisBCommitment {
    error InvalidWitness();

    struct Window {
        uint64 start;
        bytes data;
        bytes32[][] paths;
    }

    /// @dev Returns the first canonical item's length, preserving its original CBOR depth.
    /// The scan mirrors Nb2Cbor.scan, with a supplied base depth and no trailing-byte check.
    function itemLength(bytes calldata data, bool native, uint256 baseDepth)
        external
        pure
        returns (uint256 size)
    {
        if (baseDepth > C.MAX_DEPTH) C.fail(R.INPUT_TOO_LARGE);
        bytes4 eTruncated = R.TRUNCATED;
        bytes4 eNonCanonical = R.NON_CANONICAL;
        bytes4 eTooLarge = R.INPUT_TOO_LARGE;
        bytes4 err;
        assembly ("memory-safe") {
            // rem[d], the items left at depth d, in scratch memory past the free pointer (17 words).
            let p := data.offset
            let end := add(p, data.length)
            let rem := mload(0x40)
            let d := baseDepth
            mstore(add(rem, shl(5, d)), 1)
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
                    if eq(d, baseDepth) {
                        done := 1
                        break
                    }
                    d := sub(d, 1)
                }
            }
            size := sub(p, data.offset)
        }
        if (err != 0) C.fail(err);
    }

    function node(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), left, right));
    }

    function verify(Window calldata w, bytes32 root, uint64 total) external pure {
        if (
            w.start >= total || w.start % AXIS_B_PAGE_BYTES != 0 || w.data.length == 0
                || w.data.length > AXIS_B_MAX_WINDOW_BYTES || w.data.length > total - w.start
                || (w.start + w.data.length < total && w.data.length % AXIS_B_PAGE_BYTES != 0)
        ) revert InvalidWitness();
        uint256 count = (w.data.length - 1) / AXIS_B_PAGE_BYTES + 1;
        if (w.paths.length != count) revert InvalidWitness();
        uint256 depth = 0;
        for (uint256 n = (total - 1) / AXIS_B_PAGE_BYTES + 1; n > 1; n = (n + 1) / 2) {
            ++depth;
        }
        for (uint256 i = 0; i < count; ++i) {
            if (w.paths[i].length != depth) revert InvalidWitness();
            uint256 start = i * AXIS_B_PAGE_BYTES;
            uint256 end = start + AXIS_B_PAGE_BYTES;
            if (end > w.data.length) end = w.data.length;
            uint64 position = w.start + uint64(start);
            bytes32 h = keccak256(abi.encodePacked(bytes1(0), position, total, w.data[start:end]));
            uint256 index = position / AXIS_B_PAGE_BYTES;
            for (uint256 j = 0; j < depth; ++j) {
                bytes32 sibling = w.paths[i][j];
                h = index & 1 == 0 ? node(h, sibling) : node(sibling, h);
                index >>= 1;
            }
            if (h != root) revert InvalidWitness();
        }
    }

    function emptyRoot() external pure returns (bytes32 h) {
        h = 0;
        for (uint256 i = 0; i < 256; ++i) {
            h = node(h, h);
        }
    }

    function insert(bytes32 root, bytes32 sid, uint256 bitmap, bytes32[] calldata siblings)
        external
        pure
        returns (bytes32 used, bool absent)
    {
        bytes32 vacant = 0;
        bytes32 jointEmpty = 0;
        used = keccak256(abi.encodePacked(bytes1(0x02), sid));
        uint256 n = 0;
        for (uint256 i = 0; i < 256; ++i) {
            bytes32 sibling = jointEmpty;
            if ((bitmap >> i) & 1 != 0) {
                if (n >= siblings.length || siblings[n] == jointEmpty) revert InvalidWitness();
                sibling = siblings[n++];
            }
            if ((uint256(sid) >> i) & 1 == 0) {
                vacant = node(vacant, sibling);
                used = node(used, sibling);
            } else {
                vacant = node(sibling, vacant);
                used = node(sibling, used);
            }
            jointEmpty = node(jointEmpty, jointEmpty);
        }
        if (n != siblings.length) revert InvalidWitness();
        absent = vacant == root;
    }
}
// forge-lint: disable-end(unsafe-typecast)
