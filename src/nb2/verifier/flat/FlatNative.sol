// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BadStep, FlatClaim} from "./FlatTypes.sol";

library FlatNative {
    address internal constant CERT = address(0x0100);
    address internal constant MEMBER = address(0x0102);
    address internal constant REGISTRY = 0xff00000000000000000000000000000000000002;
    uint256 private constant MAX_BATCH_BYTES = 262144;
    uint256 private constant MAX_CLAIMS = 16;

    struct Batch {
        bytes buffer;
        uint256 size;
        uint256 count;
        // A batch that fails on rollover is not an immediate refusal: T1 diagnoses operations and
        // unused pages first. The failure is kept and raised by the final flush.
        bool failed;
    }

    function batch() internal pure returns (Batch memory b) {
        b.buffer = new bytes(MAX_BATCH_BYTES);
        b.size = 4;
    }

    function append(Batch memory b, FlatClaim memory claim) internal view {
        // With 16 claims the per-certificate bounds also imply <=256 signatures,
        // <=4608 path elements and <32768 CBOR tokens.
        if (b.failed) return;
        if (b.count == MAX_CLAIMS || b.size + claim.packed.length > MAX_BATCH_BYTES) {
            if (!verify(b)) {
                b.failed = true;
                return;
            }
        }
        bytes memory raw = claim.packed;
        uint256 offset = b.size;
        assembly ("memory-safe") {
            mcopy(add(add(mload(b), 32), offset), add(raw, 32), mload(raw))
        }
        b.size += raw.length;
        ++b.count;
    }

    /// @dev Raise any deferred rollover failure, then verify the pending claims.
    function flush(Batch memory b) internal view {
        if (b.failed || !verify(b)) revert BadStep();
    }

    function verify(Batch memory b) private view returns (bool) {
        uint256 count = b.count;
        if (count == 0) return true;
        bytes memory input = b.buffer;
        uint256 size = b.size;
        assembly ("memory-safe") {
            let p := add(input, 32)
            // This write must preserve the first claim, which starts at byte four.
            mstore(p, or(and(mload(p), sub(shl(224, 1), 1)), shl(224, or(0x02000000, count))))
        }
        if (!check(CERT, 2, input, size)) return false;
        b.size = 4;
        b.count = 0;
        return true;
    }

    function singleton(FlatClaim memory claim) internal view returns (bool) {
        bytes memory input = bytes.concat(hex"02000001", claim.packed);
        return check(CERT, 2, input, input.length);
    }

    function member(bytes32 root, bytes32 sid, bytes32 leaf, bytes calldata path)
        internal
        view
        returns (bool)
    {
        bytes memory input = abi.encodePacked(hex"01000001", root, sid, uint32(32), leaf, path);
        return check(MEMBER, 1, input, input.length);
    }

    function check(address target, uint256 version, bytes memory input, uint256 size)
        private
        view
        returns (bool ok)
    {
        assembly ("memory-safe") {
            ok := staticcall(gas(), target, add(input, 32), size, 0, 64)
            ok := and(
                ok,
                and(eq(returndatasize(), 64), and(eq(mload(0), version), eq(mload(32), 1)))
            )
        }
    }
}
