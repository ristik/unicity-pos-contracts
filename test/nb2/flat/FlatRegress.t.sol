// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {
    FlatClaim,
    FlatHash,
    FlatWire as W,
    BadPage,
    BadStep
} from "../../../src/nb2/verifier/flat/FlatTypes.sol";
import {FlatNative} from "../../../src/nb2/verifier/flat/FlatNative.sol";
import {FlatHarness} from "./FlatHarness.sol";

/// @dev Exposes the early-bound checks and the native batch to external calls.
contract RegressionProbe {
    function allocation(bytes calldata p) external pure {
        W.boundAllocation(p);
    }

    function receipt(bytes calldata p) external pure {
        W.boundReceipt(W.offset(p), W.offset(p) + p.length);
    }

    function deposit(bytes calldata p) external pure {
        W.boundDeposit(p);
    }

    /// @return failed whether an append recorded a failed rollover (no revert, no flush)
    function fill(uint256 claims) external view returns (bool failed, uint256 count) {
        FlatNative.Batch memory b = FlatNative.batch();
        for (uint256 i; i < claims; ++i) {
            FlatNative.append(b, FlatClaim(bytes32(i + 1), bytes32(i + 1), hex"aabbccdd"));
        }
        return (b.failed, b.count);
    }

    /// @return deferred whether the 17th claim was accepted without a revert
    function rollover(uint256 claims) external view returns (bool deferred) {
        FlatNative.Batch memory b = FlatNative.batch();
        for (uint256 i; i < claims; ++i) {
            FlatNative.append(b, FlatClaim(bytes32(i + 1), bytes32(i + 1), hex"aabbccdd"));
        }
        deferred = true;
        FlatNative.flush(b);
    }
}

/// @notice Regressions for review round 1 of PR #95: refusal order across a native rollover and
/// framing bounds that precede the scans they bound.
contract FlatRegressTest is FlatHarness {
    RegressionProbe private probe;

    function _probe() private returns (RegressionProbe) {
        if (address(probe) == address(0)) probe = new RegressionProbe();
        return probe;
    }

    // A failed intermediate batch is not an immediate refusal. 17 claims force one rollover.
    function testRolloverFailureIsDeferredToTheFinalFlush() external {
        vm.etch(address(0x0100), hex"6002600052600060205260406000f3"); // version 2, false
        RegressionProbe p = _probe();
        // The 17th append returns normally with the failure recorded; 16 do not roll over.
        (bool failed, uint256 count) = p.fill(17);
        assertTrue(failed);
        assertEq(count, 16);
        (failed, count) = p.fill(16);
        assertFalse(failed);
        assertEq(count, 16);
        vm.expectRevert(BadStep.selector);
        p.rollover(17);
        vm.expectRevert(BadStep.selector);
        p.rollover(1);
        // Accepting batches roll over without a trace.
        vm.etch(address(0x0100), hex"6002600052600160205260406000f3");
        p.rollover(17);
        p.rollover(40);
    }

    // T1 order: operations, then unused pages, then the pending batch. A false batch with an unused
    // authenticated page is BadPage; the same packet without the extra page is BadStep.
    function testFalseBatchAfterUnusedPageIsBadPage() external {
        _loadTrust(_path("transfers-600"));
        bytes memory evidence =
            vm.readFileBinary(string.concat(_path("transfers-600"), "evidence.bin"));
        (bytes memory input,) =
            _field(vm.readFileBinary(string.concat(_path("transfers-600"), "trace.bin")), 0);
        bytes memory extra = _withUnusedPage(input, evidence);
        _fails(extra, BadPage.selector);
        vm.etch(address(0x0100), hex"6002600052600060205260406000f3");
        _fails(extra, BadPage.selector);
        _fails(input, BadStep.selector);
    }

    function testEarlyBoundsAllocation() external {
        RegressionProbe p = _probe();
        p.allocation(hex"990100"); // 256 declared, no children: the scan has not run
        p.allocation(hex"80");
        vm.expectRevert(BadStep.selector);
        p.allocation(hex"990101");
        vm.expectRevert(BadStep.selector);
        p.allocation(hex"");
    }

    function testEarlyBoundsReceiptAndEmbeddedDeposit() external {
        RegressionProbe p = _probe();
        p.receipt(_receipt(hex"9841"));
        p.deposit(_deposit(hex"9841"));
        bytes[2] memory over = [_receipt(hex"9842"), _deposit(hex"9842")];
        bytes[2] memory none = [_receipt(hex"80"), _deposit(hex"80")];
        for (uint256 i; i < 2; ++i) {
            vm.expectRevert(BadStep.selector);
            this.dispatch(i, over[i]);
            vm.expectRevert(BadStep.selector);
            this.dispatch(i, none[i]);
        }
        // Truncated before the node array head.
        vm.expectRevert(BadStep.selector);
        p.receipt(hex"860141004100");
    }

    function dispatch(uint256 which, bytes calldata p) external {
        if (which == 0) _probe().receipt(p);
        else _probe().deposit(p);
    }

    function _receipt(bytes memory nodeHead) private pure returns (bytes memory) {
        return bytes.concat(hex"8601410041000000", nodeHead);
    }

    function _deposit(bytes memory nodeHead) private pure returns (bytes memory) {
        return bytes.concat(
            hex"d9988b8501",
            hex"5820",
            bytes32(uint256(1)),
            hex"01",
            hex"5820",
            bytes32(uint256(2)),
            _receipt(nodeHead)
        );
    }

    function _withUnusedPage(bytes memory input, bytes memory evidence)
        private
        pure
        returns (bytes memory)
    {
        uint256 n = evidence.length;
        uint256 pages = 1 + (n - 1) / 4096;
        uint256 depth;
        for (uint256 v = pages - 1; v != 0; v >>= 1) {
            ++depth;
        }
        // data starts after selector, offset and length words
        uint256 p = 68 + 44;
        uint256 count = uint8(input[68 + 43]);
        for (uint256 i; i < count; ++i) {
            uint256 index = uint64(bytes8(_word(input, p)));
            uint256 size = index == pages - 1 ? n - index * 4096 : 4096;
            p += 8 + size + 32 * depth;
        }
        bytes memory entry = _pageEntry(evidence, pages - 1, depth);
        uint256 dataLen = uint256(_word(input, 36)) + entry.length;
        bytes memory body = bytes.concat(
            _slice(input, 68, 43),
            bytes1(uint8(count + 1)),
            _slice(input, 68 + 44, p - 68 - 44),
            entry
        );
        body = bytes.concat(body, _slice(input, p, 68 + uint256(_word(input, 36)) - p));
        return bytes.concat(
            _slice(input, 0, 4),
            bytes32(uint256(32)),
            bytes32(dataLen),
            body,
            new bytes((32 - dataLen % 32) % 32)
        );
    }

    function _pageEntry(bytes memory evidence, uint256 index, uint256 depth)
        private
        pure
        returns (bytes memory out)
    {
        uint256 n = evidence.length;
        uint256 pages = 1 + (n - 1) / 4096;
        bytes32[] memory level = new bytes32[](1 << depth);
        for (uint256 i; i < level.length; ++i) {
            level[i] = i >= pages
                ? keccak256(abi.encode(FlatHash.PAD))
                : keccak256(
                    abi.encodePacked(
                        FlatHash.PAGE,
                        uint64(n),
                        uint64(i),
                        uint16(_size(n, i)),
                        _slice(evidence, i * 4096, _size(n, i))
                    )
                );
        }
        out = abi.encodePacked(uint64(index), _slice(evidence, index * 4096, _size(n, index)));
        uint256 cursor = index;
        for (uint256 h; h < depth; ++h) {
            out = bytes.concat(out, level[cursor ^ 1]);
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i; i < next.length; ++i) {
                next[i] =
                    keccak256(abi.encodePacked(FlatHash.PAGE_NODE, level[2 * i], level[2 * i + 1]));
            }
            level = next;
            cursor >>= 1;
        }
    }

    function _size(uint256 n, uint256 i) private pure returns (uint256) {
        return n - i * 4096 < 4096 ? n - i * 4096 : 4096;
    }

    function _slice(bytes memory b, uint256 from, uint256 len)
        private
        pure
        returns (bytes memory out)
    {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = b[from + i];
        }
    }

    // ---- Over-limit node count reaches the production receipt entry (Resume and advanceGaps). ----

    // A valid receipt whose node-array head declares 66 nodes is refused from the head, before the
    // scan, the UC fold and the header check. Early refusal is observable as gas: the unmodified
    // receipt costs far more, and so would the modified one if the precheck were removed.
    function testOverLimitReceiptIsRefusedBeforeAnyWorkThroughProductionEntries() external {
        _loadTrust(_path("root"));
        // advanceGaps (receipt blob follows the 42-byte header and the kind byte).
        bytes memory advance =
            vm.readFileBinary(string.concat(_path("cold/advance-kind1-count1"), "calldata.bin"));
        _early(advance, 43);
        // Resume (state, then the receipt blob).
        _loadTrust(_path("shared-claim"));
        (bytes memory first,) =
            _field(vm.readFileBinary(string.concat(_path("shared-claim"), "trace.bin")), 0);
        bytes memory trace = vm.readFileBinary(string.concat(_path("shared-claim"), "trace.bin"));
        (, uint256 cursor) = _field(trace, 0);
        for (uint256 k; k < 5; ++k) {
            (, cursor) = _field(trace, cursor);
        }
        (bytes memory resume,) = _field(trace, cursor);
        assertEq(uint8(first[68 + 42]), 0);
        assertEq(uint8(resume[68 + 42]), 1);
        _early(resume, 43 + 290);
    }

    function _early(bytes memory input, uint256 blobAt) private {
        uint256 where = 68 + blobAt;
        uint256 len = uint32(bytes4(_word(input, where)));
        bytes memory proof = _slice(input, where + 4, len);
        // Unmodified: reaches the whole receipt authentication.
        uint256 before = gasleft();
        (bool ok,) = RECOVERY.call(input);
        uint256 valid = before - gasleft();
        assertTrue(ok);
        assertGt(valid, 250_000);
        bytes memory bad = _swap(input, where, len, _declare66(proof));
        before = gasleft();
        (bool refused, bytes memory why) = RECOVERY.call(bad);
        uint256 early = before - gasleft();
        assertFalse(refused);
        assertEq(why, abi.encodeWithSelector(bytes4(keccak256("BadPredecessor()"))));
        assertLt(early * 3, valid);
    }

    // Replace the node-array head of a receipt proof by a declaration of 66 nodes.
    function _declare66(bytes memory proof) private pure returns (bytes memory) {
        uint256 p = 2; // 0x86 and version 1
        for (uint256 i; i < 2; ++i) {
            p = _skipBytes(proof, p);
        }
        for (uint256 i; i < 2; ++i) {
            p += _headLen(uint8(proof[p]));
        }
        uint256 oldHead = _headLen(uint8(proof[p]));
        uint256 n = uint8(proof[p]) & 31;
        if (n >= 24) n = uint8(proof[p + 1]);
        require(n <= 66, "fixture");
        // Pad with empty byte strings so the item stays canonical: the scan accepts it and only
        // the node count (66 > 65) is wrong. Without the precheck the whole UC and header run first.
        return _padded(proof, p, oldHead, n);
    }

    function _padded(bytes memory proof, uint256 p, uint256 oldHead, uint256 n)
        private
        pure
        returns (bytes memory)
    {
        bytes memory pad = new bytes(66 - n);
        for (uint256 i; i < pad.length; ++i) {
            pad[i] = 0x40;
        }
        return bytes.concat(
            _slice(proof, 0, p),
            hex"9842",
            _slice(proof, p + oldHead, proof.length - p - oldHead),
            pad
        );
    }

    function _headLen(uint8 first) private pure returns (uint256) {
        uint8 ai = first & 31;
        if (ai < 24) return 1;
        if (ai == 24) return 2;
        if (ai == 25) return 3;
        if (ai == 26) return 5;
        return 9;
    }

    function _skipBytes(bytes memory b, uint256 p) private pure returns (uint256) {
        uint8 ai = uint8(b[p]) & 31;
        uint256 n = ai;
        uint256 h = _headLen(uint8(b[p]));
        if (ai >= 24) {
            n = 0;
            for (uint256 i = 1; i < h; ++i) {
                n = (n << 8) | uint8(b[p + i]);
            }
        }
        return p + h + n;
    }

    function _swap(bytes memory input, uint256 where, uint256 oldLen, bytes memory proof)
        private
        pure
        returns (bytes memory)
    {
        uint256 total = uint256(_word(input, 36));
        bytes memory body = bytes.concat(
            _slice(input, 68, where - 68),
            bytes4(uint32(proof.length)),
            proof,
            _slice(input, where + 4 + oldLen, 68 + total - (where + 4 + oldLen))
        );
        return bytes.concat(
            _slice(input, 0, 4),
            bytes32(uint256(32)),
            bytes32(body.length),
            body,
            new bytes((32 - body.length % 32) % 32)
        );
    }

    function testReceiptBytesStringCapsAreEnforcedFromTheHead() external {
        RegressionProbe p = _probe();
        p.receipt(_capped(16384, 1));
        vm.expectRevert(BadStep.selector);
        p.receipt(_capped(16385, 1));
        vm.expectRevert(BadStep.selector);
        p.receipt(_capped(1, 2049));
    }

    // 86 01 <uc of ucLen bytes> <header of headerLen bytes> 00 00 <9841: 65 nodes, heads only>
    function _capped(uint256 ucLen, uint256 headerLen) private pure returns (bytes memory) {
        return bytes.concat(
            hex"8601",
            _bstrHead(ucLen),
            new bytes(ucLen),
            _bstrHead(headerLen),
            new bytes(headerLen),
            hex"00009841"
        );
    }

    function _bstrHead(uint256 n) private pure returns (bytes memory) {
        return n < 24
            ? abi.encodePacked(uint8(0x40 + n))
            : n < 256
                ? abi.encodePacked(uint8(0x58), uint8(n))
                : abi.encodePacked(uint8(0x59), uint16(n));
    }
}
