// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The full calldata and each field width are bounded before narrowing. Loop indices and fixed arrays start at zero.
// forge-lint: disable-start(unsafe-typecast,uninitialized-local)

import {FlatHash, FlatWire as W, BadPacket, BadPage, BadStep} from "./FlatTypes.sol";

library FlatPacket {
    uint256 private constant PAGE_SIZE = 4096;
    uint256 private constant MAX_CALLDATA = 393216;

    struct Header {
        uint64 size;
        bytes32 root;
    }

    struct Page {
        uint64 index;
        uint32 pos;
        uint16 size;
    }

    struct Operation {
        uint8 opcode;
        uint32 pos;
    }

    struct Run {
        Header header;
        bool resume;
        uint32 receiptPos;
        uint32 receiptEnd;
        uint256 pageCount;
        uint256 depth;
        Page[32] pages;
        uint256 opCount;
        Operation[16] operations;
        uint256 pageCursor;
        uint256 used;
    }

    struct Gaps {
        Header header;
        uint8 kind;
        uint32 receiptPos;
        uint32 receiptEnd;
        uint256 count;
        uint256 gapsPos;
        bytes32 startHead;
    }

    function argument(bytes calldata callData) internal pure returns (bytes calldata b) {
        uint256 total = callData.length;
        if (total > MAX_CALLDATA || total < 68 || uint256(W.word(callData, 4)) != 32) {
            revert BadPacket();
        }
        uint256 size = uint256(W.word(callData, 36));
        if (size > total - 68 || total - 68 != (size + 31) & ~uint256(31)) revert BadPacket();
        if (size % 32 != 0 && W.number(callData, 68 + size, 32 - size % 32) != 0) {
            revert BadPacket();
        }
        return callData[68:68 + size];
    }

    function _header(bytes calldata b) private pure returns (Header memory h) {
        _need(b, 0, 42);
        if (W.number(b, 0, 2) != W.VERSION) revert BadPacket();
        h.size = uint64(W.number(b, 2, 8));
        if (h.size < 14) revert BadPacket();
        h.root = W.word(b, 10);
    }

    function frameRun(bytes calldata b) internal pure returns (Run memory r) {
        r.header = _header(b);
        _need(b, 42, 1);
        uint256 mode = W.number(b, 42, 1);
        uint256 p = 43;
        if (mode > 1) revert BadPacket();
        if (mode == 1) {
            r.resume = true;
            _need(b, p, 290);
            (r.receiptPos, r.receiptEnd) = _receipt(b, p + 290);
            p = r.receiptEnd;
        }
        _need(b, p, 1);
        r.pageCount = W.number(b, p++, 1);
        if (r.pageCount == 0 || r.pageCount > 32) revert BadPacket();
        uint256 pages = 1 + (uint256(r.header.size) - 1) / PAGE_SIZE;
        for (uint256 v = pages - 1; v != 0; v >>= 1) {
            ++r.depth;
        }
        for (uint256 i; i < r.pageCount; ++i) {
            _need(b, p, 8);
            uint256 index = W.number(b, p, 8);
            p += 8;
            if (index >= pages) revert BadPacket();
            uint256 size = index == pages - 1 ? r.header.size - index * PAGE_SIZE : PAGE_SIZE;
            r.pages[i] = Page(uint64(index), uint32(p), uint16(size));
            uint256 width = size + 32 * r.depth;
            _need(b, p, width);
            p += width;
        }

        _need(b, p, 1);
        r.opCount = W.number(b, p++, 1);
        if (r.opCount == 0 || r.opCount > 16) revert BadPacket();
        for (uint256 i; i < r.opCount; ++i) {
            _need(b, p, 1);
            uint256 op = W.number(b, p++, 1);
            if (op == 0 || op > 3) revert BadPacket();
            r.operations[i] = Operation(uint8(op), uint32(p));
            p = _sparseEnd(b, p);
            p = _claimEnd(b, p);
            if (op == 1) p = _claimEnd(b, p);
        }
        if (p != b.length) revert BadPacket();
    }

    function frameGaps(bytes calldata b) internal pure returns (Gaps memory g) {
        g.header = _header(b);
        _need(b, 42, 1);
        g.kind = uint8(W.number(b, 42, 1));
        if (g.kind != 1 && g.kind != 2) revert BadPacket();
        (g.receiptPos, g.receiptEnd) = _receipt(b, 43);
        uint256 p = g.receiptEnd;
        _need(b, p, 2);
        g.count = W.number(b, p, 2);
        if (g.count == 0 || g.count > 1024) revert BadPacket();
        p += 2;
        if (g.kind == 1) {
            _need(b, p, 32);
            g.startHead = W.word(b, p);
            p += 32;
        }
        if (b.length - p != g.count * 257) revert BadPacket();
        g.gapsPos = p;
    }

    function _need(bytes calldata b, uint256 p, uint256 n) private pure {
        if (p > b.length || n > b.length - p) revert BadPacket();
    }

    function _receipt(bytes calldata b, uint256 p) private pure returns (uint32 start, uint32 end) {
        _need(b, p, 4);
        uint256 len = W.number(b, p, 4);
        p += 4;
        if (len > W.MAX_RECEIPT) revert BadPacket();
        _need(b, p, len);
        return (uint32(p), uint32(p + len));
    }

    function _sparseEnd(bytes calldata b, uint256 p) private pure returns (uint256 end) {
        _need(b, p, 32);
        end = p + 32 + 32 * W.popcount(uint256(W.word(b, p)));
        _need(b, p, end - p);
    }

    function _claimEnd(bytes calldata b, uint256 p) private pure returns (uint256) {
        _need(b, p, 1);
        uint256 mode = W.number(b, p, 1);
        if (mode == 1) return p + 1;
        if (mode != 0) revert BadPacket();
        _need(b, p, 2);
        uint256 present = W.number(b, p + 1, 1);
        if (present > 1) revert BadPacket();
        return _sparseEnd(b, p + 2 + 32 * present);
    }

    function authenticatePages(Run memory r, bytes calldata b) internal pure {
        bytes32[53] memory pad;
        pad[0] = keccak256(abi.encode(FlatHash.PAD));
        for (uint256 h; h < r.depth; ++h) {
            pad[h + 1] = FlatHash.node(FlatHash.PAGE_NODE, pad[h], pad[h]);
        }
        uint256 pages = 1 + (uint256(r.header.size) - 1) / PAGE_SIZE;
        for (uint256 i; i < r.pageCount; ++i) {
            Page memory page = r.pages[i];
            uint256 index = page.index;
            if (i != 0 && index <= r.pages[i - 1].index) revert BadPage();
            uint256 p = page.pos;
            bytes32 node = _pageLeaf(b[p:p + page.size], r.header.size, page.index);
            p += page.size;
            for (uint256 h; h < r.depth; ++h) {
                bytes32 sibling = W.word(b, p + 32 * h);
                if (((index ^ 1) << h) >= pages && sibling != pad[h]) revert BadPage();
                node = index & 1 == 0
                    ? FlatHash.node(FlatHash.PAGE_NODE, node, sibling)
                    : FlatHash.node(FlatHash.PAGE_NODE, sibling, node);
                index >>= 1;
            }
            if (node != r.header.root) revert BadPage();
        }
    }

    function _pageLeaf(bytes calldata data, uint64 size, uint64 index)
        private
        pure
        returns (bytes32 h)
    {
        bytes32 label = FlatHash.PAGE;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, label)
            mstore(add(p, 32), or(shl(192, size), or(shl(128, index), shl(112, data.length))))
            calldatacopy(add(p, 50), data.offset, data.length)
            h := keccak256(p, add(50, data.length))
        }
    }

    function read(Run memory r, bytes calldata b, uint256 pos, uint256 len)
        internal
        pure
        returns (bytes memory out)
    {
        if (pos > r.header.size || len > r.header.size - pos) revert BadStep();
        out = new bytes(len);
        uint256 cursor = r.pageCursor;
        for (uint256 done; done < len;) {
            uint256 index = pos / PAGE_SIZE;
            while (cursor < r.pageCount && r.pages[cursor].index < index) ++cursor;
            if (cursor == r.pageCount || r.pages[cursor].index != index) revert BadPage();
            r.used |= 1 << cursor;
            Page memory page = r.pages[cursor];
            uint256 offset = pos % PAGE_SIZE;
            uint256 n = page.size - offset;
            if (n > len - done) n = len - done;
            uint256 source = uint256(page.pos) + offset;
            assembly ("memory-safe") {
                calldatacopy(add(add(out, 32), done), add(b.offset, source), n)
            }
            done += n;
            pos += n;
        }
        r.pageCursor = cursor;
    }

    function blob(Run memory r, bytes calldata b, uint256 pos, uint256 cap)
        internal
        pure
        returns (bytes memory out, uint256 next)
    {
        uint256 len = uint32(bytes4(W.mword(read(r, b, pos, 4), 0)));
        if (len > cap) revert BadStep();
        out = read(r, b, pos + 4, len);
        next = pos + 4 + len;
    }
}
