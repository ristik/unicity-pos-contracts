// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The linter's boolean-cst and uninitialized-local flag every `return (false, ...)` and zero-initialised accumulator; the
// precompile calls in loops are bounded by the input; typecasts are range-checked before narrowing; CBOR encodings are
// self-delimiting, so packed concatenation does not collide.
// forge-lint: disable-start(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)

/// @notice EVM receipt evidence over calldata (section 6.2 steps 3 to 5; bft-core nb2ref rlp.go, mpt.go, deposit.go): a strict
///         RLP reader, the pinned Cancun header, the receipt-trie path keyed by RLP(txIndex) and the selected log.
library Nb2Evm {
    uint256 internal constant MAX_RLP_DEPTH = 16;
    bytes32 internal constant EMPTY_UNCLES =
        0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347;
    bytes32 internal constant EMPTY_TRIE =
        0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;

    /// @dev One item: list flag, payload position and length, item end.
    struct Item {
        bool list;
        uint256 pos;
        uint256 len;
        uint256 end;
    }

    function _byte(uint256 p) private pure returns (uint256 b) {
        assembly ("memory-safe") {
            b := shr(248, calldataload(p))
        }
    }

    function _len(uint256 p, uint256 ll, uint256 end) private pure returns (bool ok, uint256 n) {
        if (ll > 4 || end - p < ll || _byte(p) == 0) return (false, 0);
        assembly ("memory-safe") {
            n := shr(sub(256, shl(3, ll)), calldataload(p))
        }
        return (true, n);
    }

    /// @dev The head of one strict item at p inside [p, end), without its children (the reference's rlpRead).
    function head(uint256 p, uint256 end) internal pure returns (bool ok, Item memory it) {
        if (p >= end) return (false, it);
        uint256 b = _byte(p);
        if (b < 0x80) {
            it.pos = p;
            it.len = 1;
            it.end = p + 1;
            return (true, it);
        }
        if (b <= 0xb7) {
            uint256 n = b - 0x80;
            if (end - p < 1 + n) return (false, it);
            if (n == 1 && _byte(p + 1) < 0x80) return (false, it);
            it.pos = p + 1;
            it.len = n;
            it.end = p + 1 + n;
            return (true, it);
        }
        if (b <= 0xbf) {
            uint256 ll = b - 0xb7;
            (bool okl, uint256 n) = _len(p + 1, ll, end);
            if (!okl || n < 56 || n > end - p - 1 - ll) return (false, it);
            it.pos = p + 1 + ll;
            it.len = n;
            it.end = it.pos + n;
            return (true, it);
        }
        uint256 hdr;
        uint256 len;
        if (b <= 0xf7) {
            hdr = 1;
            len = b - 0xc0;
        } else {
            uint256 ll = b - 0xf7;
            (bool okl, uint256 n) = _len(p + 1, ll, end);
            if (!okl || n < 56) return (false, it);
            hdr = 1 + ll;
            len = n;
        }
        if (len > end - p - hdr) return (false, it);
        it.list = true;
        it.pos = p + hdr;
        it.len = len;
        it.end = p + hdr + len;
        return (true, it);
    }

    /// @dev Whether [p, end) starts with one item, recursively strict, at nesting depth `depth` (an item deeper than 16 is
    ///      refused): the reference's rlpRead, iteratively over a stack of open list ends.
    function check(uint256 p, uint256 end, uint256 depth)
        internal
        pure
        returns (bool ok, uint256 next)
    {
        assembly ("memory-safe") {
            // ends[k]: the end of the k-th open list; a list's items are read until its end.
            let ends := mload(0x40)
            let top := 0 // open lists
            let limit := end
            ok := 1
            for {} 1 {} {
                // read one item at p inside [p, limit) at depth (depth + top)
                if or(iszero(lt(p, limit)), gt(add(depth, top), 16)) {
                    ok := 0
                    break
                }
                let b := shr(248, calldataload(p))
                let room := sub(limit, p)
                let itemEnd := 0
                let isList := 0
                switch lt(b, 0x80)
                case 1 { itemEnd := add(p, 1) }
                default {
                    switch lt(b, 0xb8)
                    case 1 {
                        let n := sub(b, 0x80)
                        if lt(room, add(1, n)) {
                            ok := 0
                            break
                        }
                        if and(eq(n, 1), lt(shr(248, calldataload(add(p, 1))), 0x80)) {
                            ok := 0
                            break
                        }
                        itemEnd := add(add(p, 1), n)
                    }
                    default {
                        let ll := 0
                        let n := 0
                        let hdr := 1
                        switch lt(b, 0xc0)
                        case 1 { ll := sub(b, 0xb7) }
                        default {
                            isList := 1
                            switch lt(b, 0xf8)
                            case 1 { n := sub(b, 0xc0) }
                            default { ll := sub(b, 0xf7) }
                        }
                        if ll {
                            if or(gt(ll, 4), lt(sub(room, 1), ll)) {
                                ok := 0
                                break
                            }
                            if iszero(shr(248, calldataload(add(p, 1)))) {
                                ok := 0
                                break
                            }
                            n := shr(sub(256, shl(3, ll)), calldataload(add(p, 1)))
                            if lt(n, 56) {
                                ok := 0
                                break
                            }
                            hdr := add(1, ll)
                        }
                        if gt(n, sub(room, hdr)) {
                            ok := 0
                            break
                        }
                        itemEnd := add(add(p, hdr), n)
                        if isList {
                            // descend: the list's items follow its header
                            mstore(add(ends, shl(5, top)), limit)
                            top := add(top, 1)
                            limit := itemEnd
                            p := add(p, hdr)
                            if lt(p, limit) { continue }
                            // an empty list: fall through to close it
                            itemEnd := limit
                        }
                    }
                }
                p := itemEnd
                // close every finished list
                for {} and(gt(top, 0), eq(p, limit)) {} {
                    top := sub(top, 1)
                    limit := mload(add(ends, shl(5, top)))
                }
                if iszero(top) { break }
            }
            next := p
        }
    }

    /// @dev rlpDecode: exactly one strict item spanning [p, p + len).
    function decodes(uint256 p, uint256 len) internal pure returns (bool) {
        (bool ok, uint256 next) = check(p, p + len, 0);
        return ok && next == p + len;
    }

    /// @dev The children of a checked list (at most `max`; `n` is the true count).
    function kids(Item memory l, uint256 max) internal pure returns (Item[] memory out, uint256 n) {
        out = new Item[](max);
        uint256 q = l.pos;
        while (q < l.end) {
            (, Item memory it) = head(q, l.end);
            if (n < max) out[n] = it;
            ++n;
            q = it.end;
        }
    }

    function _word(uint256 p) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := calldataload(p)
        }
    }

    /// @dev A canonical RLP integer of at most `maxBytes` bytes (no leading zero; empty is zero).
    function _int(Item memory it, uint256 maxBytes) private pure returns (bool ok, uint256 v) {
        if (it.list || it.len > maxBytes || (it.len > 0 && _byte(it.pos) == 0)) return (false, 0);
        if (it.len == 0) return (true, 0);
        uint256 p = it.pos;
        uint256 l = it.len;
        assembly ("memory-safe") {
            v := shr(sub(256, shl(3, l)), calldataload(p))
        }
        return (true, v);
    }

    function _fixed(Item memory it, uint256 n) private pure returns (bool) {
        return !it.list && it.len == n;
    }

    /// @dev The pinned Cancun header (go-ethereum v1.14.11 types.Header, exactly 20 fields) bound to the certified input
    ///      record: keccak(header) == blockHash and stateRoot == the state hash. Returns the receipts root.
    function header(
        uint256 p,
        uint256 len,
        bool blockHashNull,
        bytes32 blockHash,
        bytes32 stateHash
    ) internal pure returns (bool ok, bytes32 receiptsRoot) {
        if (!decodes(p, len)) return (false, 0);
        (, Item memory l) = head(p, p + len);
        if (!l.list) return (false, 0);
        (Item[] memory f, uint256 n) = kids(l, 20);
        if (n != 20) return (false, 0);
        uint256[20] memory widths =
            [uint256(32), 32, 20, 32, 32, 32, 256, 0, 0, 0, 0, 0, 0, 32, 8, 0, 32, 0, 0, 32];
        for (uint256 i; i < 20; ++i) {
            if (f[i].list) return (false, 0);
            if (widths[i] != 0 && f[i].len != widths[i]) return (false, 0);
        }
        bool okInt;
        uint256 v;
        // difficulty: a canonical big integer, zero
        (okInt, v) = _int(f[7], 32);
        if (!okInt || v != 0) return (false, 0);
        // number: below 2^63
        (okInt, v) = _int(f[8], 8);
        if (!okInt || v > uint256(type(uint64).max) >> 1) return (false, 0);
        for (uint256 i = 9; i <= 11; ++i) {
            (okInt,) = _int(f[i], 8); // gasLimit, gasUsed, timestamp
            if (!okInt) return (false, 0);
        }
        if (f[12].len > 32) return (false, 0); // extraData
        (okInt, v) = _int(f[15], 8); // baseFeePerGas: 0 < v < 2^64
        if (!okInt || v == 0) return (false, 0);
        (okInt, v) = _int(f[17], 8); // blobGasUsed
        if (!okInt || v != 0) return (false, 0);
        (okInt, v) = _int(f[18], 8); // excessBlobGas
        if (!okInt || v != 0) return (false, 0);
        if (_word(f[1].pos) != EMPTY_UNCLES || _word(f[16].pos) != EMPTY_TRIE) return (false, 0);
        bytes32 bh;
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, p, len)
            bh := keccak256(m, len)
        }
        if (blockHashNull || bh != blockHash || _word(f[3].pos) != stateHash) return (false, 0);
        return (true, _word(f[5].pos));
    }

    function _keccakItem(uint256 p, uint256 len) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, p, len)
            h := keccak256(m, len)
        }
    }

    /// @dev RLP(i) of a transaction index as nibbles, with their count.
    function _keyNibbles(uint256 i) private pure returns (uint256[18] memory nib, uint256 n) {
        uint256 kb; // the key bytes, big-endian, and their count
        uint256 klen;
        if (i == 0) {
            kb = 0x80;
            klen = 1;
        } else if (i < 0x80) {
            kb = i;
            klen = 1;
        } else {
            uint256 bl;
            for (uint256 t = i; t != 0; t >>= 8) {
                ++bl;
            }
            kb = ((0x80 + bl) << (8 * bl)) | i;
            klen = bl + 1;
        }
        for (uint256 j; j < klen; ++j) {
            uint256 b = (kb >> (8 * (klen - 1 - j))) & 0xff;
            nib[n++] = b >> 4;
            nib[n++] = b & 0x0f;
        }
    }

    /// @dev The value at key RLP(txIndex) under `root`, the nodes being exactly the root-to-leaf path (ReceiptPath).
    function trieValue(
        bytes32 root,
        uint256 txIndex,
        uint256[] memory nodePos,
        uint256[] memory nodeLen
    ) internal pure returns (bool, uint256 vpos, uint256 vlen) {
        (uint256[18] memory nib, uint256 nn) = _keyNibbles(txIndex);
        uint256 ni;
        uint256 total = nodePos.length;
        if (total == 0 || _keccakItem(nodePos[0], nodeLen[0]) != root) return (false, 0, 0);
        if (!decodes(nodePos[0], nodeLen[0])) return (false, 0, 0);
        (, Item memory cur) = head(nodePos[0], nodePos[0] + nodeLen[0]);
        uint256 used = 1;
        while (true) {
            if (!cur.list) return (false, 0, 0);
            (Item[] memory k, uint256 n) = kids(cur, 17);
            Item memory child;
            if (n == 17) {
                if (ni == nn) {
                    Item memory v = k[16];
                    if (v.list || v.len == 0 || used != total) return (false, 0, 0);
                    return (true, v.pos, v.len);
                }
                child = k[nib[ni]];
                ++ni;
                if (!child.list && child.len == 0) return (false, 0, 0);
            } else if (n == 2) {
                Item memory hp = k[0];
                if (hp.list || hp.len == 0) return (false, 0, 0);
                uint256 f0 = _byte(hp.pos);
                uint256 flag = f0 >> 4;
                if (flag > 3) return (false, 0, 0);
                bool leaf = flag >= 2;
                // the path nibbles must prefix the remaining key
                uint256 pl;
                if (flag & 1 == 1) {
                    if (ni + pl >= nn || nib[ni + pl] != (f0 & 0x0f)) return (false, 0, 0);
                    ++pl;
                } else if (f0 & 0x0f != 0) {
                    return (false, 0, 0);
                }
                for (uint256 j = 1; j < hp.len; ++j) {
                    uint256 b = _byte(hp.pos + j);
                    if (ni + pl + 2 > nn) return (false, 0, 0);
                    if (nib[ni + pl] != (b >> 4) || nib[ni + pl + 1] != (b & 0x0f)) {
                        return (false, 0, 0);
                    }
                    pl += 2;
                }
                ni += pl;
                Item memory v = k[1];
                if (leaf) {
                    if (ni != nn || v.list || v.len == 0 || used != total) return (false, 0, 0);
                    return (true, v.pos, v.len);
                }
                if (pl == 0) return (false, 0, 0);
                child = v;
            } else {
                return (false, 0, 0);
            }
            if (child.list) {
                if (child.len + _hdrLen(child) >= 32) return (false, 0, 0);
                cur = child;
            } else if (child.len == 32) {
                if (used >= total) return (false, 0, 0);
                uint256 np = nodePos[used];
                uint256 nl = nodeLen[used];
                if (nl < 32 || _keccakItem(np, nl) != _word(child.pos)) return (false, 0, 0);
                if (!decodes(np, nl)) return (false, 0, 0);
                (, cur) = head(np, np + nl);
                ++used;
            } else {
                return (false, 0, 0);
            }
        }
        return (false, 0, 0);
    }

    function _hdrLen(Item memory it) private pure returns (uint256) {
        // The raw length of an embedded list is its header plus payload; the header is 1 byte below 56, else 1 + ll.
        if (it.len < 56) return 1;
        uint256 ll;
        for (uint256 t = it.len; t != 0; t >>= 8) {
            ++ll;
        }
        return 1 + ll;
    }

    struct Log {
        address emitter;
        uint256 topicsPos; // first topic item
        uint256 topicCount;
        uint256 dataPos;
        uint256 dataLen;
    }

    /// @dev decodeReceipt and the log selection. err: 0 ok, 1 ReceiptType, 2 ReceiptStatus, 3 LogIndex, 4 LogTopics (the log's
    ///      emitter is set whenever err is 0 or 4).
    function receiptLog(uint256 p, uint256 len, uint256 logIndex)
        internal
        pure
        returns (uint256 err, Log memory lg)
    {
        if (len == 0) return (1, lg);
        uint256 b0 = _byte(p);
        uint256 bp = p;
        uint256 bl = len;
        if (b0 < 0xc0) {
            if (b0 < 1 || b0 > 3) return (1, lg);
            bp = p + 1;
            bl = len - 1;
        }
        if (!decodes(bp, bl)) return (1, lg);
        (, Item memory r) = head(bp, bp + bl);
        if (!r.list) return (1, lg);
        (Item[] memory f, uint256 n) = kids(r, 4);
        if (n != 4) return (1, lg);
        (bool okGas,) = _int(f[1], 32);
        if (!okGas || f[0].list || f[2].list || f[2].len != 256 || !f[3].list) return (1, lg);
        if (f[0].len != 1 || _byte(f[0].pos) != 1) return (2, lg);
        // logs[logIndex]
        uint256 q = f[3].pos;
        uint256 i;
        Item memory lgItem;
        bool found;
        while (q < f[3].end) {
            (, Item memory it) = head(q, f[3].end);
            if (i == logIndex) {
                lgItem = it;
                found = true;
                break;
            }
            ++i;
            q = it.end;
        }
        if (!found || !lgItem.list) return (3, lg);
        (Item[] memory lk, uint256 ln) = kids(lgItem, 3);
        if (ln != 3 || lk[0].list || lk[0].len != 20 || !lk[1].list || lk[2].list) return (3, lg);
        // The emitter is read before the topics' shape: the caller checks it first (LogEmitter before LogTopics).
        lg.emitter = address(bytes20(_word(lk[0].pos)));
        lg.topicsPos = lk[1].pos;
        uint256 tq = lk[1].pos;
        while (tq < lk[1].end) {
            (, Item memory t) = head(tq, lk[1].end);
            if (t.list || t.len != 32) return (4, lg);
            ++lg.topicCount;
            tq = t.end;
        }
        lg.dataPos = lk[2].pos;
        lg.dataLen = lk[2].len;
        return (0, lg);
    }

    /// @dev Topic `i` of a selected log (each topic item is 0xa0 || 32 bytes).
    function topic(Log memory lg, uint256 i) internal pure returns (bytes32) {
        return _word(lg.topicsPos + 33 * i + 1);
    }
}
// forge-lint: disable-end(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)
