// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The linter's boolean-cst and uninitialized-local flag every `return (false, ...)` and zero-initialised accumulator; the
// precompile calls in loops are bounded by the input; typecasts are range-checked before narrowing; CBOR encodings are
// self-delimiting, so packed concatenation does not collide.
// forge-lint: disable-start(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)

import {Nb2Crypto} from "./Nb2Crypto.sol";

/// @notice One native UnicityCertificate in calldata: the strict acceptance of its encoding, its structure for an expected
///         partition and shard, and the shard and unicity tree folds to the seal hash (sections 6.2 and 11.3; bft-core b1ref
///         ScanUC, bft-go-base UnicityCertificate.IsValid/Verify, ureth crates/unicity/b1 certificate.rs). The seal's quorum
///         under its epoch's authority is not judged here: that is the 0x0100 certificate batch, which also holds the epoch
///         table.
library Nb2Cert {
    uint256 internal constant MAX_UC_BYTES = 24576;
    uint256 internal constant MAX_SUMMARY = 256;
    uint256 internal constant MAX_SHARD_BYTES = 33;
    uint256 internal constant MAX_SIBLINGS = 256;
    uint256 internal constant MAX_STEPS = 32;
    uint256 internal constant MAX_SIGS = 16;
    uint256 internal constant MAX_NODE_ID = 128;
    uint256 internal constant GENESIS_TIME = 1681971084;

    struct Uc {
        uint256 pos;
        uint256 len;
        uint256 irPos;
        uint256 irLen;
        uint256 round;
        bool prevNull;
        bytes32 prev;
        bytes32 stateHash;
        uint256 timestamp;
        bool blockHashNull;
        bytes32 blockHash;
        bytes32 trHash;
        bytes32 shardConfHash;
        uint256 shardPos;
        uint256 shardLen;
        uint256 shardDepth;
        uint256 sibPos;
        uint256 sibCount;
        uint256 partition;
        uint256 stepsPos;
        uint256 stepCount;
        uint256 network;
        uint256 sealRound;
        uint256 sealTimestamp;
        bytes32 sealHash;
        uint256 sigCount;
        bool emptySig;
        uint256 epoch; // the seal's root epoch
        uint256 sealPos; // the tagged seal, through its signature map
        uint256 sigMapPos;
    }

    // ---- strict canonical heads --------------------------------------------------------------------------------------

    /// @dev One canonical head inside [p, end): definite, shortest, not reserved.
    function _h(uint256 p, uint256 end)
        private
        pure
        returns (bool ok, uint256 mj, uint256 arg, uint256 q)
    {
        assembly ("memory-safe") {
            if lt(p, end) {
                let b := shr(248, calldataload(p))
                mj := shr(5, b)
                let ai := and(b, 31)
                q := add(p, 1)
                switch lt(ai, 24)
                case 1 {
                    arg := ai
                    ok := 1
                }
                default {
                    if lt(ai, 28) {
                        let n := shl(sub(ai, 24), 1)
                        if iszero(lt(sub(end, q), n)) {
                            arg := shr(sub(256, shl(3, n)), calldataload(q))
                            q := add(q, n)
                            let lo := 24
                            if gt(n, 1) { lo := shl(shl(2, n), 1) }
                            ok := iszero(lt(arg, lo))
                        }
                    }
                }
            }
        }
    }

    function _uint(uint256 p, uint256 end) private pure returns (bool ok, uint256 v, uint256 q) {
        uint256 mj;
        (ok, mj, v, q) = _h(p, end);
        ok = ok && mj == 0;
    }

    function _bytes(uint256 p, uint256 end)
        private
        pure
        returns (bool ok, uint256 dp, uint256 len, uint256 q)
    {
        uint256 mj;
        (ok, mj, len, dp) = _h(p, end);
        if (!ok || mj != 2 || len > end - dp) return (false, 0, 0, 0);
        q = dp + len;
    }

    function _b32(uint256 p, uint256 end) private pure returns (bool ok, bytes32 v, uint256 q) {
        uint256 dp;
        uint256 len;
        (ok, dp, len, q) = _bytes(p, end);
        if (!ok || len != 32) return (false, 0, 0);
        assembly ("memory-safe") {
            v := calldataload(dp)
        }
    }

    function _nullOr32(uint256 p, uint256 end)
        private
        pure
        returns (bool ok, bool nul, bytes32 v, uint256 q)
    {
        if (p < end && _byte(p) == 0xf6) return (true, true, 0, p + 1);
        (ok, v, q) = _b32(p, end);
    }

    function _head(uint256 p, uint256 end, uint256 major, uint256 arg)
        private
        pure
        returns (bool ok, uint256 q)
    {
        uint256 mj;
        uint256 a;
        (ok, mj, a, q) = _h(p, end);
        ok = ok && mj == major && a == arg;
    }

    /// @dev tag(t, [version 1, ...]) with `n` items: position of the item after the version.
    function _struct(uint256 p, uint256 end, uint256 t, uint256 n)
        private
        pure
        returns (bool ok, uint256 q)
    {
        (ok, q) = _head(p, end, 6, t);
        if (!ok) return (false, 0);
        (ok, q) = _head(q, end, 4, n);
        if (!ok) return (false, 0);
        uint256 v;
        (ok, v, q) = _uint(q, end);
        ok = ok && v == 1;
    }

    function _byte(uint256 p) private pure returns (uint256 b) {
        assembly ("memory-safe") {
            b := shr(248, calldataload(p))
        }
    }

    // ---- acceptance ---------------------------------------------------------------------------------------------------

    /// @dev Whether [pos, pos + len) is exactly one canonical native certificate inside the native scan's bounds and the SDK
    ///      codec subset (UnsupportedCertificateEncoding for an aggregator UC, DepositUC for the EVM UC), with its fields.
    function parse(uint256 pos, uint256 len) internal pure returns (bool ok, Uc memory u) {
        if (len > MAX_UC_BYTES) return (false, u);
        uint256 end = pos + len;
        u.pos = pos;
        u.len = len;
        uint256 q;
        (ok, q) = _struct(pos, end, 39001, 7);
        if (!ok) return (false, u);
        (ok, q) = _ir(u, q, end);
        if (!ok) return (false, u);
        (ok, u.trHash, q) = _b32(q, end);
        if (!ok) return (false, u);
        (ok, u.shardConfHash, q) = _b32(q, end);
        if (!ok) return (false, u);
        (ok, q) = _stc(u, q, end);
        if (!ok) return (false, u);
        (ok, q) = _utc(u, q, end);
        if (!ok) return (false, u);
        (ok, q) = _seal(u, q, end);
        ok = ok && q == end;
    }

    function _ir(Uc memory u, uint256 p, uint256 end) private pure returns (bool ok, uint256 q) {
        u.irPos = p;
        (ok, q) = _struct(p, end, 39002, 10);
        if (!ok) return (false, 0);
        (ok, u.round, q) = _uint(q, end);
        if (!ok) return (false, 0);
        (ok,, q) = _uint(q, end); // shard epoch
        if (!ok) return (false, 0);
        (ok, u.prevNull, u.prev, q) = _nullOr32(q, end);
        if (!ok) return (false, 0);
        (ok, u.stateHash, q) = _b32(q, end);
        if (!ok) return (false, 0);
        uint256 slen;
        (ok,, slen, q) = _bytes(q, end); // summary: a byte string (the SDK subset), at most 256 bytes
        if (!ok || slen > MAX_SUMMARY) return (false, 0);
        (ok, u.timestamp, q) = _uint(q, end);
        if (!ok) return (false, 0);
        (ok, u.blockHashNull, u.blockHash, q) = _nullOr32(q, end);
        if (!ok) return (false, 0);
        (ok,, q) = _uint(q, end); // fees
        if (!ok) return (false, 0);
        (ok,,, q) = _nullOr32(q, end); // executed transactions hash
        if (!ok) return (false, 0);
        u.irLen = q - p;
    }

    function _stc(Uc memory u, uint256 p, uint256 end) private pure returns (bool ok, uint256 q) {
        (ok, q) = _struct(p, end, 39003, 3);
        if (!ok) return (false, 0);
        uint256 len;
        (ok, u.shardPos, len, q) = _bytes(q, end);
        if (!ok || len == 0 || len > MAX_SHARD_BYTES) return (false, 0);
        u.shardLen = len;
        uint256 last = _byte(u.shardPos + len - 1);
        if (last == 0) return (false, 0);
        uint256 tz;
        while ((last >> tz) & 1 == 0) ++tz;
        uint256 depth = 8 * len - tz - 1;
        if (depth > 256) return (false, 0);
        u.shardDepth = depth;
        uint256 mj;
        uint256 n;
        (ok, mj, n, q) = _h(q, end);
        if (!ok || mj != 4 || n > MAX_SIBLINGS) return (false, 0);
        u.sibPos = q;
        u.sibCount = n;
        for (uint256 i; i < n; ++i) {
            (ok,, q) = _b32(q, end);
            if (!ok) return (false, 0);
        }
    }

    function _utc(Uc memory u, uint256 p, uint256 end) private pure returns (bool ok, uint256 q) {
        (ok, q) = _struct(p, end, 39004, 3);
        if (!ok) return (false, 0);
        (ok, u.partition, q) = _uint(q, end);
        if (!ok || u.partition > type(uint32).max) return (false, 0);
        uint256 mj;
        uint256 n;
        (ok, mj, n, q) = _h(q, end);
        if (!ok || mj != 4 || n > MAX_STEPS) return (false, 0);
        u.stepsPos = q;
        u.stepCount = n;
        for (uint256 i; i < n; ++i) {
            (ok, q) = _head(q, end, 4, 2);
            if (!ok) return (false, 0);
            uint256 k;
            (ok, k, q) = _uint(q, end);
            if (!ok || k > type(uint32).max) return (false, 0);
            (ok,, q) = _b32(q, end);
            if (!ok) return (false, 0);
        }
    }

    function _seal(Uc memory u, uint256 p, uint256 end) private pure returns (bool ok, uint256 q) {
        u.sealPos = p;
        (ok, q) = _struct(p, end, 39005, 8);
        if (!ok) return (false, 0);
        (ok, u.network, q) = _uint(q, end);
        if (!ok || u.network == 0 || u.network > type(uint16).max) return (false, 0);
        (ok, u.sealRound, q) = _uint(q, end);
        if (!ok) return (false, 0);
        (ok, u.epoch, q) = _uint(q, end); // root epoch: judged by the authority verdict
        if (!ok) return (false, 0);
        (ok, u.sealTimestamp, q) = _uint(q, end);
        if (!ok) return (false, 0);
        (ok,, q) = _b32(q, end); // previous hash
        if (!ok) return (false, 0);
        (ok, u.sealHash, q) = _b32(q, end);
        if (!ok) return (false, 0);
        uint256 mj;
        uint256 n;
        u.sigMapPos = q;
        (ok, mj, n, q) = _h(q, end);
        if (!ok || mj != 5 || n > MAX_SIGS) return (false, 0);
        u.sigCount = n;
        uint256 prevKey;
        uint256 prevKeyLen;
        for (uint256 i; i < n; ++i) {
            uint256 kp = q;
            uint256 klen;
            uint256 dp;
            (ok, mj, klen, dp) = _h(q, end);
            if (!ok || mj != 3 || klen > end - dp || klen > MAX_NODE_ID || !_utf8(dp, klen)) {
                return (false, 0);
            }
            q = dp + klen;
            // Core deterministic order: encoded keys strictly increasing bytewise (a duplicate is not increasing).
            if (i > 0 && !_less(prevKey, prevKeyLen, kp, q - kp)) return (false, 0);
            prevKey = kp;
            prevKeyLen = q - kp;
            uint256 vlen;
            (ok,, vlen, q) = _bytes(q, end);
            if (!ok) return (false, 0);
            if (klen == 0 || vlen == 0) u.emptySig = true;
        }
    }

    /// @dev Bytewise a < b over calldata ranges.
    function _less(uint256 a, uint256 alen, uint256 b, uint256 blen) private pure returns (bool) {
        uint256 n = alen < blen ? alen : blen;
        for (uint256 i; i < n; i += 32) {
            bytes32 x;
            bytes32 y;
            assembly ("memory-safe") {
                x := calldataload(add(a, i))
                y := calldataload(add(b, i))
            }
            uint256 m = n - i;
            if (m < 32) {
                uint256 mask = type(uint256).max << (8 * (32 - m));
                x &= bytes32(mask);
                y &= bytes32(mask);
            }
            if (x != y) return x < y;
        }
        return alen < blen;
    }

    /// @dev Go's utf8.Valid: no overlong forms, no surrogates, nothing above U+10FFFF. ASCII words take a fast path.
    function _utf8(uint256 p, uint256 len) private pure returns (bool) {
        bool ascii = true;
        assembly ("memory-safe") {
            let hi := 0x8080808080808080808080808080808080808080808080808080808080808080
            for { let i := 0 } lt(i, len) { i := add(i, 32) } {
                let w := calldataload(add(p, i))
                let m := sub(len, i)
                if lt(m, 32) { w := and(w, not(shr(shl(3, m), not(0)))) }
                if and(w, hi) {
                    ascii := 0
                    break
                }
            }
        }
        if (ascii) return true;
        uint256 i;
        while (i < len) {
            uint256 c = _byte(p + i);
            if (c < 0x80) {
                ++i;
                continue;
            }
            uint256 n;
            uint256 lo = 0x80;
            uint256 hi = 0xbf;
            if (c >= 0xc2 && c <= 0xdf) {
                n = 1;
            } else if (c >= 0xe0 && c <= 0xef) {
                n = 2;
                if (c == 0xe0) lo = 0xa0;
                else if (c == 0xed) hi = 0x9f;
            } else if (c >= 0xf0 && c <= 0xf4) {
                n = 3;
                if (c == 0xf0) lo = 0x90;
                else if (c == 0xf4) hi = 0x8f;
            } else {
                return false;
            }
            if (i + n >= len) return false;
            uint256 c1 = _byte(p + i + 1);
            if (c1 < lo || c1 > hi) return false;
            for (uint256 j = 2; j <= n; ++j) {
                uint256 cj = _byte(p + i + j);
                if (cj < 0x80 || cj > 0xbf) return false;
            }
            i += n + 1;
        }
        return true;
    }

    // ---- structure (IsValid) ---------------------------------------------------------------------------------------

    /// @dev UnicityCertificate.IsValid(partition, shard, nil) after acceptance: the input record rules, the unicity tree
    ///      certificate's partition, the shard (when `shardLen` is nonzero; an aggregator UC is judged for its own shard) and
    ///      its sibling count, and the seal's own validity.
    function valid(Uc memory u, uint256 partition, uint256 shardPos, uint256 shardLen)
        internal
        pure
        returns (bool)
    {
        if (u.round != 0 && u.timestamp == 0) return false;
        bool sameState = !u.prevNull && u.prev == u.stateHash;
        if (sameState != u.blockHashNull) return false;
        if (u.partition != partition) return false;
        if (shardLen != 0) {
            if (shardLen != u.shardLen) return false;
            if (
                Nb2Crypto.keccakCd(shardPos, shardLen) != Nb2Crypto.keccakCd(u.shardPos, u.shardLen)
            ) return false;
        }
        if (u.sibCount != u.shardDepth) return false;
        if (u.sealRound < 1 || u.sealTimestamp < GENESIS_TIME || u.sigCount == 0 || u.emptySig) {
            return false;
        }
        return true;
    }

    /// @dev The shard tree and unicity tree folds equal the seal hash (SealRoot).
    function folds(Uc memory u) internal view returns (bool) {
        uint256 m;
        assembly ("memory-safe") {
            m := mload(0x40)
        }
        // h = H(IR || b(TRHash) || b(ShardConfHash)), the CBOR encodings concatenated.
        uint256 irLen = u.irLen;
        uint256 irPos = u.irPos;
        bytes32 tr = u.trHash;
        bytes32 sch = u.shardConfHash;
        assembly ("memory-safe") {
            calldatacopy(m, irPos, irLen)
            let w := add(m, irLen)
            mstore8(w, 0x58)
            mstore8(add(w, 1), 0x20)
            mstore(add(w, 2), tr)
            mstore8(add(w, 34), 0x58)
            mstore8(add(w, 35), 0x20)
            mstore(add(w, 36), sch)
        }
        bytes32 h = Nb2Crypto.sha256Mem(m, irLen + 68);
        uint256 depth = u.shardDepth;
        uint256 shardPos = u.shardPos;
        for (uint256 i; i < depth; ++i) {
            uint256 d = depth - 1 - i;
            bytes32 sib;
            uint256 bit;
            uint256 sp = u.sibPos + 34 * i + 2;
            assembly ("memory-safe") {
                sib := calldataload(sp)
                bit := and(
                    shr(sub(7, mod(d, 8)), shr(248, calldataload(add(shardPos, div(d, 8))))),
                    1
                )
            }
            h = bit == 0 ? _pair(m, h, sib) : _pair(m, sib, h);
        }
        // UnicityTreeData: H(b(shardTreeRoot)); the IMT leaf H(b(0x01) || b(key4) || b(data)).
        assembly ("memory-safe") {
            mstore8(m, 0x58)
            mstore8(add(m, 1), 0x20)
            mstore(add(m, 2), h)
        }
        h = Nb2Crypto.sha256Mem(m, 34);
        uint256 part = u.partition;
        assembly ("memory-safe") {
            mstore(m, or(shl(232, 0x410144), shl(200, part)))
            mstore8(add(m, 7), 0x58)
            mstore8(add(m, 8), 0x20)
            mstore(add(m, 9), h)
        }
        h = Nb2Crypto.sha256Mem(m, 41);
        uint256 q = u.stepsPos;
        for (uint256 i; i < u.stepCount; ++i) {
            // [key, b(hash)]: the canonical array head, then the key's head.
            (uint256 key, uint256 q2) = _stepKey(q + 1);
            bytes32 sh;
            assembly ("memory-safe") {
                sh := calldataload(add(q2, 2))
            }
            q = q2 + 34;
            bool after_ = part > key;
            assembly ("memory-safe") {
                mstore(m, or(shl(232, 0x410044), shl(200, key)))
                mstore8(add(m, 7), 0x58)
                mstore8(add(m, 8), 0x20)
                mstore8(add(m, 41), 0x58)
                mstore8(add(m, 42), 0x20)
                switch after_
                case 1 {
                    mstore(add(m, 9), sh)
                    mstore(add(m, 43), h)
                }
                default {
                    mstore(add(m, 9), h)
                    mstore(add(m, 43), sh)
                }
            }
            h = Nb2Crypto.sha256Mem(m, 75);
        }
        return h == u.sealHash;
    }

    function _stepKey(uint256 p) private pure returns (uint256 v, uint256 q) {
        uint256 b = _byte(p);
        uint256 ai = b & 31;
        if (ai < 24) return (ai, p + 1);
        uint256 n = 1 << (ai - 24);
        assembly ("memory-safe") {
            v := shr(sub(256, shl(3, n)), calldataload(add(p, 1)))
        }
        q = p + 1 + n;
    }

    function _pair(uint256 m, bytes32 l, bytes32 r) private view returns (bytes32) {
        assembly ("memory-safe") {
            mstore8(m, 0x58)
            mstore8(add(m, 1), 0x20)
            mstore(add(m, 2), l)
            mstore8(add(m, 34), 0x58)
            mstore8(add(m, 35), 0x20)
            mstore(add(m, 36), r)
        }
        return Nb2Crypto.sha256Mem(m, 68);
    }

    /// @dev Whether the 32-byte state ID lies in the certificate's shard: its first `depth` bits are the shard's prefix bits.
    function inShard(Uc memory u, bytes32 sid) internal pure returns (bool) {
        uint256 depth = u.shardDepth;
        uint256 shardPos = u.shardPos;
        for (uint256 i; i < depth; ++i) {
            uint256 sb;
            assembly ("memory-safe") {
                sb := and(
                    shr(sub(7, mod(i, 8)), shr(248, calldataload(add(shardPos, div(i, 8))))),
                    1
                )
            }
            uint256 kb = (uint256(sid) >> (255 - i)) & 1;
            if (sb != kb) return false;
        }
        return true;
    }

    /// @dev The packed CERT_BATCH_V2 claim of an accepted certificate: partition u32 | shard length u16 | shard | its own
    ///      ShardConfHash | IR.hash | SHA-256(IR) | UC length u32 | UC.
    function claim(Uc memory u, uint256 partition) internal view returns (bytes memory c) {
        bytes32 irHash = Nb2Crypto.sha256Cd(u.irPos, u.irLen);
        uint256 sl = u.shardLen;
        uint256 ul = u.len;
        c = new bytes(4 + 2 + sl + 96 + 4 + ul);
        uint256 sp = u.shardPos;
        uint256 up = u.pos;
        bytes32 sch = u.shardConfHash;
        bytes32 st = u.stateHash;
        assembly ("memory-safe") {
            let w := add(c, 32)
            mstore(w, or(shl(224, partition), shl(208, sl)))
            calldatacopy(add(w, 6), sp, sl)
            w := add(add(w, 6), sl)
            mstore(w, sch)
            mstore(add(w, 32), st)
            mstore(add(w, 64), irHash)
            mstore(add(w, 96), shl(224, ul))
            calldatacopy(add(w, 100), up, ul)
        }
    }
}
// forge-lint: disable-end(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)
