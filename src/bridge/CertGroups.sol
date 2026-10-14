// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BudgetExceeded, UCScanRejected} from "./BridgeErrors.sol";
import {Anchor} from "./BridgeTypes.sol";

/// @notice The bridge's side of `CERT_BATCH_V2` (briefs/b1-any-age-contract.md §2, §3, §5): the structural scan of
///         every claim's UnicityCertificate and the canonical first-occurrence grouping that the batch price is
///         computed from. It does no cryptography and reads no state. It computes exactly the quantities the
///         native batch charges for, so the composing verifier can price the whole relation before the one native call:
///
///         K claim occurrences, C request bytes, E distinct declared epochs, S distinct complete seals (the whole
///         tagged CBOR slice, signature map included), Q the sum of their signature counts, A distinct claims (the
///         whole packed claim, expected tuple and full UC bytes), P the shard siblings plus Unicity-tree steps of the
///         distinct claims.
///
///         Identity is exact bytes. A digest only indexes: on equal digests the full bytes are compared, so a forced
///         digest collision never merges two different seals or claims. Reordering the occurrences changes none of the
///         counts. The scan accepts a superset of what the native scanner accepts (it does not check map-key order or
///         the content of hashes and signatures); the native batch stays the authority on the certificate, and a
///         request the native scan halts on simply fails there. Every count it does produce is of canonical input.
///
///         The depth of a claim's shard tree is derived from the claim's own native shard id (contract §6), never from
///         a policy: `d = 8*len - trailingZeroBits(lastByte) - 1`, and the certificate must carry exactly `d` siblings.
library CertGroups {
    // ---- the frozen first-profile limits that bound this scan (contract §4) ----
    uint256 internal constant MAX_CLAIMS = 16; // K, and so E, S, A
    uint256 internal constant MAX_BATCH_BYTES = 262_144; // C
    uint256 internal constant MAX_UC_BYTES = 24_576; // per occurrence
    uint256 internal constant MAX_SIGS_PER_SEAL = 16;
    uint256 internal constant MAX_TOTAL_SIGS = 256; // Q
    uint256 internal constant MAX_SHARD_BYTES = 33;
    uint256 internal constant MAX_SHARD_DEPTH = 256;
    uint256 internal constant MAX_UNICITY_STEPS = 32; // per claim
    uint256 internal constant MAX_RAW_STEPS = 4_608; // over all occurrences, before deduplication
    uint256 internal constant MAX_NESTING = 16;
    /// @dev The bridge's cumulative CBOR item budget for everything Solidity traverses (contract §4, arch's ruling of 2026-10-14): UC occurrences here,
    ///      and the policy and IR openings the verifier counts against the same budget. The native batch keeps its own 32,768; this is the stricter
    ///      bridge admission limit, so a dense request is refused with BudgetExceeded before any native call.
    uint256 internal constant MAX_ITEMS = 4_096;
    uint256 internal constant CLAIM_FIXED = 106; // partition 4 + shardLen 2 + three hashes 96 + ucLen 4

    // ---- the frozen price schedule (contract §5) ----
    uint256 internal constant SCAN_BASE = 60_000;
    uint256 internal constant SCAN_PER_BYTE = 16;
    uint256 internal constant SCAN_PER_PAIR = 500; // x K*(K-1)
    uint256 internal constant COMMON_READS = 1_100; // 100 x 11 words
    uint256 internal constant PER_EPOCH = 29_900; // 1000 x 16 key parses + 100 x (11 + 8*16) words
    uint256 internal constant PER_SIGNATURE = 6_000;
    uint256 internal constant PER_CLAIM = 2_000;
    uint256 internal constant PER_STEP = 250;

    uint256 private constant TAG_UC = 39001;
    uint256 private constant TAG_SHARD_TREE = 39003;
    uint256 private constant TAG_UNICITY_TREE = 39004;
    uint256 private constant TAG_SEAL = 39005;
    uint8 private constant NULL = 0xf6;

    /// @dev E, S, Q, A, P, K and C of one request.
    struct Counts {
        uint256 k;
        uint256 c;
        uint256 e;
        uint256 s;
        uint256 q;
        uint256 a;
        uint256 p;
        uint256 items; // CBOR items traversed over all occurrences, before deduplication: the verifier subtracts them from its shared budget
    }

    /// @dev What the scan reads of one occurrence.
    struct Occurrence {
        uint256 epoch;
        uint256 sealStart; // offset of the seal's tag head in the UC
        uint256 sealLen;
        uint256 sigs;
        uint256 steps;
        bytes32 sealIndex; // digest used only to index
        bytes32 claimIndex;
    }

    /// @dev Cumulative budgets over all occurrences of one request.
    struct Budget {
        uint256 limit; // items this scan may still use in total (MAX_ITEMS less what the caller already spent)
        uint256 items;
        uint256 steps;
        uint256[] stack; // the nesting stack of the skip, allocated once
    }

    /// @notice `G_scan(C,K)`: the allowance for structural traversal, identities and bounded pair comparisons.
    function scanGas(uint256 c, uint256 k) internal pure returns (uint256) {
        return SCAN_BASE + SCAN_PER_BYTE * c + SCAN_PER_PAIR * k * (k - 1);
    }

    /// @notice `G_batch`: what the native call is forwarded and charges, true or false.
    function batchGas(Counts memory n) internal pure returns (uint256) {
        return scanGas(n.c, n.k) + COMMON_READS + PER_EPOCH * n.e + PER_SIGNATURE * n.q + PER_CLAIM
            * n.a + PER_STEP * n.p;
    }

    /// @notice Scan and group the claims of one batch.
    function measure(Anchor[] memory anchors) internal pure returns (Counts memory) {
        return measure(anchors, type(uint256).max, MAX_ITEMS);
    }

    /// @dev With the items the caller has already spent on other CBOR (the policy, the IR openings) taken from the shared budget.
    function measure(Anchor[] memory anchors, uint256 spent) internal pure returns (Counts memory) {
        if (spent > MAX_ITEMS) revert BudgetExceeded();
        return measure(anchors, type(uint256).max, MAX_ITEMS - spent);
    }

    /// @dev `indexMask` is ANDed into the index digests. Production passes all ones; the tests pass 0 to force every
    ///      digest to collide, which must change no count.
    function measure(Anchor[] memory anchors, uint256 indexMask, uint256 itemLimit)
        internal
        pure
        returns (Counts memory n)
    {
        uint256 k = anchors.length;
        if (k == 0 || k > MAX_CLAIMS) revert BudgetExceeded();
        n.k = k;
        n.c = 4;
        Budget memory budget;
        budget.limit = itemLimit;
        budget.stack = new uint256[](MAX_NESTING + 1);
        Occurrence[] memory occ = new Occurrence[](k);
        for (uint256 i = 0; i < k; ++i) {
            Anchor memory a = anchors[i];
            if (a.shard.length == 0 || a.shard.length > MAX_SHARD_BYTES) revert UCScanRejected();
            if (a.uc.length > MAX_UC_BYTES) revert BudgetExceeded();
            n.c += CLAIM_FIXED + a.shard.length + a.uc.length;
            if (n.c > MAX_BATCH_BYTES) revert BudgetExceeded();
            occ[i] = _scan(a, budget);
            occ[i].sealIndex =
                keccak256Slice(a.uc, occ[i].sealStart, occ[i].sealLen) & bytes32(indexMask);
            occ[i].claimIndex = _claimIndex(a) & bytes32(indexMask);
        }
        for (uint256 i = 0; i < k; ++i) {
            if (_firstEpoch(occ, i)) ++n.e;
            if (_firstSeal(anchors, occ, i)) {
                ++n.s;
                n.q += occ[i].sigs;
            }
            if (_firstClaim(anchors, occ, i)) {
                ++n.a;
                n.p += occ[i].steps;
            }
        }
        if (n.q > MAX_TOTAL_SIGS) revert BudgetExceeded();
        n.items = budget.items;
    }

    // -----------------------------------------------------------------------------------------
    // Grouping: first occurrence by exact bytes
    // -----------------------------------------------------------------------------------------

    function _firstEpoch(Occurrence[] memory occ, uint256 i) private pure returns (bool) {
        for (uint256 j = 0; j < i; ++j) {
            if (occ[j].epoch == occ[i].epoch) return false;
        }
        return true;
    }

    function _firstSeal(Anchor[] memory a, Occurrence[] memory occ, uint256 i)
        private
        pure
        returns (bool)
    {
        for (uint256 j = 0; j < i; ++j) {
            if (
                occ[j].sealIndex == occ[i].sealIndex && occ[j].sealLen == occ[i].sealLen
                    && _sliceEq(
                        a[j].uc, occ[j].sealStart, a[i].uc, occ[i].sealStart, occ[i].sealLen
                    )
            ) return false;
        }
        return true;
    }

    function _firstClaim(Anchor[] memory a, Occurrence[] memory occ, uint256 i)
        private
        pure
        returns (bool)
    {
        for (uint256 j = 0; j < i; ++j) {
            if (occ[j].claimIndex == occ[i].claimIndex && _claimEq(a[j], a[i])) return false;
        }
        return true;
    }

    function _claimEq(Anchor memory x, Anchor memory y) private pure returns (bool) {
        return x.partition == y.partition && x.shardConfHash == y.shardConfHash
            && x.expectedStateRoot == y.expectedStateRoot && x.expectedIRHash == y.expectedIRHash
            && x.shard.length == y.shard.length && x.uc.length == y.uc.length
            && _sliceEq(x.shard, 0, y.shard, 0, x.shard.length)
            && _sliceEq(x.uc, 0, y.uc, 0, x.uc.length);
    }

    function _claimIndex(Anchor memory a) private pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                a.partition,
                a.shard,
                a.shardConfHash,
                a.expectedStateRoot,
                a.expectedIRHash,
                keccak256Slice(a.uc, 0, a.uc.length)
            )
        );
    }

    /// @dev keccak256 of `b[start:start+len]` without copying.
    function keccak256Slice(bytes memory b, uint256 start, uint256 len)
        internal
        pure
        returns (bytes32 h)
    {
        if (start + len > b.length) revert UCScanRejected();
        assembly ("memory-safe") {
            h := keccak256(add(add(b, 32), start), len)
        }
    }

    /// @dev Byte equality of two slices of the same length.
    function _sliceEq(bytes memory a, uint256 ao, bytes memory b, uint256 bo, uint256 len)
        private
        pure
        returns (bool same)
    {
        if (ao + len > a.length || bo + len > b.length) revert UCScanRejected();
        same = true;
        assembly ("memory-safe") {
            let pa := add(add(a, 32), ao)
            let pb := add(add(b, 32), bo)
            let i := 0
            for {} lt(add(i, 32), add(len, 1)) { i := add(i, 32) } {
                if xor(mload(add(pa, i)), mload(add(pb, i))) {
                    same := 0
                    break
                }
            }
            if same {
                let rest := sub(len, i)
                if rest {
                    let shift := shl(3, sub(32, rest))
                    if shr(shift, xor(mload(add(pa, i)), mload(add(pb, i)))) { same := 0 }
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // The structural scan of one UnicityCertificate
    // -----------------------------------------------------------------------------------------

    /// @dev `tag(39001,[1, IR, h, h, tag(39003,[1, shard, [sib*]]), tag(39004,[1, partition, [step*]]),
    ///      tag(39005,[1, network, round, epoch, time, h, h, sigs])])`, no trailing byte. The seal is the UC's last
    ///      item, so its complete tagged slice runs to the end of the UC.
    function _scan(Anchor memory a, Budget memory bud) private pure returns (Occurrence memory o) {
        bytes memory uc = a.uc;
        uint256 d = shardDepth(a.shard);
        uint256 pos = _tagged(uc, 0, TAG_UC, 7, bud);
        pos = _skip(uc, pos, bud); // version
        pos = _skip(uc, pos, bud); // input record
        pos = _skip(uc, pos, bud); // technical record hash
        pos = _skip(uc, pos, bud); // shard configuration hash

        pos = _tagged(uc, pos, TAG_SHARD_TREE, 3, bud);
        pos = _skip(uc, pos, bud); // version
        pos = _shardEquals(uc, pos, a.shard, bud);
        uint256 siblings;
        (siblings, pos) = _count(uc, pos, 4, bud);
        if (siblings != d) revert UCScanRejected();
        pos = _skipN(uc, pos, siblings, bud);

        pos = _tagged(uc, pos, TAG_UNICITY_TREE, 3, bud);
        pos = _skip(uc, pos, bud); // version
        pos = _skip(uc, pos, bud); // partition
        uint256 steps;
        (steps, pos) = _count(uc, pos, 4, bud);
        if (steps > MAX_UNICITY_STEPS) revert BudgetExceeded();
        pos = _skipN(uc, pos, steps, bud);
        o.steps = siblings + steps;
        bud.steps += o.steps;
        if (bud.steps > MAX_RAW_STEPS) revert BudgetExceeded();

        o.sealStart = pos;
        pos = _tagged(uc, pos, TAG_SEAL, 8, bud);
        pos = _skip(uc, pos, bud); // version
        pos = _skip(uc, pos, bud); // network
        pos = _skip(uc, pos, bud); // root round
        (uint8 major, uint256 epoch, uint256 next) = _head(uc, pos);
        if (major != 0 || epoch > type(uint64).max) revert UCScanRejected();
        _item(bud);
        o.epoch = epoch;
        pos = next;
        pos = _skip(uc, pos, bud); // timestamp
        pos = _skip(uc, pos, bud); // previous hash
        pos = _skip(uc, pos, bud); // hash
        (o.sigs, pos) = _count(uc, pos, 5, bud);
        if (o.sigs > MAX_SIGS_PER_SEAL) revert BudgetExceeded();
        pos = _skipN(uc, pos, 2 * o.sigs, bud);
        if (pos != uc.length) revert UCScanRejected();
        o.sealLen = pos - o.sealStart;
    }

    /// @notice The depth of a native shard id: the bits before its terminator. `shard` is 1..33 bytes whose last byte
    ///         is nonzero (the terminator is that byte's lowest set bit).
    function shardDepth(bytes memory shard) internal pure returns (uint256 d) {
        uint256 len = shard.length;
        if (len == 0 || len > MAX_SHARD_BYTES) revert UCScanRejected();
        uint8 last = uint8(shard[len - 1]);
        if (last == 0) revert UCScanRejected();
        uint256 tz;
        while ((last >> tz) & 1 == 0) {
            ++tz;
        }
        d = 8 * len - tz - 1;
        if (d > MAX_SHARD_DEPTH) revert UCScanRejected();
    }

    /// @dev A declared container whose immediate children alone exceed what is left is refused before any of them is walked.
    function _fits(Budget memory bud, uint256 children) private pure {
        if (children > bud.limit - bud.items) revert BudgetExceeded();
    }

    function _item(Budget memory bud) private pure {
        if (++bud.items > bud.limit) revert BudgetExceeded();
    }

    /// @dev `tag(t, array(n))`; returns the position of the first element. Counts the two heads as items.
    function _tagged(bytes memory b, uint256 pos, uint256 tag, uint256 n, Budget memory bud)
        private
        pure
        returns (uint256)
    {
        (uint8 major, uint256 arg, uint256 p) = _head(b, pos);
        if (major != 6 || arg != tag) revert UCScanRejected();
        (major, arg, p) = _head(b, p);
        if (major != 4 || arg != n) revert UCScanRejected();
        _item(bud);
        _item(bud);
        return p;
    }

    function _shardEquals(bytes memory b, uint256 pos, bytes memory shard, Budget memory bud)
        private
        pure
        returns (uint256)
    {
        (uint8 major, uint256 len, uint256 p) = _head(b, pos);
        if (major != 2 || len != shard.length || len > b.length - p) revert UCScanRejected();
        if (!_sliceEq(b, p, shard, 0, len)) revert UCScanRejected();
        _item(bud);
        return p + len;
    }

    /// @dev Element count of an array (`want` 4) or map (`want` 5) at `pos`; null is empty.
    function _count(bytes memory b, uint256 pos, uint8 want, Budget memory bud)
        private
        pure
        returns (uint256 n, uint256 next)
    {
        _item(bud);
        if (pos < b.length && uint8(b[pos]) == NULL) return (0, pos + 1);
        uint8 major;
        (major, n, next) = _head(b, pos);
        if (major != want || n > b.length) revert UCScanRejected();
        _fits(bud, major == 5 ? 2 * n : n);
    }

    function _skipN(bytes memory b, uint256 pos, uint256 n, Budget memory bud)
        private
        pure
        returns (uint256)
    {
        uint256 len = b.length;
        for (uint256 i = 0; i < n; ++i) {
            // the common element is a 32-byte string (a hash): 0x58 0x20 and 32 bytes
            if (pos + 34 <= len && uint8(b[pos]) == 0x58 && uint8(b[pos + 1]) == 0x20) {
                if (++bud.items > bud.limit) revert BudgetExceeded();
                pos += 34;
            } else {
                pos = _skip(b, pos, bud);
            }
        }
        return pos;
    }

    /// @dev One CBOR head: definite lengths only, shortest form only.
    function _head(bytes memory b, uint256 pos)
        private
        pure
        returns (uint8 major, uint256 arg, uint256 next)
    {
        uint256 len = b.length;
        if (pos >= len) revert UCScanRejected();
        uint256 first;
        assembly ("memory-safe") {
            first := byte(0, mload(add(add(b, 32), pos)))
        }
        major = uint8(first >> 5);
        uint256 ai = first & 0x1f;
        next = pos + 1;
        if (ai < 24) return (major, ai, next);
        if (ai > 27) revert UCScanRejected();
        uint256 width = uint256(1) << (ai - 24);
        if (width > len - next) revert UCScanRejected();
        assembly ("memory-safe") {
            arg := shr(sub(256, shl(3, width)), mload(add(add(b, 32), next)))
        }
        next += width;
        if (
            (ai == 24 && arg < 24) || (ai == 25 && arg <= type(uint8).max)
                || (ai == 26 && arg <= type(uint16).max) || (ai == 27 && arg <= type(uint32).max)
        ) revert UCScanRejected();
    }

    /// @dev Skips one complete item with nesting bounded by MAX_NESTING and the cumulative item budget. A leaf is
    ///      skipped without touching the nesting stack, which is allocated once per request. Every iteration consumes
    ///      a head, so the loop is bounded by the input length.
    function _skip(bytes memory b, uint256 pos, Budget memory bud) private pure returns (uint256) {
        (uint8 major, uint256 arg, uint256 next) = _head(b, pos);
        if (++bud.items > bud.limit) revert BudgetExceeded();
        if (major == 2 || major == 3) {
            if (arg > b.length - next) revert UCScanRejected();
            return next + arg;
        }
        if (major < 2 || major == 7) return next;
        uint256[] memory left = bud.stack;
        uint256 depth;
        while (true) {
            uint256 kids;
            if (major == 4 || major == 5) {
                if (arg > b.length) revert UCScanRejected();
                kids = major == 5 ? 2 * arg : arg;
                _fits(bud, kids);
            } else if (major == 6) {
                kids = 1;
            }
            pos = next;
            if (kids != 0) {
                if (++depth > MAX_NESTING) revert BudgetExceeded();
                left[depth] = kids;
            } else {
                while (depth != 0) {
                    if (--left[depth] != 0) break;
                    --depth;
                }
                if (depth == 0) return pos;
            }
            // the next item inside the open container
            (major, arg, next) = _head(b, pos);
            if (++bud.items > bud.limit) revert BudgetExceeded();
            if (major == 2 || major == 3) {
                if (arg > b.length - next) revert UCScanRejected();
                next += arg;
                major = 7; // a completed leaf
                arg = 0;
            } else if (major < 2 || major == 7) {
                major = 7;
                arg = 0;
            }
        }
        return pos; // unreachable
    }
}
