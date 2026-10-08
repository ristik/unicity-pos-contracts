// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Continuity} from "./Continuity.sol";

// Loops are bounded by the immutable V ceiling (at most 128 eligible identities) and the committee ceiling (at most 32 members).
// forge-lint: disable-start(unsafe-typecast)

/// @title Selection
/// @notice The ranking and the deterministic bounded greedy election of design v5 section 5, over a frozen snapshot. It is a pure
/// function of the last committed committee `o` (with its committed weights), the eligible identities of the snapshot and the
/// profile: no storage, no clock, no search.
///
///  1. Rank eligible identities by descending weight, then ascending StakingID.
///  2. Seed: the best eligible incumbents up to the target (trimming the lowest ranks), then the best outsiders up to the target.
///     The complete seed is rejected, with no alternative searched, when the eligible set is smaller than the minimum or the seed
///     fails any continuity predicate against `o`.
///  3. Visit each remaining outsider once, in rank order: it replaces the lowest-ranked retained incumbent only when it outranks it
///     and the trial committee passes every continuity predicate against the same `o`. A removed incumbent is never re-enqueued.
///
/// The Go model in bft-core (`continuity/selection_test.go`) is the reference; `test/p85/fixtures/selection-vectors.json` is its output.
library Selection {
    /// @dev An eligible identity of the snapshot: its current binding hash and assigned weight (positive).
    struct Entry {
        uint64 id;
        bytes32 binding;
        uint64 weight;
    }

    struct Config {
        uint32 nMin;
        uint32 nTarget;
        uint32 nMax;
        Continuity.Params churn;
    }

    /// @dev Why an election finds no candidate. Churn reasons name the first applicable family: membership (M, turnover) before
    /// weight (distance, overlap).
    enum Reason {
        None,
        InvalidProfile,
        Cardinality,
        MembershipChurn,
        WeightChurn
    }

    /// @dev The eligible list is not strictly ascending by identity, or carries a zero weight.
    error InvalidEligible();

    /// @notice The elected committee ascending by identity, or the reason there is none (then the committee is empty).
    function select(Continuity.Member[] memory o, Entry[] memory e, Config memory cfg)
        internal
        pure
        returns (Reason reason, Continuity.Member[] memory chosen)
    {
        if (
            cfg.nMin == 0 || cfg.nTarget < cfg.nMin || cfg.nMax < cfg.nTarget || cfg.nMax > 32
                || cfg.churn.distDen == 0
        ) {
            return (Reason.InvalidProfile, chosen);
        }
        uint256 n = e.length;
        for (uint256 i = 0; i < n; ++i) {
            if (e[i].weight == 0 || (i > 0 && e[i].id <= e[i - 1].id)) revert InvalidEligible();
        }
        if (n < cfg.nMin) return (Reason.Cardinality, chosen);

        bool[] memory incumbent = _incumbents(o, e);
        uint256[] memory rank = _rank(e);

        // the seed
        bool[] memory inS = new bool[](n);
        uint256 count;
        for (uint256 r = 0; r < n && count < cfg.nTarget; ++r) {
            if (incumbent[rank[r]]) {
                inS[rank[r]] = true;
                ++count;
            }
        }
        for (uint256 r = 0; r < n && count < cfg.nTarget; ++r) {
            if (!incumbent[rank[r]]) {
                inS[rank[r]] = true;
                ++count;
            }
        }
        chosen = _committee(e, inS, count);
        (uint8 failed,) = Continuity.check(o, chosen, cfg.churn);
        if (failed != 0) return (_churnReason(failed), new Continuity.Member[](0));

        // each remaining outsider, once, in rank order
        for (uint256 r = 0; r < n; ++r) {
            uint256 x = rank[r];
            if (incumbent[x] || inS[x]) continue;
            uint256 low = n; // the lowest-ranked retained incumbent: the last in rank order that is one
            for (uint256 q = n; q > 0; --q) {
                uint256 idx = rank[q - 1];
                if (incumbent[idx] && inS[idx]) {
                    low = idx;
                    break;
                }
            }
            if (low == n || !_better(e[x], e[low])) continue;
            inS[low] = false;
            inS[x] = true;
            Continuity.Member[] memory trial = _committee(e, inS, count);
            (failed,) = Continuity.check(o, trial, cfg.churn);
            if (failed == 0) {
                chosen = trial;
            } else {
                inS[low] = true;
                inS[x] = false;
            }
        }
    }

    function _churnReason(uint8 failed) private pure returns (Reason) {
        if (failed & (Continuity.FAIL_MEMBERSHIP | Continuity.FAIL_TURNOVER) != 0) {
            return Reason.MembershipChurn;
        }
        return Reason.WeightChurn;
    }

    /// @dev Strict rank order: descending weight, then ascending identity.
    function _better(Entry memory a, Entry memory b) private pure returns (bool) {
        if (a.weight != b.weight) return a.weight > b.weight;
        return a.id < b.id;
    }

    /// @dev Which eligible identities are members of the committee `o` (both ascending by identity).
    function _incumbents(Continuity.Member[] memory o, Entry[] memory e)
        private
        pure
        returns (bool[] memory incumbent)
    {
        incumbent = new bool[](e.length);
        uint256 i;
        for (uint256 j = 0; j < e.length; ++j) {
            while (i < o.length && o[i].id < e[j].id) ++i;
            if (i < o.length && o[i].id == e[j].id) incumbent[j] = true;
        }
    }

    function _committee(Entry[] memory e, bool[] memory inS, uint256 count)
        private
        pure
        returns (Continuity.Member[] memory out)
    {
        out = new Continuity.Member[](count);
        uint256 k;
        for (uint256 i = 0; i < e.length; ++i) {
            if (inS[i]) out[k++] = Continuity.Member(e[i].id, e[i].binding, e[i].weight);
        }
    }

    /// @dev Indices of `e` in rank order: a bottom-up merge sort, O(V log V), stable on the strict total order.
    function _rank(Entry[] memory e) private pure returns (uint256[] memory rank) {
        uint256 n = e.length;
        rank = new uint256[](n);
        uint256[] memory tmp = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            rank[i] = i;
        }
        for (uint256 width = 1; width < n; width *= 2) {
            for (uint256 lo = 0; lo < n; lo += 2 * width) {
                uint256 mid = lo + width < n ? lo + width : n;
                uint256 hi = lo + 2 * width < n ? lo + 2 * width : n;
                uint256 a = lo;
                uint256 b = mid;
                uint256 k = lo;
                while (a < mid && b < hi) {
                    if (_better(e[rank[b]], e[rank[a]])) tmp[k++] = rank[b++];
                    else tmp[k++] = rank[a++];
                }
                while (a < mid) tmp[k++] = rank[a++];
                while (b < hi) tmp[k++] = rank[b++];
            }
            (rank, tmp) = (tmp, rank);
        }
    }
}
