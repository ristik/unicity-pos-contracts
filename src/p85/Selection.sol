// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Continuity} from "./Continuity.sol";
import {Quantize} from "./Quantize.sol";

// Loops are bounded by the immutable V ceiling (at most 128 eligible identities) and the committee ceiling (at most 32 members).
// forge-lint: disable-start(unsafe-typecast, calls-loop)

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
    /// @dev An eligible identity of the snapshot: its current binding hash and RAW bonded weight x (positive). The committed weight q of a
    /// committee is derived from the raw weights of its members (`Quantize`); ranking stays on x.
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

        Prior memory prior = _prior(o, e);
        bool[] memory incumbent = prior.incumbent;
        uint256[] memory rank = _rank(e);

        // the seed
        bool[] memory inS = new bool[](n);
        uint256 count = 0;
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
        (uint8 failed, Continuity.Measured memory r0) = Continuity.check(o, chosen, cfg.churn);
        if (failed != 0) return (_churnReason(failed), new Continuity.Member[](0));

        // Each remaining outsider, once, in rank order. A trial replaces the lowest-ranked retained incumbent by the outsider. While the raw
        // total of the committee and of the trial are both within the cap B, q = x and the trial's measurement against the same `o` follows
        // from the running one by constant-size deltas plus one pass over the retained incumbents (the weight distance depends on the new
        // total). When either exceeds B, every weight of the trial committee changes with its total, so the trial is quantized and judged by
        // a full measurement; a trial that is accepted back within the cap resynchronizes the running measurement.
        uint256 rawTotal = 0;
        for (uint256 i = 0; i < n; ++i) {
            if (inS[i]) rawTotal += e[i].weight;
        }
        Trial memory t;
        if (rawTotal <= Quantize.WEIGHT_CAP_B) t = _trialOf(o, e, prior, inS, r0);
        bool replacedAny = false;
        // The lowest-ranked retained incumbent only ever moves toward better ranks (a removed incumbent is never re-added), so one
        // downward pointer over the whole pass finds it.
        uint256 q = n;
        for (uint256 r = 0; r < n; ++r) {
            uint256 x = rank[r];
            if (incumbent[x] || inS[x]) continue;
            while (q > 0 && !(incumbent[rank[q - 1]] && inS[rank[q - 1]])) --q;
            if (q == 0) continue; // no retained incumbent left to replace
            uint256 low = rank[q - 1];
            if (!_better(e[x], e[low])) continue;
            uint256 nextRaw = rawTotal - e[low].weight + e[x].weight;
            if (rawTotal <= Quantize.WEIGHT_CAP_B && nextRaw <= Quantize.WEIGHT_CAP_B) {
                Trial memory next = _step(t, e, prior, low, x);
                failed = Continuity.judge(
                    _measured(next, _sharedDistance(next, e, prior, inS, low)),
                    o.length,
                    count,
                    cfg.churn
                );
                if (failed == 0) {
                    inS[low] = false;
                    inS[x] = true;
                    t = next;
                    rawTotal = nextRaw;
                    replacedAny = true;
                }
            } else {
                inS[low] = false;
                inS[x] = true;
                Continuity.Measured memory m;
                (failed, m) = Continuity.check(o, _committee(e, inS, count), cfg.churn);
                if (failed == 0) {
                    rawTotal = nextRaw;
                    replacedAny = true;
                    if (rawTotal <= Quantize.WEIGHT_CAP_B) t = _trialOf(o, e, prior, inS, m);
                } else {
                    inS[low] = true;
                    inS[x] = false;
                }
            }
        }
        if (replacedAny) chosen = _committee(e, inS, count);
    }

    /// @dev The running trial state of the committee `inS`, whose measurement against `o` is `m`. Valid only while the committee's raw total
    /// is within the cap (then its committed weights are the raw ones).
    function _trialOf(
        Continuity.Member[] memory o,
        Entry[] memory e,
        Prior memory prior,
        bool[] memory inS,
        Continuity.Measured memory m
    ) private pure returns (Trial memory t) {
        t = Trial({
            total: Continuity.totalWeight(o, false),
            totalNew: 0,
            replaced: m.replaced,
            onlyOld: m.removed - m.replaced,
            onlyNew: m.added - m.replaced,
            unchangedOld: m.unchangedOld,
            unchangedNew: m.unchangedNew,
            sharedNew: 0,
            sharedOld: 0
        });
        for (uint256 i = 0; i < e.length; ++i) {
            if (inS[i]) {
                t.totalNew += e[i].weight;
                if (prior.incumbent[i]) {
                    t.sharedNew += e[i].weight;
                    t.sharedOld += prior.weight[i];
                }
            }
        }
    }

    /// @dev The running measurement of the current successor against `o`. Every retained incumbent is shared with `o`; every other
    /// member of the successor is an outsider.
    struct Trial {
        uint256 total; // V, the committed weight of o
        uint256 totalNew; // W
        uint256 replaced; // shared identities with a changed binding
        uint256 onlyOld;
        uint256 onlyNew;
        uint256 unchangedOld;
        uint256 unchangedNew;
        uint256 sharedNew; // successor weight of the shared identities
        uint256 sharedOld; // their committed weight
    }

    /// @dev What the last committed committee says about each eligible identity (both ascending by identity).
    struct Prior {
        bool[] incumbent;
        uint256[] weight; // committed weight, zero for an outsider
        bool[] same; // an incumbent whose binding is unchanged
        uint256[] list; // the eligible incumbents, as indices into the eligible list
    }

    /// @dev `t` after the lowest-ranked retained incumbent `low` is replaced by the outsider `x`.
    function _step(Trial memory t, Entry[] memory e, Prior memory prior, uint256 low, uint256 x)
        private
        pure
        returns (Trial memory n)
    {
        n = Trial(
            t.total,
            t.totalNew - e[low].weight + e[x].weight,
            t.replaced,
            t.onlyOld + 1,
            t.onlyNew + 1,
            t.unchangedOld,
            t.unchangedNew,
            t.sharedNew - e[low].weight,
            t.sharedOld - prior.weight[low]
        );
        if (prior.same[low]) {
            n.unchangedOld -= prior.weight[low];
            n.unchangedNew -= e[low].weight;
        } else {
            n.replaced -= 1;
        }
    }

    /// @dev The shared identities' share of D's numerator at the trial's totals: the retained incumbents except `low`.
    function _sharedDistance(
        Trial memory t,
        Entry[] memory e,
        Prior memory prior,
        bool[] memory inS,
        uint256 low
    ) private pure returns (uint256 sum) {
        for (uint256 k = 0; k < prior.list.length; ++k) {
            uint256 i = prior.list[k];
            if (i == low || !inS[i]) continue;
            uint256 a = uint256(e[i].weight) * t.total;
            uint256 b = prior.weight[i] * t.totalNew;
            sum += a > b ? a - b : b - a;
        }
    }

    /// @dev D's numerator: successor-only members weigh against zero, committed-only ones against zero, shared ones by their
    /// difference at the new total (`sharedDistance`).
    function _measured(Trial memory t, uint256 sharedDistance)
        private
        pure
        returns (Continuity.Measured memory r)
    {
        r.replaced = uint64(t.replaced);
        r.removed = uint64(t.onlyOld + t.replaced);
        r.added = uint64(t.onlyNew + t.replaced);
        r.m = r.removed + r.added;
        r.unchangedOld = t.unchangedOld;
        r.unchangedNew = t.unchangedNew;
        r.totalOld = t.total;
        r.totalNew = t.totalNew;
        r.distanceNumerator = t.total * (t.totalNew - t.sharedNew) + t.totalNew
            * (t.total - t.sharedOld) + sharedDistance;
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

    /// @dev What the committee `o` says about each eligible identity (both ascending by identity).
    function _prior(Continuity.Member[] memory o, Entry[] memory e)
        private
        pure
        returns (Prior memory p)
    {
        p.incumbent = new bool[](e.length);
        p.weight = new uint256[](e.length);
        p.same = new bool[](e.length);
        uint256[] memory list = new uint256[](e.length);
        uint256 count = 0;
        uint256 i = 0;
        for (uint256 j = 0; j < e.length; ++j) {
            while (i < o.length && o[i].id < e[j].id) ++i;
            if (i < o.length && o[i].id == e[j].id) {
                p.incumbent[j] = true;
                p.weight[j] = o[i].weight;
                p.same[j] = o[i].binding == e[j].binding;
                list[count++] = j;
            }
        }
        p.list = new uint256[](count);
        for (uint256 k = 0; k < count; ++k) {
            p.list[k] = list[k];
        }
    }

    function _committee(Entry[] memory e, bool[] memory inS, uint256 count)
        private
        pure
        returns (Continuity.Member[] memory out)
    {
        out = new Continuity.Member[](count);
        uint256[] memory raw = new uint256[](count);
        uint256 k = 0;
        for (uint256 i = 0; i < e.length; ++i) {
            if (inS[i]) {
                raw[k] = e[i].weight;
                out[k++] = Continuity.Member(e[i].id, e[i].binding, 0);
            }
        }
        uint256[] memory q = Quantize.quantize(raw);
        for (k = 0; k < count; ++k) {
            out[k].weight = uint64(q[k]);
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
