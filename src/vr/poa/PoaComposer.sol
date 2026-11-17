// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the frozen ceilings: 16 committee members, 4 pending ForceRemoves, a pool of 6 and so 64 trials.
// forge-lint: disable-start(boolean-cst, calls-loop, unsafe-typecast)

import {Continuity} from "../../p85/Continuity.sol";
import {Quantize} from "../../p85/Quantize.sol";

/// @title PoaComposer
/// @notice The PoA module's composition rule (bft-core briefs/validator-registry-design-final.md section 3.7.3): a bounded,
/// deterministic trial search. Pure: the module gathers the inputs from VR and its own state, and this library decides.
///
/// Pool (at most 6 changes, so at most 64 trials):
/// - removals, at most 4: (1) individually feasible ForceRemoves by ascending `scheduledAt`, (2) the other ForceRemoves by ascending
///   `scheduledAt`, (3) Removing members by ascending id; ties between ForceRemoves break by change id;
/// - binding replacements: 1, or 2 when there are at most 2 removals, by ascending id;
/// - joiners: 1, or 2 when there are at most 2 removals, in admission order.
///
/// Mandatory: when the oldest individually feasible ForceRemove is overdue (`progress > scheduledAt + forceDeadline`), every trial
/// includes it and trials without it are not evaluated.
///
/// Each trial is a complete successor S judged against the original committee O: the committee limits (in range, or strictly toward
/// it), and continuity (`M <= maxM`, `3 max(removed, added) < min(|O|, |S|)`, `D <= bound`, unchanged-binding overlap strictly above
/// 2/3 of both). The empty trial (S = O) is a candidate only with `dueWork > 0`. Of the passing trials the best-ranked wins:
/// (1) it includes the oldest feasible ForceRemove (when none is mandatory); (2) more removals; (3) `| |S| - nTarget |` ascending;
/// (4) more total changes; (5) lexicographically smaller sorted ids. The ranking is a strict total order (pool ids are distinct), so
/// "the first passing trial in rank order" and "the best-ranked passing trial" are the same trial.
///
/// Weights: incumbents keep their raw weight, joiners have unit raw weight, and S is quantized by the shared `Quantize` rule (on a PoA
/// generation every raw weight is 1). O carries its committed weights. A trial whose raw total exceeds 2^64 - 1 (the protocol's
/// bound, possible only with weights carried over at the maximum) is not acceptable; the search goes on with the other trials. Carried
/// non-unit weights keep continuity aligned with VR, but such a committee does not gain the equal-weight headcount premise (design
/// 8.3 needs a pinned h_max for weighted profiles), and the 3.7.3 arithmetic facts (pure removal from five) are equal-weight facts.
///
/// Cost: a trial is a few bit sets over O. Its continuity measurement is derived in one pass over O (the shared `Continuity.judge`
/// takes it), with S's quantization from `Quantize.divisor`, so the 64 trials allocate nothing per member. `test/vr/poa` checks every
/// chosen trial against an exact-rational model and every published output against VR's full `Continuity.check`.
library PoaComposer {
    uint8 internal constant REMOVE = 1;
    uint8 internal constant REPLACE = 2;
    uint8 internal constant JOIN = 3;

    uint256 internal constant MAX_REMOVALS = 4;
    uint256 internal constant MAX_POOL = 6;
    uint256 internal constant MAX_COMMITTEE = 16;

    /// @dev A member of O: `binding` is the continuity binding (the hash of the four node and key words; the payee is not part of it).
    struct Seat {
        uint64 id;
        bytes32 binding;
        uint64 weight; // committed
        uint64 rawWeight;
    }

    struct ForceRemove {
        uint64 changeId;
        uint64 id;
        uint64 scheduledAt;
    }

    /// @dev A staged binding of a member, or a joiner with the binding it would join with.
    struct Candidate {
        uint64 id;
        bytes32 binding;
    }

    struct Input {
        Seat[] o; // the committee in force, strictly ascending id, 1 to 16 members
        ForceRemove[] forceRemoves; // Scheduled ForceRemoves; may repeat an id or name a non-member (both ignored)
        uint64[] removing; // Removing members, ascending id
        Candidate[] staged; // members with a staged binding, ascending id
        Candidate[] joiners; // eligible joiners (non-members), admission order
        uint64 progress;
        uint64 forceDeadline; // maxElectionInterval + 2 * LIFETIME
        uint32 nMin;
        uint32 nTarget;
        uint32 nMax;
        uint32 dueWork;
        Continuity.Params params;
    }

    struct Change {
        uint8 kind;
        uint64 id;
        bytes32 binding; // the new binding for REPLACE and JOIN
        uint8 seat; // the index in O for REMOVE and REPLACE
    }

    struct Pool {
        Change[] changes; // bit i of a trial mask is changes[i]; the removals come first
        uint256 removeBits;
        uint256 joinBits;
        uint8[] byId; // pool indices in ascending id
        bool oldestFeasible; // changes[0] is the oldest individually feasible ForceRemove
        bool mandatory; // ... and it is overdue
    }

    /// @dev One member of a trial successor: `src` is the index into O for an incumbent, or MAX_COMMITTEE + the pool index for a joiner.
    struct Slot {
        uint64 id;
        bytes32 binding;
        uint64 rawWeight;
        uint64 weight;
        uint8 src;
        bool replaced;
    }

    // ---------------------------------------------------------------------------------------------
    // pool
    // ---------------------------------------------------------------------------------------------

    function _indexOf(Seat[] memory o, uint64 id) private pure returns (bool, uint256) {
        for (uint256 i = 0; i < o.length; ++i) {
            if (o[i].id == id) return (true, i);
        }
        return (false, 0);
    }

    /// @notice Whether removing `id` alone from O passes continuity, bindings and raw weights otherwise unchanged ("individually
    /// feasible", design 3.6.3; the same predicate as VR's watchdog).
    function feasible(Seat[] memory o, uint64 id, Continuity.Params memory p)
        internal
        pure
        returns (bool)
    {
        (bool member, uint256 i) = _indexOf(o, id);
        if (!member || o.length < 2) return false;
        return _continuity(_base(o), p, uint256(1) << i, 0, 0);
    }

    /// @dev (feasible first) then ascending scheduledAt, then ascending change id.
    function _frBefore(ForceRemove memory a, bool fa, ForceRemove memory b, bool fb)
        private
        pure
        returns (bool)
    {
        if (fa != fb) return fa;
        if (a.scheduledAt != b.scheduledAt) return a.scheduledAt < b.scheduledAt;
        return a.changeId < b.changeId;
    }

    /// @notice The pool of design 3.7.3 and the mandatory flag.
    function pool(Input memory inp) internal pure returns (Pool memory pl) {
        // the ForceRemoves of members, one per id (its earliest by scheduledAt, then change id)
        uint256 nf = inp.forceRemoves.length;
        ForceRemove[] memory fr = new ForceRemove[](nf);
        bool[] memory fe = new bool[](nf);
        uint256 k = 0;
        for (uint256 i = 0; i < nf; ++i) {
            ForceRemove memory x = inp.forceRemoves[i];
            (bool member,) = _indexOf(inp.o, x.id);
            if (!member) continue;
            bool dup = false;
            for (uint256 j = 0; j < k; ++j) {
                if (fr[j].id != x.id) continue;
                dup = true;
                if (_frBefore(x, false, fr[j], false)) fr[j] = x;
            }
            if (!dup) fr[k++] = x;
        }
        for (uint256 i = 0; i < k; ++i) {
            fe[i] = feasible(inp.o, fr[i].id, inp.params);
        }
        // insertion sort on the strict order above
        for (uint256 i = 1; i < k; ++i) {
            ForceRemove memory x = fr[i];
            bool xf = fe[i];
            uint256 j = i;
            while (j > 0 && _frBefore(x, xf, fr[j - 1], fe[j - 1])) {
                fr[j] = fr[j - 1];
                fe[j] = fe[j - 1];
                --j;
            }
            fr[j] = x;
            fe[j] = xf;
        }

        Change[] memory c = new Change[](MAX_POOL);
        uint256 n = 0;
        for (uint256 i = 0; i < k && n < MAX_REMOVALS; ++i) {
            (, uint256 idx) = _indexOf(inp.o, fr[i].id);
            c[n++] = Change(REMOVE, fr[i].id, 0, uint8(idx));
        }
        for (uint256 i = 0; i < inp.removing.length && n < MAX_REMOVALS; ++i) {
            uint64 id = inp.removing[i];
            (bool member, uint256 idx) = _indexOf(inp.o, id);
            if (!member || _inPool(c, n, id)) continue;
            c[n++] = Change(REMOVE, id, 0, uint8(idx));
        }
        uint256 removals = n;
        uint256 cap = removals <= 2 ? 2 : 1;
        uint256 taken = 0;
        for (uint256 i = 0; i < inp.staged.length && taken < cap; ++i) {
            Candidate memory s = inp.staged[i];
            (bool member, uint256 idx) = _indexOf(inp.o, s.id);
            if (!member || _inPool(c, n, s.id)) continue;
            c[n++] = Change(REPLACE, s.id, s.binding, uint8(idx));
            ++taken;
        }
        taken = 0;
        for (uint256 i = 0; i < inp.joiners.length && taken < cap; ++i) {
            Candidate memory j = inp.joiners[i];
            (bool member,) = _indexOf(inp.o, j.id);
            if (member || _inPool(c, n, j.id)) continue;
            pl.joinBits |= uint256(1) << n;
            c[n++] = Change(JOIN, j.id, j.binding, 0);
            ++taken;
        }
        pl.changes = new Change[](n);
        pl.byId = new uint8[](n);
        for (uint256 i = 0; i < n; ++i) {
            pl.changes[i] = c[i];
            // insertion into the ascending-id order
            uint256 pos = i;
            while (pos > 0 && c[pl.byId[pos - 1]].id > c[i].id) {
                pl.byId[pos] = pl.byId[pos - 1];
                --pos;
            }
            pl.byId[pos] = uint8(i);
        }
        pl.removeBits = (uint256(1) << removals) - 1;
        pl.oldestFeasible = k > 0 && fe[0];
        pl.mandatory = pl.oldestFeasible
            && uint256(inp.progress) > uint256(fr[0].scheduledAt) + uint256(inp.forceDeadline);
    }

    function _inPool(Change[] memory c, uint256 n, uint64 id) private pure returns (bool) {
        for (uint256 i = 0; i < n; ++i) {
            if (c[i].id == id) return true;
        }
        return false;
    }

    // ---------------------------------------------------------------------------------------------
    // trials
    // ---------------------------------------------------------------------------------------------

    /// @notice The bounded trial search. `found` is false for NoCandidate (LimitsUnreachable); otherwise `mask` selects the winning
    /// changes of `pl`.
    function choose(Input memory inp)
        internal
        pure
        returns (bool found, uint256 mask, Pool memory pl)
    {
        pl = pool(inp);
        Base memory b = _base(inp.o);
        uint256 trials = uint256(1) << pl.changes.length;
        for (uint256 m = 0; m < trials; ++m) {
            if (pl.mandatory && m & 1 == 0) continue;
            if (m == 0 && inp.dueWork == 0) continue;
            if (found && !_ranksBefore(inp, pl, m, mask)) continue;
            if (_accepts(inp, pl, m, b)) {
                found = true;
                mask = m;
            }
        }
    }

    function _popcount(uint256 x) private pure returns (uint256 c) {
        while (x != 0) {
            c += x & 1;
            x >>= 1;
        }
    }

    function _absDiff(uint256 a, uint256 b) private pure returns (uint256) {
        return a > b ? a - b : b - a;
    }

    function _size(Input memory inp, Pool memory pl, uint256 m) private pure returns (uint256) {
        return inp.o.length - _popcount(m & pl.removeBits) + _popcount(m & pl.joinBits);
    }

    /// @notice Whether trial `a` ranks strictly before trial `b` (design 3.7.3 ranking keys 1 to 5).
    function _ranksBefore(Input memory inp, Pool memory pl, uint256 a, uint256 b)
        private
        pure
        returns (bool)
    {
        if (pl.oldestFeasible && !pl.mandatory) {
            bool ia = a & 1 != 0;
            bool ib = b & 1 != 0;
            if (ia != ib) return ia;
        }
        uint256 ra = _popcount(a & pl.removeBits);
        uint256 rb = _popcount(b & pl.removeBits);
        if (ra != rb) return ra > rb;
        uint256 da = _absDiff(_size(inp, pl, a), inp.nTarget);
        uint256 db = _absDiff(_size(inp, pl, b), inp.nTarget);
        if (da != db) return da < db;
        uint256 ta = _popcount(a);
        uint256 tb = _popcount(b);
        if (ta != tb) return ta > tb;
        // equal counts: the sorted id lists first differ at the smallest id in exactly one trial, and that trial is smaller
        for (uint256 k = 0; k < pl.byId.length; ++k) {
            uint256 bit = uint256(1) << pl.byId[k];
            if ((a & bit) != (b & bit)) return a & bit != 0;
        }
        return false;
    }

    function _limitDistance(Input memory inp, uint256 n) private pure returns (uint256) {
        if (n < inp.nMin) return inp.nMin - n;
        if (n > inp.nMax) return n - inp.nMax;
        return 0;
    }

    /// @notice Whether trial `m` is acceptable: the committee limits (in range, or strictly toward it) and continuity O -> S.
    function accepts(Input memory inp, Pool memory pl, uint256 m) internal pure returns (bool) {
        return _accepts(inp, pl, m, _base(inp.o));
    }

    function _accepts(Input memory inp, Pool memory pl, uint256 m, Base memory b)
        private
        pure
        returns (bool)
    {
        uint256 size = _size(inp, pl, m);
        if (size == 0 || size > MAX_COMMITTEE) return false;
        uint256 d = _limitDistance(inp, size);
        if (d != 0 && d >= _limitDistance(inp, inp.o.length)) return false;
        uint256 removedO = 0;
        uint256 replacedO = 0;
        uint256 joins = 0;
        for (uint256 j = 0; j < pl.changes.length; ++j) {
            if (m & (uint256(1) << j) == 0) continue;
            Change memory c = pl.changes[j];
            if (c.kind == REMOVE) {
                removedO |= uint256(1) << c.seat;
            } else if (c.kind == REPLACE) {
                // a staged binding equal in its four node and key words (a payee change) is no continuity replacement
                if (c.binding != inp.o[c.seat].binding) replacedO |= uint256(1) << c.seat;
            } else {
                ++joins;
            }
        }
        return _continuity(b, inp.params, removedO, replacedO, joins);
    }

    /// @dev O's committed and raw weights as flat words, and V = O's committed total.
    struct Base {
        uint256[] ow;
        uint256[] raw;
        uint256 v;
    }

    function _base(Seat[] memory o) private pure returns (Base memory b) {
        uint256 n = o.length;
        b.ow = new uint256[](n);
        b.raw = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            b.ow[i] = o[i].weight;
            b.raw[i] = o[i].rawWeight;
            b.v += o[i].weight;
        }
    }

    /// @dev Continuity O -> S for S = O without `removedO`, with the bindings of `replacedO` changed and `joins` unit-weight joiners
    /// (bit i is o[i]). S's weights are the shared quantization of its raw weights (`Quantize`: q = max(1, floor(x / s)) with the rule's
    /// divisor s); the measurement is `Continuity.measure`'s, accumulated in one pass, and the predicates are `Continuity.judge`.
    /// Unchecked: at most 16 + 2 members of 64-bit weights, so every sum and product fits in 256 bits.
    function _continuity(
        Base memory b,
        Continuity.Params memory p,
        uint256 removedO,
        uint256 replacedO,
        uint256 joins
    ) private pure returns (bool) {
        uint256 n = b.ow.length;
        uint256 size = n - _popcount(removedO) + joins;
        if (size == 0) return false;
        Continuity.Measured memory r;
        unchecked {
            uint256 rawTotal = joins;
            for (uint256 i = 0; i < n; ++i) {
                if (removedO & (uint256(1) << i) == 0) rawTotal += b.raw[i];
            }
            // the protocol's raw-total bound (Quantize.quantize, VR's output validation): a trial above it is not a candidate
            if (rawTotal > type(uint64).max) return false;
            uint256 s = Quantize.divisor(rawTotal, size, Quantize.WEIGHT_CAP_B);
            uint256 w = joins; // a joiner's quantized unit weight is max(1, floor(1 / s)) = 1
            for (uint256 i = 0; i < n; ++i) {
                if (removedO & (uint256(1) << i) == 0) w += _q(b.raw[i], s);
            }
            uint256 v = b.v;
            r.totalOld = v;
            r.totalNew = w;
            for (uint256 i = 0; i < n; ++i) {
                uint256 ow = b.ow[i];
                if (removedO & (uint256(1) << i) != 0) {
                    r.distanceNumerator += ow * w;
                    continue;
                }
                uint256 q = _q(b.raw[i], s);
                r.distanceNumerator += _absDiff(q * v, ow * w);
                if (replacedO & (uint256(1) << i) == 0) {
                    r.unchangedOld += ow;
                    r.unchangedNew += q;
                }
            }
            r.distanceNumerator += joins * v;
            r.replaced = uint64(_popcount(replacedO));
            r.removed = uint64(_popcount(removedO)) + r.replaced;
            r.added = uint64(joins) + r.replaced;
            r.m = r.removed + r.added;
        }
        return Continuity.judge(r, n, size, p) == 0;
    }

    function _q(uint256 raw, uint256 s) private pure returns (uint256) {
        if (s == 1) return raw;
        uint256 v = raw / s;
        return v == 0 ? 1 : v;
    }

    /// @notice The successor of trial `m`, strictly ascending id, quantized: what the module publishes.
    function successor(Input memory inp, Pool memory pl, uint256 m)
        internal
        pure
        returns (Slot[] memory s)
    {
        uint256 size = _size(inp, pl, m);
        s = new Slot[](size);
        uint256 k = 0;
        for (uint256 i = 0; i < inp.o.length; ++i) {
            Seat memory o = inp.o[i];
            bool removed = false;
            bool replaced = false;
            bytes32 binding = o.binding;
            for (uint256 j = 0; j < pl.changes.length; ++j) {
                if (m & (uint256(1) << j) == 0 || pl.changes[j].id != o.id) continue;
                if (pl.changes[j].kind == REMOVE) removed = true;
                if (pl.changes[j].kind == REPLACE) {
                    replaced = true;
                    binding = pl.changes[j].binding;
                }
            }
            if (!removed) s[k++] = Slot(o.id, binding, o.rawWeight, 0, uint8(i), replaced);
        }
        for (uint256 j = 0; j < pl.changes.length; ++j) {
            if (m & (uint256(1) << j) == 0 || pl.changes[j].kind != JOIN) continue;
            Slot memory x = Slot(
                pl.changes[j].id, pl.changes[j].binding, 1, 0, uint8(MAX_COMMITTEE + j), false
            );
            uint256 pos = k++;
            while (pos > 0 && s[pos - 1].id > x.id) {
                s[pos] = s[pos - 1];
                --pos;
            }
            s[pos] = x;
        }
        if (size == 0) return s;
        uint256[] memory raw = new uint256[](size);
        for (uint256 i = 0; i < size; ++i) {
            raw[i] = s[i].rawWeight;
        }
        uint256[] memory q = Quantize.quantize(raw);
        for (uint256 i = 0; i < size; ++i) {
            s[i].weight = uint64(q[i]);
        }
    }
}

/// @title PoaComposerEngine
/// @notice The composer as its own immutable, stateless contract, so the PoA module stays under EIP-170. The module calls it with a
/// STATICCALL (it is pure) and pins its address as an immutable, so the module's code hash covers it. A revert here reverts the
/// module's `elect` step (a module fault).
contract PoaComposerEngine {
    /// @notice The trial search, and for a winning trial its quantized successor.
    function compose(PoaComposer.Input memory inp)
        external
        pure
        returns (
            bool found,
            uint256 mask,
            PoaComposer.Pool memory pl,
            PoaComposer.Slot[] memory successor
        )
    {
        (found, mask, pl) = PoaComposer.choose(inp);
        if (found) successor = PoaComposer.successor(inp, pl, mask);
    }
}
