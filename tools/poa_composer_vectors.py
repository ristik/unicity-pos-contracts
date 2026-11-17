#!/usr/bin/env python3
"""Exact-rational model of the PoA composer (bft-core briefs/validator-registry-design-final.md section 3.7.3; VT-03, section 11).

An independent reading of the design text, written for the vectors and not derived from the Solidity:
- continuity with Python Fractions (D = sum |w_i/W - v_i/V| exactly, overlap > 2/3 as fractions), not integer cross-multiplication;
- the trial order is a literal sort of every candidate trial by the five ranking keys, and the first passing trial wins
  (the Solidity keeps a running best).

Regenerate with  python3 tools/poa_composer_vectors.py > test/vr/poa/fixtures/poa-composer.json

Each vector's `input` and `expect` are flat integer word lists (PoaComposerVectors.t.sol decodes them):
  input  = [n, (id, binding, weight, raw) * n, nf, (changeId, id, scheduledAt) * nf, nr, id * nr, ns, (id, binding) * ns,
            nj, (id, binding) * nj, progress, forceDeadline, nMin, nTarget, nMax, dueWork, maxM, distNum, distDen]
  expect = [found, mandatory, oldestFeasible, np, (kind, id) * np, nc, (kind, id) * nc]   kinds: 1 remove, 2 replace, 3 join
"""
import itertools
import json
import random
from fractions import Fraction

B = 65536
REMOVE, REPLACE, JOIN = 1, 2, 3


def quantize(x):
    n, total = len(x), sum(x)
    if total <= B:
        return list(x)
    s = -(-total // (B - n))
    return [max(1, v // s) for v in x]


def continuity(o, s, max_m, dist):
    """o, s: {id: (binding, weight)}."""
    shared = set(o) & set(s)
    replaced = sum(1 for i in shared if o[i][0] != s[i][0])
    removed = len(set(o) - set(s)) + replaced
    added = len(set(s) - set(o)) + replaced
    if removed + added > max_m:
        return False
    if not 3 * max(removed, added) < min(len(o), len(s)):
        return False
    v = sum(w for _, w in o.values())
    w = sum(w for _, w in s.values())
    d = sum(abs(Fraction(s[i][1] if i in s else 0, w) - Fraction(o[i][1] if i in o else 0, v)) for i in set(o) | set(s))
    if d > dist:
        return False
    uo = sum(o[i][1] for i in shared if o[i][0] == s[i][0])
    us = sum(s[i][1] for i in shared if o[i][0] == s[i][0])
    return Fraction(uo, v) > Fraction(2, 3) and Fraction(us, w) > Fraction(2, 3)


class Scenario:
    def __init__(self, name, seats, frs=(), removing=(), staged=(), joiners=(), progress=1000, force_deadline=33768,
                 limits=(1, 5, 16), due_work=0, max_m=4, dist=(1, 2)):
        self.name = name
        self.seats = list(seats)  # (id, binding, weight, raw), ascending id
        self.frs = list(frs)  # (changeId, id, scheduledAt)
        self.removing = list(removing)
        self.staged = list(staged)  # (id, binding)
        self.joiners = list(joiners)  # (id, binding)
        self.progress = progress
        self.force_deadline = force_deadline
        self.limits = limits
        self.due_work = due_work
        self.max_m = max_m
        self.dist = dist

    # ---- the model ----

    def o(self):
        return {i: (b, w) for i, b, w, _ in self.seats}

    def raw(self):
        return {i: r for i, _, _, r in self.seats}

    def successor(self, changes):
        rem = {c[1] for c in changes if c[0] == REMOVE}
        rep = {c[1]: c[2] for c in changes if c[0] == REPLACE}
        joins = [(c[1], c[2]) for c in changes if c[0] == JOIN]
        members = [(i, rep.get(i, b), self.raw()[i]) for i, b, _, _ in self.seats if i not in rem]
        members += [(i, b, 1) for i, b in joins]
        members.sort()
        if not members:
            return {}
        q = quantize([r for _, _, r in members])
        return {m[0]: (m[1], qi) for m, qi in zip(members, q)}

    def individually_feasible(self, i):
        o = self.o()
        if i not in o or len(o) < 2:
            return False
        return continuity(o, self.successor([(REMOVE, i, 0)]), self.max_m, Fraction(*self.dist))

    def pool(self):
        members = {s[0] for s in self.seats}
        best = {}
        for cid, i, at in self.frs:
            if i not in members:
                continue
            if i not in best or (at, cid) < (best[i][2], best[i][0]):
                best[i] = (cid, i, at)
        frs = sorted(best.values(), key=lambda f: (not self.individually_feasible(f[1]), f[2], f[0]))
        pool = [(REMOVE, f[1], 0) for f in frs][:4]
        for i in sorted(self.removing):
            if len(pool) < 4 and i in members and all(c[1] != i for c in pool):
                pool.append((REMOVE, i, 0))
        removals = len(pool)
        cap = 2 if removals <= 2 else 1
        taken = 0
        for i, b in sorted(self.staged):
            if taken < cap and i in members and all(c[1] != i for c in pool):
                pool.append((REPLACE, i, b))
                taken += 1
        taken = 0
        for i, b in self.joiners:
            if taken < cap and i not in members and all(c[1] != i for c in pool):
                pool.append((JOIN, i, b))
                taken += 1
        oldest = bool(frs) and self.individually_feasible(frs[0][1])
        mandatory = oldest and self.progress > frs[0][2] + self.force_deadline
        return pool, oldest, mandatory

    def limit_distance(self, n):
        lo, _, hi = self.limits
        return lo - n if n < lo else (n - hi if n > hi else 0)

    def accepts(self, changes):
        s = self.successor(changes)
        if not s or len(s) > 16:
            return False
        d = self.limit_distance(len(s))
        if d != 0 and d >= self.limit_distance(len(self.seats)):
            return False
        return continuity(self.o(), s, self.max_m, Fraction(*self.dist))

    def choose(self):
        pool, oldest, mandatory = self.pool()
        trials = []
        for r in range(len(pool) + 1):
            for subset in itertools.combinations(range(len(pool)), r):
                if mandatory and 0 not in subset:
                    continue
                if not subset and self.due_work == 0:
                    continue
                changes = [pool[k] for k in subset]
                removals = sum(1 for c in changes if c[0] == REMOVE)
                size = len(self.seats) - removals + sum(1 for c in changes if c[0] == JOIN)
                key = (
                    (0 if 0 in subset else 1) if (oldest and not mandatory) else 0,
                    -removals,
                    abs(size - self.limits[1]),
                    -len(changes),
                    sorted(c[1] for c in changes),
                )
                trials.append((key, subset))
        trials.sort()
        for _, subset in trials:
            if self.accepts([pool[k] for k in subset]):
                return True, subset, pool, oldest, mandatory
        return False, (), pool, oldest, mandatory

    # ---- encoding ----

    def vector(self):
        found, subset, pool, oldest, mandatory = self.choose()
        inp = [len(self.seats)]
        for i, b, w, r in self.seats:
            inp += [i, b, w, r]
        inp += [len(self.frs)] + [x for f in self.frs for x in f]
        inp += [len(self.removing)] + list(self.removing)
        inp += [len(self.staged)] + [x for s in self.staged for x in s]
        inp += [len(self.joiners)] + [x for j in self.joiners for x in j]
        inp += [self.progress, self.force_deadline, *self.limits, self.due_work, self.max_m, *self.dist]
        exp = [int(found), int(mandatory), int(oldest), len(pool)] + [x for c in pool for x in c[:2]]
        exp += [len(subset)] + [x for k in subset for x in pool[k][:2]]
        return {"name": self.name, "input": inp, "expect": exp,
                "chosen": [{"kind": ["", "remove", "replace", "join"][pool[k][0]], "id": pool[k][1]} for k in subset],
                "found": found}


def unit(n, start=1):
    return [(i, 1000 + i, 1, 1) for i in range(start, start + n)]


def weighted(ws):
    q = quantize(ws)
    return [(i + 1, 1000 + i + 1, q[i], ws[i]) for i in range(len(ws))]


def j(i):
    return (i, 1000 + i)


def st(i):
    return (i, 5000 + i)


def named():
    s = []
    # section 3.7.3 arithmetic facts (equal weights, distance 1/2)
    s.append(Scenario("n4 pure removal fails", unit(4), removing=[2], limits=(1, 4, 16)))
    s.append(Scenario("n4 swap passes", unit(4), removing=[2], joiners=[j(9)], limits=(1, 4, 16)))
    s.append(Scenario("n4 growth to 5 passes", unit(4), joiners=[j(9)], limits=(1, 5, 16)))
    s.append(Scenario("n4 growth by two refused", unit(4), joiners=[j(9), j(10)], limits=(1, 6, 16)))
    s.append(Scenario("n5 pure removal passes", unit(5), removing=[3], limits=(1, 4, 16)))
    s.append(Scenario("n5 swap preferred at target 5", unit(5), removing=[3], joiners=[j(9)], limits=(1, 5, 16)))
    s.append(Scenario("n5 two removals refused", unit(5), removing=[2, 4], limits=(1, 3, 16)))
    s.append(Scenario("n7 two joiners", unit(7), joiners=[j(9), j(10), j(11)], limits=(1, 9, 16)))
    s.append(Scenario("n7 two removals refused", unit(7), removing=[2, 3], limits=(1, 5, 16)))
    s.append(Scenario("n10 two removals", unit(10), removing=[2, 3], limits=(1, 8, 16)))
    s.append(Scenario("n10 three removals refused", unit(10), removing=[2, 3, 4], limits=(1, 7, 16)))
    s.append(Scenario("n10 two removals two joiners", unit(10), removing=[2, 3], joiners=[j(20), j(21)], limits=(1, 10, 16)))
    s.append(Scenario("n4 binding replacement", unit(4), staged=[st(2)], limits=(1, 4, 16)))
    s.append(Scenario("n4 replacement and removal refused", unit(4), removing=[1], staged=[st(2)], limits=(1, 4, 16)))
    s.append(Scenario("n7 two replacements", unit(7), staged=[st(2), st(5)], limits=(1, 7, 16)))
    # the empty trial
    s.append(Scenario("n5 empty trial in range", unit(5), due_work=1, limits=(1, 5, 16)))
    s.append(Scenario("n5 empty trial outside the limits: NoCandidate", unit(5), due_work=1, limits=(6, 6, 7)))
    s.append(Scenario("n5 no work no empty trial", unit(5), due_work=0, limits=(1, 5, 16)))
    s.append(Scenario("n5 limits strictly toward", unit(5), joiners=[j(9)], due_work=1, limits=(7, 7, 8)))
    # ForceRemove: two infeasible lower ids plus a feasible id 9 (weights 5, 5, 1 x 8)
    w10 = weighted([5, 5, 1, 1, 1, 1, 1, 1, 1, 1])
    s.append(Scenario("n10 two infeasible lower ids and a feasible 9", w10, frs=[(1, 1, 100), (2, 2, 200), (3, 9, 300)],
                      limits=(1, 10, 16)))
    s.append(Scenario("n10 infeasible ids alone: NoCandidate", w10, frs=[(1, 1, 100), (2, 2, 200)], limits=(1, 10, 16)))
    # two feasible removals with the overdue older one winning (n = 7: two removals fail turnover)
    s.append(Scenario("n7 two feasible: older wins", unit(7), frs=[(4, 5, 100), (5, 3, 200)], limits=(1, 7, 16)))
    s.append(Scenario("n7 two feasible: overdue older is mandatory", unit(7), frs=[(4, 5, 100), (5, 3, 200)],
                      progress=100 + 33768 + 1, limits=(1, 7, 16)))
    s.append(Scenario("n7 tie on scheduledAt breaks by change id", unit(7), frs=[(9, 6, 100), (8, 2, 100)], limits=(1, 7, 16)))
    s.append(Scenario("n7 duplicate ForceRemove keeps the earliest", unit(7), frs=[(4, 5, 300), (5, 3, 200), (6, 5, 100)],
                      limits=(1, 7, 16)))
    # repeated omission: the removal fails the limits, other work passes empty; once overdue it is mandatory and nothing passes
    s.append(Scenario("n5 omission before the deadline", unit(5), frs=[(1, 4, 100)], due_work=1, limits=(5, 5, 16)))
    s.append(Scenario("n5 omission after the deadline: NoCandidate", unit(5), frs=[(1, 4, 100)], due_work=1,
                      progress=100 + 33768 + 1, limits=(5, 5, 16)))
    s.append(Scenario("n5 at the deadline not yet mandatory", unit(5), frs=[(1, 4, 100)], due_work=1,
                      progress=100 + 33768, limits=(5, 5, 16)))
    # pool bounds: four removals leave one replacement and one joiner
    s.append(Scenario("n10 pool of six", unit(10), frs=[(1, 2, 10), (2, 3, 20)], removing=[4, 5, 6],
                      staged=[st(7), st(8)], joiners=[j(20), j(21)], limits=(1, 10, 16)))
    s.append(Scenario("n16 at the ceiling", unit(16), joiners=[j(20)], limits=(1, 16, 16)))
    s.append(Scenario("n16 ceiling swap", unit(16), removing=[3], joiners=[j(20)], limits=(1, 16, 16)))
    return s


def randomized(rng, count):
    out = []
    for k in range(count):
        n = rng.choice([4, 5, 7, 10])
        if rng.random() < 0.25:
            seats = weighted([rng.choice([1, 1, 1, 2, 3, 5]) for _ in range(n)])
        else:
            seats = unit(n)
        ids = [x[0] for x in seats]
        frs = []
        for c in range(rng.choice([0, 0, 1, 2, 3, 4])):
            frs.append((c + 1, rng.choice(ids + [99]), rng.choice([100, 200, 300, 300])))
        removing = sorted(rng.sample(ids, rng.choice([0, 0, 1, 1, 2, 3])))
        staged = [st(i) for i in sorted(rng.sample(ids, rng.choice([0, 0, 1, 2, 3])))]
        joiners = [j(20 + i) for i in range(rng.choice([0, 1, 1, 2, 3]))]
        lo = rng.choice([1, 1, max(1, n - 1), n, n + 1])
        tgt = rng.choice([lo, lo + 1, n, n + 2])
        tgt = max(lo, tgt)
        hi = rng.choice([tgt, tgt + 1, 16])
        hi = min(16, max(tgt, hi))
        tgt = min(tgt, hi)
        lo = min(lo, tgt)
        progress = rng.choice([1000, 300 + 33768 + 1, 100 + 33768])
        out.append(Scenario("random %d n%d" % (k, n), seats, frs=frs, removing=removing, staged=staged, joiners=joiners,
                            progress=progress, limits=(lo, tgt, hi), due_work=rng.choice([0, 0, 1, 2]),
                            max_m=rng.choice([2, 4, 4, 8]), dist=rng.choice([(1, 2), (1, 2), (1, 3), (2, 3)])))
    return out


def main():
    rng = random.Random(1143)
    scenarios = named() + randomized(rng, 400)
    head = {
        "schema": "unicity.vr.poa-composer/v1",
        "specification": "briefs/validator-registry-design-final.md section 3.7.3 (exact-rational model, tools/poa_composer_vectors.py)",
    }
    lines = [json.dumps(sc.vector(), separators=(",", ":")) for sc in scenarios]
    print("{")
    for k, v in head.items():
        print(" %s: %s," % (json.dumps(k), json.dumps(v)))
    print(' "vectors": [')
    print(",\n".join("  " + x for x in lines))
    print(" ]")
    print("}")


if __name__ == "__main__":
    main()
