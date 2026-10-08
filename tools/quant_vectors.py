#!/usr/bin/env python3
"""Reference vectors of the weight quantization rule (briefs/leader-lookup.md, amended by leader-lookup-review.md F2).

    quant(x, n, B):  X = sum(x); if X <= B: q = x; else s = ceil(X / (B - n)), q_i = max(1, floor(x_i / s)).

Written with exact integer arithmetic (no floats). The Solidity library, bft-core's evmassign.Quantize and ureth's quant::quantize are all
checked against this file; regenerate with  python3 tools/quant_vectors.py > test/p85/fixtures/quant-vectors.json  and copy it to the other
two repositories' testdata.
"""
import json
import random

B = 65536
U64 = 2**64 - 1


def quant(x, b=B):
    n = len(x)
    if n == 0 or n >= b or any(v == 0 for v in x):
        return None
    total = sum(x)
    if total > U64:
        return None
    if total <= b:
        return list(x)
    s = -(-total // (b - n))
    return [max(1, v // s) for v in x]


def case(name, x, b=B):
    q = quant(x, b)
    out = {"name": name, "b": b, "x": [str(v) for v in x]}
    if q is None:
        out["error"] = True
    else:
        out["q"] = [str(v) for v in q]
        total = sum(x)
        out["s"] = str(1 if total <= b else -(-total // (b - len(x))))
    return out


def vectors():
    rnd = random.Random(85)
    cases = [
        case("a small committee is unchanged", [6, 1, 1, 1]),
        case("X = B is unchanged", [B - 3, 1, 1, 1]),
        case("X = B+1 halves everything", [B - 2, 1, 1, 1]),
        case("X = B+1, two halves and a minimum", [B // 2, B // 2, 1]),
        case("a dominant member and minimum bonds", [10**8] + [1] * 63),
        case("raw weights 2^40", [2**40 + i for i in range(5)]),
        case("sixty-four equal members at the cap", [B // 64] * 64),
        case("sixty-four equal members just over the cap", [B // 64 + 1] * 64),
        case("a hundred members over the cap", [10**6] * 100),
        case("a single member", [5]),
        case("a single member over the cap", [B + 7]),
        case("near the uint64 limit", [U64 // 4] * 4),
        case("a sum above uint64", [U64, 1]),
        case("a zero weight", [3, 0, 2]),
        case("no members", []),
        case("n = b-1 members, all ones, a small cap", [1] * 9, 10),
        case("n = b-1 members over a small cap", [3] * 9, 10),
        case("n = b members is refused", [1] * 10, 10),
        case("a different cap", [100, 200, 300, 400], 600),
    ]
    for i in range(24):
        n = rnd.choice([2, 3, 5, 8, 16, 32, 64, 100])
        mag = rnd.choice([10, 1000, 10**6, 10**9, 2**40])
        cases.append(case(f"random {i} (n={n}, magnitude {mag})", [rnd.randint(1, mag) for _ in range(n)]))
    return {"format": "UNICITY_P85_QUANT/v1", "b": B, "cases": cases}


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=1))
