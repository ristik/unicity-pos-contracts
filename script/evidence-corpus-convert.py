#!/usr/bin/env python3
"""Writes the forge-shaped evidence digest corpus from bft-core's verbatim one.

    evidence-corpus-convert.py <evidence-digest-corpus-go-v1.json> <evidence-digest-corpus-v1.json>

The Go file (bft-core s1ref/testdata/evidence-digest-corpus-v1.json, byte-identical, checked by bft-core xrepo/check.py) has decimal-string numbers, bare hex and
null for an absent commit hash or anchor. foundry's vm.parseJson reads a digit-only string as a number and cannot read null into a struct, so the file the tests read
has: JSON numbers, 0x-prefixed hex, `committing` (the vote has a commit hash) and `hasAnchor` flags, and zero values for the absent commit hash, seal and anchor. Nothing else
changes; CI regenerates the file and fails if it differs from the committed one.
"""
import json
import sys

NUMBERS = {"network", "epoch", "round", "parent", "timestamp", "commitRound", "commitEpoch", "highQcRound", "slot"}
HEX = {"genesis", "key", "exec", "commitHash", "voteInfo", "voteInfoHash", "preimage", "digest", "sig64", "sig65", "sigHighS", "genesisId",
       "previousHash", "sigBytes", "signature"}
ZERO32 = "0x" + "00" * 32


def conv(o, name=None):
    if isinstance(o, dict):
        return {k: conv(v, k) for k, v in o.items()}
    if isinstance(o, list):
        return [conv(v, name) for v in o]
    if isinstance(o, str) and name in NUMBERS:
        return int(o)
    if isinstance(o, str) and name in HEX:
        return "0x" + o
    return o


def main():
    src = json.load(open(sys.argv[1]))
    out = {k: v for k, v in src.items() if k != "contexts"}
    out = conv(out)
    out["notes"] = [n for n in src["notes"] if not n.startswith("Numbers are decimal strings")] + [
        "Forge-shaped conversion of bft-core's verbatim file (evidence-digest-corpus-go-v1.json) by script/evidence-corpus-convert.py: numbers are JSON numbers, hex is 0x-prefixed, "
        "`committing` and `hasAnchor` flags, zero values for an absent commit hash, seal and anchor. Every figure in bft-core's file is checked against the production encoder and verifier in s1ref's tests."]
    out["keys"] = {k: "0x" + v for k, v in src["keys"].items()}
    out["contexts"] = []
    for c in src["contexts"]:
        c = dict(c)
        c2 = {k: v for k, v in c.items() if k not in ("votes", "timeouts", "pairs")}
        c2 = conv(c2)
        votes = []
        for v in c["votes"]:
            committing = v["commitHash"] is not None
            v = dict(v)
            if not committing:
                v["commitHash"] = "00" * 32
            if "seal" not in v:
                v["seal"] = {"network": "0", "commitRound": "0", "commitEpoch": "0", "timestamp": "0", "previousHash": "00" * 32, "commitHash": "00" * 32,
                             "sigBytes": "", "signature": ""}
            w = conv(v)
            # `committing` follows `timestamp`
            ordered = {}
            for k, x in w.items():
                ordered[k] = x
                if k == "timestamp":
                    ordered["committing"] = committing
            votes.append(ordered)
        timeouts = []
        for t in c["timeouts"]:
            has = t["anchor"] is not None
            t = dict(t)
            if not has:
                t["anchor"] = {"genesisId": "00" * 32, "epoch": "0", "slot": "0"}
            w = conv(t)
            ordered = {}
            for k, x in w.items():
                if k == "anchor":
                    ordered["hasAnchor"] = has
                ordered[k] = x
            timeouts.append(ordered)
        c2["votes"], c2["timeouts"], c2["pairs"] = votes, timeouts, c["pairs"]
        out["contexts"].append(c2)
    with open(sys.argv[2], "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")


main()
