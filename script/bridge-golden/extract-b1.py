#!/usr/bin/env python3
"""Extract the B1 A' request vectors the bridge wrappers must reproduce byte for byte.

Usage: extract-b1.py <bft-core checkout at 9136c66146e56e1c5dc02c51e810a8df7f6b4fe4> <out.json>
Source: b1ref/testdata/b1-vectors-aprime.json (bft-core #416, independently constructed by b1gen).
"""
import json
import sys

want = ["cert.single.ok", "rsmt.single-leaf.ok", "rsmt.small.ok", "rsmt.small.leaf0.ok", "rsmt.small.leaf8.ok"]
d = json.load(open(sys.argv[1] + "/b1ref/testdata/b1-vectors-aprime.json"))
out = {}
for v in d["vectors"]:
    if v["id"] in want:
        out[v["id"]] = {"op": v["op"], "request": "0x" + v["request"], "output": "0x" + v["expected"]["output"]}
assert sorted(out) == sorted(want), sorted(out)
json.dump(out, open(sys.argv[2], "w"), indent=2, sort_keys=True)
open(sys.argv[2], "a").write("\n")
