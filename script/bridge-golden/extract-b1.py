#!/usr/bin/env python3
"""Extract the B1 vectors the bridge wrappers and the Solidity scan must reproduce.

Usage: extract-b1.py <bft-core checkout at the protocol-4 oracle revision> <out.json>
Source: b1ref/testdata/b1-vectors-anyage.json (corpus b1-vectors/any-age-v1, bft-core #606/#610), independently constructed by b1gen.
Kept: every CERT_BATCH_V2 vector with a stated grouping (valid batches and false/registry ones: C,K,E,S,Q,A,P and the charge), every
CERT_BATCH_V2 vector that must halt as malformed or over a limit (the Solidity scan must refuse what is structurally refusable), and the
RSMT_MEMBER_V1 vectors the wrappers reproduce. The registry pre-state is dropped: the Solidity side never reads it.
"""
import json
import sys

rsmt = ["rsmt.single-leaf.ok", "rsmt.small.ok", "rsmt.small.leaf0.ok", "rsmt.small.leaf8.ok"]
d = json.load(open(sys.argv[1] + "/b1ref/testdata/b1-vectors-anyage.json"))
out = {"corpus": d["format"], "pins": d["pins"], "vectors": {}}
for v in d["vectors"]:
    e = v["expected"]
    if v["op"] == "CERT_BATCH_V2" and ("grouping" in e or e["status"] == "error"):
        row = {"op": v["op"], "request": "0x" + v["request"], "status": e["status"], "family": v["family"]}
        if "grouping" in e:
            row["grouping"] = e["grouping"]
            row["gas"] = e["gas"]
            row["output"] = "0x" + e["output"] if "output" in e else ""
        else:
            row["sentinel"] = e.get("sentinel", "")
        out["vectors"][v["id"]] = row
    elif v["id"] in rsmt:
        out["vectors"][v["id"]] = {"op": v["op"], "request": "0x" + v["request"], "output": "0x" + e["output"]}
assert all(r in out["vectors"] for r in rsmt), "rsmt vectors missing"
json.dump(out, open(sys.argv[2], "w"), indent=1, sort_keys=True)
open(sys.argv[2], "a").write("\n")
