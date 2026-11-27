#!/usr/bin/env python3
"""Convert bft-core's verbatim post-term seal corpus (s1ref/s1gen BuildPostTermCorpus, format p85-post-term-seal/1) into the
forge-shaped file PostTermCorpus.t.sol reads: 0x-prefixed hex, JSON numbers that fit a uint64, the charged member's key resolved, and
the contracts' PostTermSeal: the native seal fields with PreviousHash as the opaque signed word (no VoteInfo opening). CI regenerates it
and fails when the committed copy differs.

Usage: post-term-corpus-convert.py <post-term-corpus-go-v1.json> <post-term-corpus-v1.json>
"""
import json
import sys

# The statement is the seal's signed fields (astra option (a)): commitRound, commitEpoch, commitTimestamp, previousHash, hash. The
# corpus' VoteInfo fields are informational and are not part of the contracts' PostTermSeal.
STATEMENT = {"commitRound", "commitEpoch", "commitTimestamp", "previousHash", "hash"}
VOTE_INFO = {"votingEpoch", "votingRound", "parent", "exec", "voteTimestamp"}


def hx(s):
    return "0x" + s


def u(s):
    v = int(s)
    assert 0 <= v < 2**64, s
    return v


def convert(go):
    out = {"format": "p85-post-term-seal/forge/1", "source": go["format"], "scenarios": []}
    for sc in go["scenarios"]:
        pre, suc, cl = sc["predecessor"], sc["successor"], sc["closure"]
        keys = [m["key"] for m in pre["members"]]
        o = {
            "id": sc["id"],
            "network": u(sc["network"]),
            "genesis": hx(sc["genesis"]),
            "epoch": u(pre["epoch"]),
            "start": u(pre["start"]),
            "activationRound": u(sc["activationRound"]),
            "keys": [hx(k) for k in keys],
            "weights": [u(m["weight"]) for m in pre["members"]],
            "successorKeys": [hx(m["key"]) for m in suc["members"]],
            "successorWeights": [u(m["weight"]) for m in suc["members"]],
            "hRound": u(cl["hRound"]),
            "hRecordId": hx(cl["hRecordId"]),
            "terminalRoot": hx(cl["terminalRoot"]),
            "submissions": [],
        }
        assert u(pre["end"]) == u(suc["start"]) == o["activationRound"]
        assert u(cl["closedEpoch"]) == o["epoch"] and u(suc["epoch"]) == o["epoch"] + 1
        for sub in sc["submissions"]:
            st = sub["statement"]
            assert STATEMENT <= set(st) and set(st) <= STATEMENT | VOTE_INFO, sub["id"]
            # where the generator rebuilt the seal bytes, it did so from exactly this previousHash
            assert sub["previousHash"] in ("", st["previousHash"]), sub["id"]
            assert (sub["digest"] == "") == (sub["previousHash"] == ""), sub["id"]
            o["submissions"].append({
                "id": sub["id"],
                "epoch": u(st["commitEpoch"]),
                "previousHash": hx(st["previousHash"]),
                "commitRound": u(st["commitRound"]),
                "commitTimestamp": u(st["commitTimestamp"]),
                "hash": hx(st["hash"]),
                "indices": sub["indices"],
                "signatures": [hx(x["signature"]) for x in sub["signatures"]],
                "signatureValid": [bool(x["valid"]) for x in sub["signatures"]],
                "chargedKey": hx(keys[sub["charged"]]),
                "digest": hx(sub["digest"] or "00" * 32),
                "hasDigest": sub["digest"] != "",
                "reason": sub["reason"],
                "accept": bool(sub["accept"]),
                "offence": sub["offence"],
            })
        out["scenarios"].append(o)
    return out


def main():
    go = json.load(open(sys.argv[1]))
    with open(sys.argv[2], "w") as f:
        json.dump(convert(go), f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
