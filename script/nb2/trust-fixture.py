#!/usr/bin/env python3
"""Derive the CERT_BATCH_V2 test double's epoch table from the pinned NB2 vector file.

Each deployment's trust-base bundle (tag 39015) lists its RootTrustBaseV2 entries (tag 39000). On chain the 0x0100 batch reads
the same history from the seal registry; the forge double (test/nb2/verifier/Nb2Doubles.sol) is loaded with this table.
Usage: python3 -I script/nb2/trust-fixture.py test/nb2/vectors/nb2-vectors.json > test/nb2/verifier/trust.json
"""
import json
import sys


def item(b, p):
    ib = b[p]
    mj, ai = ib >> 5, ib & 31
    p += 1
    if ai < 24:
        a = ai
    else:
        n = 1 << (ai - 24)
        a = int.from_bytes(b[p:p + n], 'big')
        p += n
    if mj == 0:
        return a, p
    if mj in (2, 3):
        return b[p:p + a], p + a
    if mj == 4:
        out = []
        for _ in range(a):
            x, p = item(b, p)
            out.append(x)
        return out, p
    if mj == 5:
        out = {}
        for _ in range(a):
            k, p = item(b, p)
            v, p = item(b, p)
            out[bytes(k)] = v
        return out, p
    if mj == 6:
        x, p = item(b, p)
        return (a, x), p
    return None, p


def table(bundle_hex):
    raw = bytes.fromhex(bundle_hex[2:])
    (tag, body), end = item(raw, 0)
    assert tag == 39015 and end == len(raw)
    entries = [e for e in body if isinstance(e, list)][0]
    rows = []
    for t, e in entries:
        assert t == 39000
        rows.append(e)
    out = {"network": rows[0][1], "epochs": [], "starts": [], "ends": [], "totals": [],
           "memberEpochs": [], "memberIds": [], "memberKeys": [], "memberWeights": []}
    for i, e in enumerate(rows):
        epoch, start, nodes = e[2], e[3], e[4]
        out["epochs"].append(epoch)
        out["starts"].append(start)
        out["ends"].append(rows[i + 1][3] if i + 1 < len(rows) else 0)
        out["totals"].append(sum(n[2] for n in nodes))
        for nid, key, weight in nodes:
            out["memberEpochs"].append(epoch)
            out["memberIds"].append("0x" + bytes(nid).hex())
            out["memberKeys"].append("0x" + bytes(key).hex())
            out["memberWeights"].append(weight)
    return out


def main():
    d = json.load(open(sys.argv[1]))
    print(json.dumps({name: table(dep["trustBundle"]) for name, dep in sorted(d["deployments"].items())}, indent=1))


if __name__ == "__main__":
    main()
