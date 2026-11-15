#!/usr/bin/env python3
"""Native bridge v2 vectors for the vault tests (NB2-04, bft-core#1100).

test/nb2/vectors/nb2-vectors.json is native-bridge-plugins protocol/vectors/nb2/nb2-vectors.json verbatim, pinned by its
.sha256 (the NB2-03 Go reference's output, bft-core#1099). This script checks the pin and writes the forge-shaped file
test/nb2/vectors/nb2-vault-forge.json: the deployments, the constructor's config vectors, the gap proofs, the chain folds
and the vault sequences, with every optional key present and every expected error pre-encoded as its exact revert data
(the vector's `revert`, cross-checked against its rule's selector and ABI arguments), and the state after every step. Nothing is recomputed; values are copied or re-encoded.

    python3 script/nb2-vectors.py            # rewrite the forge-shaped file
    python3 script/nb2-vectors.py --check    # fail if it is not current
"""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIR = ROOT / "test" / "nb2" / "vectors"
SRC = DIR / "nb2-vectors.json"
PIN = DIR / "nb2-vectors.json.sha256"
OUT = DIR / "nb2-vault-forge.json"

RECIPIENT = {"accepts": 0, "reverts": 1, "reenters-redeem": 2, "reenters-deposit": 3}


def word(n):
    return n.to_bytes(32, "big")


def num(s):
    s = str(s)
    return int(s, 16) if s.startswith("0x") else int(s)


def hexb(b):
    return "0x" + b.hex()


def encode_error(rules, name, args):
    """The revert data of rule `name` with its arguments, from the rules list's signature and selector."""
    rule = rules[name]
    sig = rule["signature"]
    types = [t for t in sig[sig.index("(") + 1 : -1].split(",") if t]
    if len(args) != len(types):
        raise SystemExit(f"{name}: {len(args)} args for {sig}")
    head, tail = b"", b""
    for t, a in zip(types, args):
        if t == "bytes":
            data = bytes.fromhex(a[2:])
            head += word(32 * len(types) + len(tail))
            tail += word(len(data)) + data + b"\0" * (-len(data) % 32)
        elif t in ("uint256", "uint64", "bytes32"):
            head += word(num(a))
        else:
            raise SystemExit(f"{name}: unsupported argument type {t}")
    return hexb(bytes.fromhex(rule["selector"][2:]) + head + tail)


def revert_data(rules, expect):
    """The exact on-chain revert bytes of an expectation (empty for success): the vector's own `revert`, cross-checked
    against the encoding of its rule name and arguments."""
    name = expect.get("onChainError") or expect.get("error")
    if not name:
        return "0x"
    rev = expect["revert"]
    if rev != encode_error(rules, name, expect.get("args", [])):
        raise SystemExit(f"{name}: revert bytes {rev} disagree with the rule and its arguments")
    return rev


def cbor_items(b, pos):
    """(major, arg, payload start, end) of the strict item at pos; enough of CBOR to walk a valid Γ."""
    ib = b[pos]
    major, ai = ib >> 5, ib & 31
    pos += 1
    if ai < 24:
        arg = ai
    else:
        n = 1 << (ai - 24)
        arg = int.from_bytes(b[pos : pos + n], "big")
        pos += n
    if major == 2:
        return major, arg, pos, pos + arg
    if major == 4:
        end = pos
        for _ in range(arg):
            end = cbor_items(b, end)[3]
        return major, arg, pos, end
    return major, arg, pos, pos


def gamma_fields(g):
    _, n, pos, _ = cbor_items(g, 0)
    out = []
    for _ in range(n):
        major, arg, start, end = cbor_items(g, pos)
        out.append((major, arg, g[start:end]))
        pos = end
    return out


def state(s):
    return {
        "deposits": str(s["deposits"]),
        "segment": str(s["segment"]),
        "population": str(s["population"]),
        "outstanding": str(s["outstanding"]),
        "head": s["head"],
        "previousHead": s["previousHead"],
        "current": s.get("current") or [],
        "previous": s.get("previous") or [],
        "accounting": s["accounting"],
        "tags0": s["tagWords"][0],
        "tags1": s["tagWords"][1],
    }


EMPTY_STATE = {
    "deposits": "0",
    "segment": "0",
    "population": "0",
    "outstanding": "0",
    "head": "0x" + "00" * 32,
    "previousHead": "0x" + "00" * 32,
    "current": [],
    "previous": [],
    "accounting": "0x" + "00" * 32,
    "tags0": [],
    "tags1": [],
}


def build():
    raw = SRC.read_bytes()
    want = PIN.read_text().split()[0]
    got = hashlib.sha256(raw).hexdigest()
    if got != want:
        raise SystemExit(f"{SRC.name}: sha256 {got}, pinned {want}")
    v = json.loads(raw)
    rules = {r["name"]: r for r in v["rules"]}

    deployments = []
    for name, d in sorted(v["deployments"].items()):
        f = gamma_fields(bytes.fromhex(d["gamma"][2:]))
        deployments.append(
            {
                "name": name,
                "production": d["build"] == "production",
                "gamma": d["gamma"],
                "domain": d["domain"],
                "K": str(d["K"]),
                "B": str(d["B"]),
                "genesisHead": d["genesisHead"],
                "vault": d["vault"],
                "chainId": str(d["chainId"]),
                "verifierCodeHash": d["verifierCodeHash"],
                "verifier": hexb(f[14][2]),
                "qmax": str(int.from_bytes(f[18][2], "big")),
            }
        )

    config = []
    for c in v["config"]:
        config.append(
            {
                "id": c["id"],
                "production": v["deployments"][c["deployment"]]["build"] == "production",
                "gamma": c["gamma"],
                "vault": c["address"],
                "chainId": str(c["chainId"]),
                "verifierCodeHash": c["verifierCodeHash"],
                "expectRevert": revert_data(rules, c["constructor"]),
                "domain": c.get("domain") or "0x" + "00" * 32,
            }
        )

    gaps = [
        {
            "id": g["id"],
            "K": str(g["K"]),
            "eta": g["eta"],
            "root": g["root"],
            "proof": g["proof"],
            "expectRevert": revert_data(rules, g["expect"]),
        }
        for g in v["gapProofs"]
    ]

    folds = [
        {
            "id": f["id"],
            "domain": f["domain"],
            "K": str(f["K"]),
            "eta": f["eta"],
            "a": str(f["a"]),
            "history": f["history"],
            "storedHead": f["storedHead"],
            "expectRevert": revert_data(rules, f["expect"]),
        }
        for f in v["chainFolds"]
    ]

    vault = []
    for s in v["vault"]:
        steps = []
        for st in s["steps"]:
            deposit = st["op"] == "deposit"
            steps.append(
                {
                    "op": "0" if deposit else "1",
                    "value": st.get("value", "0"),
                    "firstOwner": st.get("firstOwner", "0x"),
                    "rho": st.get("rho", "0x" + "00" * 32),
                    "claimedEta": st.get("claimedEta", "0x" + "00" * 32),
                    "claimedStart": str(st.get("claimedStart", 0)),
                    "history": st.get("history", "0x"),
                    "verifierReverts": "verifierRevert" in st,
                    "verifierData": st.get("verifierRevert", st.get("verifierReturn", "0x")),
                    "recipient": str(RECIPIENT[st.get("recipient", "accepts")]),
                    "expectRevert": revert_data(rules, st["expect"]),
                    "innerRevert": encode_error(rules, st["innerError"], []) if st.get("innerError") else "0x",
                    "events": [{"topics": e["topics"], "data": e["data"]} for e in st["events"]],
                    "post": state(st["state"]),
                }
            )
        vault.append(
            {
                "id": s["id"],
                "deployment": s["deployment"],
                "harness": "harnessState" in s,
                "harnessState": state(s["harnessState"]) if "harnessState" in s else EMPTY_STATE,
                "steps": steps,
                "finalState": state(s["final"]),
            }
        )

    out = {
        "source": "native-bridge-plugins protocol/vectors/nb2/nb2-vectors.json",
        "sha256": want,
        "deployments": deployments,
        "config": config,
        "gapProofs": gaps,
        "chainFolds": folds,
        "vault": vault,
    }
    return json.dumps(out, indent=1, sort_keys=False) + "\n"


def main():
    text = build()
    if "--check" in sys.argv[1:]:
        if not OUT.exists() or OUT.read_text() != text:
            raise SystemExit(f"{OUT.relative_to(ROOT)} is not current: run python3 script/nb2-vectors.py")
        print(f"{OUT.relative_to(ROOT)} is current")
        return
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
