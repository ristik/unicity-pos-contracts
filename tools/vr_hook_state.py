#!/usr/bin/env python3
"""Folds the raw forge dumps of test/vr/VRHookState.t.sol into test/vr/fixtures/vr-hook.json, the fixture ureth's VR hook test runs.

Usage (from the repository root):
    VR_WRITE_HOOK_STATE=test/vr/fixtures/vr-hook-raw forge test --match-contract VRHookStateTest
    python3 tools/vr_hook_state.py test/vr/fixtures/vr-hook-raw test/vr/fixtures/vr-hook.json

The fixture holds, once, the runtime code and its keccak256 of every account the scenarios use (the VR core and its three facets,
the PoA module and composer, and the test modules), each identical across scenarios; then per scenario the nonzero storage of those
accounts before the block, the slots the block changes (zero for a cleared slot), the block's records, clock and pinned H, and what
forge observed after the hooks (outcome, health, cursor, open output, last acknowledged, active module).
"""
import json
import pathlib
import sys

try:
    from Crypto.Hash import keccak  # type: ignore

    def keccak256(b):
        return keccak.new(digest_bits=256, data=b).digest()
except ImportError:  # pragma: no cover
    import subprocess

    def keccak256(b):
        out = subprocess.run(["cast", "keccak", "0x" + b.hex()], capture_output=True, text=True, check=True).stdout.strip()
        return bytes.fromhex(out[2:])


ACCOUNTS = {
    "vr": "0xff00000000000000000000000000000000000003",
    "governanceFacet": "0xff00000000000000000000000000000000000004",
    "repairFacet": "0xff00000000000000000000000000000000000005",
    "recordsFacet": "0xff00000000000000000000000000000000000006",
    "poa": "0xff00000000000000000000000000000000000007",
    "composer": "0xff00000000000000000000000000000000000008",
    "poaNext": "0x00000000000000000000000000000000000c0de7",
    "mock": "0x00000000000000000000000000000000000c0de1",
    "mockNext": "0x00000000000000000000000000000000000c0de2",
    "holder": "0x00000000000000000000000000000000000c0de3",
    "holderNext": "0x00000000000000000000000000000000000c0de4",
    "governorNext": "0x00000000000000000000000000000000000c0de5",
}


def word(x):
    return "0x" + int(x, 16).to_bytes(32, "big").hex()


def storage(a):
    return {word(k): word(v) for k, v in a.get("storage", {}).items() if int(v, 16) != 0}


def main(raw, dest):
    raw, dest = pathlib.Path(raw), pathlib.Path(dest)
    code = {}
    scenarios = {}
    for meta_path in sorted(raw.glob("*.meta.json")):
        name = meta_path.name[: -len(".meta.json")]
        meta = json.loads(meta_path.read_text())
        pre = {k.lower(): v for k, v in json.loads((raw / f"{name}.pre.json").read_text()).items()}
        post = {k.lower(): v for k, v in json.loads((raw / f"{name}.post.json").read_text()).items()}
        pre_s, diff = {}, {}
        for role, addr in ACCOUNTS.items():
            if addr not in pre:
                assert addr not in post, (name, role)
                continue
            c = pre[addr].get("code", "0x")
            if c in ("0x", ""):
                continue
            assert post[addr]["code"] == c, (name, role, "code changed in the block")
            assert int(pre[addr].get("balance", "0x0"), 16) == 0 and int(post[addr].get("balance", "0x0"), 16) == 0, (name, role)
            if role in code:
                assert code[role]["code"] == c, (name, role, "runtime differs between scenarios")
            else:
                code[role] = {"address": addr, "code": c, "codeHash": "0x" + keccak256(bytes.fromhex(c[2:])).hex()}
            before, after = storage(pre[addr]), storage(post[addr])
            if before:
                pre_s[addr] = dict(sorted(before.items()))
            changed = {k: after.get(k, word("0x0")) for k in set(before) | set(after) if before.get(k) != after.get(k)}
            if changed:
                diff[addr] = dict(sorted(changed.items()))
        n = meta["recordCount"]
        recs = meta["records"] if isinstance(meta["records"], dict) else json.loads(meta["records"])
        records = [recs[f"r{i}"] for i in range(n)] if n else []
        scenarios[name] = {
            "h": meta["h"],
            "progress": meta["progress"],
            "ucTime": meta["ucTime"],
            "blockNumber": meta["blockNumber"],
            "records": records,
            "pre": pre_s,
            "changed": diff,
            "expect": {
                "applied": meta["applied"],
                "outcome": meta["outcome"],
                "health": meta["health"],
                "cursor": meta["cursor"],
                "openOutput": meta["openOutput"],
                "lastAcked": meta["lastAcked"],
                "activeModule": meta["activeModule"].lower(),
            },
        }
        chain = meta["chainId"]
        origin = meta["origin"]
    fixture = {
        "format": "unicity-vr-hook-state-v1",
        "generator": "unicity-pos-contracts test/vr/VRHookState.t.sol + tools/vr_hook_state.py",
        "chainId": chain,
        "origin": origin,
        "accounts": dict(sorted(code.items())),
        "scenarios": scenarios,
    }
    dest.write_text(json.dumps(fixture, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:3])
