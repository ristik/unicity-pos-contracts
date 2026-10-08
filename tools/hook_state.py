#!/usr/bin/env python3
"""Folds the raw forge dumps of test/p85/HookState.t.sol into test/p85/fixtures/hook-<scenario>.json.

Usage (from the repository root):
    P85_WRITE_HOOK_STATE=test/p85/fixtures/hook-raw forge test --match-contract HookStateTest
    python3 tools/hook_state.py test/p85/fixtures/hook-raw test/p85/fixtures

Each fixture holds the three P85 modules before and after custody applied the scenario's records (code, balance, nonce, storage), the
records as the registry would hold them, the chain id the state was produced under and the keccak256 of every runtime.
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


def norm(addr):
    return addr.lower()


def word(x):
    return "0x" + int(x, 16).to_bytes(32, "big").hex()


def account(a, with_code):
    out = {"balance": a.get("balance", "0x0"), "nonce": a.get("nonce", 0)}
    if with_code:
        out["code"] = a["code"]
        out["codeHash"] = "0x" + keccak256(bytes.fromhex(a["code"][2:])).hex()
    out["storage"] = {word(k): word(v) for k, v in sorted(a.get("storage", {}).items(), key=lambda kv: int(kv[0], 16)) if int(v, 16) != 0}
    return out


def main(raw, dest):
    raw, dest = pathlib.Path(raw), pathlib.Path(dest)
    for meta_path in sorted(raw.glob("*.meta.json")):
        name = meta_path.name[: -len(".meta.json")]
        meta = json.loads(meta_path.read_text())
        pre = {norm(k): v for k, v in json.loads((raw / f"{name}.pre.json").read_text()).items()}
        post = {norm(k): v for k, v in json.loads((raw / f"{name}.post.json").read_text()).items()}
        modules = {m: norm(meta[m]) for m in ("custody", "election", "evidence")}
        records = [meta["records"][f"r{i}"] for i in range(meta["recordCount"])]
        fixture = {
            "scenario": name,
            "chainId": meta["chainId"],
            "registry": meta["registry"],
            "modules": {m: a for m, a in modules.items()},
            "pre": {a: account(pre[a], True) for a in modules.values()},
            "post": {a: account(post[a], False) for a in modules.values()},
            "records": [
                {k: (v if isinstance(v, str) or k in ("index", "kind", "progress", "ucTime") else v) for k, v in r.items()} for r in records
            ],
        }
        (dest / f"hook-{name}.json").write_text(json.dumps(fixture, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:3])
