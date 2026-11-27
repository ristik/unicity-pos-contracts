#!/usr/bin/env python3
"""Compare the pinned UCT artifact creation code and runtime templates."""

import json
from pathlib import Path
import subprocess
import sys

NATIVE = ["FlatReceipts", "FlatLineage", "NativeBridgeVerifier11", "NativeBridgeRecovery11",
          "NativeBridgeVault11", "NativeBridgeVault11Ordinary"]


def hashes(checkout, contract):
    source = "NativeBridgeVault11" if contract.endswith("Ordinary") else contract
    path = checkout / "out" / f"{source}.sol" / f"{contract}.json"
    artifact = json.loads(path.read_text())
    return {
        field: subprocess.check_output(
            ["cast", "keccak", artifact[field]["object"]], text=True
        ).strip()
        for field in ("bytecode", "deployedBytecode")
    }


def main():
    base, candidate = map(Path, sys.argv[1:])
    for checkout in (base, candidate):
        subprocess.run(
            ["forge", "build", "--force", "src/nb2/NativeBridgeVault11.sol"],
            cwd=checkout,
            check=True,
            stdout=sys.stderr,
        )
    result = {}
    for name in NATIVE:
        result[name] = hashes(candidate, name)
        if hashes(base, name) != result[name]:
            raise SystemExit(f"UCT artifact drift in {name}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
