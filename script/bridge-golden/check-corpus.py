#!/usr/bin/env python3
"""Check test/bridge/golden.json against the sealed shared corpus pinned in corpus-pin.json.

usage: check-corpus.py <checkout of the corpus repository>

The checks, each fatal:
  1. the checkout is the pinned commit (when it is a git checkout);
  2. every corpus file matches SHA256SUMS, and SHA256(SHA256SUMS) is MANIFEST.sha256 and the pinned digest;
  3. the SDK trust document is the pinned one, and the golden mint and return histories embed its digest;
  4. the golden file is the pinned bytes (so it cannot be edited by hand or regenerated unpinned);
  5. every golden value the pin lists as shared occurs in the corpus, so the doubles cannot drift from it.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fail(msg):
    sys.exit("check-corpus: " + msg)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    pin = json.loads((HERE / "corpus-pin.json").read_text())
    checkout = pathlib.Path(sys.argv[1])
    root = checkout / pin["corpus"]["directory"]
    if (checkout / ".git").exists():
        head = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        if head != pin["corpus"]["commit"]:
            fail(f"corpus checkout is {head}, pinned {pin['corpus']['commit']}")

    sums = (root / "SHA256SUMS").read_bytes()
    for line in sums.decode().splitlines():
        digest, name = line.split("  ", 1)
        if sha((root / name).read_bytes()) != digest:
            fail(f"corpus file {name} does not match SHA256SUMS")
    manifest = sha(sums)
    if manifest != (root / "MANIFEST.sha256").read_text().strip() or manifest != pin["corpus"]["manifestSha256"]:
        fail(f"corpus digest {manifest} is not the pinned {pin['corpus']['manifestSha256']}")

    trust = sha((root / "config" / "sdk-root-trust-base.json").read_bytes())
    if trust != pin["corpus"]["trustDocumentSha256"]:
        fail(f"corpus trust document {trust} is not the pinned one")

    raw = (REPO / pin["golden"]["file"]).read_bytes()
    if sha(raw) != pin["golden"]["sha256"]:
        fail(f"{pin['golden']['file']} is not the pinned bytes; regenerate at the oracle and update the pin")
    golden = json.loads(raw)
    for op in ("mint", "return"):
        if trust not in golden[op]["history"].lower():
            fail(f"golden {op} history does not embed the corpus trust document digest")

    corpus = "".join(p.read_text().lower() for p in sorted(root.rglob("*.json")))
    for path in pin["golden"]["sharedPaths"]:
        node = golden
        for part in path.strip("/").split("/"):
            node = node[int(part)] if isinstance(node, list) else node[part]
        if node[2:].lower() not in corpus:
            fail(f"golden {path} does not occur in the corpus")
    print(f"ok: golden agrees with corpus {manifest[:8]} at {pin['corpus']['commit'][:8]} "
          f"({len(pin['golden']['sharedPaths'])} shared values)")


main()
