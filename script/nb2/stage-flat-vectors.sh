#!/usr/bin/env bash
# Stage only the signed input corpus. No reference producer runs during replay.
set -euo pipefail
bft_repo=${1:?usage: stage-flat-vectors.sh /path/to/bft-core}
contracts=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
commit=8c1b6ca9ff18648f98f3df588e70d70285e6adc6
prefix=testvectors/nb2-continuation-v1.1
out="$contracts/test/nb2/flat/generated"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git -C "$bft_repo" archive "$commit" "$prefix" | tar -xf - -C "$tmp"
vectors="$tmp/$prefix"
(
    cd "$vectors"
    printf '%s  MANIFEST\n' 3be02f4163a1a9e06d5b83c0a50ab8468c6a060c1352d3a969a96b477be28034 |
        shasum -a 256 -c -
    shasum -a 256 -c MANIFEST >/dev/null
    cd transcripts
    printf '%s  MANIFEST\n' 41856353c08fa85b87ce59e470ac152213ac7de3031fb8a721989ae08755a651 |
        shasum -a 256 -c -
    shasum -a 256 -c MANIFEST >/dev/null
)
python3 - "$vectors" "$contracts/script/nb2/trust-fixture.py" <<'PY'
import gzip
import json
from pathlib import Path
import runpy
import shutil
import sys

vectors = Path(sys.argv[1])
transcripts = vectors / "transcripts"
trust_table = runpy.run_path(sys.argv[2])["table"]
for scenario in sorted(transcripts.glob("*/trace.bin.gz")):
    with gzip.open(scenario, "rb") as source, scenario.with_suffix("").open("wb") as target:
        shutil.copyfileobj(source, target)
    bundle = scenario.with_name("utb.cbor").read_bytes()
    trust = trust_table("0x" + bundle.hex())
    scenario.with_name("trust.json").write_text(json.dumps(trust))
for outcome in sorted((transcripts / "cold").glob("advance-*/outcome.json")):
    expected = json.loads(outcome.read_text())
    outcome.with_name("event.bin").write_bytes(bytes.fromhex("".join(expected["Topics"]) + expected["Data"]))
PY
mkdir -p "$out"
cp -R "$vectors/." "$out/"
