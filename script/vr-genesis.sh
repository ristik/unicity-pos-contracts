#!/usr/bin/env bash
# Builds the VR generation's contracts genesis (VT-14, bft-core#1158): ValidatorRegistry 0xff..03 with its facets 0xff..04-06, PoaElection
# 0xff..07, PoaComposerEngine 0xff..08 (deployed first, checked to be the compiled engine and no proxy) and FoundationMultisig 0xff..09,
# constructed from the plan `ubft vr-genesis plan` writes, and folds the state into:
#   <out>/alloc.json       genesis alloc entries {address: {balance, code, storage, nonce}} of exactly those seven accounts
#   <out>/deployment.json  addresses, code hashes, the network word, the genesis committee digest
#
# Usage: script/vr-genesis.sh <vr-genesis-input.json> <out-dir>
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$#" -eq 2 ] || { echo "usage: $0 <vr-genesis-input.json> <out-dir>" >&2; exit 2; }
out=$(mkdir -p "$2" && cd "$2" && pwd)
mkdir -p script/genesis-out
work=$(mktemp -d script/genesis-out/vr.XXXXXX)
trap 'rm -rf "$work"' EXIT
VR_GENESIS_JSON=$(cat "$1") VR_OUT="$work" forge script script/VRGenesis.s.sol:VRGenesis -q >/dev/null
python3 - "$work" "$out" <<'PY'
import json, sys
work, out = sys.argv[1], sys.argv[2]
state = json.load(open(f"{work}/state.json"))
dep = json.load(open(f"{work}/deployment.json"))
keep = {dep[k].lower() for k in ("registry", "governanceFacet", "repairFacet", "recordsFacet", "module", "composer", "governor")}
if len(keep) != 7:
    sys.exit("the deployment names fewer than seven distinct accounts")
alloc = {}
for addr, acct in state.items():
    if addr.lower() not in keep:
        continue
    entry = {"balance": acct.get("balance", "0x0"), "code": acct.get("code", "0x"), "nonce": acct.get("nonce", "0x0")}
    # a slot only read (the composer's EIP-1967 probe) is dumped with value zero: a zero slot is no storage
    storage = {k: v for k, v in (acct.get("storage") or {}).items() if int(v, 16) != 0}
    if storage:
        entry["storage"] = storage
    alloc[addr.lower()] = entry
missing = keep - set(alloc)
if missing:
    sys.exit(f"accounts missing from the state dump: {sorted(missing)}")
if alloc[dep["composer"].lower()].get("storage"):
    sys.exit("the composer engine has storage: it is not the stateless engine")
json.dump(alloc, open(f"{out}/alloc.json", "w"), indent=2, sort_keys=True)
json.dump(dep, open(f"{out}/deployment.json", "w"), indent=2, sort_keys=True)
print(f"wrote {out}/alloc.json ({len(alloc)} accounts) and {out}/deployment.json")
PY
