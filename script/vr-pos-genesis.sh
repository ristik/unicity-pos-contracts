#!/usr/bin/env bash
# Builds the PoS-prototype VR generation's contracts genesis (VT-04, bft-core#1144): ValidatorRegistry 0xff..03 with its facets 0xff..04-06,
# the PosElectionAdapter 0xff..07, the FoundationMultisig 0xff..09 and the P85 stack (custody holder 0, election, evidence, selection engine,
# reader, governed policy, reward pool, factory) constructed from the plan `ubft vr-genesis plan` writes plus its `pos` object, and folds the
# state into:
#   <out>/alloc.json       genesis alloc entries {address: {balance, code, storage, nonce}} of exactly those accounts
#   <out>/deployment.json  addresses, code hashes, the network word, the genesis committee digest, the P85 stack's addresses
#
# Usage: script/vr-pos-genesis.sh <vr-genesis-input.json with a pos object> <out-dir>
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$#" -eq 2 ] || { echo "usage: $0 <vr-genesis-input.json> <out-dir>" >&2; exit 2; }
out=$(mkdir -p "$2" && cd "$2" && pwd)
mkdir -p script/genesis-out
work=$(mktemp -d script/genesis-out/vrpos.XXXXXX)
trap 'rm -rf "$work"' EXIT
VR_GENESIS_JSON=$(cat "$1") VR_OUT="$work" forge script script/VRPosGenesis.s.sol:VRPosGenesis -q >/dev/null
python3 - "$work" "$out" <<'PY'
import json, sys
work, out = sys.argv[1], sys.argv[2]
state = json.load(open(f"{work}/state.json"))
dep = json.load(open(f"{work}/deployment.json"))
core = ("registry", "governanceFacet", "repairFacet", "recordsFacet", "module", "governor")
stack = ("factory", "custody", "genesisImpl", "election", "electionPublication", "evidence", "selection", "reader", "policy", "rewardPool")
keep = {dep[k].lower() for k in core + stack}
if len(keep) != len(core) + len(stack):
    sys.exit("the deployment names fewer distinct accounts than expected")
alloc = {}
for addr, acct in state.items():
    if addr.lower() not in keep:
        continue
    entry = {"balance": acct.get("balance", "0x0"), "code": acct.get("code", "0x"), "nonce": acct.get("nonce", "0x0")}
    storage = {k: v for k, v in (acct.get("storage") or {}).items() if int(v, 16) != 0}
    if storage:
        entry["storage"] = storage
    alloc[addr.lower()] = entry
missing = keep - set(alloc)
if missing:
    sys.exit(f"accounts missing from the state dump: {sorted(missing)}")
json.dump(alloc, open(f"{out}/alloc.json", "w"), indent=2, sort_keys=True)
json.dump(dep, open(f"{out}/deployment.json", "w"), indent=2, sort_keys=True)
print(f"wrote {out}/alloc.json ({len(alloc)} accounts) and {out}/deployment.json")
PY
