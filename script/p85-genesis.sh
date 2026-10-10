#!/usr/bin/env bash
# Builds the proof-of-stake genesis state of the EVM shard (the P85 modules, initialized by the factory with the genesis identities bonded)
# and folds it into the files the lane consumes:
#   <out>/alloc.json       genesis alloc entries {address: {balance, code, storage, nonce}} of the P85 accounts
#   <out>/deployment.json  addresses, code hashes, manifest hash, network word, caps
#
# Usage: script/p85-genesis.sh <genesis.json from `ubft pos-relayer genesis --out-contracts`> <out-dir>
# Environment: P85_NETWORK_WORD P85_CHAIN_ID P85_ROOTS (the registry address) P85_TREASURY, and the caps the election price is measured at:
#   P85_V_MAX P85_L_MAX P85_N_MAX (devnet/testnet 16 2 8), P85_CADENCE_ROUNDS P85_CADENCE_SECONDS.
# Optional: P85_DIST_NUM / P85_DIST_DEN, the election's weight-distance bound (testnet profile default 1/2; production uses 1/4). The roots' EVM
# configuration must commit the same bound as `continuity_max_distance`.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$#" -eq 2 ] || { echo "usage: $0 <genesis.json> <out-dir>" >&2; exit 2; }
for v in P85_NETWORK_WORD P85_CHAIN_ID P85_ROOTS P85_TREASURY P85_V_MAX P85_L_MAX P85_N_MAX P85_CADENCE_ROUNDS P85_CADENCE_SECONDS; do
	[ -n "${!v:-}" ] || { echo "set $v" >&2; exit 2; }
done
out=$(mkdir -p "$2" && cd "$2" && pwd)
mkdir -p script/genesis-out
work=$(mktemp -d script/genesis-out/run.XXXXXX)
trap 'rm -rf "$work"' EXIT
P85_GENESIS_JSON=$(cat "$1") P85_OUT="$work" forge script script/P85Genesis.s.sol:P85Genesis -q >/dev/null
python3 - "$work" "$out" <<'PY'
import json, sys
work, out = sys.argv[1], sys.argv[2]
state = json.load(open(f"{work}/state.json"))
dep = json.load(open(f"{work}/deployment.json"))
keep = {dep[k].lower() for k in ("factory", "custody", "election", "evidence", "selection", "reader", "policy")}
alloc = {}
for addr, acct in state.items():
    if addr.lower() not in keep:
        continue
    entry = {"balance": acct.get("balance", "0x0"), "code": acct.get("code", "0x"), "nonce": acct.get("nonce", "0x0")}
    if acct.get("storage"):
        entry["storage"] = acct["storage"]
    alloc[addr.lower()] = entry
missing = keep - set(alloc)
if missing:
    sys.exit(f"accounts missing from the state dump: {sorted(missing)}")
json.dump(alloc, open(f"{out}/alloc.json", "w"), indent=2, sort_keys=True)
json.dump(dep, open(f"{out}/deployment.json", "w"), indent=2, sort_keys=True)
print(f"wrote {out}/alloc.json ({len(alloc)} accounts) and {out}/deployment.json")
PY
