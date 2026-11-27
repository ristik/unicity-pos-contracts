#!/usr/bin/env bash
set -euo pipefail
rpc=$1
agg=$2
chain=$3
out=$NB2_OUT
"$out/dnb-tool" trust-bundle --trust-base test-nodes/trust-base.json --out "$out/trust.cbor" --out-pin "$out/trust.pin"
cp test-nodes/execution-genesis-hash "$out/execution.pin"
sed -n 's/.*anvilKey *= *"\([0-9a-f]*\)".*/\1/p' scripts/nb2-evidence/main.go > "$out/sender.key"
chmod 600 "$out/sender.key"
test -s "$out/sender.key"
trap 'rm -f "$out/sender.key"' EXIT
cp "$NB2_PLUGIN/protocol/profile.json" "$out/profile.json"
cp "$NB2_CONTRACTS/tools/nb2-flat-b1/lane.ts" "$NB2_PLUGIN/packages/native-bridge-plugin/scripts/t3-lane.ts"
"$NB2_PLUGIN/node_modules/.bin/tsx" "$NB2_PLUGIN/packages/native-bridge-plugin/scripts/t3-lane.ts" "$out" "$rpc" "$agg" "$chain" "$NB2_CONTRACTS/out" "$out/nb2-evidence"
