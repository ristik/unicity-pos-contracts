#!/usr/bin/env bash
# COLD gas of the mandatory hook's records and of the election at the deployment's caps (test/p85/HookGasCold.t.sol): one JSON line per
# (kind, V, L, C): {"kind":..,"v":..,"l":..,"c":..,"cold_gas":..}. The committee is the worst the caps admit: C members of L lots each.
# Usage: script/measure-hook-gas.sh V L C [kind...]     kinds: ack stage closure recovery elect elect-gov elect-heavy (default: all)
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$#" -ge 3 ] || { echo "usage: $0 V L C [kind...]" >&2; exit 2; }
v=$1; l=$2; c=$3; shift 3
kinds=${*:-ack stage closure recovery elect elect-gov elect-heavy}
for k in $kinds; do
  P85_GAS_KIND=$k P85_GAS_V=$v P85_GAS_L=$l P85_GAS_C=$c forge test --match-contract HookGasColdTest --match-test test_measureCold -vv 2>&1 \
    | grep -o 'HOOK-GAS {.*}' | head -1 | sed 's/^HOOK-GAS //' || echo "{\"kind\":\"$k\",\"v\":$v,\"l\":$l,\"c\":$c,\"error\":\"no measurement\"}"
done
