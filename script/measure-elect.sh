#!/usr/bin/env bash
# Measures the worst-case election for a chosen (V, L, C) and prints one JSON line {"v":..,"l":..,"c":..,"gas":..}: the input of the genesis
# tool's ElectGas pin (bft-core `ubft engine-api b1-profile --elect-measurement`) and of its check (`engine-api check-elect-gas`).
# Usage: script/measure-elect.sh V L C     (devnet/testnet default: 16 2 8)
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$#" -eq 3 ] || { echo "usage: $0 V L C" >&2; exit 2; }
line=$(P85_MEASURE_V="$1" P85_MEASURE_L="$2" P85_MEASURE_C="$3" forge test --match-test test_measureFromTheEnvironment -vv 2>&1 | grep -o 'ELECT-MEASURE {.*}' | head -1 | sed 's/^ELECT-MEASURE //')
[ -n "$line" ] || { echo "measurement failed: no ELECT-MEASURE line (parameters outside the profile ceilings?)" >&2; exit 1; }
echo "$line"
