#!/usr/bin/env bash
# NB2-02 (bft-core#1098) gas bake-off: generate the candidates, run every workload, build the tables.
#   bench/nb2/run.sh            # optimizer_runs = 200 (the repository's default profile)
#   RUNS=1 bench/nb2/run.sh     # the size-first profile the repository applies to src/bridge
# Writes results/*.csv (raw rows, one per measured transaction) and RESULTS.md; with RUNS other
# than 200 they go to results-runs$RUNS/ and RESULTS-runs$RUNS.md. Takes about two minutes.
set -euo pipefail
cd "$(dirname "$0")"
RUNS="${RUNS:-200}"
export FOUNDRY_OPTIMIZER_RUNS="$RUNS"
python3 gen.py
rm -rf results && mkdir -p results
forge --version | head -1 > results/toolchain.txt
forge build
forge test --isolate --mc CorrectnessTest
forge test --isolate --mc 'Bench_'
if [ "$RUNS" = 200 ]; then
    python3 tables.py results "$RUNS" > RESULTS.md
    echo "wrote RESULTS.md"
else
    rm -rf "results-runs$RUNS" && mv results "results-runs$RUNS"
    python3 tables.py "results-runs$RUNS" "$RUNS" > "RESULTS-runs$RUNS.md"
    echo "wrote RESULTS-runs$RUNS.md"
fi
