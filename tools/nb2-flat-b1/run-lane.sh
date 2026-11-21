#!/usr/bin/env bash
# Run in a dedicated copy of bft-core with a built ubft and B1-capable ureth.
set -euo pipefail
: "${NB2_OUT:?set evidence output directory}"
: "${NB2_CONTRACTS:?set contracts checkout with compiled artifacts}"
: "${NB2_PLUGIN:?set pinned T2 checkout with npm ci completed}"
: "${URETH_BIN:?set B1-enabled executable}"
: "${AGG_BIN:?set paired aggregator-go executable}"
export CI_MONGO_NAME=nb2-t3-1265-mongo
export M2_PROFILE2=1 Q3_B1=1
export URETH_PIN_COMMIT="$( "$URETH_BIN" --version | awk '/Commit SHA/ {print $3}' )"
export POST_M2A_URETH_BIN="$URETH_BIN" POST_M2A_URETH_COMMIT="$URETH_PIN_COMMIT"
export M2_RUN_LOG_DIR="$NB2_OUT/paired"
mkdir -p "$M2_RUN_LOG_DIR"
claim=$(scripts/lane-slot.sh acquire --owner nb2-t3-1265 --profile paired-default)
read -r LANE_SLOT lane_token <<<"$claim"
export LANE_SLOT
lane_pid=
cleanup() {
    if [ -n "$lane_pid" ]; then kill -TERM "$lane_pid" 2>/dev/null || true; wait "$lane_pid" || true; fi
    bash scripts/ci/mongo-up.sh down "$NB2_OUT/mongo"
    scripts/lane-slot.sh release --owner nb2-t3-1265 --token "$lane_token"
}
trap cleanup EXIT
trap 'exit 143' HUP INT TERM
bash scripts/ci/mongo-up.sh up "$NB2_OUT/mongo"
python3 - <<'PY'
from pathlib import Path
p = Path("scripts/reth-paired-devnet.sh")
s = p.read_text()
needle = '# Both the standalone H4 probe'
i = s.index(needle)
s = s[:i] + '''# This isolated lane needs the aggregation partition without P85 custody.
ANYAGE_LANE=1
chainID=$postM2aChainID partitionID=8 rootRpcPort=$((25866+LANE_PORT_OFFSET))
source scripts/lib/agg-lib.sh
''' + s[i:]
i = s.index('echo "waiting for block 1 and a certificate')
end = s.index('\nfi', s.index('fail "v2 bootstrap did not produce', i)) + 3
s = s[:end] + '''
$mined && $certified || exit 1
bash "$NB2_CONTRACTS/tools/nb2-flat-b1/lane-probe.sh" "http://127.0.0.1:$rethEthBase" "http://127.0.0.1:$(agg_port 1)" "$postM2aChainID"
exit $?
''' + s[end:]
p.with_name("nb2-t3-paired.sh").write_text(s)
PY
bash scripts/nb2-t3-paired.sh 4 10 &
lane_pid=$!
status=0
wait "$lane_pid" || status=$?
lane_pid=
exit "$status"
