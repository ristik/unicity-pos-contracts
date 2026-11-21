#!/usr/bin/env bash
# Regenerate test/nb2/flat/differential/*.txt from the pinned bft-core oracle.
# usage: run.sh /path/to/bft-core-at-8c1b6ca9f [go-binary]
set -euo pipefail
bft=${1:?bft-core checkout at the pinned commit}
go=${2:-go}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
test "$(git -C "$bft" rev-parse HEAD)" = 8c1b6ca9ff18648f98f3df588e70d70285e6adc6
cp "$here/flat_differential_test.go" "$bft/nb2ref/flat_differential_test.go"
trap 'rm -f "$bft/nb2ref/flat_differential_test.go"' EXIT
mkdir -p "$repo/test/nb2/flat/differential"
(cd "$bft" && NB2_DIFF_OUT="$repo/test/nb2/flat/differential" "$go" test -count=1 ./nb2ref -run '^TestFlatDifferentialCorpus$')
