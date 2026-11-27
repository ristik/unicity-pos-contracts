#!/usr/bin/env bash
# Regenerate test/nb2/flat/differential/*.txt from the pinned bft-core oracle.
# usage: run.sh /path/to/bft-core-at-8c1b6ca9f [go-binary]
set -euo pipefail
bft=${1:?bft-core checkout at the pinned commit}
go=${2:-go}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
test "$(git -C "$bft" rev-parse HEAD)" = 8c1b6ca9ff18648f98f3df588e70d70285e6adc6
# Work in a disposable copy so that nothing in the caller's worktree is replaced or removed.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git -C "$bft" archive HEAD | tar -xf - -C "$tmp"
test ! -e "$tmp/nb2ref/flat_differential_test.go"
cp "$here/flat_differential_test.go" "$tmp/nb2ref/flat_differential_test.go"
bft=$tmp
mkdir -p "$repo/test/nb2/flat/differential"
(cd "$bft" && NB2_DIFF_OUT="$repo/test/nb2/flat/differential" "$go" test -count=1 ./nb2ref -run '^TestFlatDifferentialCorpus$')
