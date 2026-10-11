#!/usr/bin/env bash
# The custody's storage layout is protocol surface (bft-core reads slots through proofs, the genesis alloc carries them): it must not move.
# Checks that StakeCustody and its genesis implementation CustodyGenesis (which runs in the custody's storage by delegatecall) have one layout, and
# that it is the layout committed in docs/p85/custody-storage-layout.txt (taken before the genesis functions were extracted).
set -euo pipefail
cd "$(dirname "$0")/.."
flat() { forge inspect "$1" storageLayout --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin); t=d['types']
for e in d['storage']: print('%s slot=%s offset=%s bytes=%s'%(e['label'],e['slot'],e['offset'],t[e['type']]['numberOfBytes']))"; }
a=$(flat StakeCustody); b=$(flat CustodyGenesis)
[ "$a" = "$b" ] || { echo "StakeCustody and CustodyGenesis disagree on the storage layout" >&2; diff <(echo "$a") <(echo "$b") >&2; exit 1; }
[ "$a" = "$(cat docs/p85/custody-storage-layout.txt)" ] || { echo "the custody storage layout changed from docs/p85/custody-storage-layout.txt" >&2; diff <(echo "$a") docs/p85/custody-storage-layout.txt >&2; exit 1; }
echo "custody storage layout: unchanged ($(echo "$a" | wc -l) variables), shared by CustodyGenesis"
