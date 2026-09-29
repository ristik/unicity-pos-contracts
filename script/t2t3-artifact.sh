#!/usr/bin/env bash
# Rebuilds canonical WUCT and FeeCollector test-instance artifacts with the pinned compiler.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v forge >/dev/null
command -v jq >/dev/null

forge clean
forge build --force >/dev/null
forge script script/T2T3Artifacts.s.sol:T2T3Artifacts --sig 'run()' --offline >/dev/null

settings=$(forge config --json | jq -c '{solc: .solc, evm_version, optimizer, optimizer_runs, via_ir, bytecode_hash, cbor_metadata}')
oz_revision=$(git -C lib/openzeppelin-contracts rev-parse HEAD)
wuct_source_sha=$(shasum -a 256 src/WUCT.sol | awk '{print $1}')
fee_source_sha=$(shasum -a 256 src/FeeCollector.sol | awk '{print $1}')

jq -n \
	--argjson compiler "$settings" \
	--arg openzeppelinRevision "$oz_revision" \
	--arg wuctSourceSha256 "$wuct_source_sha" \
	--arg feeCollectorSourceSha256 "$fee_source_sha" \
	--argjson wuctAbi "$(jq -c '.abi' out/WUCT.sol/WUCT.json)" \
	--argjson feeCollectorAbi "$(jq -c '.abi' out/FeeCollector.sol/FeeCollector.json)" \
	--argjson wuctStorageLayout "$(jq -c '.storageLayout' out/WUCT.sol/WUCT.json)" \
	--argjson feeCollectorStorageLayout "$(jq -c '.storageLayout' out/FeeCollector.sol/FeeCollector.json)" \
	--argjson runtimes "$(jq -c '.' out/t2t3-runtimes.json)" \
	'{profile: $runtimes.profile,
	  compiler: $compiler,
	  dependency: {name: "OpenZeppelin Contracts", revision: $openzeppelinRevision},
	  sourceSha256: {wuct: $wuctSourceSha256, feeCollector: $feeCollectorSourceSha256},
	  wuct: {abi: $wuctAbi, runtimeBytecode: $runtimes.wuctRuntimeBytecode,
	         codeHash: $runtimes.wuctCodeHash, storageLayout: $wuctStorageLayout},
	  feeCollector: {abi: $feeCollectorAbi, runtimeBytecode: $runtimes.feeCollectorRuntimeBytecode,
	                 codeHash: $runtimes.feeCollectorCodeHash,
	                 constructorTestValues: {treasury: $runtimes.feeCollectorTestTreasury,
	                                         treasuryShareBps: $runtimes.feeCollectorTreasuryShareBps},
	                 storageLayout: $feeCollectorStorageLayout}}' \
	>artifacts/t2t3-test-v1.json

echo "wrote artifacts/t2t3-test-v1.json wuct_runtime_bytes=$(jq -r '(.wuct.runtimeBytecode | length) / 2 - 1' artifacts/t2t3-test-v1.json) feeCollector=$(jq -r '.feeCollector.codeHash' artifacts/t2t3-test-v1.json)"
