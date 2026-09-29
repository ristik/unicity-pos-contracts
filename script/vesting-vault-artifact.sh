#!/usr/bin/env bash
# Rebuilds the canonical ImmutableVestingVault test-instance artifact with the pinned toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v forge >/dev/null
command -v jq >/dev/null

forge clean
forge build --force >/dev/null
forge script script/VestingVaultArtifacts.s.sol:VestingVaultArtifacts --sig 'run()' --offline >/dev/null

settings=$(forge config --json | jq -c '{solc: .solc, evm_version, optimizer, optimizer_runs, via_ir, bytecode_hash, cbor_metadata}')
oz_revision=$(git -C lib/openzeppelin-contracts rev-parse HEAD)
source_sha=$(shasum -a 256 src/ImmutableVestingVault.sol | awk '{print $1}')

jq -n \
	--argjson compiler "$settings" \
	--arg openzeppelinRevision "$oz_revision" \
	--arg sourceSha256 "$source_sha" \
	--argjson abi "$(jq -c '.abi' out/ImmutableVestingVault.sol/ImmutableVestingVault.json)" \
	--argjson storageLayout "$(jq -c '.storageLayout' out/ImmutableVestingVault.sol/ImmutableVestingVault.json)" \
	--argjson runtime "$(jq -c '.' out/vesting-vault-runtimes.json)" \
	'{profile: $runtime.profile,
	  compiler: $compiler,
	  dependency: {name: "OpenZeppelin Contracts", revision: $openzeppelinRevision},
	  sourceSha256: $sourceSha256,
	  abi: $abi,
	  runtimeBytecode: $runtime.runtimeBytecode,
	  codeHash: $runtime.codeHash,
	  constructorTestValues: {recipient: $runtime.testRecipient, principal: $runtime.testPrincipal,
	                          start: $runtime.testStart, cliff: $runtime.testCliff,
	                          duration: $runtime.testDuration},
	  storageLayout: $storageLayout}' \
	>artifacts/vesting-vault-test-v1.json

echo "wrote artifacts/vesting-vault-test-v1.json runtime_bytes=$(jq -r '(.runtimeBytecode | length) / 2 - 1' artifacts/vesting-vault-test-v1.json) codeHash=$(jq -r '.codeHash' artifacts/vesting-vault-test-v1.json)"
