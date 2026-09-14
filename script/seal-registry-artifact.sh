#!/usr/bin/env bash
# Regenerates artifacts/seal-registry-v1.json from a clean build. CI runs it and fails if the committed
# artifact differs. Requires forge, cast and jq.
set -euo pipefail
cd "$(dirname "$0")/.."

forge build --force >/dev/null
out=out/SealRegistry.sol/SealRegistry.json

layout_entries=$(jq '.storageLayout.storage | length' "$out")
if [ "$layout_entries" != 0 ]; then
	echo "SealRegistry declares Solidity storage variables ($layout_entries); the layout must be empty" >&2
	exit 1
fi

runtime=$(jq -r '.deployedBytecode.object' "$out")
code_hash=$(cast keccak "$runtime")

names=(
	layoutVersion genesisCommitment config.shardConfHash assignment.epoch assignment.rootEpoch
	clock.rootRound origin.rootEpoch origin.timestamp origin.treeRoot origin.identity origin.trHash
	round.authorized input.commitment certified.round certified.stateHash certified.hasBlockHash
	certified.blockHash phase outcomes.round outcomes.commitment transition.cursor inbox.consumed
)
slots='[]'
for name in "${names[@]}"; do
	key=$(cast keccak "unicity.seal-registry.v1/$name")
	slots=$(jq -c --arg name "$name" --arg key "$key" '. + [{name: $name, key: $key}]' <<<"$slots")
done

settings=$(forge config --json | jq -c '{solc: .solc, evm_version, optimizer, optimizer_runs, via_ir, bytecode_hash, cbor_metadata}')

mkdir -p artifacts
jq -n \
	--argjson settings "$settings" \
	--argjson abi "$(jq -c '.abi' "$out")" \
	--arg runtime "$runtime" \
	--arg codeHash "$code_hash" \
	--argjson slots "$slots" \
	'{
		profile: "sealRegistry/v1",
		specification: "bft-core docs/design/f4a-seal-registry-contract.md, accepted in #153 (last changed by 9545881e5d3ce7307ebf3ec792b1ea5aa5e9d8f1)",
		compiler: $settings,
		abi: $abi,
		runtimeBytecode: $runtime,
		codeHash: $codeHash,
		slotKeys: $slots,
		systemCaller: "0xff00000000000000000000000000000000000001",
		genesisStorage: [
			{name: "layoutVersion", value: "1"},
			{name: "genesisCommitment", value: "SHA-256(CBOR(G)), with G built over this codeHash (#153 §5.3 step 2)"},
			{name: "config.shardConfHash", value: "fullShardConfHash (#153 §5.3 step 3)"},
			{name: "assignment.epoch", value: "G.shardEpoch"},
			{name: "assignment.rootEpoch", value: "G.rootEpoch"},
			{name: "phase", value: "2"}
		],
		genesisNote: "Every other field is absent (zero) at genesis. This artifact does not contain a deployable genesis record: genesisCommitment and fullShardConfHash depend on the deployment configuration and are produced by the Go construction of #153 §5.3 using codeHash above. The tests install #153 §5.4 worked-vector values as storage fixtures only."
	}' >artifacts/seal-registry-v1.json

echo "wrote artifacts/seal-registry-v1.json codeHash=$code_hash runtimeBytes=$(( (${#runtime} - 2) / 2 ))"
