#!/usr/bin/env bash
# Regenerates artifacts/seal-registry.json from a clean build. CI runs it and fails if the committed
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

# Fixed words: F(name) = keccak256(UTF8("unicity.seal-registry/" || name)). There is no layoutVersion.
operational=(
	genesisCommitment config.shardConfHash assignment.epoch assignment.rootEpoch
	assignment.activeConfHash assignment.spanCommitment
	clock.rootRound origin.rootEpoch origin.timestamp origin.treeRoot origin.identity origin.trHash
	round.authorized input.commitment certified.round certified.stateHash certified.hasBlockHash
	certified.blockHash phase outcomes.round outcomes.commitment transition.cursor inbox.consumed
	transition.bodyID transition.genesisID transition.frozenID transition.commitID
	transition.frozenParent transition.successorTR
)
b1fixed=(b1.network b1.wCert b1.profileHash b1.initialized b1.head b1.count)
b1prefixes=(b1.queue b1.entry b1.member)

keyed() { # name... -> [{name,key}]
	local arr='[]' name key
	for name in "$@"; do
		key=$(cast keccak "unicity.seal-registry/$name")
		arr=$(jq -c --arg name "$name" --arg key "$key" '. + [{name: $name, key: $key}]' <<<"$arr")
	done
	echo "$arr"
}
slots=$(keyed "${operational[@]}" "${b1fixed[@]}")
prefixes=$(keyed "${b1prefixes[@]}")

settings=$(forge config --json | jq -c '{solc: .solc, evm_version, optimizer, optimizer_runs, via_ir, bytecode_hash, cbor_metadata}')

# Tuple inputs print as "tuple" in the ABI; forge's canonical method identifiers carry the signature.
open_selector=$(jq -r '.methodIdentifiers | to_entries[] | select(.key | startswith("open(")) | .value' "$out")
open_signature=$(jq -r '.methodIdentifiers | to_entries[] | select(.key | startswith("open(")) | .key' "$out")

mkdir -p artifacts
jq -n \
	--argjson settings "$settings" \
	--argjson abi "$(jq -c '.abi' "$out")" \
	--arg runtime "$runtime" \
	--arg codeHash "$code_hash" \
	--argjson slots "$slots" \
	--argjson prefixes "$prefixes" \
	--arg openSelector "0x$open_selector" \
	--arg openSignature "$open_signature" \
	'{
		profile: "sealRegistry",
		specification: "B1 #62 pruned authenticated registry history (briefs/b1-design-v4.md, A-prime): one fresh privileged layout with a circular queue of live root-epoch intervals; no layout-version word",
		compiler: $settings,
		abi: $abi,
		openSignature: $openSignature,
		openSelector: $openSelector,
		runtimeBytecode: $runtime,
		codeHash: $codeHash,
		systemCaller: "0xff00000000000000000000000000000000000001",
		registryAddress: "0xff00000000000000000000000000000000000002",
		slotKeys: $slots,
		b1Layout: {
			fixedWordFormula: "F(name) = keccak256(UTF8(\"unicity.seal-registry/\" || name))",
			kMax: "b1.wCert + 1",
			queue: {
				prefix: ($prefixes[0]),
				formula: "Q(i) = keccak256(abi.encode(F(\"b1.queue\"), uint256(i))), 0 <= i < K_max; value is the epoch number; head < K_max; count distinguishes epoch zero from empty"
			},
			entry: {
				prefix: ($prefixes[1]),
				formula: "E(e,f) = keccak256(abi.encode(F(\"b1.entry\"), uint256(e), uint256(f)))",
				fields: ["present", "bodyKind", "bodyID", "activationCommitID", "start", "end", "hasEnd", "signingScheme", "signingConfigHash", "memberCount", "totalWeight"]
			},
			member: {
				prefix: ($prefixes[2]),
				formula: "M(e,j,f) = keccak256(abi.encode(F(\"b1.member\"), uint256(e), uint256(j), uint256(f))), j < memberCount",
				fields: ["nodeIDLength", "nodeID0", "nodeID1", "nodeID2", "nodeID3", "key0", "key1", "weight"],
				encoding: "nodeID bytes in wire order, left-aligned, zero right padding; key = 33-byte compressed secp256k1 key in key0 (bytes 0..31) and the top byte of key1 (byte 32), rest zero"
			},
			bounds: {
				maxMembers: 64,
				maxNodeIDBytes: 128,
				entryMetadataWords: 11,
				memberWords: 8,
				maxEntryWords: 523,
				maxLiveAddressedWords: "6 + 524 * K_max (524 = 523 entry words + 1 queue word; excludes the operational slots)"
			}
		},
		genesisStorage: [
			{name: "genesisCommitment", value: "SHA-256(CBOR(G)), with G built over this codeHash (#153 §5.3 step 2)"},
			{name: "config.shardConfHash", value: "fullShardConfHash (#153 §5.3 step 3)"},
			{name: "assignment.epoch", value: "G.shardEpoch"},
			{name: "assignment.rootEpoch", value: "G.rootEpoch"},
			{name: "assignment.activeConfHash", value: "fullShardConfHash (same as immutable genesis configuration hash)"},
			{name: "phase", value: "2"},
			{name: "b1.network", value: "root network id (u16)"},
			{name: "b1.wCert", value: "W_cert, with W_cert <= delta_ev < delta_hold"},
			{name: "b1.profileHash", value: "execution profile hash"},
			{name: "b1.initialized", value: "1"},
			{name: "b1.count", value: "1"},
			{name: "b1.queue[0]", value: "genesis epoch (head = 0 is absent)"},
			{name: "b1.entry(genesis epoch)", value: "the authenticated genesis entry: present=1, activationCommitID=0, hasEnd=0, memberCount, totalWeight"},
			{name: "b1.member(genesis epoch, j)", value: "full members under the root consensus keys, 8 words each"}
		],
		genesisNote: "Zero words are absent from a genesis allocation. The genesis builder (src/B1Genesis.sol) applies the runtime bounds to the genesis entry and refuses a profile whose g_sys does not cover the envelope. This artifact does not contain a deployable genesis record: genesisCommitment, fullShardConfHash and the entry members depend on deployment configuration and are produced by the Go construction using codeHash above.",
		gasProfile: {
			envelope: "g_sys >= 67536 + 326144*K_max + 22100*(524*K_max+4) + 7100*524*K_max + G_rest(K_max, C_max)",
			gRestBound: {
				base: 1000000,
				perInsert: 800000,
				perDelete: 200000,
				perEntry: 1000000,
				operationalWrites: {count: 28, pricePerWrite: 22100},
				formula: "G_rest(a, p) = base + perInsert*a + perDelete*p; G_rest(K_max) = base + perEntry*K_max, since a <= K_max and p <= K_max",
				covers: "everything in open + finalize except the history SSTOREs of the rectangle: SLOADs, hashing, decode, memory, logs, operational-registry writes (28, each priced at 22100) and finalize",
				price: "Cancun, cold: SLOAD 2100, SSTORE 22100 set / 5000 reset, gross (no refund credit)"
			},
			analysis: "docs/b1-registry-gas.md"
		}
	}' >artifacts/seal-registry.json

echo "wrote artifacts/seal-registry.json codeHash=$code_hash runtimeBytes=$(( (${#runtime} - 2) / 2 ))"
