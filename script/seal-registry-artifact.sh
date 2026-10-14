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
	records.count records.tip records.progress records.ucTime records.targetCount records.targetTip records.importedRound
)
b1fixed=(b1.network b1.format b1.profileHash b1.initialized b1.genesisEpoch b1.importedTipEpoch b1.originReady)
b1prefixes=(b1.entry b1.member records.entry records.closure records.retirement)

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
		specification: "B1 permanent registry (briefs/b1-any-age-contract.md section 1): every installed validator epoch is kept forever, looked up directly by epoch; append-only with a durable imported-tip cursor; no window, ring, queue, pruning or deletion; no layout-version word (b1.format = 2)",
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
			cursors: {
				format: "b1.format = 2",
				genesisEpoch: "b1.genesisEpoch = g, the first epoch of this deployment (zero is a valid occupied epoch; an absent word reads zero)",
				importedTipEpoch: "b1.importedTipEpoch = I, the greatest contiguously installed epoch; the durable import cursor (count = I - g + 1, derived)",
				originReady: "b1.originReady = 0 before the first usable root origin, 1 thereafter; the usable origin is origin.rootEpoch (U) and clock.rootRound (O), with g <= U = I once ready"
			},
			entry: {
				prefix: ($prefixes[0]),
				formula: "E(e,f) = keccak256(abi.encode(F(\"b1.entry\"), uint256(e), uint256(f)))",
				fields: ["present", "bodyKind", "bodyID", "activationCommitID", "start", "end", "hasEnd", "signingScheme", "signingConfigHash", "memberCount", "totalWeight"]
			},
			member: {
				prefix: ($prefixes[1]),
				formula: "M(e,j,f) = keccak256(abi.encode(F(\"b1.member\"), uint256(e), uint256(j), uint256(f))), j < memberCount",
				fields: ["nodeIDLength", "nodeID0", "nodeID1", "nodeID2", "nodeID3", "key0", "key1", "weight"],
				encoding: "nodeID bytes in wire order, left-aligned, zero right padding; key = 33-byte compressed secp256k1 key in key0 (bytes 0..31) and the top byte of key1 (byte 32), rest zero"
			},
			bounds: {
				maxMeasuredB: 2,
				maxMembers: 16,
				maxNodeIDBytes: 128,
				entryMetadataWords: 11,
				memberWords: 8,
				maxEntryWords: 139,
				maxAddressedWords: "139 * (I - g + 1) + 7 fixed words, growing by 139 words per installed epoch and never shrinking (excludes the operational slots)"
			}
		},
		recordsLayout: {
			fixedWords: ["records.count", "records.tip", "records.progress", "records.ucTime", "records.targetCount", "records.targetTip", "records.importedRound"],
			entry: {
				prefix: ($prefixes[2]),
				formula: "R(i,j) = keccak256(abi.encode(F(\"records.entry\"), uint64(i), uint64(j)))",
				fields: ["recordID", "predecessor", "kind", "progress", "ucTime", "dataByteLength", "data0", "data1", "data2", "data3", "data4", "data5", "data6", "data7", "data8", "closedEpoch"]
			},
			closure: {
				prefix: ($prefixes[3]),
				formula: "keccak256(abi.encode(F(\"records.closure\"), uint64(closedEpoch), hRecordID, uint64(hRound))) = first index + 1"
			},
			retirement: {
				prefix: ($prefixes[4]),
				formula: "keccak256(abi.encode(F(\"records.retirement\"), uint64(id), uint64(generation))) = first index + 1"
			},
			maxImport: 32
		},
		genesisStorage: [
			{name: "genesisCommitment", value: "SHA-256(CBOR(G)), with G built over this codeHash (#153 §5.3 step 2)"},
			{name: "config.shardConfHash", value: "fullShardConfHash (#153 §5.3 step 3)"},
			{name: "assignment.epoch", value: "G.shardEpoch"},
			{name: "assignment.rootEpoch", value: "G.rootEpoch"},
			{name: "assignment.activeConfHash", value: "fullShardConfHash (same as immutable genesis configuration hash)"},
			{name: "records.ucTime", value: "pinned genesis UC time"},
			{name: "phase", value: "2"},
			{name: "b1.network", value: "root network id (u16)"},
			{name: "b1.format", value: "2"},
			{name: "b1.profileHash", value: "execution profile hash"},
			{name: "b1.initialized", value: "1"},
			{name: "b1.genesisEpoch", value: "genesis epoch g (a zero epoch is an absent word)"},
			{name: "b1.importedTipEpoch", value: "genesis epoch (I = g; a zero epoch is an absent word); b1.originReady is 0 and absent"},
			{name: "b1.entry(genesis epoch)", value: "the authenticated genesis entry: present=1, activationCommitID=0, hasEnd=0, memberCount, totalWeight"},
			{name: "b1.member(genesis epoch, j)", value: "full members under the root consensus keys, 8 words each"}
		],
		genesisNote: "Zero words are absent from a genesis allocation. The genesis builder (src/B1GenesisBuilder.sol) applies the runtime bounds to the genesis entry and refuses B > 2 with UnmeasuredB, G_rest below the measured-plus-margin allowance, or g_sys below the envelope. This artifact does not contain a deployable genesis record: genesisCommitment, fullShardConfHash and the entry members depend on deployment configuration and are produced by the Go construction using codeHash above.",
		gasProfile: {
			envelope: "g_sys >= 155936 + (505244 + 177800*16)*B + G_rest(B)",
			gRestBound: {
				basis: "Measured-plus-margin, not proven: maximal actual-call fixtures at B = 0, 1, 2 (16-member entries, three node-ID shapes); ureth must re-measure under the real client and may lower or raise the constants before activation",
				safetyFactor: {numerator: 3, denominator: 2},
				base: 1150000,
				perEpoch: 250000,
				operationalWrites: {count: 28, pricePerWrite: 22100},
				formula: "G_rest(B) = base + perEpoch*B",
				covers: "everything in open + finalize except the history SSTOREs of the rectangle (139*B entry words, the two closure words of the former tip and the two cursor words, each at 22100, nothing cleared): SLOADs, hashing, decode, memory, logs, operational-registry writes (28, each priced at 22100) and finalize",
				price: "Cancun, cold: SLOAD 2100, SSTORE 22100 set / 5000 reset, gross (no refund credit)"
			},
			analysis: "docs/b1-registry-gas.md"
		}
	}' >artifacts/seal-registry.json

echo "wrote artifacts/seal-registry.json codeHash=$code_hash runtimeBytes=$(( (${#runtime} - 2) / 2 ))"
