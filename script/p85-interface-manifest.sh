#!/usr/bin/env bash
# Regenerates artifacts/p85-pr2-interface.json: the function selectors, custom-error selectors and
# event topics of the P85 PR2 modules. CI runs it and fails if the committed file differs.
# Requires forge and jq.
set -euo pipefail
cd "$(dirname "$0")/.."

forge build >/dev/null

modules=(StakeCustody Evidence ElectionPolicy FixedPolicy PosFactory)
result='{}'
for name in "${modules[@]}"; do
	selectors=$(forge inspect "$name" methodIdentifiers --json | jq -S .)
	errors=$(forge inspect "$name" errors --json | jq -S .)
	events=$(forge inspect "$name" events --json | jq -S .)
	result=$(jq -n --argjson r "$result" --arg name "$name" --argjson selectors "$selectors" \
		--argjson errors "$errors" --argjson events "$events" \
		'$r + {($name): {methodIdentifiers: $selectors, errors: $errors, events: $events}}')
done
printf '%s\n' "$result" | jq -S . >artifacts/p85-pr2-interface.json
echo "wrote artifacts/p85-pr2-interface.json"
