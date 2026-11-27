# ERC20 NB2 contract checks

The version 3 profile uses the factory, vault and recovery templates in
`src/nb2/erc20`. The generator specializes the pinned native source for the
ERC20 receipt, config, asset checks and token custody. The native sources
compile from their original paths with their existing settings.

Run the checks with Foundry 1.8.1 and Solidity 0.8.37.

```sh
python3 script/nb2-erc20/generate.py --check
forge fmt --check
FOUNDRY_OUT=out-fixture FOUNDRY_CACHE_PATH=cache-fixture forge test --match-path 'test/nb2/erc20/*.sol'
forge build --force --sizes src/nb2/erc20 src/nb2/NativeBridgeVault11.sol
python3 script/nb2-erc20/measure-activation.py
python3 script/nb2-erc20/compare-native.py /path/to/baseline .
```

The activation measurement creates a disposable loopback Cancun node. It mines
two callers' activation transactions for the same token in one block. The
receipt identifies which transaction created the pair. The script also
measures a later idempotent lookup with empty initcodes.
Use `--sdk-root <fixture-root-trust-pin>` to export the production ERC20
profile's deployed graph and the receipt for two activations in one transaction.
The native hash comparison rebuilds both checkouts on the same production
target before reading their artifacts.

The binary proof fixtures come from the ERC20 vectors at bft-core
`332f4d32f754afb3af5aaeee4256df267031d8e5`. Run the Go oracle with
`NB2_ERC20_VECTORS` pointing to the JSON output path and
`go test ./nb2ref -run '^TestERC20FlatReturnVectors$' -count=1`.
Decode the first asset's Gamma, Evidence, Verdict, Packet, Complete and
Recovery fields as hex into their lowercase `.bin` files. The second asset's
Gamma supplies `foreign-gamma.bin`. Solidity runs the receipt and lineage
logic over those bytes with B1 and RSMT responses supplied by the test harness.
The Go oracle checks the signed witnesses against fixture authorities.

Deploy or reuse the pinned FlatReceipts implementation and deploy the ERC20
lineage, ordinary verifier and factory under the selected release pins.
Derive Γ from `factory.config(token)` after checking the selected chain and
factory. Submit `activate` with the two complete, argument-free templates.
Record the certified `ERC20Activated` locator and both runtime hashes for the
wallet. Funding requires separately qualified ERC20 settlement measurements.
The SDK simulates the vault's `previewPayout(address,uint256)` with a bounded
`eth_call`. Its `PayoutPreviewPassed()` revert confirms the exact deltas and
rolls back the token transfer.
