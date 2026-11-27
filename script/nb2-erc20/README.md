# ERC20 NB2 contract checks

The version 3 profile uses the factory, vault and recovery templates in
`src/nb2/erc20`. The generator specializes the pinned native source for the
ERC20 receipt, config, asset checks and token custody. The native sources
compile from their original paths with their existing settings.

Run the checks with Foundry 1.8.1 and Solidity 0.8.37.

```sh
python3 script/nb2-erc20/generate.py --check
forge fmt --check
forge test --match-path 'test/nb2/erc20/*.sol'
forge build --sizes src/nb2/erc20 src/nb2/NativeBridgeVault11.sol
python3 script/nb2-erc20/measure-activation.py
python3 script/nb2-erc20/compare-native.py /path/to/baseline .
```

The activation measurement creates a disposable loopback Cancun node. It mines
two callers' activation transactions for the same token in one block. The
receipt identifies which transaction created the pair. The script also
measures a later idempotent lookup with empty initcodes.

The binary proof fixtures come from the ERC20 vectors at bft-core
`106e8c14a21de4a9f5634c82e429a4435d6c130e`. Run the Go oracle with
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
