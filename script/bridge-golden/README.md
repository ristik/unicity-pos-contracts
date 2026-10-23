# Bridge golden vectors

`test/bridge/golden.json` pins the Solidity code to bytes produced by the Go oracle; no value in it was written by hand. The
composed relation itself runs natively (0x0105) and is pinned by the oracle's `native-compose` corpus in ureth.

| File | Source | Regenerate |
| --- | --- | --- |
| `test/bridge/golden.json` | bft-core `bridgeprofile`, **native bridge protocol 5** (the Unicity Trust Base history as the trust input: lock proofs carry its genesis EntryID as `trustBaseId`; protocol 4's any-age verification (any-age verification: one `CERT_BATCH_V2` call over the anchor table, policy `AGG_PARTITION_V2`, the contract limits; since owner §36 the gate is an estimate with no budget), oracle revision `17dfe06becad1e3890f1f8bc233bf806d234bf02` (bft-core#741 merge: B7 PR 3, the 2 MiB envelope on the parity corpus; recorded in `corpus-pin.json`). Contents: Cfg and the unicity-native identifiers, identity-family vectors, the one-partition policy, derivations, storage slots and trie keys, RLP words, kernel inputs and outputs (`448+128*m` bytes), a canonical proof envelope per operation built on **real certified anchors** (the DN-B depth-1 topology puts the leaves of a return under two UCs: UC, native InputRecord opening, RSMT paths, the leaf-to-anchor index, the batch request and verdict the reference `b1ref.Cert` returned for the whole table, and the oracle's gas estimate components with the grouping E, S, Q, A, P) and, for every leaf, the RSMT request and verdict (`b1ref.Member`, including the verdict `false` for the pre-3.0 value `txHash`), and the native InputRecord openings produced by the SDK's own encoder | Copy `golden_pr5_test.go.txt` to `bridgeprofile/golden_pr5_test.go` in a checkout of that revision, then `BRIDGE_PR5_GOLDEN=<out.json> go test ./bridgeprofile -run TestGenPR5Golden -count=1`. The file is not part of bft-core. |

## Sealed corpus pin

`corpus-pin.json` pins the shared corpus (native-bridge-plugins `protocol/vectors`, the protocol 6 seal of split PR5 (native-bridge-plugins#52, candidate until the final reseal on the oracle's merge commit): the protocol 5 families regenerated at protocol 6 plus `split/`, manifest digest `57a44dc2…`, `trustBaseId` (the trust-base genesis EntryID) `cde64957…`), the oracle
commit, the SHA-256 of `golden.json` and the list of golden values the corpus also contains.
`python3 script/bridge-golden/check-corpus.py <corpus checkout>` verifies the corpus files and digest, that
both golden histories embed the corpus `trustBaseId`, that `golden.json` is the pinned bytes, and that each
shared value occurs in the corpus. CI runs it against the pinned commit, so a golden that drifts from the
corpus, or a corpus that moves, fails the build.

To refresh: regenerate `golden.json` at the new oracle revision, update `corpus-pin.json` (commit, digest,
golden SHA-256; `sharedPaths` is every `0x` value of `golden.json` of 32 bytes or more found in the corpus),
and rerun the check. When bft-core and native-bridge-plugins merge, re-pin to the merged commits.

The values `semanticProfileHash`, `b1ProfileHash`, `tokenVerifier` and `tokenVerifierCodeHash` in the
golden Cfg are the oracle's DEV fixture values, not the pinned runtime artifacts of a deployment.

Cfg hash and policy hash are those of the golden file (`cfg.hash`, `policy.hash`); the Cfg field order and
domains are unchanged from the pre-3.0 profile. The policy is the protocol-4 body `["UNICITY_BR_AGG_PARTITION", 2, partition]`.

Since B7 direct PR 2 the contract binds the configuration and checks the fixed result of 0x0105; the envelope, the anchors and
the leaf paths of the golden are opaque inputs it forwards. The golden's gate components remain for the plug-ins' estimate.

## Split lineage vectors (protocol 6)

`test/bridge/split-golden.json` is the extraction of the oracle's split corpus (bft-core `bridgeprofile/testdata/split-corpus`, the
`BRIDGE_COMPOSE_V2` native cases and the lineage results): for each of 18 cases the compose input, the 480-byte output, the status
(`config/compose-status-v2.json`: the V1 codes, then the split reasons 63..69, then `ErrCertScan` 70 and `ErrCertSigLength` 71) and
the gas. `split-pin.json` pins the sealed corpus (native-bridge-plugins `protocol/vectors/split`, the same commit and manifest digest as
`corpus-pin.json`), the SHA-256 of every corpus file read (each checked against the sealed SHA256SUMS) and of the extraction; the
oracle commit (`fdb08865`, #809 + #810) is the one whose bytes the extraction names as its source (the sealed files are byte-identical).

```
python3 script/bridge-golden/split-golden.py check   <native-bridge-plugins checkout>   # pin, manifest, file digests, extraction equals the file
python3 script/bridge-golden/split-golden.py extract <native-bridge-plugins checkout>   # rewrite the file (then update split-pin.json's sha256)
```

`SplitVerifier.t.sol` replays the cases through the real `TokenVerifier` (the 0x0105 double answers only the exact input bytes).

### Vault layout (protocol 6)

Slots 0 to 5 and 7 are unchanged (the lock digest stays at slot 5 where the lock-proof readers expect it). Slot 6 is no longer
`spentNullifier` (nonce => nullifier): it is `redeemedAmount` (nonce => sum of redeemed part amounts). New: slot 8 `lockedAmount`
(nonce => amount), slot 9 `spentPart` (nonce => partId => nullifier). Readers of the old spent word (the plug-ins' `spentSlot` and
`spentNullifier(nonce)`) must move to `spentPart(nonce, partId)` and `redeemedAmount(nonce)`; this is a fresh deployment, nothing
upgrades in place.

Consumers of the old layout and event, to be moved in lockstep with the fresh deployment (the break list):

- native-bridge-plugins: `spentSlot`, `SLOT_SPENT_NULLIFIER`, `RedeemTransport.spentNullifier(nonce)` (PR4);
- bft-core `bridgeprofile/lock.go` (`SlotSpentNullifier`, `SpentSlot`: the slot is now `redeemedAmount[n]`) and the amendment
  `docs/pos/specification/amendments/b2-whole-token-bridge-profile.md` (replay guard text, slot table);
- bft-core `deploy/testnet/bridge/rehearse_bridge.py`: the event `RedemptionCredited(uint256,bytes32,address,uint256)` is now
  `RedemptionCredited(uint256,bytes32,address,bytes32,uint256,uint256)` (topics: nonce, partId, recipient) and its
  `spentNullifier(uint256)` calls become `spentPart(uint256,bytes32)` and `redeemedAmount(uint256)`.
