# Bridge golden vectors

`test/bridge/golden.json` pins the Solidity code to bytes produced by the Go oracle; no value in it was written by hand. The
composed relation itself runs natively (0x0105) and is pinned by the oracle's `native-compose` corpus in ureth.

| File | Source | Regenerate |
| --- | --- | --- |
| `test/bridge/golden.json` | bft-core `bridgeprofile`, **native bridge protocol 5** (the Unicity Trust Base history as the trust input: lock proofs carry its genesis EntryID as `trustBaseId`; protocol 4's any-age verification (any-age verification: one `CERT_BATCH_V2` call over the anchor table, policy `AGG_PARTITION_V2`, the contract limits; since owner §36 the gate is an estimate with no budget), oracle revision `d71d8e2b69159deb6ba302a81bf355ec448a3716` (bft-core dev4/b7-nested-parity: embedded-object error parity; recorded in `corpus-pin.json`). Contents: Cfg and the unicity-native identifiers, identity-family vectors, the one-partition policy, derivations, storage slots and trie keys, RLP words, kernel inputs and outputs (`448+128*m` bytes), a canonical proof envelope per operation built on **real certified anchors** (the DN-B depth-1 topology puts the leaves of a return under two UCs: UC, native InputRecord opening, RSMT paths, the leaf-to-anchor index, the batch request and verdict the reference `b1ref.Cert` returned for the whole table, and the oracle's gas estimate components with the grouping E, S, Q, A, P) and, for every leaf, the RSMT request and verdict (`b1ref.Member`, including the verdict `false` for the pre-3.0 value `txHash`), and the native InputRecord openings produced by the SDK's own encoder | Copy `golden_pr5_test.go.txt` to `bridgeprofile/golden_pr5_test.go` in a checkout of that revision, then `BRIDGE_PR5_GOLDEN=<out.json> go test ./bridgeprofile -run TestGenPR5Golden -count=1`. The file is not part of bft-core. |

## Sealed corpus pin

`corpus-pin.json` pins the shared corpus (native-bridge-plugins `protocol/vectors`, commit `83b1ae4f…` (embedded-object parity cases, after B7 direct PR 2b: the
`native-compose` cases and the status table, the composed path without the kernels' aggregates), manifest digest `9fd0fe37…`, `trustBaseId` (the trust-base genesis EntryID) `cde64957…`), the oracle
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
