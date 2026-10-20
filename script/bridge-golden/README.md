# Bridge golden vectors

`test/bridge/golden.json` and `test/bridge/b1-vectors.json` pin the Solidity code to bytes produced by the
Go oracle and the A' reference oracle; no value in them was written by hand.

| File | Source | Regenerate |
| --- | --- | --- |
| `test/bridge/golden.json` | bft-core `bridgeprofile`, **native bridge protocol 5** (the Unicity Trust Base history as the trust input: lock proofs carry its genesis EntryID as `trustBaseId`; protocol 4's any-age verification (any-age verification: one `CERT_BATCH_V2` call over the anchor table, policy `AGG_PARTITION_V2`, the contract gate and limits, unchanged), oracle revision `ed4b71fbd047139bdd585c9dc50fe106dd83cdb3` (the bft-core #658 merge, recorded in `corpus-pin.json`). Contents: Cfg and the unicity-native identifiers, identity-family vectors, the one-partition policy, derivations, storage slots and trie keys, RLP words, kernel inputs and outputs (`448+128*m` bytes), a canonical proof envelope per operation built on **real certified anchors** (the DN-B depth-1 topology puts the leaves of a return under two UCs: UC, native InputRecord opening, RSMT paths, the leaf-to-anchor index, the batch request and verdict the reference `b1ref.Cert` returned for the whole table, and the oracle's gate components with the grouping E, S, Q, A, P) and, for every leaf, the RSMT request and verdict (`b1ref.Member`, including the verdict `false` for the pre-3.0 value `txHash`), and the native InputRecord openings produced by the SDK's own encoder | Copy `golden_pr5_test.go.txt` to `bridgeprofile/golden_pr5_test.go` in a checkout of that revision, then `BRIDGE_PR5_GOLDEN=<out.json> go test ./bridgeprofile -run TestGenPR5Golden -count=1`. The file is not part of bft-core. |
| `test/bridge/b1-vectors.json` | bft-core `b1ref/testdata/b1-vectors-anyage.json` (corpus `b1-vectors/any-age-v1`, #606/#610, independently constructed by `b1ref/b1gen`): every `CERT_BATCH_V2` vector with a stated grouping (valid, false and registry-failed batches: C, K, E, S, Q, A, P and the charge), every `CERT_BATCH_V2` vector that must halt (the Solidity scan refuses what it is built to refuse), and the `RSMT_MEMBER_V1` vectors the wrappers reproduce. The registry pre-state is dropped. `test/bridge/CertGroupsVectors.t.sol` reproduces the counts and the charge of all 155 grouped vectors the scan accepts | `python3 script/bridge-golden/extract-b1.py <bft-core checkout> test/bridge/b1-vectors.json` |

## Sealed corpus pin

`corpus-pin.json` pins the shared corpus (native-bridge-plugins `protocol/vectors` on `main`, commit `affbc5de…` (after
#526 steps 1–3; artifactVersion 6), manifest digest `8ca2a20d…`, `trustBaseId` (the trust-base genesis EntryID) `cde64957…`), the oracle
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

The bounds the contract enforces (`BridgeBounds`, with `CertGroups` for the scan) are contract section 4 of
`briefs/b1-any-age-contract.md`; the tests assert the gate components of `mint.envelope.gate` and `return.envelope.gate`
(intrinsic, kernel, batch with its grouping, leaves) against the oracle's.
