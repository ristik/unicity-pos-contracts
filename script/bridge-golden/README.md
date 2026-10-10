# Bridge golden vectors

`test/bridge/golden.json` and `test/bridge/b1-vectors.json` pin the Solidity code to bytes produced by the
Go oracle and the A' reference oracle; no value in them was written by hand.

| File | Source | Regenerate |
| --- | --- | --- |
| `test/bridge/golden.json` | bft-core `bridgeprofile` on the SDK 3.0.1 profile (native bridge protocol v3: sharded policy, one anchor per distinct UC, shared gas gate), oracle revision `43767c79af064554177b7bbd402941bed1c8fcad` (bft-core `b3/bruteforce-oracle`, the revision the sealed shared corpus is pinned to; recorded in `corpus-pin.json`). Contents: Cfg and the unicity-native identifiers, identity-family vectors, policy, derivations, storage slots and trie keys, RLP words, kernel inputs and outputs (`448+128*m` bytes), a canonical proof envelope per operation built on **real certified anchors** (the DN-B depth-1 topology puts the leaves of a return under two UCs: UC, native InputRecord opening, RSMT paths, the leaf-to-anchor index and the oracle's gate components) and, for every B1 call of those envelopes, the request bytes and the verdict that the A' reference returned (`RefB1` for 0x0100, `b1ref.Member` for 0x0102, including the verdict `false` for the pre-3.0 value `txHash`), and the native InputRecord openings produced by the SDK's own encoder | Copy `golden_pr5_test.go.txt` to `bridgeprofile/golden_pr5_test.go` in a checkout of that revision, then `BRIDGE_PR5_GOLDEN=<out.json> go test ./bridgeprofile -run TestGenPR5Golden -count=1`. The file is not part of bft-core. |
| `test/bridge/b1-vectors.json` | bft-core `b1ref/testdata/b1-vectors-aprime.json` (#416, independently constructed by `b1ref/b1gen`): the UC and RSMT requests the wrappers must reproduce byte for byte. Unchanged by the SDK 3.0.1 profile (B1 needs no change), and identical at the oracle revision above | `python3 script/bridge-golden/extract-b1.py <bft-core checkout> test/bridge/b1-vectors.json` |

## Sealed corpus pin

`corpus-pin.json` pins the shared corpus (native-bridge-plugins `protocol/vectors`, commit
`e9c140d9…`, manifest digest `61646550…`, SDK trust document SHA-256 `e5454ae4…`), the oracle commit, the
SHA-256 of `golden.json` and the list of golden values the corpus also contains.
`python3 script/bridge-golden/check-corpus.py <corpus checkout>` verifies the corpus files and digest, that
both golden histories embed the trust document digest, that `golden.json` is the pinned bytes, and that each
shared value occurs in the corpus. CI runs it against the pinned commit, so a golden that drifts from the
corpus, or a corpus that moves, fails the build.

To refresh: regenerate `golden.json` at the new oracle revision, update `corpus-pin.json` (commit, digest,
golden SHA-256; `sharedPaths` is every `0x` value of `golden.json` of 32 bytes or more found in the corpus),
and rerun the check. When bft-core and native-bridge-plugins merge, re-pin to the merged commits.

The values `semanticProfileHash`, `b1ProfileHash`, `tokenVerifier` and `tokenVerifierCodeHash` in the
golden Cfg are the oracle's DEV fixture values, not the pinned runtime artifacts of a deployment.

Cfg hash and policy hash are those of the golden file (`cfg.hash`, `policy.hash`); the Cfg field order and
domains are unchanged from the pre-3.0 profile, only the derived `ty` and `aid` (unicity-native family, no
vault) and the profile pins change them. The policy is the v3 sharded body (`UNICITY_BR_AGG_SHARDED`, depth 1).

The bounds the contract enforces (`BridgeBounds`) are the `limits` of `profile-v3.json`; the tests assert the gate
components of `mint.envelope.gate` and `return.envelope.gate` and the worst admitted bundle (6,976,692 of 7,000,000).
