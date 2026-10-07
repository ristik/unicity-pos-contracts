# Bridge golden vectors

`test/bridge/golden.json` and `test/bridge/b1-vectors.json` pin the Solidity code to bytes produced by the
Go oracle and the A' reference oracle; no value in them was written by hand.

| File | Source | Regenerate |
| --- | --- | --- |
| `test/bridge/golden.json` | bft-core `bridgeprofile` on the SDK 3.0.1 profile (native bridge protocol v2), **candidate** oracle revision `8745b71942eb7d81d89e4142baf5eae30e34a14d` (bft-core branch `bridge/sdk3-rebase`, bridge PR2, not yet merged or pushed when this file was generated; it is the revision the candidate corpus `1b7180d7…62df5` was produced from). Contents: Cfg and the unicity-native identifiers, identity-family vectors, policy, derivations, storage slots and trie keys, RLP words, kernel inputs and outputs (`448+128*m` bytes), a canonical proof envelope per operation built on a **real certified anchor** (UC, native InputRecord opening, RSMT paths) and, for every B1 call of those envelopes, the request bytes and the verdict that the A' reference returned (`RefB1` for 0x0100, `b1ref.Member` for 0x0102, including the verdict `false` for the pre-3.0 value `txHash`), and the native InputRecord openings produced by the SDK's own encoder | Copy `golden_pr5_test.go.txt` to `bridgeprofile/golden_pr5_test.go` in a checkout of that revision, then `BRIDGE_PR5_GOLDEN=<out.json> go test ./bridgeprofile -run TestGenPR5Golden -count=1`. The file is not part of bft-core. |
| `test/bridge/b1-vectors.json` | bft-core `b1ref/testdata/b1-vectors-aprime.json` (#416, independently constructed by `b1ref/b1gen`): the UC and RSMT requests the wrappers must reproduce byte for byte. Unchanged by the SDK 3.0.1 profile (B1 needs no change), and identical in the candidate revision above | `python3 script/bridge-golden/extract-b1.py <bft-core checkout> test/bridge/b1-vectors.json` |

When bft-core PR2 merges, regenerate `golden.json` at the merged revision (and, once the single
corpus lands in native-bridge-plugins `protocol/vectors`, compare the shared cases) and update the revision
above. The values `semanticProfileHash`, `b1ProfileHash`, `tokenVerifier` and `tokenVerifierCodeHash` in the
golden Cfg are the oracle's DEV fixture values, not the pinned runtime artifacts of a deployment.

Cfg hash and policy hash are those of the golden file (`cfg.hash`, `policy.hash`); the Cfg field order and
domains are unchanged from the pre-3.0 profile, only the derived `ty` and `aid` (unicity-native family, no
vault) and the profile pins change them.
