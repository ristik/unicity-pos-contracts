# NB2-05: the v2 token and receipt verifier, measurements and the decision gate

Ticket ristik/bft-core#1101. Spec: bft-core `docs/design/native-bridge-v2.md` sections 6, 7, 8, 11.2 and 14 (protocol 9).
Vectors: native-bridge-plugins `protocol/vectors/nb2/nb2-vectors.json`, pinned in `test/nb2/vectors/` by its sha256.

## What is built

`src/nb2/verifier/`. `NativeBridgeVerifierV2` implements `INativeBridgeVerifierV2.verifyReturn(Γ, evidence)`. It checks
in the frozen order of section 11.2 and reverts with the section 14 rule `<Name>()`.

All bridge semantics are EVM bytecode:
- Γ and D.
- The strict CBOR scanner and the SDK token wire.
- The split walk, allocation proofs and sums.
- J and the receipt-backed origin: Cancun header, receipt-trie path, typed receipts, the Deposited log, secret opening,
  salt, type, owner and data.
- Unlocks, the minter key, state IDs, deadlines and reference times.
- The return burn, btid and eta.

Native code is used only through the generic primitives:

| Address | Primitive | Used for |
|---|---|---|
| `0x0100` | CERT_BATCH_V2 | each certificate's seal under its epoch's historical authority |
| `0x0102` | RSMT membership | each inclusion proof |
| `0x01` | ecrecover | unlock signers; the universal minter key, as `k·G` |
| `0x02` | SHA-256 | H_U |
| `0x05` | modexp | key decompression and the on-curve check |

The `0x0105` bridge composition is not used.

**Certificates are judged locally up to the seal root.** That covers encoding, network, structure and folds. Their
authority verdict (epoch entry, round interval, quorum) is a claim. Claims are collected in check order, deduplicated, and
flushed in balanced calls of at most 16 claims. A flush runs before the first later refusal and before acceptance. A false
call is re-checked one claim at a time, and the earliest failing claim refuses: QuorumNotMet for an aggregator UC,
DepositUC for the EVM UC. This is the on-chain classification ruled on 2026-11-15 (spec §11.2, §11.3, §14.4,
`onChainError` in the vectors).

**Unlock recovery IDs 2 and 3** are UnlockRecovery (the NB2 restriction, astra's delta review).

**EIP-170.** The receipt path (EVM UC, header, trie, receipt, log) and each aggregator certificate's local checks are
`Nb2ReceiptVerifier`, a second contract (about 6,000 gas per hop for the extra call). The
verifier creates it in its constructor and holds it as an immutable, so `verifierCodeHash` pins both.

| Contract | Runtime bytes |
|---|---:|
| Verifier | 18,716 |
| Receipt helper | 12,452 |

**Revert data** is always the 4-byte `<Rule>()` (or `CertBatchFailed()`, `MembershipFailed()`, `InvalidMinterScalar()`),
at most 36 bytes for `PrecompileFailed(uint256)` or a compiler panic, far below the vault's 1024-byte `VerifierRefused`
bound. Acceptance returns exactly the 192-byte verdict. `test_returnAndRevertSizes` asserts both over every vector.

**The build selector `admitsTestSet`** (the production (64, 16) set, or the test {4, 8} × {2, 4} set) is an immutable. The two
builds therefore have different code hashes (`test_buildsHaveDistinctCodeHashes`).

## Tests (`test/nb2/verifier`, about 8 s)

Every verifier vector (114) is checked byte for byte against the Go reference (nb2ref), whose output the vectors are:
- an accepted vector returns exactly its 192-byte verdict;
- a refused vector reverts with exactly its `expect.revert` bytes.

There is no second corpus.

The vectors cover these cases:
- hostile lineage: changed amounts, owners and assets, a parent that both splits and returns, alternate proof encodings,
  counterfeit deposit evidence;
- epoch change between deposit and burn (`test_epochChangeBetweenDepositAndBurn`);
- the multi-fault `SealRoot-before-epoch`.

The suite also runs:
- the config vectors (ConfigShape);
- the seal receipts, through the same receipt path, with their inner rule;
- the gap, chain-fold and segment-log vectors;
- the minter-scalar primitives and constants.

`0x0100` and `0x0102` are test doubles (`Nb2Doubles.sol`). The certificate-batch double holds the vectors' trust history,
derived by `script/nb2/trust-fixture.py`. Precompile behaviour itself is covered by the ureth unit tests and fixtures.

## Measurements

**Method.** Measured in forge, with the verifier's own execution timed inside the call. The doubles' gas is replaced by the
native schedules:
- CERT_BATCH_V2: `60,000 + 16C + 500k(k-1) + 1,100 + 29,900E + 7,200Q + 2,000A + 250P`;
- membership: `2,000 + 16L + 250(1+d)`;
- plus 100 gas for each warm precompile call.

Calldata is the evidence at 16/4 gas per byte. The larger tokens come from the same deterministic world as the vectors
(`script/nb2/large_tokens_test.go.txt`, verified by the Go reference first; a subset is in `test/nb2/verifier/large.json`).
Compiler: solc 0.8.37, via-IR, Cancun, `optimizer_runs = 1` (size-first, like `src/bridge`).

| Token | Evidence bytes | Verifier exec | of which 0x0100 | of which 0x0102 | Calldata | Total |
|---|---:|---:|---:|---:|---:|---:|
| mint + burn | 4,242 | 690,772 | 201,424 | 11,900 | 57,900 | 748,672 |
| mint + transfer + burn | 5,208 | 843,577 | 240,216 | 16,326 | 72,852 | 916,429 |
| reference token, part 60 (one split) | 7,527 | 1,298,645 | 320,816 | 28,226 | 108,912 | 1,407,557 |
| reference token, part 25 (two splits) | 9,758 | 1,707,872 | 405,400 | 40,126 | 143,672 | 1,851,544 |
| 20 transfers | 24,586 | 3,942,427 | 1,126,328 | 124,804 | 374,068 | 4,316,495 |
| 50 transfers | 55,519 | 8,973,617 | 2,589,216 | 304,066 | 854,956 | 9,828,573 |
| 20 nested splits | 68,944 | 13,478,204 | 3,084,152 | 355,946 | 1,064,812 | 14,543,016 |
| 40 nested splits | 133,774 | 28,109,697 | 6,025,912 | 702,278 | 2,073,400 | 30,183,097 |
| 80 nested splits (not committed; before the certificate move below) | 263,214 | 65,646,021 | 11,957,464 | 1,389,608 | 4,086,648 | 69,732,669 |

**Per hop.** Each additional transfer, with its own UC (one seal of 3 signatures), costs:

| Component | Gas |
|---|---:|
| Solidity | 112,108 |
| 0x0100 | 47,939 |
| 0x0102 | 5,857 |
| Calldata | 15,950 |
| **Total** | **181,855** |

That hop adds 1,026 bytes. Each nested split level (a hop, the split burn and the child mint) adds 3,238 bytes and about
739,000 gas.

**Origin receipt on its own.** The Solidity side costs 187,156 gas: J's scan and decode, the EVM UC, the header, the
receipt-trie path, the receipt and log, and the deposit checks. The EVM UC's 0x0100 claim adds about 35,800 gas when it
shares a batch call, or about 126,800 gas in a call of its own. J's calldata is about 2.0 KB, about 31,000 gas. In total
that is about 255,000 gas marginal, or 345,000 gas standalone. The design's "about 100k / 2 KiB" hypothesis is low by about
2.5×.

**Against the 500,000 reserve.** A return's gas limit is the vault's replay and settlement cost, plus `gasReserve` 500,000,
plus the verifier's cost. For the two-split reference part at P = 0 that is about 63,800 + 500,000 + 1,852,000, about
2.42M. The verifier, not the segment replay, dominates every realistic return.

**Largest token history.**
- *Bytes.* 512 KiB of evidence holds about 500 transfers or about 160 nested split levels.
- *Gas.* Gas binds long before bytes. At about 182k gas per transfer, a 512 KiB token needs roughly 90M gas.
- *At a 30M userGasLimit (PARAM, not pinned):* the largest admitted history is about 155 transfers (about 160 KB), or about
  40 nested split levels (133 KB, 30.2M gas: at the limit).
- *At 20 KiB of evidence:* about 3.4M gas (about 16 hops).

**Where the Solidity gas goes.**
- The strict scanner costs about 460 gas per CBOR item (225 items for a two-transaction token).
- The typed decode is a second walk.
- Each aggregator UC's strict acceptance (map order, UTF-8, shape) costs about 27,000 gas, and its folds about 4,000.
- These are EVM parsing costs, not avoidable checks.

## Decision gate (with the owner)

**Option 1: Solidity over the existing generic primitives, as built.**
- It works and passes every vector.
- It costs about 0.9M gas for a two-transaction token, about 1.85M for the reference part, and about 182k per further hop.
- With a 30M userGasLimit, about 160 hops fit.

**Option 2: one additional generic native primitive** for token-transition and lineage validation, with no vault knowledge.
- Candidate: extract the lineage code of the current `0x0105` crate.
- It would replace the 112k of Solidity per hop with a native charge, estimated at 20k to 30k per hop (16 gas per input byte
  plus signatures and hashes).
- The 0x0100 batch, 0x0102 and calldata, about 70k per hop, remain.
- The total per hop would fall from about 182k to about 95k (about 1.9×). A 30M gas limit would admit about 300 hops instead
  of about 160.
- The cost: new ureth consensus surface, a pin bump, CI cost, and a second implementation to keep equal to the reference.

**Default taken (recorded for the owner in `briefs/owner-questions.md`): option 1 for the first release.**
- It meets "working" with no new native code.
- Option 2's gain is bounded (under 2× per hop), because certificates and calldata dominate once the parsing is native.
- Revisit if the production userGasLimit is below about 10M, or if expected tokens exceed about 50 hops.
- Certificate consolidation (several transactions under one UC) cuts the 0x0100 share without any new primitive: identical
  claims are charged once per call.

NB2-10 (#1106) can therefore remove `0x0104`/`0x0105` unless the owner picks option 2.
