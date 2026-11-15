# NB2-02 gas bake-off: K, B, recent-buffer layout and segment commitment

This harness measures native bridge v2's replay and settlement gas (bft-core#1098, part of #1096) with a mock token
verifier. It runs on its own: the repository's `foundry.toml` never compiles `bench/`, no CI workflow runs it, and it
is not a pull-request gate. Measured tables: [`RESULTS.md`](RESULTS.md) (`optimizer_runs = 200`) and
[`RESULTS-runs1.md`](RESULTS-runs1.md) (the size-first profile the repository applies to `src/nb2/verifier`).

```
bench/nb2/run.sh            # about two minutes; needs forge and python3
RUNS=1 bench/nb2/run.sh
```

The toolchain was forge 1.8.1, with the repository pin: solc 0.8.37, via-IR, optimizer on, EVM Cancun,
`bytecode_hash = none` and no CBOR metadata. The tables were produced on the dev server.

## What is measured

`gen.py` generates one vault per candidate from `templates/` into `src/gen/`, plus the test wrappers into
`test/gen/`; neither directory is committed. Each vault implements the redeem order of spec section 11.1 (range,
gap fold, recent scan, verifier `STATICCALL`, verdict checks, effects, seal, payout), the deposit of section 5.2,
the archive chain of section 10.3 and the `SegmentSealed` event of section 13.2.

| Axis | Candidates |
|---|---|
| Recent buffer | **tags**: flat arrival-order slots plus position tags (spec 9.2), which is in effect the shared 2K-slot arena with packed bucket indices. **sparse**: per-bucket arrays with generation/count words (design v2 section 6.2), where B = 32 needs a second count word. |
| Commitment | **gap**: circular-gap tree (spec 10.1/10.2). **mp**: sorted-leaf tree with an adjacent-leaf multiproof (interior proofs carry 2t + h - 1 - t siblings, plus below-minimum and above-maximum proofs). **radix**: compressed (crit-bit) radix tree, built with a one-pass stack, proof 33 + 33d bytes. **raw**: the flat segment as the control (proof = the 32K sorted bytes, binary-searched). |
| K, B | K in {32, 64, 128}, B in {8, 16, 32} |
| Parameter form | `imm`: K and B as constructor immutables (any power of two, K = 4 included). `cK_B`: compile-time constants. |

**Measurement.** `forge test --isolate` runs each top-level call as its own transaction. A figure is
`vm.lastCallGas().gasTotalUsed`: the whole transaction, with the 21,000 base and the calldata included, and every
account and slot cold, as a wallet's transaction meets them. No refund occurs in any row: the guard is transient
and nothing is ever cleared. The evidence is the mock's 192-byte verdict, so real token evidence and verification
(NB2-05, #1101) come on top.

**Workloads.** Most workloads come from the ticket:

- occupancy m in {0, 1, K/2, K-2, K-1}, where the call at K-1 is the sealing transaction;
- historical segments P in {0, 1, 10, 100};
- the current and the previous endpoint;
- uniform identifiers, or every identifier ground into the claimed identifier's bucket.

The harness adds three more:

- **Arrival orders.** Ground buckets arrive in random, descending or sort-adversarial order. The adversarial order
  has descending 8-element chunks and perfectly interleaved merges.
- **Storage generations.** Segments 0 and 1 are the first writes of each buffer; segment 2 onward is steady state.
- **One-bucket historical segments.**

A uniform cell is the mean of 16 claimed identifiers. A ground-bucket cell is exact.

For P > 0, the P segments are built by the reference, and the vault's segment counter and endpoint head are moved
there with `vm.store`, unmeasured. The vault reads exactly the slots it reads in production.

**Checks.** Every measured seal is checked against `test/Ref.sol`, an independent plain-Solidity reference of all
four commitments and the archive chain. The check covers the exact event length, strict order, the multiset of
paid identifiers, the chain step and the vault's new head. `test/Correctness.t.sol` runs every candidate at
K = 4, 8, 16, 32 (immutables) through several seals with real historical proofs, on both endpoints. It also checks
these refusals: `AlreadyPaid` in the current and the previous buffer, `BadGapProof` for a paid identifier,
`ChainMismatch` for a wrong start head or a tampered sibling, `FutureIndex`, `StaleEndpoint` and
`BadHistoryLength`. Mutating the gap check or the scan comparison makes the suite fail. NB2-04 (#1100) owns the
vault's real test suite; this suite only keeps the measurements honest.

## Results (`optimizer_runs = 200`, tags layout, gap commitment, immutables, steady state)

| | K = 32, B = 16 | **K = 64, B = 16** | K = 128, B = 16 |
|---|---:|---:|---:|
| Typical payment (uniform, current, m = K/2, P = 0) | 59,411 | **63,791** | 71,383 |
| Same, previous endpoint | 69,929 | **78,083** | 103,428 |
| Cheapest call (current, m = 0) | 53,598 | **53,574** | 53,574 |
| Sealing transaction, uniform | 183,429 | **299,630** | 541,341 |
| Sealing transaction, one bucket (sort-adversarial) | 200,993 | **342,766** | 636,935 |
| Worst sealing surcharge (uniform seal minus the call at m = K-2) | 120,569 | **229,830** | 452,534 |
| Worst recent scan (previous, m = K-2, one bucket: 2K-2 reads, minus cheapest) | 140,464 | **282,548** | 571,146 |
| Worst call (previous, m = K-1, one bucket: 2K-1 reads plus a one-bucket seal) | 274,546 | **487,339** | 925,807 |
| Envelope (worst minus cheapest), steady | 220,948 | **433,765** | 872,233 |
| Envelope including segments 0 and 1 | 240,824 | **453,641** | 892,109 |
| Replay per historical segment, gap (gas / bytes) | 5,205 / 225 | **5,950 / 257** | 6,630 / 289 |
| Replay per intervening payment (gas / bytes) | 163 / 7.0 | **93 / 4.0** | 52 / 2.3 |
| P = 10 / P = 100 historical segments | 115,384 / 583,795 | **126,393 / 661,926** | 146,367 / 743,042 |
| Capacity at L_max = 512 KiB, 20 KiB evidence, 2 KiB framing (segments / payments) | 2,230 / 71,360 | **1,952 / 124,928** | 1,736 / 222,208 |

Deposit: 48,758 for the first (the accounting word goes from zero to nonzero) and 31,670 in steady state. The
`RESULTS-runs1.md` figures agree with these within about 2%, because almost all of the hot code is inline
assembly.

### Commitment (K = 64, uniform segments)

| | gap | multiproof | radix | raw |
|---|---:|---:|---:|---:|
| Gas per historical segment | 5,950 | 5,746 | 5,389 | 34,733 |
| Mean proof bytes | 257 | 246 | 222 | 2,048 |
| Worst-case proof bytes | **257 (fixed)** | 385 | 2,112 (d = K-1, grindable) | 2,048 |
| Sealing transaction, uniform | 298,872 | 295,114 | 320,385 | 274,060 |

### Layout (K = 64, B = 16)

| | tags | sparse |
|---|---:|---:|
| Cheapest / typical (m = K/2) payment | 53,574 / 63,791 | 58,779 / 69,909 |
| Envelope, steady | 433,765 | 406,586 |
| Identifier slots, hard bound | 128 | 2,048 |
| Late zero-to-nonzero slot writes | none after segment 1 | at every new bucket high-water mark |

## Recommendation

- **K = 64**
- **B = 16**
- **Position tags**
- **Circular-gap tree**
- **K and B as constructor immutables**
- **gasReserve = 500,000**

The reasoning, one choice at a time:

- **K = 64.** Typical cost hardly depends on K, and the amortised seal is about 3.6k per payment at both 64 and
  128. Larger K trades a smaller replay cost (93 against 52 gas per intervening payment) and 1.8 times the
  capacity against twice the peak seal and twice the gas-limit envelope (434k against 872k). It also costs 7.6k
  more per typical payment, which K = 128 wins back only after about 185 intervening payments. K = 64 already
  covers about 125,000 intervening payments at 512 KiB (Section 12.5), far beyond `returnReserveSegments = 64`.
- **B = 16.** It keeps one tag word per buffer at K = 64. B = 32 saves about 2.5k on a typical payment but needs
  two tag words and widens the envelope by 10k. B = 8 doubles the expected matches. Grinding defeats any B, so B
  only shapes typical cost.
- **Position tags.** They are cheaper on every ordinary payment (one cold read fewer). Their storage is bounded at
  2K slots, and once segment 1 is done they never write a slot from zero again. The sparse layout's only gain, a
  6% smaller envelope, is cancelled by its late high-water writes (about 17.1k each).
- **Circular-gap tree.** It is within about 10% of the best average per-segment cost (radix; the multiproof is 3.5% cheaper). It is the only candidate with
  a fixed proof size, which the size preflight (12.5) and the history-length rule of 11.1 depend on. The
  multiproof's worst case is 50% larger. The radix proof can be ground to about K times larger against a known
  identifier, and its seal costs 21k more. The raw control is six times dearer per segment.
- **Immutables.** They cost 170 to 350 gas per payment, about 7k per seal at K = 64, about 185 gas per historical
  segment and 1.9 KB of code. That is cheap for one code base that runs both K = 4 tests and the production lane.
- **gasReserve = 500,000.** The measured envelope is 453,641 including the first-generation segments; the reserve
  rounds it up by about 10% for NB2-04's own implementation. The worst sealing surcharge (229,830) plus the worst
  recent scan (282,548) overstates the envelope, because identifiers the scan already read are warm when the seal
  reads them.

## Analytic estimates of the design, checked

| Estimate (design v2 section 10) | Measured | Verdict |
|---|---|---|
| 5,000 to 8,000 gas per historical segment at K = 64 (primitive 4,508) | 5,950 | confirmed |
| Recent lookup about 4,200 (current) or 12,600 (previous) at K = 64, B = 16, m = 32 | 7,700 or 22,000 above the m = 0 call | corrected: the tag loop and the previous buffer's tag word roughly double it |
| Worst previous-endpoint lookup about 266,700 for 127 cold reads | 282,548 for 126 reads with loops | confirmed |
| Non-sealing budgets 60–110k (P = 0), 65–118k (1), 110–190k (10), 560–910k (100) | 53.6–88k, 72.9k, 126.4k, 661.9k | confirmed, at the low end |
| Sealing surcharge 180,000 to 350,000 at K = 64 | 229,830 (uniform); a one-bucket seal is 342,766 in total | confirmed |
| Segment log 17,000 to 19,000 per seal | 18,533 (analytic, inside the seal) | confirmed |
| Deposit 30–60k; the first accounting write adds about 17,100 | 31,670 and +17,088 | confirmed |
| gasReserve planning value 620,000 (180–350k seal plus a 266,700 scan) | envelope 453,641 | corrected to 500,000 |
| Heapsort for long buckets | heapsort of one bucket of 64: about 92k; the hybrid merge sort here: about 45k (random) to 52k (sort-adversarial order) | prefer the hybrid; the spec's "such as heapsort" allows it |

## Notes for NB2-04 (#1100)

These were learned while making the harness representative. None of them changes the wire format.

- **Heads by parity.** Store `H[j mod 2] = H_j`. A seal then writes one head slot, not two.
- **One accounting write.** Write the accounting word once per redemption, the seal's `c + 1, m = 0` included.
  Keep the guard in transient storage.
- **Sorting.** Long buckets use insertion-sorted chunks of 8, then bottom-up merges through scratch memory with
  `MCOPY`. Its worst order is the "sort-adversarial" one in the tables. Heapsort costs about twice as much (about 92k against
  about 50k for one bucket of 64).
- **Gathering.** The seal gathers identifiers by a counting pass over the tag words, then a scatter that checks each
  identifier's bucket against its tag. It does not re-read the newest identifier.
- **Memory-safe assembly.** All assembly must be `memory-safe`. Without that, via-IR runs out of stack in `redeem`.

## Spec changes requested (sent to the NB2-01 agent through the orchestrator)

1. **Section 4.1 and the PARAM blocks.**
   - Set `K = 64`, `B = 16`, recent-buffer layout = position tags, segment commitment = circular-gap tree, and K and
     B as constructor immutables.
   - The admitted `(K, B)` set becomes production `(64, 16)` plus the test pair used by the K = 4 lane (proposed
     `(4, 2)`), not the full candidate grid.
2. **Section 12.4.** `gasReserve = 500,000` at K = 64, B = 16. Define it as the measured envelope (most expensive
   call minus the cheapest, first-generation segments included) rounded up, not as the sum of the two worst
   cases.
3. **Section 15.** Replace the parameter table's defaults with the chosen values and point to this harness for the
   measurements.
