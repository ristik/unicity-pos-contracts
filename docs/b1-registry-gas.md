# B1 registry: layout, update projection and the bounded `G_rest` analysis

Scope: bft-core #62 (B1), PR 3 of 4, from the A′ design (`briefs/b1-design-v4.md`: "full authenticated
root members in deterministically pruned ordinary EVM state"). Nothing here activates in production:
the registry has no deployment, and the genesis and update bytes below are the contract the Go (PR 1)
and ureth (PR 2, PR 4) sides pin against.

## What the registry stores

One fresh layout, no layout-version word, no migration. Fixed words are
`F(name) = keccak256(UTF8("unicity.seal-registry/" || name))`. All operational fields keep their
meaning under the new prefix; `layoutVersion` is deleted and `b1.initialized` takes its place in the
open-time initialization check.

| Word | Meaning |
|---|---|
| `b1.network`, `b1.wCert`, `b1.profileHash` | immutable profile words (genesis only); `K_max = b1.wCert + 1` |
| `b1.initialized`, `b1.head`, `b1.count` | mutable: `initialized = 1` at genesis; `head < K_max`; `count` distinguishes an occupied epoch-zero word from emptiness; `head` resets to 0 when the ring empties |
| `Q(i) = keccak256(abi.encode(F("b1.queue"), uint256(i)))` | ring slot `i < K_max`: the epoch stored there |
| `E(e,f) = keccak256(abi.encode(F("b1.entry"), e, f))`, `f = 0..10` | `present=1, bodyKind, bodyID, activationCommitID, start, end, hasEnd, signingScheme, signingConfigHash, memberCount, totalWeight` |
| `M(e,j,f) = keccak256(abi.encode(F("b1.member"), e, j, f))`, `f = 0..7` | `nodeIDLength`, four nodeID words (wire order, left-aligned, zero right padding), two key words (33-byte compressed key: bytes 0..31, then byte 32 left-aligned), `weight` |

An entry is at most `11 + 8*64 = 523` addressed words plus one queue word; live B1 storage is at most
`6 + 524*K_max` addressed words. Deletion clears every metadata word, every member word and the queue
word: no tombstones, no stale tails.

`artifacts/seal-registry.json` records the compiled runtime and code hash, every fixed slot key, the
three prefix keys, the field lists, the bounds, the genesis word list and the gas constants. CI
regenerates it with `script/seal-registry-artifact.sh`; `test/SealRegistryArtifact.t.sol` checks it
against independent derivations.

## The privileged update (`open`)

`open(...)` keeps the 24 operational arguments and gains a final `B1Update` (selector `0x724236c0`):

```
B1Update { uint64 priorTipEpoch; bool hasOldTipEnd; uint64 oldTipEnd; B1Entry[] newEntries }
B1Entry  { uint64 epoch; uint64 bodyKind; bytes32 bodyID; bytes32 activationCommitID; uint64 start;
           bool hasEnd; uint64 end; uint64 signingScheme; bytes32 signingConfigHash; B1Member[] members }
B1Member { uint64 nodeIDLength; bytes32[4] nodeID; bytes32[2] key; uint64 weight }
```

This is the Rust-validated projection of the authenticated canonical Update. The origin round `O`
(`rootRound`), origin epoch (`rootEpoch`), origin identity and block number are the existing `open`
arguments and are not repeated; network, profile hash, parent hash, root genesis and execution chain
identity are bound by the committed root input and the Rust bindings and are not re-checked here. The
update is decoded **from calldata** (no memory copy), so memory does not grow with the update.

With `L = max(0, O - W_cert)`, `open` applies, on the one disposable candidate:

1. Operational checks (unchanged except that a stale root round is now refused on the acknowledgement
   path too: the clock must be monotone on every open).
2. Parent binding: `count` in `1..K_max`, `head < K_max`, the tail is open, and `priorTipEpoch` is the
   tail epoch. New entries are present iff `oldTipEnd` is supplied; `oldTipEnd` must exceed the tail's
   start.
3. Prune from the head while the entry's effective end is `<= L` (equality removes; `end = L + 1` is
   retained; the open tail and a boundary-crossing predecessor are retained however old). The former
   tip's effective end is `oldTipEnd`; a deleted tip is never closed first.
4. If the former tip survives, write `end`/`hasEnd` once; its successor must be epoch `tip + 1`
   starting at `oldTipEnd`. If everything expired, the first new entry must have a later epoch and
   `start <= L`.
5. Append the new entries into freed ring slots after pruning (occupancy never exceeds `K_max`; a
   survivor plus insertion over `K_max` is `RingFull`): consecutive epochs, `end` = next start, only the
   last open, no closed entry with `end <= L`, `start <= O`, epoch absent, and the shared entry shape
   rules (1..64 members, nodeIDs 1..128 bytes with zero padding, strictly increasing raw nodeID order
   which also refuses duplicates, compressed-key prefix 02/03 with zero padding, positive weights with
   a checked u64 total, non-zero body/signing-config identities and, for non-genesis entries, a
   non-zero activation identity).
6. The final tail must be the origin epoch. `finalize` re-asserts a non-empty ring within `K_max`
   whose tail is present, open and equal to `origin.rootEpoch`.

Any error reverts the whole call: no partial deletion or insertion is publishable. The contract does
not verify signatures, key curve points, key uniqueness or lineage: the paired Go node authenticates
the history and the Rust client validates full member semantics before execution. Only `A_SYS` can
call `open`/`finalize`; there is no other mutating entry point, no delegatecall, no create, no
selfdestruct.

## Genesis

There is no constructor. `src/B1GenesisBuilder.sol` (never deployed) builds the genesis allocation's
non-zero words from `B1GenesisParams`, passing the genesis entry through the same `B1Layout.checkEntry`
as runtime entries, and refuses: `W_cert <= delta_ev < delta_hold` violations or `K_max` overflow,
`g_sys` below the envelope below, `G_rest` below the frozen bound, a genesis entry that is not the open
interval of the root genesis epoch. `test/SealRegistryB1Genesis.t.sol` pins the fixture's storage
digest so an independent builder can be compared word for word.

## Gas: the envelope and `G_rest`

Design v4 requires, before activation,

```
g_sys >= 67536 + 326144*K + 22100*(524*K + 4) + 7100*524*K + G_rest(K, C_max)
```

The `22100`/`7100` terms are a conservative SSTORE rectangle (every addressed write at the cold
zero-to-non-zero price, every clear at 7100, no refund credit); `G_rest` bounds everything else in
`open` + `finalize`. The registry meters ordinarily (gross), so the rectangle and `G_rest` are an
activation check, not a runtime debit.

**Loop analysis.** Every loop is bounded by a count that is checked first: the prune loop by `count <=
K_max` (each iteration clears `11 + 8*m` words with `m <= 64` read from storage), the insertion loop by
`a <= K_max` (each entry: `checkEntry` over `<= 64` members, 4 nodeID words each, then `523` writes), and
`finalize` is constant. There is no recursion, no external call and no allocation per word (slot
hashes use temporary memory above the free pointer without moving it), so non-storage gas is affine in
`K`: `G_rest(K) = c0 + c1*K`. `C_max` (the calldata size of the update) adds no term beyond what is
measured: calldata is read in place.

**Measurement.** `test/SealRegistryB1Gas.t.sol` runs the worst entry (64 members, 128-byte node IDs,
523 words) at `K_max` in `{1,2,4,8,16}` in three shapes: *replace* (a full ring deleted and `K` new
entries inserted, `p = a = K`), *insert* (`p = 0`, `a = K - 1`) and *prune* (`p = K - 1`, `a = 0`).
The insert shape is tight: every addressed write is a fresh set, so the rectangle has no slack and the
calibrated set/read costs (measured with a slot loop in the same environment) can be subtracted to leave
`G_rest` exactly. Deletions are bounded against the rectangle's `7100` per clear (the EVM charges at
most `5000`), whose slack covers the per-word non-storage work.

| `K_max` | insert: gross (open + finalize) | rectangle (`a=K-1`) | measured `G_rest` | frozen `G_rest(K)` | replace: gross | rectangle (`a=p=K`) |
|---|---|---|---|---|---|---|
| 1 | n/a | n/a | n/a | 1 250 000 | 12 889 834 | 15 389 200 |
| 2 | 12 729 045 | 11 668 800 | 620 675 | 2 250 000 | 25 258 600 | 30 690 000 |
| 4 | 37 032 593 | 34 829 600 | 1 716 480 | 4 250 000 | 49 977 361 | 61 291 600 |
| 8 | 85 699 070 | 81 151 200 | 3 916 000 | 8 250 000 | 99 455 382 | 122 494 800 |
| 16 | 182 971 262 | 173 794 400 | 8 305 749 | 16 250 000 | 198 406 254 | 244 901 200 |

Measured `G_rest` is about `550 000` per inserted entry plus about `70 000` fixed (finalize alone is
`~67 000`, including its cold reads). The frozen bound is `G_rest(K) = 250 000 + 1 000 000 * K`: at
least 1.8x the measured per-entry insertion cost, which also leaves room for the per-word non-storage
work of deletions (inside the rectangle's slack). The fixtures fail if the runtime ever exceeds the
bound, and the bound is part of the artifact.

**Limits of this evidence.** These are gross-gas measurements under forge's test EVM with the pinned
compiler profile, not a claim about the final client: ureth PR 4 must repeat them under the real client
(same envelope, real DB, x86-64 and arm64) before activation, and any change to the runtime, compiler
profile or the entry bounds invalidates the frozen constants. Under forge, clears of seeded slots were
observed to cost less than the EVM's `5000`, which is why the deletion shapes are checked against the
rectangle rather than used to derive `G_rest`. `K_max` is bounded only by `g_sys`: the profile check
above refuses a `W_cert` the budget cannot cover; live history is never truncated.

`test_deletionRefundsDoNotFundTheCall` shows the gross rule on the maximal replacement: the call earns a
non-zero refund, a budget equal to gross minus the maximum refund fails with no state change, and a
gross budget succeeds. `test_aBudgetShortOfTheNeededGasDiscardsTheWholeCandidate` shows an
out-of-gas candidate leaves no partial deletion or insertion.
