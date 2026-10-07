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

The `22100`/`7100` terms are a conservative rectangle for the **history** SSTOREs only (every
addressed history write at the cold zero-to-non-zero price, every clear at 7100, no refund credit).
`G_rest` is everything else in `open` + `finalize`: SLOADs, slot hashing, calldata decode, memory, the
event, **the operational-registry writes** and **the whole of `finalize`**. The registry meters
ordinarily (gross), so the rectangle and `G_rest` are an activation check, not a runtime debit.

**Frozen bound.** `G_rest(a, p) = 1 000 000 + 800 000*a + 200 000*p` for `a` inserted and `p` deleted
entries; since `a <= K_max` and `p <= K_max`, `G_rest(K_max) = 1 000 000 + 1 000 000*K_max`. The
constants are in `B1GenesisBuilder` and the artifact. They hold for the pinned runtime and compiler
profile (`0.8.37`, IR, optimizer 200 runs) only.

### Accounting: where the gas can go

Every loop's bound is checked before the loop runs, and every iteration is a straight-line block, so
non-history cost is affine in `(a, p)` with no term in `K_max` alone.

| Block | Bound (checked first) | Per-iteration work outside the history SSTOREs | Data-dependent branches |
|---|---|---|---|
| operational checks | none | a fixed set of cold SLOADs; 15 effect writes, and on the acknowledgement path 11 more writes and one fixed-size log | `transitionCount` 0 or 1: the acknowledgement path is the superset |
| parent binding | none | `head`, `count`, queue slot, tail words (cold SLOADs) | none (reverts are cheaper than success) |
| prune loop | `count <= K_max` (`B1StateInvalid`), so `p + 1` iterations | one queue slot, two entry words (or the supplied tip end), then in `_deleteEntry` one `memberCount` load, `8*m + 12` slot hashes (2 to 4 words each) | the `count == 1` select; break |
| closure | none | two writes, only when the tip survives | survives or not |
| insert loop | `a <= K_max` (`TooManyEntries`) | one presence SLOAD, `checkEntry`, `523` slot hashes and calldata reads | see below |
| `checkEntry` per member | `m <= 64` (`BadMemberCount`) | node ID padding (4 fixed words), key prefix, weight sum, ordering | `_lessThan` exits at the first differing node-ID word (1 to 4 words, then length) |
| `finalize` | none | nine cold SLOADs, 2 writes | none |

The calldata update is read in place (no copy), slot hashes use scratch memory above the free pointer
that is never kept, and no call, create or recursion exists, so memory does not grow with the update.
The only per-member data-dependent code is the ordering comparison, so the fixtures drive its worst
branches: **variant 0** members differ in node-ID word 0 (the comparison exits at its first word),
**variant 1** members share a 96-byte prefix and differ in word 3 (four words compared), **variant 2**
node IDs are all-zero bytes of lengths 1 to 64 (all four words equal, ordered by length). Entries with
fewer members or shorter IDs cost strictly less in every block above.

### Method

`test/SealRegistryB1Gas.t.sol` runs the real `open` and `finalize` against committed state with every
first storage access cold (`vm.cool`), records the storage accesses, and prices each SSTORE with the
exact Cancun rules (EIP-2929, 2200, 3529: 2100 cold surcharge; 100 when the value is unchanged or the
slot is dirty; 20000 for a clean zero to non-zero; 2900 for any other clean change). That model is
itself tested against the EVM (`SealRegistryB1GasModelTest`: a cold set is 22100, a cold clear or
overwrite 5000, a dirty rewrite 100, a cold read 2100, a warm read 100, a write after a cold read 2900).

Two properties of the test EVM matter and are handled explicitly. First, calls from the test body start
cold, so each of `open` and `finalize` is priced as its own cold call (conservative). Second, the test EVM
credits the capped refund to the call that earned it, so a raw `gasleft()` difference around a call that
clears slots is **net**; the fixtures add the credit (`lastFrameGas().gasRefunded`) back to get gross
(`test_theFixturesAddBackTheRefundCreditSoGrossIsMeasured` calibrates this against a control with no
refund). Earlier fixtures measured net gas and so saw deletions cheaper than the EVM's 5000.

For each fixture:

```
history = exact price of every write to a history slot (what the rectangle covers)
rest*   = gross - history - (operational writes, exact) + 28 * 22100
```

`rest*` keeps every SLOAD, the event and finalize in `G_rest`, and re-prices the operational writes
(at most 26 in `open`, 2 in `finalize`) at the 22100 worst case whatever their state. Every fixture
asserts `rest* <= G_rest(a, p)`, `rest* <= G_rest(K_max)`, `history <= rectangle(a, p)` (with the
write-count premises: non-zero history writes at most `524*a + 4`, all history writes at most
`524*(a + p) + 4`, a non-zero write at most 22100, a write of zero at most 5000), and the end-to-end
`gross <= rectangle + G_rest(K_max)`.

Shapes, all with 64 members and 128-byte node IDs (variant 2: lengths 1 to 64), at `K_max` in
`{1, 2, 4, 8, 16}`: **replace** (full ring deleted, `K` entries inserted, `a = p = K`), **mixed** (a
full ring loses `K - 1` entries, the surviving tip is closed, `K - 1` inserted), **insert** (a ring of one
open tail gains `K - 1`, `p = 0`), **prune** (`K - 1` deleted, `a = 0`).

### Measured `rest*` (worst node-ID variant, variant 1)

| `K_max` | replace (`a=p=K`) | mixed (`a=p=K-1`) | insert (`a=K-1`) | prune (`p=K-1`) | frozen `G_rest(K_max)` |
|---|---|---|---|---|---|
| 1 | 1 482 921 | n/a | n/a | n/a | 2 000 000 |
| 2 | 2 233 622 | 1 490 882 | 1 363 236 | 851 362 | 3 000 000 |
| 4 | 3 732 587 | 2 990 290 | 2 607 343 | 1 106 663 | 5 000 000 |
| 8 | 6 730 442 | 5 988 145 | 5 094 623 | 1 617 238 | 9 000 000 |
| 16 | 12 720 398 | 11 978 881 | 10 064 191 | 2 638 406 | 17 000 000 |

Fitted unit costs: about 620 000 per inserted entry (`checkEntry` and the `523` slot hashes), about
130 000 per deleted entry (the `523` slot hashes and loads), and a base near 750 000 (28 operational
writes at 22100 is 619 000 of it, plus cold reads, the log and finalize). The frozen constants leave
at least a 1.29x margin on every fixture (replace 1.34x; insert at `K_max = 16` is the tightest), and the
fixtures fail if the runtime ever exceeds them. The full per-fixture figures (gross, history SSTORE,
rectangle, operational SSTORE, SLOAD) are printed by `forge test --match-path
test/SealRegistryB1Gas.t.sol -vv`.

**Limits of this evidence.** These are gross-gas measurements under forge's test EVM, not a claim about
the final client: ureth PR 4 must repeat them under the real client (same envelope, real database,
x86-64 and arm64) before activation, and any change to the runtime, compiler profile or the entry bounds
invalidates the frozen constants. The bound is derived for the maximal shape (64 members, 128-byte IDs,
`K_max` entries); the linear form extends to any admitted `K_max` because no block above depends on
`K_max` except through `a` and `p`. `K_max` is bounded only by `g_sys`: the profile check above refuses a
`W_cert` the budget cannot cover; live history is never truncated.

`test_deletionRefundsDoNotFundTheCall` shows the gross rule on the maximal replacement: the call earns a
non-zero refund, a budget equal to gross minus the maximum refund fails with no state change, and a
gross budget succeeds. `test_aBudgetShortOfTheNeededGasDiscardsTheWholeCandidate` shows an
out-of-gas candidate leaves no partial deletion or insertion.
