# B1 permanent registry: layout, update and the bounded `G_rest` analysis

Scope: the registry of any-age UC verification (`briefs/b1-any-age-contract.md` section 1, design `b1-any-age-by-signatures.md`). Every
validator epoch the root authenticates is stored once, in full, and kept forever: no window, no ring, no pruning, no deletion. The
reference state machine is bft-core `b1state.Registry.Apply`; this contract mirrors it, one named error per Go sentinel.

## What the registry stores

One fresh layout; `b1.format` = 2 is its only version marker. Fixed words are
`F(name) = keccak256(UTF8("unicity.seal-registry/" || name))`.

| Word | Meaning |
|---|---|
| `b1.network`, `b1.format`, `b1.profileHash` | immutable (genesis only): network, the format (2), the execution profile hash |
| `b1.initialized` | 1 at genesis |
| `b1.genesisEpoch` (g) | the first epoch of this deployment; zero is a valid occupied epoch (an absent word reads zero, the entry's `present` word says it exists) |
| `b1.importedTipEpoch` (I) | the greatest contiguously installed epoch; the durable import cursor (the number of entries is `I - g + 1`, derived) |
| `b1.originReady` | 0 before the first usable root origin, 1 after |
| `origin.rootEpoch` (U), `clock.rootRound` (O) | the usable origin, as before; once ready `g <= U = I` |
| `E(e,f) = keccak256(abi.encode(F("b1.entry"), e, f))`, `f = 0..11` | `present=1, bodyKind, bodyID, activationCommitID, start, end, hasEnd, signingScheme, signingConfigHash, memberCount, totalWeight`, and `commitment` (C_e, below) |
| `M(e,j,f) = keccak256(abi.encode(F("b1.member"), e, j, f))`, `f = 0..7` | `nodeIDLength`, four nodeID words, two key words, `weight` |

Removed from the windowed layout: `b1.wCert`, `b1.head`, `b1.count` and the `b1.queue` ring. An entry is `12 + 8*N` addressed words (N <= 16, so
at most 140); storage grows by that much per installed epoch and never shrinks. Entries are looked up directly by epoch.

**B7 trust cache.** `E(e,11)` holds `C_e = keccak256(keccak256("unicity.seal-registry.v2/epoch-commitment") || genesisCommitment ||
b1.profileHash || e || fields 0-4 and 7-10 || the 8 words of every member in order)` (bft-core `b1state.Deployment.EpochCommitment`,
pinned by the `b7rel` vectors). It is written with the entry (by the genesis builder and by `open`) and never rewritten: closing an epoch
writes only `end` and `hasEnd`, which C_e excludes. `epochCommitments(uint64[])` returns the cached C_e, `end` and `hasEnd` of at most 64
named epochs by direct lookup (`CommitmentViewBounds`, `EpochCommitmentMissing(epoch)` for an absent entry or a zero cache); nothing
enumerates the history. The members are hashed straight from calldata (a static member is ABI-encoded as its 8 stored words), after
`checkEntry` has read every member field through the ABI decoder.

`artifacts/seal-registry.json` records the compiled runtime and code hash, every fixed slot key, the prefix keys, the field lists, the bounds, the
genesis word list and the gas constants. CI regenerates it with `script/seal-registry-artifact.sh`; `test/SealRegistryArtifact.t.sol` checks it
against independent derivations.

## The privileged update (`open`)

`open(...)` is unchanged in shape (selector `0x724236c0`); the final `B1Update` is
`{ priorTipEpoch, hasOldTipEnd, oldTipEnd, B1Entry[] newEntries }`, an `B1Entry` carrying `epoch, bodyKind, bodyID, activationCommitID, start,
hasEnd, end, signingScheme, signingConfigHash, members[]`. The origin epoch and round are the `rootEpoch` and `rootRound` arguments. In order:

1. The imported tip is present and open (else `B1StateInvalid`); `priorTipEpoch == I` (`PriorTipMismatch`).
2. No new entries: `hasOldTipEnd` false (`OldTipEndMismatch`) and the tip is the origin epoch (`OriginEpochMismatch`). Otherwise `hasOldTipEnd` and
   `oldTipEnd` equal the first entry's start (`OldTipEndMismatch`), and for each entry in order: not a genesis body (`BadAppend`); epoch `I+1+i`
   (`AppendGap`); the previous entry's end is this start (`NonContiguousEpochs`); start and end not after the origin round (`StartAfterOrigin`); only
   the last is open (`InvalidInterval`) and it names the origin epoch (`OriginEpochMismatch`); the entry shape (members 1..16, node IDs, keys,
   weights, identities, `end > start`); the start exceeds the previous start (`AppendStartNotIncreasing`); the first start exceeds the origin
   round when the usable epoch is the tip (`AppendClosesUsableOrigin`); the epoch is absent (`EntryAlreadyPresent`). The former tip is closed once, at
   the first start; the entry is written; `b1.importedTipEpoch` advances.
3. The origin advances (`Registry.advance`): not backwards in epoch or round, onto an installed epoch at or after the genesis epoch, inside its
   interval; `b1.originReady` becomes 1. The usable epoch must be the imported tip (`ImportedUsableMismatch`): there is no preload mode.
4. `finalize` re-asserts format 2, `originReady = 1`, `g <= I = U`, and the tip present and open.

How many epochs one block imports (B) is not a registry word: the paired verifier's profile admits at most B and the system-call gas covers it.
Several named origin errors (`OriginEpochRegression`, `OriginRoundRegression`, `OriginBeyondImportedTip`, `FirstOriginBeforeGenesis`,
`OriginAtOrAfterEnd`, `ImportedUsableMismatch`) are defence in depth that the earlier checks make unreachable from `open`, exactly as in the Go model.

## Genesis

`src/B1GenesisBuilder.sol` builds the genesis words under the runtime's bounds: the operational words, `b1.network`, `b1.format` = 2,
`b1.profileHash`, `b1.initialized`, `b1.genesisEpoch` = `b1.importedTipEpoch` = the genesis epoch (absent when zero), and the open genesis entry with
its members. It refuses `B == 0`, `delta_ev >= delta_hold`, `B` above the measured cap (2), a `gRest` below the measured allowance and a `gSys` below
the envelope.

## Gas

The system call budget is `g_sys >= 155936 + (527344 + 177800*16)*B + G_rest(B)` with `G_rest(B) = 1,150,000 + 250,000*B`. The first part is a
conservative rectangle for the history writes only (per imported epoch 140 entry words at 22,100, the C_e cache word included, the two closure words of the former tip and the
two cursor words, no refund credit, nothing is cleared); `G_rest` bounds every other cost of open + finalize (SLOADs, hashing, decode, memory,
the 28 operational writes priced at 22,100, and the whole of finalize).

Measured by `test/SealRegistryB1Gas.t.sol` against committed, cold state with the real calls (Cancun prices checked against the EVM in the same file),
16-member entries, three node-ID shapes:

| Fixture | gross (open + finalize) | history SSTORE (exact) | rest* (worst operational writes) | 1.5 x rest* | `G_rest(B)` |
|---|---:|---:|---:|---:|---:|
| B = 0 (no import) | 173,313 | 0 | 728,513 | 1,092,770 | 1,150,000 |
| B = 1, worst shape | 3,675,454 | 3,097,100 | 910,354 | 1,365,531 | 1,400,000 |
| B = 2, worst shape | 6,951,338 | 6,189,000 | 1,074,438 | 1,611,657 | 1,650,000 |

The affine allowance is fitted to these three points with the 1.5x margin the test enforces; it is a measurement of this runtime under forge's test
EVM, not an instruction-level proof or a claim about the final client: the ureth system-integration work re-measures. The B = 2 maximal import
(two full-width epochs) costs 6.95M gross, which is why the system call has its own reservation rather than the 7M ordinary budget.
