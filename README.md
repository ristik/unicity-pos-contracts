# unicity-pos-contracts

The contract package for Unicity's enshrined EVM and PoS. This repository exists to satisfy the
precondition on [bft-core F4 (#12)](https://github.com/ristik/bft-core/issues/12): *"Contract
repository/toolchain and ownership must be recorded before implementation; no complete PoS contract
package is assumed to exist in BFT Core."*

**Implemented so far:** the fixed-profile SealRegistry (`src/SealRegistry.sol`, see
[below](#sealregistry-v1)). Nothing here is deployed, and no genesis, activation or PoS feature follows
from merging it.

## Ownership and process

Owner: @ristik. Work is tracked in [ristik/bft-core](https://github.com/ristik/bft-core) — this
repository holds code, not the backlog. Follow
[bft-core's `docs/pos/PROCESS.md`](https://github.com/ristik/bft-core/blob/integration/enshrined-evm/docs/pos/PROCESS.md):
claim a bounded unit of work on the bft-core issue, branch per ticket, link companion PRs across
both repositories, and pin compatible revisions in both directions.

PROCESS.md's standing requirement for this repository specifically: **contract changes need
invariant, malicious-caller/reentrancy and boundary tests.** A contract without those is not
reviewable, regardless of what it does.

## Scope

| bft-core ticket | Expected contribution |
| --- | --- |
| [F4 (#12)](https://github.com/ristik/bft-core/issues/12) | SealRegistry — latest origin, certified clock, trust-base bodies, assignment and transition cursors; explicitly authenticated genesis initialisation; permissionless verification must not mutate the privileged clock or assignment |
| [P2 (#30)](https://github.com/ristik/bft-core/issues/30) | Immutable native stake custody |
| [P4 (#32)](https://github.com/ristik/bft-core/issues/32) | Retirement queue and protected claims |
| [T2 (#29)](https://github.com/ristik/bft-core/issues/29) | Immutable allocation and WUCT contracts |
| [T3 (#37)](https://github.com/ristik/bft-core/issues/37) | FeeCollector and independent Treasury |
| [B4 (#65)](https://github.com/ristik/bft-core/issues/65) | Native BridgeVault and permanent lock interface |

PoS, inbox and bridge features stay disabled until their own gates pass. Deployment, issuance,
bridge activation and the PoS switch are separate explicit authorisations, never a consequence of
merging here.

## Toolchain

[Foundry](https://book.getfoundry.sh) (`forge` / `cast` / `anvil`), Solidity pinned in
`foundry.toml`. Chosen because the deliverables above are invariant- and adversary-driven —
`forge test` gives stateful invariant testing and fuzzing in-language, which is what
"malicious-caller/reentrancy and boundary tests" actually needs, and it is the form auditors for
this class of work expect.

```bash
curl -L https://foundry.paradigm.xyz | bash && foundryup --install v1.8.1   # the pinned version CI uses
git submodule update --init                                                 # forge-std v1.16.2
forge build
forge test
forge fmt --check
bash script/seal-registry-artifact.sh && git diff --exit-code artifacts/    # artifact is current
```

Foundry's macOS release binaries link `libusb` at the Homebrew path. On a MacPorts host, run them with
`DYLD_FALLBACK_LIBRARY_PATH=/opt/local/lib`, and run the artifact script with a non-system `bash`
(macOS strips `DYLD_*` variables when it starts `/bin/bash`).

## Execution environment

These contracts run on Unicity's enshrined EVM, **not** on stock Ethereum. Two differences already
measured against the pinned execution client bind anything written here — see
[`ureth`](https://github.com/ristik/ureth)'s `UNICITY.md` and bft-core's
`docs/design/f1-baseline.md` §4:

- The genesis base fee is not preserved (it descends to a 7-wei integer-division fixed point, which is *not* a configurable floor), and
- the block gas limit is unpinned under the default builder (a standard `--builder.gaslimit` flag pins our own builder; follower enforcement against peer blocks is unevidenced).

Both are open, owned by [F5 (#13)](https://github.com/ristik/bft-core/issues/13). Do not write a
contract whose economics assume either is already fixed; if you depend on one, say so explicitly and
link F5.

The SealRegistry in particular is written against the privileged system call implemented in `ureth`,
whose profile is
[ADR 0004](https://github.com/ristik/bft-core/blob/integration/enshrined-evm/docs/adr/0004-reth-system-call-fee-profile.md).
Read that before designing storage layout: the system call writes `sealRegistryCommitment` into this
contract's storage, authenticated by the block's `stateRoot` and proved with `eth_getProof`, so the
layout is protocol surface, not an implementation detail.

## SealRegistry v1

`src/SealRegistry.sol` implements profile `sealRegistry/v1` exactly as specified in bft-core
[`docs/design/f4a-seal-registry-contract.md`](https://github.com/ristik/bft-core/blob/integration/enshrined-evm/docs/design/f4a-seal-registry-contract.md)
(#153): one shard configuration, one shard configuration epoch, one root epoch, no pending transitions
and no forced transactions.

- **Layout.** No Solidity state variables. The 22 fields of §4.2 live at
  `keccak256("unicity.seal-registry.v1/" || name)`. A test requires the compiled storage layout to be empty.
- **Genesis.** No constructor. Genesis places the runtime code at `a_sr` and writes the six §5.4 words.
- **Transitions.** `open` and `finalize` carry the §6.1 signatures and selectors, preconditions O1 to
  O10 and F1 to F3 (one custom error each), and the §6.2 and §6.3 effects. The only caller is
  `a_sys = 0xff00000000000000000000000000000000000001`. Nothing is payable, and the code makes no
  external calls.
- **Compiler.** Solidity 0.8.37 with the IR pipeline (owner decision on bft-core #12): the sixteen-argument
  `open` signature exceeds the legacy code generator's stack in the ABI decoder. No metadata hash or CBOR
  trailer is emitted, so the code hash depends only on the source and these settings.
- **Artifact.** `artifacts/seal-registry-v1.json` records the compiler settings, ABI, runtime bytecode,
  code hash, slot keys and genesis word names. `script/seal-registry-artifact.sh` regenerates it, and CI
  fails if it is stale. It is **not** a deployable genesis record: `genesisCommitment` and
  `fullShardConfHash` come from the Go construction of #153 §5.3 over this code hash.

**What the contract enforces, and what it does not.** It enforces its caller, its own state machine and
bounded checks on its arguments. These belong to the execution client (bft-core #11) and are not claimed
here:

- a reverted or out-of-gas system call invalidates the block;
- `open` runs first, and `finalize` runs after the forced prefix, each exactly once;
- the post-block `phase` check;
- `g_sys` accounting;
- the header `extraData` check;
- rejection of any other transaction from `a_sys`;
- the calldata is a faithful projection of the authenticated `rootInput`. Solidity's decoder ignores
  trailing calldata, which a test records.

**Tests** (`forge test`):

| file | covers |
| --- | --- |
| `test/SealRegistry.t.sol` | unit, boundary and fuzzed malicious-caller tests |
| `test/SealRegistryInvariant.t.sol` | stateful invariants driven by `a_sys` and arbitrary senders |
| `test/SealRegistryArtifact.t.sol` | the committed artifact against the compiled contract |

The slot keys are checked against the independent vector from bft-core's `f4aregistry` model.
