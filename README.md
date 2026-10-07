# unicity-pos-contracts

The contract package for Unicity's enshrined EVM and PoS. This repository exists to satisfy the
precondition on [bft-core F4 (#12)](https://github.com/ristik/bft-core/issues/12): *"Contract
repository/toolchain and ownership must be recorded before implementation; no complete PoS contract
package is assumed to exist in BFT Core."*

**Implemented so far:** the SealRegistry (with the B1 pruned authenticated root-epoch history, see
[`docs/b1-registry-gas.md`](docs/b1-registry-gas.md)), WUCT native wrapper, simplified FeeCollector,
immutable timestamp vesting vault, and the P85 custody, identity and evidence modules (`src/`,
`src/p85/`). Nothing here is deployed, and no genesis, activation, issuance or PoS feature follows
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
bash script/t2t3-artifact.sh && git diff --exit-code artifacts/t2t3-test-v1.json
bash script/vesting-vault-artifact.sh && git diff --exit-code artifacts/vesting-vault-test-v1.json
bash script/p85-interface-manifest.sh && git diff --exit-code artifacts/p85-pr2-interface.json
```

OpenZeppelin Contracts is pinned as a submodule at v5.4.0 (commit recorded in `foundry.lock`). The
T2T3 artifact script deploys canonical test instances in Foundry's local VM and records the actual
runtime bytes, including FeeCollector's immutable treasury and split ratio. These test values are
fixtures, not a production allocation or fee policy.

The vesting vault fixes principal, recipient, start, cliff, and duration at construction. Its linear
timestamp schedule follows OpenZeppelin VestingWallet's cliff gate and cumulative vested arithmetic;
it does not derive entitlement from balance. Donations and forced transfers are reported as surplus
and never increase the claim. `script/vesting-vault-artifact.sh` records its canonical runtime,
including constructor immutables, under the same pinned compiler profile.

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

## SealRegistry

`src/SealRegistry.sol` implements the assignment-aware registry profile for H3 and, for B1 (bft-core
#62), the pruned authenticated root-epoch history. It retains the immutable genesis configuration hash,
tracks a separate active EVM assignment hash and shard epoch, and stores the live root-epoch intervals
(full members and weights) that certificate verification reads. The paired BFT/Ureth verifier
authenticates the ordered supersession chain and the history and supplies their bounded projections;
the contract checks the projection's old/new context, commitment digest, epoch arithmetic and the
queue invariants. Layout, update projection, genesis and the gas analysis are in
[`docs/b1-registry-gas.md`](docs/b1-registry-gas.md).

- **Layout.** No Solidity state variables. One fresh layout (no layout-version word, no migration): every
  field lives at `keccak256("unicity.seal-registry/" || name)`, plus a circular queue of epochs and
  per-epoch entry and member words at derived slots. A test requires the compiled storage layout to be empty.
- **Genesis.** No constructor. Genesis places the runtime code at `a_sr` and writes the operational words,
  the immutable profile words (`b1.network`, `b1.wCert`, `b1.profileHash`), `b1.initialized`, the queue and
  the genesis entry with its members. `src/B1GenesisBuilder.sol` builds those words under the runtime's
  bounds and refuses a profile whose `g_sys` does not cover the registry envelope; it is a build-time
  helper and is not part of the runtime.
- **Transitions.** Ordinary blocks require certified and authorized epochs plus the active hash to match
  storage. Root-only acknowledgements still advance root epoch by exactly one and preserve the assignment.
  Direct EVM assignment acknowledgements advance root and shard epochs by one. Only a paired-verifier
  projection can fold a multi-step supersession span; its root/shard deltas and commitment are checked,
  while the immutable genesis hash is never rewritten. Every `open` prunes intervals whose end is at or
  below `L = max(0, O - W_cert)`, closes the former tip once and inserts the new live intervals. Only the
  system caller may `open` or `finalize`.
- **Compiler.** Solidity 0.8.37 with the IR pipeline (owner decision on bft-core #12); no metadata hash or
  CBOR trailer is emitted.
- **Artifact.** `artifacts/seal-registry.json` records compiler settings, ABI, runtime bytecode, code hash,
  slot keys, the B1 layout description and bounds, the genesis word list and the gas constants.
  `script/seal-registry-artifact.sh` regenerates it. The artifact is not a deployable genesis record:
  `genesisCommitment`, `fullShardConfHash` and the genesis members come from the Go construction over this
  code hash.

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

## WUCT and FeeCollector test profiles

`src/WUCT.sol` follows the WETH9 deposit/withdraw flow on OpenZeppelin's ERC20 base. Deposits mint
one WUCT per wei. Withdrawals burn before sending native coin, and `ReentrancyGuard` protects the
external transfer. There is no privileged mint or permit surface. Forced native transfers can add
excess backing; they cannot create WUCT.

`src/FeeCollector.sol` is intended as the configured fee beneficiary. Anyone may call `split()` to
classify the balance above treasury-credit and reward-pot liabilities. The constructor pins the
treasury address and treasury share in basis points; integer remainder stays in the retained reward
pot. The treasury pulls its credit with `withdraw()`. There is no per-assignment attribution or
reward payout implementation; the reward pot is retained while T8 is disabled.

| file | covers |
| --- | --- |
| `test/T2T3.t.sol` | deposit/withdraw boundaries, fuzzed backing and ratio accounting, absent mint/permit, forced transfers, malicious receivers, reentrancy and pull-credit limits |
| `test/T2T3Invariant.t.sol` | stateful WUCT backing/supply and FeeCollector liability/accounting invariants |
| `test/T2T3Artifact.t.sol` | canonical test-instance runtime, hashes, constructor values and compiler settings |

These contracts and artifacts are test-profile material only. They do not select production
allocation amounts, a fee split, or a production treasury authority.

## P85 custody, identity and evidence (PR 2 of 5)

`src/p85/` holds the clean-room native-UCT custody modules of
[bft-core #85](https://github.com/ristik/bft-core/issues/85): `StakeCustody`, `Evidence`, the
`admitDelegation` surface of `ElectionPolicy`, an immutable `FixedPolicy` source and the one-shot
`PosFactory`. Election, governance and rewards are later PRs. Read
[`docs/p85/INTERFACE.md`](docs/p85/INTERFACE.md) for the authority matrix, the interface frozen for
PR3, the fixtures that PR1 replaces and the design interpretations to confirm, and
[`docs/p85/PROVENANCE.md`](docs/p85/PROVENANCE.md) for the clean-room provenance manifest.

The P85 modules compile under a size-first optimizer profile (`optimizer_runs = 1`, restricted to
`src/p85/**` in `foundry.toml`) so that `StakeCustody` stays under EIP-170; the SealRegistry's pinned
settings and code hash are unaffected.
