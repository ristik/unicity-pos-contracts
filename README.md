# unicity-pos-contracts

The contract package for Unicity's enshrined EVM and PoS. This repository exists to satisfy the
precondition on [bft-core F4 (#12)](https://github.com/ristik/bft-core/issues/12): *"Contract
repository/toolchain and ownership must be recorded before implementation; no complete PoS contract
package is assumed to exist in BFT Core."*

**Nothing is implemented yet.** This is the recorded home and toolchain, not a delivery. The first
contract lands with F4.

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
curl -L https://foundry.paradigm.xyz | bash && foundryup   # install
forge build
forge test
forge fmt --check
```

## Execution environment

These contracts run on Unicity's enshrined EVM, **not** on stock Ethereum. Two differences already
measured against the pinned execution client bind anything written here — see
[`ureth`](https://github.com/ristik/ureth)'s `UNICITY.md` and bft-core's
`docs/design/f1-baseline.md` §4:

- The base fee currently has no floor (decays 7/8 per empty block), and
- the block gas limit is not pinned by configuration (drifts +1/1024 per block).

Both are open, owned by [F5 (#13)](https://github.com/ristik/bft-core/issues/13). Do not write a
contract whose economics assume either is already fixed; if you depend on one, say so explicitly and
link F5.

The SealRegistry in particular is written against the privileged system call implemented in `ureth`,
whose profile is
[ADR 0004](https://github.com/ristik/bft-core/blob/integration/enshrined-evm/docs/adr/0004-reth-system-call-fee-profile.md).
Read that before designing storage layout: the system call writes `sealRegistryCommitment` into this
contract's storage, authenticated by the block's `stateRoot` and proved with `eth_getProof`, so the
layout is protocol surface, not an implementation detail.
