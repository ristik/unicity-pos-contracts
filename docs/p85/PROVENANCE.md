# P85 PR2 provenance manifest

Scope: the contracts under `src/p85/` and the tests under `test/p85/` (issue
[ristik/bft-core#85](https://github.com/ristik/bft-core/issues/85), PR 2 of 5).

## Method

Clean-room direction, as chosen in the P85 design (section 8): the contracts were written from the
written specification only, namely `p85-design-v5.md` (including its "Review fixes 2026-10-07"
changelog and review) and `docs/design/pos-architecture.md` on bft-core PR #415. No upstream staking
source, storage layout, algorithm implementation or test was opened, copied or translated while
writing this code. The tests were written from the design's acceptance table (section 9), not from
any upstream test suite.

This is an engineering direction, not a retrospective claim that earlier investigators of the design
never read upstream code, and not a legal conclusion about provenance. No GPL port and no inherited
audit is assumed. Newly authored files carry `SPDX-License-Identifier: Apache-2.0`.

## Design inspirations (ideas only, nothing imported)

| Project (pinned revision) | Idea retained | Local replacement |
|---|---|---|
| Polygon StakeManager / SlashingManager, `eef53596046eda70a53653a8e5ff79b1cbf0a4f9` | Principal, rewards and penalty transfers are separate ledgers | Native-UCT lots; canonical per-offence ID instead of a batch nonce, so a third conflicting statement is the same offence |
| Cosmos SDK staking, `v0.53.0` | Liability for offences committed while bonded outlives unbonding | Exposure records bound to the assignment that held the key; root-acknowledged closure; a rotation cannot move an old offence onto a new deposit |
| Ethereum consensus specs, `v1.5.0` | Exit is distinct from withdrawability; objective signed conflicts | Root closure anchors and a UC-time floor; a retirement request cannot release funds |
| Aptos `stake.move`, `1d47dfc1f1499dba071952a03eb8ddab8ca02f00` | Explicit balance stages; owner/operator separation | Free / encumbered / draining / credit categories driven by certified reference closure, not by a local epoch status |

## Imported general-purpose code

| Dependency | Use | License |
|---|---|---|
| OpenZeppelin Contracts v5.4.0 (`lib/openzeppelin-contracts`, already pinned by this repository) | `ReentrancyGuard` only | MIT (its own license; unchanged) |
| forge-std (`lib/forge-std`, already pinned) | tests only | MIT / Apache-2.0 (its own license) |

No other third-party source is included. The secp256k1 point decompression in `KeyLib` uses the
modexp precompile and the standard curve constants; it was derived from the curve equation
`y^2 = x^3 + 7`, not from any library.

## Not claimed

Production economics, audits, parameter freezing, and acceptance of the architecture are outside this
change. Internal dev-to-review is still required.
