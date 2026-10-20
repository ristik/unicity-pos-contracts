# Operator rewards and prospective governance: published behavior

Development behavior of `RewardPool` and `GovernanceParams` (T8 #47 / P7 #54; design `briefs/t8-p7-design.md`). Production funding, rates, the governance
authority and its succession are not set here (they belong to the production reviews, bft-core #439). These contracts are not audited.

## Who is paid, and for what

- **Assignment, not performance.** Rewards are paid per authenticated *assignment interval* to the operator payees frozen in the assignment's exposures,
  weighted by the committed (quantized) weight. Nothing measures signing, participation or uptime: **an assigned but idle validator receives the same
  reward as a working one**, and a validator that is not assigned receives nothing, however well it behaves. There are no participation counters.
  Slashing is the separate evidence path (`Evidence`), not a reward reduction.
- **Only BFT Core validator-entity operators.** The payee is the `operatorPayee` of the identity's accepted binding. There is no EVM-node incentive and no PoA
  operator remuneration on chain.
- **Authenticated timeline.** The pool reads the root records the registry holds and custody has applied (Ack, RecoveryAck; SessionClosed, Closure and
  Retirement move no boundary), never caller-supplied finality, weights or payees. A candidate that was never acknowledged earns nothing; in a recovery the
  stalled successor J owns `[jOffset, kOffset)` and the restored incumbent slate K owns the rest.

## Accounting

- Intervals are half-open `[a, b)` of canonical ordinary progress. `b` is the earliest of the owner's end, the next point of the fixed 1,000-unit grid
  (anchored at the reward start) and the progress at which a new policy snapshot (a rate change) took effect. A caller chooses no endpoint or length.
- An interval is closed only up to the current progress, and the tail of the latest assignment only when the pool and custody have applied every record and
  no election result is open.
- Budget = `min(floor(rate * length / 1000), available)`; each member gets `floor(budget * weight / totalWeight)`; the rounding dust returns to `available` in
  the same call. Zero funding or a zero rate gives a zero budget and still advances; later funding never reopens a closed interval. One call closes one
  interval and settles it atomically (committees are at most 16 members; a larger genesis committee is refused at deployment).
- **Conservation:** `balance = available + unclaimed credits + surplus`. Value that arrives other than through `fund()` or the genesis allocation (a forced
  transfer) is surplus and is never allocated. Principal, custody credits, treasury credits, bridge backing and `FeeCollector.rewardPot` are never touched.
- **Exhaustion:** when `available` is spent, budgets shrink to what is left and then to zero. Principal is unaffected, as the pool holds none.
- Claims are pull payments, `claim(amount, to)` by the payee; a recipient that reverts fails only its own claim.

## Governance of the economic parameters

- The ten economic and protection policy fields and the reward rate change only through `GovernanceParams`: one pending proposal, a delay of 2,000
  progress rounds **and** 3,600 UC seconds, execution only schedules, and the election entry point activates it at its next eligible boundary. Bounds
  (`PolicyBounds`, rate at most 10 UCT per 1,000 progress units) are checked at queue, execute and activation.
- A snapshot never changes and its ID is never reused. Existing assignments, lots and cases keep the terms they captured; a reduction affects only new
  obligations.
- **Immutable in this deployment:** bond unit and minimum, election cadence and cardinality, turnover, module addresses, resource and gas limits, checkpoint
  and clock policy. There is no setter; a change is a new genesis.
- **Fee rewards are not distributed.** Collected fees stay in the `FeeCollector` (treasury credit and its `rewardPot`); assignment-attributed fee
  distribution is a separate, later scope decision.
