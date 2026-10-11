# P85 hook gas, COLD, at the deployment's caps

Measured by `script/measure-hook-gas.sh V L C [kind...]` (test `test/p85/HookGasCold.t.sol`). The committee is the worst the caps admit: `nMax` members of `lMax` lots each. The scenario is built in `setUp`, so the measured call (`custody.applyRootRecords(1)` or `election.elect`) is the first touch of every account and slot it reads, as the system call meets them in a fresh transaction (the older `HookGas.t.sol` figures are measured inside the transaction that built the state: warm, a lower bound). `RecoveryAck + saved closure` is the RecoveryAck of a J whose closure is already staged (pending-J path): it activates J, derives K (one exposure per incumbent member) and applies the saved closure. Gas, `forge 1.8.1`, solc 0.8.37, p85 profile (`optimizer_runs = 1`).

| caps (vMax/lMax/nMax) | Ack | stage J's closure | closure of an Active J | **RecoveryAck + saved closure** | election (plain) | election (heavy) |
|---|---|---|---|---|---|---|
| 16/2/8 | 313,646 | 188,794 | 1,037,566 | **3,629,888** | 5,185,568 | 5,406,283 |
| 32/4/10 | 336,018 | 188,794 | 1,972,852 | **6,204,138** | 9,387,583 | 10,375,460 |
| 64/8/16 | 403,134 | 188,794 | 5,348,678 | **15,398,599** | 23,382,966 | 27,266,872 |
| 128/8/32 | 582,110 | 188,794 | 10,551,094 | **30,450,998** | 47,520,691 | 64,640,380 |

## What it implies for the pinned hook reservation

The profile reserves `H_records x hookRecordGas` for the records and `electGas` for the election (the lane: `hRecords = 2`, `hookRecordGas = 3,000,000`, `electGas = 6,758,060` = 1.25 x the measured heavy election at 16/2/8) inside `systemGas`. The pinned B1 profile of the devnet lane has `systemGas = 300,887,744`.

- **The lane's 3,000,000 per record does not cover the worst committee its own caps admit**: a RecoveryAck with a pending closure at 16/2/8 is 3,629,888 cold. The lane passes because its committees are smaller (4-5 members of one lot: 1.44M warm at four members). A deployment that keeps `hookRecordGas = 3,000,000` at vMax/lMax/nMax = 16/2/8 can fill a committee the hook cannot apply within its reservation; the block would then be built with less than the record needs (the hook's own out-of-gas rule: an invalid block). Size `hookRecordGas` from the table at the deployment's caps, with the 1.25 margin the election price already carries.
- The reservation to pin, `H_records = 2` (the records of one block), the margin 1.25 on the worst record and on the heavy election:

| caps | records: H_records=2 x 1.25 x the worst record | election price (1.25 x heavy) | hook gross | share of the pinned systemGas 300,887,744 |
|---|---|---|---|---|
| 16/2/8 | 2 x 4,537,360 = 9,074,720 | 6,757,853 | 15,832,573 | 5.3% |
| 32/4/10 | 2 x 7,755,172 = 15,510,344 | 12,969,325 | 28,479,669 | 9.5% |
| 64/8/16 | 2 x 19,248,248 = 38,496,496 | 34,083,590 | 72,580,086 | 24.1% |
| 128/8/32 | 2 x 38,063,747 = 76,127,494 | 80,800,475 | 156,927,969 | 52.2% |
- These are the hook's terms only. The 300,887,744 includes the B1 import and finalize terms of the lane's profile; a profile with larger caps must recompute the whole system envelope ("never accept because each call fits g_sys separately"): the hook share alone is 52% of the lane's pinned figure at the profile ceiling.
- Not measured: a closure of an Active J that is the incumbent of a pending session (the session locks only defer the release), and committees of different lot counts per member (the worst case here is uniform, `lMax` per member). The RecoveryAck dominates every record, as it should: it derives K and closes J in one record.

## What the figures do not include

- **The real registry's `recordAt` cost** (measured, `test/RegistryRecordAtGas.t.sol`, cold): the real `recordAt` is 47,361 for a RecoveryAck (nine payload words) and 39,623 for a Closure, against 40,391 and 33,756 for the stand-in these figures use, so the figures understate the real read by about 6-7k per record (0.2% of the RecoveryAck at 16/2/8); the four count/target/clock reads are 23,330 (the hook's gate reads are budgeted at 150,000). The 1.25 margin absorbs both; the records come from `MockRootRecords`, called by the test contract.
- **`SessionClosed` and `Retirement` records are unmeasured** here (the warm figures of `HookGas.t.sol` bound them far below the RecoveryAck: 0.4M and 0.2M at four members). Only the records that scale with the committee (Ack, the staging and the closure of J, the RecoveryAck) and the election are in the table.
- Other committee shapes at `recovery` (cold): 5 members x 2 lots 2,405,614; 6 x 1 2,281,165; 6 x 2 2,813,701; 7 x 2 3,221,793; 8 x 2 3,629,888. A reservation of 3,000,000 with the profile's 1.25 margin covers up to about 2.4M: 6 x 1, and 5 x 2 only barely (2,405,614 x 1.25 = 3,007,018).
