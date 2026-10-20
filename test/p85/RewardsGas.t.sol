// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {HookGasColdTest} from "./HookGasCold.t.sol";
import {P85Base} from "./P85Base.sol";
import {RewardPool} from "../../src/p85/RewardPool.sol";
import {Limits, ElectionParams, RecordKind} from "../../src/p85/P85Types.sol";

/// @notice COLD gas of the reward pool's two entry points at the largest committee the election admits (16 members of one lot, the package caps'
/// nMax), and a ceiling for each (T8 #47: "settlement work is bounded"). The pool is ordinary EVM work, not part of the mandatory hook, so the
/// ceilings are regression guards with room, not a pinned price; what bounds the work is structural: at most two records per `advanceRecords`, one
/// interval and at most 16 members per `closeInterval` (a larger genesis committee is refused at deployment).
///
/// As in `HookGasColdTest`, everything but the measured call is built in `setUp`, so the call is the first touch of every account and slot it reads.
/// The committee is a 16-member J acknowledged at offset 100 (after which a second 16-member candidate is closed by a SessionClosed record), so
/// `advanceRecords(2)` reads an Ack and a SessionClosed over 16-member exposures, and J's interval [100, 1000) settles 16 members.
abstract contract RewardsGasBase is HookGasColdTest {
    /// @dev Measured on this tree (advanceRecords(2): 197,902; closeInterval over 16 members: 684,847 cold gas) and set at about 2.5 times; a change that
    /// makes either call several times dearer fails here. A block's gas limit is far above both.
    uint256 internal constant CEILING_ADVANCE_2 = 500_000;
    uint256 internal constant CEILING_CLOSE_16 = 1_700_000;

    RewardPool internal pool;

    function _manifestLimits() internal pure override returns (Limits memory) {
        return Limits({vMax: 32, lMax: 1, rMax: 4, maxBatch: 32});
    }

    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: 16,
            nMax: 16,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: 100_000,
            cadenceSeconds: 604_800
        });
    }

    function setUp() public virtual override {
        (kind, V, L, C) = ("rewards", 32, 1, 16);
        P85Base.setUp();
        pool = factory.REWARDS();
        _populate();
        _reserve(RES_J, ASG_J, 0, 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        _reserve(RES_J2, ASG_J2, C, 2);
        pushRecord(RecordKind.SessionClosed, abi.encode(RES_J2));
        applyAll();
        clock(1_500, 2_000);
        _stage();
    }

    function _stage() internal virtual {}

    /// @dev Not a measurement run of the hook scenarios: the parent's own test is disabled here.
    function test_measureCold() public pure override {}
}

contract RewardsGasAdvanceTest is RewardsGasBase {
    function test_advanceRecordsOfTwoRecordsOverSixteenMembers() public {
        uint256 before_ = gasleft();
        uint32 n = pool.advanceRecords(2);
        uint256 used = before_ - gasleft();
        emit log_named_uint("advanceRecords(2), 16-member committees, cold", used);
        assertEq(n, 2);
        assertLt(used, CEILING_ADVANCE_2);
    }
}

contract RewardsGasCloseTest is RewardsGasBase {
    function _stage() internal override {
        pool.advanceRecords(2);
        pool.closeInterval(); // the genesis committee's interval [0, 100): four members
    }

    function test_closeIntervalOverSixteenMembers() public {
        uint256 before_ = gasleft();
        (uint64 a, uint64 b, uint256 budget) = pool.closeInterval();
        uint256 used = before_ - gasleft();
        emit log_named_uint("closeInterval, 16 members, cold", used);
        assertEq(a, 100);
        assertEq(b, 1_000);
        assertGt(budget, 0);
        assertLt(used, CEILING_CLOSE_16);
    }
}
