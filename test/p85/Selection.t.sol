// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Continuity} from "../../src/p85/Continuity.sol";
import {Selection} from "../../src/p85/Selection.sol";

/// @notice Reproduces every case of the Go reference model's selection vectors, then exercises the refusals and the gas at the
/// ceiling separately.
contract SelectionTest is Test {
    string internal constant VECTORS = "/test/p85/fixtures/selection-vectors.json";

    struct VMember {
        uint64 id;
        uint64 binding;
        uint64 weight;
    }

    struct VConfig {
        uint64 distDen;
        uint64 distNum;
        uint64 maxM;
        uint64 nMax;
        uint64 nMin;
        uint64 nTarget;
    }

    struct VCase {
        uint64[] chosen;
        uint64[] chosenWeights;
        VConfig config;
        VMember[] eligible;
        string name;
        VMember[] oldCommittee;
        uint8 reason;
    }

    function _old(VMember[] memory v) internal pure returns (Continuity.Member[] memory out) {
        out = new Continuity.Member[](v.length);
        for (uint256 k; k < v.length; ++k) {
            out[k] = Continuity.Member(v[k].id, bytes32(uint256(v[k].binding)), v[k].weight);
        }
    }

    function _eligible(VMember[] memory v) internal pure returns (Selection.Entry[] memory out) {
        out = new Selection.Entry[](v.length);
        for (uint256 k; k < v.length; ++k) {
            out[k] = Selection.Entry(v[k].id, bytes32(uint256(v[k].binding)), v[k].weight);
        }
    }

    function _cfg(VConfig memory c) internal pure returns (Selection.Config memory) {
        return Selection.Config(
            uint32(c.nMin),
            uint32(c.nTarget),
            uint32(c.nMax),
            Continuity.Params(c.maxM, c.distNum, c.distDen)
        );
    }

    function _select(
        Continuity.Member[] memory o,
        Selection.Entry[] memory e,
        Selection.Config memory c
    ) external pure returns (Selection.Reason, Continuity.Member[] memory) {
        return Selection.select(o, e, c);
    }

    function test_goReferenceVectors() public view {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), VECTORS));
        VCase[] memory cases = abi.decode(vm.parseJson(json, ".cases"), (VCase[]));
        assertGt(cases.length, 500);
        assertEq(cases[0].name, "an unchanged committee is re-elected");
        assertEq(cases[0].oldCommittee.length, 10);
        assertEq(cases[0].config.nTarget, 10);
        uint256 elected;
        for (uint256 c; c < cases.length; ++c) {
            VCase memory k = cases[c];
            (Selection.Reason reason, Continuity.Member[] memory chosen) =
                Selection.select(_old(k.oldCommittee), _eligible(k.eligible), _cfg(k.config));
            assertEq(uint8(reason), k.reason, k.name);
            assertEq(chosen.length, k.chosen.length, k.name);
            for (uint256 i; i < chosen.length; ++i) {
                assertEq(chosen[i].id, k.chosen[i], k.name);
                assertEq(chosen[i].weight, k.chosenWeights[i], k.name);
            }
            if (reason == Selection.Reason.None) ++elected;
        }
        assertGt(elected, 150);
    }

    function _uniform(uint64 from, uint64 to, uint64 w)
        internal
        pure
        returns (Selection.Entry[] memory out)
    {
        out = new Selection.Entry[](to - from + 1);
        for (uint64 i = from; i <= to; ++i) {
            out[i - from] = Selection.Entry(i, bytes32(uint256(i)), w);
        }
    }

    function _members(Selection.Entry[] memory e)
        internal
        pure
        returns (Continuity.Member[] memory out)
    {
        out = new Continuity.Member[](e.length);
        for (uint256 i; i < e.length; ++i) {
            out[i] = Continuity.Member(e[i].id, e[i].binding, e[i].weight);
        }
    }

    function test_unsortedOrZeroWeightEligibleListsAreRefused() public {
        Selection.Entry[] memory e = _uniform(1, 6, 5);
        Selection.Config memory cfg = Selection.Config(4, 10, 16, Continuity.Params(4, 1, 4));
        Continuity.Member[] memory o = _members(e);
        e[2].id = 1;
        vm.expectRevert(Selection.InvalidEligible.selector);
        this._select(o, e, cfg);
        e = _uniform(1, 6, 5);
        e[3].weight = 0;
        vm.expectRevert(Selection.InvalidEligible.selector);
        this._select(o, e, cfg);
    }

    /// @dev The worst case the hook reserves gas for: 128 eligible identities, a full 16-member committee, every outsider ranked above
    /// the weakest incumbent so each of the 112 outsiders is tried (and refused by the churn budget).
    function test_gasAtTheCeiling() public {
        Selection.Entry[] memory e = new Selection.Entry[](128);
        for (uint64 i; i < 128; ++i) {
            // incumbents 1..16 weigh 10; outsiders 17..128 weigh 11, so each outranks the weakest incumbent
            e[i] = Selection.Entry(i + 1, bytes32(uint256(i + 1)), i < 16 ? 10 : 11);
        }
        Continuity.Member[] memory o = new Continuity.Member[](16);
        for (uint64 i; i < 16; ++i) {
            o[i] = Continuity.Member(i + 1, bytes32(uint256(i + 1)), 10);
        }
        // the seed must pass: allow it a wide budget, then every trial replaces one incumbent
        Selection.Config memory cfg = Selection.Config(4, 16, 16, Continuity.Params(100, 1, 1));
        uint256 before = gasleft();
        (Selection.Reason reason, Continuity.Member[] memory chosen) = Selection.select(o, e, cfg);
        uint256 used = before - gasleft();
        emit log_named_uint("selection gas, 128 eligible, committee 16", used);
        assertEq(uint8(reason), uint8(Selection.Reason.None));
        assertEq(chosen.length, 16);
    }

    /// @dev A swap that leaves the committed side of the unchanged-binding overlap at or below two thirds is refused even though the
    /// successor side passes: the swapped-out incumbent must leave the committed overlap. `heavy` is the weight of a committed member
    /// that is no longer eligible; the seed (thirteen of fourteen incumbents) passes for heavy < 55 and the swap passes for heavy >= 40.
    function _overlapOldSide(uint64 heavy) internal pure returns (bool swapped) {
        Continuity.Member[] memory o = new Continuity.Member[](15);
        for (uint64 i; i < 14; ++i) {
            o[i] = Continuity.Member(i + 1, bytes32(uint256(i + 1)), 10);
        }
        o[14] = Continuity.Member(15, bytes32(uint256(15)), heavy);
        Selection.Entry[] memory e = new Selection.Entry[](15);
        for (uint64 i; i < 14; ++i) {
            e[i] = Selection.Entry(i + 1, bytes32(uint256(i + 1)), 10);
        }
        e[14] = Selection.Entry(20, bytes32(uint256(20)), 11);
        Selection.Config memory cfg = Selection.Config(1, 13, 16, Continuity.Params(4, 1, 1));
        (Selection.Reason reason, Continuity.Member[] memory chosen) = Selection.select(o, e, cfg);
        require(reason == Selection.Reason.None && chosen.length == 13, "seed must pass");
        for (uint256 k; k < chosen.length; ++k) {
            if (chosen[k].id == 20) return true;
        }
        return false;
    }

    function test_theCommittedOverlapLosesTheSwappedOutIncumbent() public pure {
        assertFalse(_overlapOldSide(45), "committed overlap 120/185 is not above two thirds");
        assertTrue(_overlapOldSide(39), "committed overlap 120/179 is");
    }

    // --- bft-core#854: an outsider that breaks the bound is skipped, not a veto on the whole election ----------------------------

    /// @dev The testnet package's profile: committees of four to six, a distance bound of 1/2.
    function _pkg() internal pure returns (Selection.Config memory) {
        return Selection.Config(4, 6, 16, Continuity.Params(4, 1, 2));
    }

    function _ids(Continuity.Member[] memory c) internal pure returns (uint256 packed) {
        for (uint256 i; i < c.length; ++i) {
            packed = packed * 100 + c[i].id;
        }
    }

    /// @dev Five unit members, plus a weight-2 outsider (identity 6) alone: the whole committee of six is D = 4/7 > 1/2 from the five, no
    /// outsider can be kept, and the incumbents alone are the committee itself, so there is no change to elect.
    function test_aWeightTwoOutsiderAloneLeavesNoFeasibleChange() public view {
        Selection.Entry[] memory e = new Selection.Entry[](6);
        for (uint64 i; i < 5; ++i) {
            e[i] = Selection.Entry(i + 1, bytes32(uint256(i + 1)), 1);
        }
        e[5] = Selection.Entry(6, bytes32(uint256(6)), 2);
        Continuity.Member[] memory o = _members(_uniform(1, 5, 1));
        (Selection.Reason reason, Continuity.Member[] memory chosen) = this._select(o, e, _pkg());
        assertEq(uint8(reason), uint8(Selection.Reason.WeightChurn));
        assertEq(chosen.length, 0);
    }

    /// @dev The same, with a unit outsider behind the heavy one: the heavy one is skipped and the unit one joins.
    function test_theHeavyOutsiderIsSkippedAndTheNextUnitOutsiderJoins() public view {
        Selection.Entry[] memory e = new Selection.Entry[](7);
        for (uint64 i; i < 5; ++i) {
            e[i] = Selection.Entry(i + 1, bytes32(uint256(i + 1)), 1);
        }
        e[5] = Selection.Entry(6, bytes32(uint256(6)), 2);
        e[6] = Selection.Entry(7, bytes32(uint256(7)), 1);
        Continuity.Member[] memory o = _members(_uniform(1, 5, 1));
        (Selection.Reason reason, Continuity.Member[] memory chosen) = this._select(o, e, _pkg());
        assertEq(uint8(reason), uint8(Selection.Reason.None));
        assertEq(_ids(chosen), 1_02_03_04_05_07);
        for (uint256 i; i < chosen.length; ++i) {
            assertEq(chosen[i].weight, 1);
        }
    }

    /// @dev The overbound lane: four unit members and a weight-3 joiner alone (D = 6/7) stay refused as WeightChurn.
    function test_theOverboundJoinerAloneIsStillRefused() public view {
        Selection.Entry[] memory e = new Selection.Entry[](5);
        for (uint64 i; i < 4; ++i) {
            e[i] = Selection.Entry(i + 1, bytes32(uint256(i + 1)), 1);
        }
        e[4] = Selection.Entry(5, bytes32(uint256(5)), 3);
        Continuity.Member[] memory o = _members(_uniform(1, 4, 1));
        (Selection.Reason reason,) = this._select(o, e, _pkg());
        assertEq(uint8(reason), uint8(Selection.Reason.WeightChurn));
    }

    /// @dev A committee that lost a member to ineligibility and meets a heavy outsider: the incumbents left are a feasible change.
    function test_aShrunkCommitteeIsAChangeWhileTheHeavyOutsiderIsSkipped() public view {
        Selection.Entry[] memory e = new Selection.Entry[](5);
        for (uint64 i; i < 4; ++i) {
            e[i] = Selection.Entry(i + 1, bytes32(uint256(i + 1)), 1);
        }
        e[4] = Selection.Entry(6, bytes32(uint256(6)), 3);
        Continuity.Member[] memory o = _members(_uniform(1, 5, 1));
        (Selection.Reason reason, Continuity.Member[] memory chosen) = this._select(o, e, _pkg());
        assertEq(uint8(reason), uint8(Selection.Reason.None));
        assertEq(_ids(chosen), 1_02_03_04);
    }

    /// @dev The incumbents that are left must pass on their own, and they must reach the minimum.
    function test_theIncumbentsAloneMustPassAndReachTheMinimum() public view {
        Selection.Entry[] memory e = new Selection.Entry[](5);
        e[0] = Selection.Entry(1, bytes32(uint256(1)), 1);
        e[1] = Selection.Entry(2, bytes32(uint256(2)), 1);
        for (uint64 i = 2; i < 5; ++i) {
            e[i] = Selection.Entry(i + 4, bytes32(uint256(i + 4)), 1);
        }
        Continuity.Member[] memory o = _members(_uniform(1, 5, 1));
        (Selection.Reason reason,) = this._select(o, e, _pkg());
        assertEq(uint8(reason), uint8(Selection.Reason.MembershipChurn));
        // three incumbents left (turnover passes at 2 of 5 only with a one-third budget), one heavy outsider: below nMin = 4 after the skip
        e = new Selection.Entry[](4);
        for (uint64 i; i < 3; ++i) {
            e[i] = Selection.Entry(i + 1, bytes32(uint256(i + 1)), 1);
        }
        e[3] = Selection.Entry(6, bytes32(uint256(6)), 3);
        (reason,) = this._select(o, e, _pkg());
        assertTrue(reason != Selection.Reason.None);
    }

    /// @dev The worst case of the fallback: a full committee of 16 and 112 outsiders that are each tried and refused (the seed fails too).
    function test_gasOfTheFallbackAtTheCeiling() public {
        Selection.Entry[] memory e = new Selection.Entry[](128);
        for (uint64 i; i < 128; ++i) {
            e[i] = Selection.Entry(i + 1, bytes32(uint256(i + 1)), i < 15 ? 1 : 1000);
        }
        Continuity.Member[] memory o = new Continuity.Member[](15);
        for (uint64 i; i < 15; ++i) {
            o[i] = Continuity.Member(i + 1, bytes32(uint256(i + 1)), 1);
        }
        Selection.Config memory cfg = Selection.Config(4, 16, 16, Continuity.Params(4, 1, 2));
        uint256 before = gasleft();
        (Selection.Reason reason,) = Selection.select(o, e, cfg);
        uint256 used = before - gasleft();
        emit log_named_uint(
            "fallback gas, 128 eligible, 15 incumbents, 113 refused outsiders", used
        );
        assertEq(uint8(reason), uint8(Selection.Reason.WeightChurn));
        // each refused outsider is one full measurement; the whole election at these ceilings is bounded at 35M (ElectionGas.t.sol)
        assertLt(used, 15_000_000);
    }
}
