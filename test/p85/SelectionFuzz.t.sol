// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Continuity} from "../../src/p85/Continuity.sol";
import {Selection} from "../../src/p85/Selection.sol";
import {NaiveSelection} from "./NaiveSelection.sol";

/// @notice `Selection` measures each replacement trial incrementally; `NaiveSelection` rebuilds and re-checks the whole trial
/// committee. On random inputs, in the regime where trials actually pass and fail, the two must agree on the reason and the committee.
contract SelectionFuzzTest is Test {
    function _rnd(uint256 seed, uint256 salt, uint256 mod) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(seed, salt))) % mod;
    }

    function _case(uint256 seed)
        internal
        pure
        returns (
            Continuity.Member[] memory o,
            Selection.Entry[] memory e,
            NaiveSelection.Entry[] memory ne,
            Selection.Config memory cfg,
            NaiveSelection.Config memory ncfg
        )
    {
        uint256 universe = 6 + _rnd(seed, 1, 30);
        uint256 eligiblePct = 50 + _rnd(seed, 2, 46);
        uint256 maxOldWeight = 5 + _rnd(seed, 3, 40);
        // the last committee: a random subset of the universe
        uint256 k = 0;
        Continuity.Member[] memory tmpO = new Continuity.Member[](universe);
        Selection.Entry[] memory tmpE = new Selection.Entry[](universe);
        NaiveSelection.Entry[] memory tmpNE = new NaiveSelection.Entry[](universe);
        uint256 oi = 0;
        for (uint256 id = 1; id <= universe; ++id) {
            bool inOld = _rnd(seed, 100 + id, 100) < 40;
            uint64 oldWeight = uint64(1 + _rnd(seed, 200 + id, maxOldWeight));
            if (inOld) {
                tmpO[oi++] = Continuity.Member(uint64(id), bytes32(uint256(id)), oldWeight);
            }
            if (_rnd(seed, 300 + id, 100) < eligiblePct) {
                // eligible: an incumbent keeps or changes its weight and binding; an outsider is new
                uint64 w = inOld && _rnd(seed, 400 + id, 100) < 60
                    ? oldWeight
                    : uint64(1 + _rnd(seed, 500 + id, maxOldWeight + 5));
                bytes32 b = inOld && _rnd(seed, 600 + id, 100) < 90
                    ? bytes32(uint256(id))
                    : bytes32(uint256(id) + 1_000);
                tmpE[k] = Selection.Entry(uint64(id), b, w);
                tmpNE[k] = NaiveSelection.Entry(uint64(id), b, w);
                ++k;
            }
        }
        if (oi == 0) {
            tmpO[oi++] = Continuity.Member(uint64(universe + 1), bytes32(uint256(universe + 1)), 5);
        }
        o = new Continuity.Member[](oi);
        for (uint256 i = 0; i < oi; ++i) {
            o[i] = tmpO[i];
        }
        e = new Selection.Entry[](k);
        ne = new NaiveSelection.Entry[](k);
        for (uint256 i = 0; i < k; ++i) {
            e[i] = tmpE[i];
            ne[i] = tmpNE[i];
        }
        // a target at most the committed size, so the seed leaves outsiders to try against retained incumbents
        uint32 nTarget = uint32(1 + _rnd(seed, 8, oi));
        uint32 nMin = uint32(1 + _rnd(seed, 7, nTarget));
        uint32 nMax = nTarget + uint32(_rnd(seed, 9, 4));
        uint64 maxM = uint64(2 + _rnd(seed, 10, 8));
        uint64 den = uint64(1 + _rnd(seed, 11, 3));
        uint64 num = uint64(1 + _rnd(seed, 12, 2));
        cfg = Selection.Config(nMin, nTarget, nMax, Continuity.Params(maxM, num, den));
        ncfg = NaiveSelection.Config(nMin, nTarget, nMax, Continuity.Params(maxM, num, den));
    }

    /// @dev One comparison per external call, so each starts with fresh memory.
    function compare(uint256 seed) external pure {
        (
            Continuity.Member[] memory o,
            Selection.Entry[] memory e,
            NaiveSelection.Entry[] memory ne,
            Selection.Config memory cfg,
            NaiveSelection.Config memory ncfg
        ) = _case(seed);
        (Selection.Reason r, Continuity.Member[] memory c) = Selection.select(o, e, cfg);
        (NaiveSelection.Reason nr, Continuity.Member[] memory nc) =
            NaiveSelection.select(o, ne, ncfg);
        assertEq(uint8(r), uint8(nr), "reason");
        assertEq(c.length, nc.length, "size");
        for (uint256 i; i < c.length; ++i) {
            assertEq(c[i].id, nc[i].id);
            assertEq(c[i].binding, nc[i].binding);
            assertEq(c[i].weight, nc[i].weight);
        }
    }

    function testFuzz_incrementalSelectionEqualsTheNaiveForm(uint256 seed) public view {
        this.compare(seed);
    }

    /// @dev A fixed sweep, so the equivalence does not depend on what the fuzzer happens to draw.
    function test_incrementalSelectionEqualsTheNaiveFormOverASweep() public view {
        for (uint256 seed = 1; seed <= 1_500; ++seed) {
            this.compare(seed);
        }
    }

    /// @dev The seed of design v5 section 5, written independently: the best incumbents up to the target, then the best outsiders.
    function _seedIDs(Continuity.Member[] memory o, Selection.Entry[] memory e, uint256 target)
        internal
        pure
        returns (uint256 mask)
    {
        uint256 n = e.length;
        bool[] memory used = new bool[](n);
        uint256 count = 0;
        for (uint256 pass = 0; pass < 2; ++pass) {
            while (count < target) {
                uint256 best = n;
                for (uint256 i; i < n; ++i) {
                    if (used[i]) continue;
                    bool inc = false;
                    for (uint256 j; j < o.length; ++j) {
                        if (o[j].id == e[i].id) inc = true;
                    }
                    if (inc != (pass == 0)) continue;
                    if (
                        best == n || e[i].weight > e[best].weight
                            || (e[i].weight == e[best].weight && e[i].id < e[best].id)
                    ) best = i;
                }
                if (best == n) break;
                used[best] = true;
                mask |= uint256(1) << e[best].id;
                ++count;
            }
        }
    }

    /// @dev The generator must reach accepted replacements, not only seed failures, or the equivalence above proves little.
    function test_theGeneratorExercisesAcceptedReplacements() public pure {
        uint256 replaced;
        uint256 refusedSeed;
        for (uint256 seed = 1; seed <= 400; ++seed) {
            (
                Continuity.Member[] memory o,
                Selection.Entry[] memory e,,
                Selection.Config memory cfg,
            ) = _case(seed);
            (Selection.Reason r, Continuity.Member[] memory c) = Selection.select(o, e, cfg);
            if (r != Selection.Reason.None) {
                ++refusedSeed;
                continue;
            }
            uint256 chosenMask;
            for (uint256 i; i < c.length; ++i) {
                chosenMask |= uint256(1) << c[i].id;
            }
            if (chosenMask != _seedIDs(o, e, cfg.nTarget)) ++replaced;
        }
        assertGt(replaced, 8, "cases in which a replacement was accepted");
        assertGt(refusedSeed, 5, "cases in which the seed or the cardinality refused");
    }
}
