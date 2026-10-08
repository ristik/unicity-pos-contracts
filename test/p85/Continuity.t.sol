// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Continuity} from "../../src/p85/Continuity.sol";

/// @notice Reproduces every case of bft-core's continuity vectors (the Go reference's output) with the Solidity port, and checks the
/// port's refusals and the exact boundaries separately.
contract ContinuityTest is Test {
    string internal constant VECTORS = "/test/p85/fixtures/continuity-vectors.json";

    // vm.parseJson decodes an object's fields in the order they appear in the file; the Go reference writes them in this order
    struct VMember {
        uint64 id;
        uint64 binding;
        uint64 weight;
    }

    struct VResult {
        uint64 added;
        string distanceNumerator;
        uint8 failed;
        uint64 m;
        uint64 removed;
        uint64 replaced;
        uint256 totalNew;
        uint256 totalOld;
        uint256 unchangedNew;
        uint256 unchangedOld;
    }

    struct VCase {
        uint64 distDen;
        uint64 distNum;
        string invalid;
        uint64 maxM;
        string name;
        VMember[] newCommittee;
        VMember[] oldCommittee;
        VResult result;
    }

    function _members(VMember[] memory v) internal pure returns (Continuity.Member[] memory out) {
        out = new Continuity.Member[](v.length);
        for (uint256 k; k < v.length; ++k) {
            out[k] = Continuity.Member(v[k].id, bytes32(uint256(v[k].binding)), v[k].weight);
        }
    }

    function _check(
        Continuity.Member[] memory o,
        Continuity.Member[] memory s,
        Continuity.Params memory p
    ) external pure returns (uint8, Continuity.Measured memory) {
        return Continuity.check(o, s, p);
    }

    function test_goReferenceVectors() public view {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), VECTORS));
        VCase[] memory cases = abi.decode(vm.parseJson(json, ".cases"), (VCase[]));
        assertGt(cases.length, 400);
        uint256 invalid;
        for (uint256 c; c < cases.length; ++c) {
            VCase memory k = cases[c];
            Continuity.Member[] memory o = _members(k.oldCommittee);
            Continuity.Member[] memory s = _members(k.newCommittee);
            Continuity.Params memory p = Continuity.Params(k.maxM, k.distNum, k.distDen);
            if (bytes(k.invalid).length != 0) {
                bool successor = keccak256(bytes(k.invalid)) == keccak256("successor");
                try this._check(o, s, p) {
                    revert(string.concat("accepted an invalid committee: ", k.name));
                } catch (bytes memory err) {
                    assertEq(
                        err,
                        abi.encodeWithSelector(Continuity.InvalidCommittee.selector, successor),
                        k.name
                    );
                }
                ++invalid;
                continue;
            }
            (uint8 failed, Continuity.Measured memory r) = Continuity.check(o, s, p);
            assertEq(r.replaced, k.result.replaced, k.name);
            assertEq(r.removed, k.result.removed, k.name);
            assertEq(r.added, k.result.added, k.name);
            assertEq(r.m, k.result.m, k.name);
            assertEq(r.unchangedOld, k.result.unchangedOld, k.name);
            assertEq(r.unchangedNew, k.result.unchangedNew, k.name);
            assertEq(r.totalOld, k.result.totalOld, k.name);
            assertEq(r.totalNew, k.result.totalNew, k.name);
            assertEq(vm.toString(r.distanceNumerator), k.result.distanceNumerator, k.name);
            assertEq(failed, k.result.failed, k.name);
        }
        assertEq(invalid, 6);
    }

    function _eq(uint64 n, uint64 w) internal pure returns (Continuity.Member[] memory out) {
        out = new Continuity.Member[](n);
        for (uint64 i; i < n; ++i) {
            out[i] = Continuity.Member(i + 1, bytes32(uint256(i + 1)), w);
        }
    }

    function test_policyWithoutADenominatorIsRefused() public {
        Continuity.Member[] memory c = _eq(4, 1);
        vm.expectRevert(Continuity.InvalidParams.selector);
        this._check(c, c, Continuity.Params(4, 1, 0));
    }

    function test_unsortedAndDuplicateCommitteesAreRefusedOnTheirSide() public {
        Continuity.Member[] memory good = _eq(4, 1);
        Continuity.Member[] memory bad = _eq(4, 1);
        (bad[1], bad[2]) = (bad[2], bad[1]);
        Continuity.Params memory p = Continuity.Params(4, 1, 4);
        vm.expectRevert(abi.encodeWithSelector(Continuity.InvalidCommittee.selector, false));
        this._check(bad, good, p);
        vm.expectRevert(abi.encodeWithSelector(Continuity.InvalidCommittee.selector, true));
        this._check(good, bad, p);
        Continuity.Member[] memory dup = _eq(4, 1);
        dup[2].id = dup[1].id;
        vm.expectRevert(abi.encodeWithSelector(Continuity.InvalidCommittee.selector, true));
        this._check(good, dup, p);
    }

    function test_aTotalAbove64BitsIsRefused() public {
        Continuity.Member[] memory big = _eq(3, type(uint64).max / 2);
        Continuity.Member[] memory ok = _eq(3, 1);
        vm.expectRevert(abi.encodeWithSelector(Continuity.InvalidCommittee.selector, false));
        this._check(big, ok, Continuity.Params(4, 1, 4));
    }

    /// @dev The default committee sizes at the ceiling: 128 members, one replaced, measured with full-width weights.
    function test_aFullCommitteeAtTheCeilingIsMeasuredExactly() public pure {
        Continuity.Member[] memory o = _eq(128, type(uint64).max / 129);
        Continuity.Member[] memory s = _eq(128, type(uint64).max / 129);
        s[127].binding = bytes32(uint256(999));
        (uint8 failed, Continuity.Measured memory r) =
            Continuity.check(o, s, Continuity.Params(4, 1, 4));
        assertEq(r.replaced, 1);
        assertEq(r.m, 2);
        assertEq(failed, 0);
    }
}
