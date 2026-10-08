// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Quantize} from "../../src/p85/Quantize.sol";

/// @notice The quantization rule against the shared reference vectors, and its invariants as properties.
contract QuantizeTest is Test {
    function _call(uint256[] memory x, uint256 b) external pure returns (uint256[] memory) {
        return Quantize.quantize(x, b);
    }

    function _strings(string memory json, string memory key)
        internal
        pure
        returns (uint256[] memory)
    {
        return vm.parseJsonUintArray(json, key);
    }

    function test_theSharedVectors() public {
        string memory json = vm.readFile("test/p85/fixtures/quant-vectors.json");
        assertEq(vm.parseJsonUint(json, ".b"), Quantize.WEIGHT_CAP_B);
        uint256 count = abi.decode(vm.parseJson(json, ".cases[*].b"), (uint256[])).length;
        assertGt(count, 30);
        for (uint256 i = 0; i < count; ++i) {
            string memory c = string.concat(".cases[", vm.toString(i), "]");
            uint256[] memory x = vm.parseJsonUintArray(json, string.concat(c, ".x"));
            uint256 b = vm.parseJsonUint(json, string.concat(c, ".b"));
            if (vm.keyExistsJson(json, string.concat(c, ".error"))) {
                vm.expectRevert();
                this._call(x, b);
                continue;
            }
            uint256[] memory want = vm.parseJsonUintArray(json, string.concat(c, ".q"));
            uint256[] memory got = Quantize.quantize(x, b);
            assertEq(got.length, want.length, vm.parseJsonString(json, string.concat(c, ".name")));
            for (uint256 k = 0; k < got.length; ++k) {
                assertEq(got[k], want[k], vm.parseJsonString(json, string.concat(c, ".name")));
            }
        }
    }

    function test_refusals() public {
        uint256[] memory none = new uint256[](0);
        vm.expectRevert(Quantize.EmptyCommittee.selector);
        this._call(none, 100);
        uint256[] memory zero = new uint256[](2);
        zero[0] = 1;
        vm.expectRevert(Quantize.ZeroWeight.selector);
        this._call(zero, 100);
        uint256[] memory two = new uint256[](2);
        two[0] = 1;
        two[1] = 1;
        vm.expectRevert(Quantize.CommitteeAboveCap.selector);
        this._call(two, 2);
        uint256[] memory big = new uint256[](2);
        big[0] = type(uint64).max;
        big[1] = 1;
        vm.expectRevert(Quantize.WeightOverflow.selector);
        this._call(big, 100);
        uint256[] memory huge = new uint256[](2);
        huge[0] = type(uint256).max;
        huge[1] = 1;
        vm.expectRevert(Quantize.WeightOverflow.selector);
        this._call(huge, 100);
    }

    /// @dev Σq <= B, 1 <= q <= x, the raw order is preserved weakly, and the whole set is unchanged at or below the cap.
    function testFuzz_invariants(uint8 count, uint64 seed, uint8 magnitude) public pure {
        uint256 n = bound(count, 1, 100);
        uint256[] memory x = new uint256[](n);
        uint256 total;
        uint256 mag = uint256(1) << bound(magnitude, 1, 40);
        for (uint256 i = 0; i < n; ++i) {
            x[i] = (uint256(keccak256(abi.encode(seed, i))) % mag) + 1;
            total += x[i];
        }
        uint256[] memory q = Quantize.quantize(x);
        uint256 sum;
        for (uint256 i = 0; i < n; ++i) {
            assertGe(q[i], 1);
            assertLe(q[i], x[i]);
            sum += q[i];
            for (uint256 j = 0; j < n; ++j) {
                if (x[i] >= x[j]) assertGe(q[i], q[j]);
            }
            if (total <= Quantize.WEIGHT_CAP_B) assertEq(q[i], x[i]);
        }
        assertLe(sum, Quantize.WEIGHT_CAP_B);
        // the drift bound of the design (F3): each member's share moves by less than 2n/Q... checked on the largest member
        if (total > Quantize.WEIGHT_CAP_B) {
            uint256 maxI;
            for (uint256 i = 1; i < n; ++i) {
                if (x[i] > x[maxI]) maxI = i;
            }
            // |q_m/Q - x_m/X| < 2n/Q  <=>  |q_m*X - x_m*Q| * 1 < 2n*X  (cross-multiplied, exact)
            uint256 a = q[maxI] * total;
            uint256 c = x[maxI] * sum;
            uint256 diff = a > c ? a - c : c - a;
            assertLt(diff, 2 * n * total);
        }
    }
}
