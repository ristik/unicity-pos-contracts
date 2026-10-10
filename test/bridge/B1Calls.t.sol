// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {Anchor} from "../../src/bridge/BridgeTypes.sol";
import {BudgetExceeded} from "../../src/bridge/BridgeErrors.sol";

/// @dev Exposes the internal request builders so their caps can be tested directly.
contract B1CallsHarness {
    function uc(Anchor memory a) external pure returns (bytes memory) {
        return B1Calls.ucRequest(a);
    }

    function member(bytes memory value) external pure returns (bytes memory) {
        return B1Calls.memberRequest(bytes32(0), bytes32(0), value, bytes32(0), new bytes32[](0));
    }
}

/// @notice The request caps that the composing verifier cannot reach (its shard is one byte, its UC is
///         tighter-bounded by the profile, and its RSMT value is always a 32-byte leaf value) are
///         enforced by the wrappers themselves.
contract B1CallsTest is Test {
    B1CallsHarness internal h = new B1CallsHarness();

    function _anchor(uint256 shardLen, uint256 ucLen) internal pure returns (Anchor memory a) {
        a.shard = new bytes(shardLen);
        a.uc = new bytes(ucLen);
    }

    function test_ucRequest_capsAreEnforced() public {
        assertEq(h.uc(_anchor(33, 24576)).length, 4 + 4 + 2 + 33 + 96 + 4 + 24576);
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.uc(_anchor(34, 0));
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.uc(_anchor(1, 24577));
    }

    function test_memberRequest_valueCap() public {
        assertEq(h.member(new bytes(4096)).length, 4 + 32 + 32 + 4 + 4096 + 32);
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.member(new bytes(4097));
    }
}
