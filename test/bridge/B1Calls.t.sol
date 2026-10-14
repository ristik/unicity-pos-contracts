// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {Anchor} from "../../src/bridge/BridgeTypes.sol";
import {BudgetExceeded} from "../../src/bridge/BridgeErrors.sol";

/// @dev Exposes the internal request builders so their caps can be tested directly.
contract B1CallsHarness {
    function batch(Anchor[] memory a) external pure returns (bytes memory) {
        return B1Calls.batchRequest(a);
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

    function _table(uint256 k, uint256 shardLen, uint256 ucLen)
        internal
        pure
        returns (Anchor[] memory t)
    {
        t = new Anchor[](k);
        for (uint256 i = 0; i < k; ++i) {
            t[i] = _anchor(shardLen, ucLen);
        }
    }

    function test_batchRequest_capsAreEnforced() public {
        // header 4, then per claim: partition 4, shard length 2, shard, three words, UC length 4, UC
        assertEq(h.batch(_table(1, 33, 24576)).length, 4 + 4 + 2 + 33 + 96 + 4 + 24576);
        assertEq(h.batch(_table(16, 1, 10)).length, 4 + 16 * (4 + 2 + 1 + 96 + 4 + 10));
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.batch(_table(1, 34, 0));
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.batch(_table(1, 1, 24577));
    }

    function test_batchRequest_claimCountIsOneToSixteen() public {
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.batch(_table(0, 1, 1));
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.batch(_table(17, 1, 1));
        bytes memory req = h.batch(_table(16, 1, 1));
        assertEq(bytes4(req), bytes4(hex"02000010"), "version 2, flags 0, K = 16");
    }

    function test_memberRequest_valueCap() public {
        assertEq(h.member(new bytes(4096)).length, 4 + 32 + 32 + 4 + 4096 + 32);
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.member(new bytes(4097));
    }
}
