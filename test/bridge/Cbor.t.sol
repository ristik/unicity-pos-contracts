// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Cbor} from "../../src/bridge/Cbor.sol";
import {CborMalformed} from "../../src/bridge/BridgeErrors.sol";

contract CborHarness {
    function readBytes(bytes memory b, uint256 pos, uint256 min, uint256 max)
        external
        pure
        returns (bytes memory out, uint256 next)
    {
        return Cbor.readBytes(b, pos, min, max);
    }
}

/// @notice The byte-string reader copies with `mcopy`, which never traps on an out-of-range source:
///         the declared length is checked against the input before anything is copied.
contract CborTest is Test {
    CborHarness internal h = new CborHarness();

    function test_readBytes_copiesExactly() public view {
        (bytes memory out, uint256 next) = h.readBytes(hex"43aabbcc", 0, 0, 8);
        assertEq(out, hex"aabbcc");
        assertEq(next, 4);
    }

    function test_readBytes_aDeclaredLengthPastTheInputIsMalformed() public {
        vm.expectRevert(abi.encodeWithSelector(CborMalformed.selector));
        h.readBytes(hex"43aabb", 0, 0, 8);
        vm.expectRevert(abi.encodeWithSelector(CborMalformed.selector));
        h.readBytes(hex"5820aabb", 0, 0, 64);
    }
}
