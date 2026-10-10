// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {P85Genesis} from "../../script/P85Genesis.s.sol";

/// @dev Exposes the genesis script's bound reader and its check.
contract P85GenesisHarness is P85Genesis {
    function bound() external view returns (uint64, uint64) {
        return _distanceBound();
    }

    function checked(uint256 num, uint256 den) external pure returns (uint64, uint64) {
        return _checkedBound(num, den);
    }
}

/// @notice The genesis script's election distance bound: the testnet default is pinned and a malformed bound is refused. (The environment is
/// never written here: a process-wide variable would leak into the other tests, so the default test relies on P85_DIST_* being unset.)
contract GenesisScriptTest is Test {
    P85GenesisHarness h = new P85GenesisHarness();

    function test_theDefaultIsTheTestnetBoundOneHalf() public view {
        (uint64 n, uint64 d) = h.bound();
        assertEq(n, 1);
        assertEq(d, 2);
        assertEq(h.TESTNET_DIST_NUM(), 1);
        assertEq(h.TESTNET_DIST_DEN(), 2);
    }

    function test_theProductionBoundIsAccepted() public view {
        (uint64 n, uint64 d) = h.checked(1, 4);
        assertEq(n, 1);
        assertEq(d, 4);
    }

    function test_aBoundOfOneIsAccepted() public view {
        (uint64 n, uint64 d) = h.checked(3, 3);
        assertEq(n, 3);
        assertEq(d, 3);
    }

    function _refused(uint256 num, uint256 den) internal {
        vm.expectRevert(bytes("P85: distance bound must satisfy 0 < num <= den"));
        h.checked(num, den);
    }

    function test_aZeroDenominatorIsRefused() public {
        _refused(1, 0);
    }

    function test_aZeroNumeratorIsRefused() public {
        _refused(0, 4);
    }

    function test_aBoundAboveOneIsRefused() public {
        _refused(3, 2);
    }

    function test_aDenominatorBeyondUint64IsRefused() public {
        _refused(1, uint256(type(uint64).max) + 1);
    }
}
