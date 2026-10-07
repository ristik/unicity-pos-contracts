// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {IPolicySource} from "../../src/p85/IP85.sol";
import {Policy} from "../../src/p85/P85Types.sol";

/// @notice Test-only policy source without the development-profile bounds, to exercise guards that
/// the bounded FixedPolicy makes redundant (and to model a later, laxer policy snapshot).
contract UncheckedPolicy is IPolicySource {
    Policy[] internal _snapshots;

    constructor(Policy memory first) {
        _snapshots.push(first);
    }

    function addSnapshot(Policy memory p) external {
        _snapshots.push(p);
    }

    function currentPolicyID() external view returns (uint32) {
        return uint32(_snapshots.length);
    }

    function policyAt(uint32 policyID) external view returns (Policy memory) {
        return _snapshots[policyID - 1];
    }

    function policy() external view returns (Policy memory) {
        return _snapshots[_snapshots.length - 1];
    }
}
