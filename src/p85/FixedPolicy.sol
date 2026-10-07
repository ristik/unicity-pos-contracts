// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Policy} from "./P85Types.sol";
import {IPolicySource} from "./IP85.sol";
import {PolicyBounds} from "./PolicyBounds.sol";

/// @title FixedPolicy
/// @notice Immutable policy source holding the DEV-DEFAULT policy chosen at genesis. PR4's
/// GovernanceParams replaces this module at the same manifest slot and adds prospective, bounded
/// activation; custody and evidence only ever read `policy()` and capture what they need.
contract FixedPolicy is IPolicySource {
    error UnknownPolicy();

    uint16 internal immutable PENALTY_BPS;
    uint16 internal immutable LIFETIME_CAP_BPS;
    uint16 internal immutable BOUNTY_BPS;
    uint128 internal immutable BOUNTY_CAP;
    uint64 internal immutable EVIDENCE_WINDOW;
    uint64 internal immutable SUFFIX_EVIDENCE_WINDOW;
    uint64 internal immutable HOLD_NORMAL;
    uint64 internal immutable HOLD_SUFFIX;
    uint64 internal immutable HOLD_RETIREMENT;
    uint64 internal immutable TIME_FLOOR;

    constructor(Policy memory p) {
        PolicyBounds.validate(p);
        PENALTY_BPS = p.penaltyBps;
        LIFETIME_CAP_BPS = p.lifetimeCapBps;
        BOUNTY_BPS = p.bountyBps;
        BOUNTY_CAP = p.bountyCap;
        EVIDENCE_WINDOW = p.evidenceWindow;
        SUFFIX_EVIDENCE_WINDOW = p.suffixEvidenceWindow;
        HOLD_NORMAL = p.holdNormal;
        HOLD_SUFFIX = p.holdSuffix;
        HOLD_RETIREMENT = p.holdRetirement;
        TIME_FLOOR = p.timeFloor;
    }

    function currentPolicyID() external pure returns (uint32) {
        return 1;
    }

    function policyAt(uint32 policyID) external view returns (Policy memory) {
        if (policyID != 1) revert UnknownPolicy();
        return _policy();
    }

    function policy() external view returns (Policy memory) {
        return _policy();
    }

    function _policy() private view returns (Policy memory) {
        return Policy({
            penaltyBps: PENALTY_BPS,
            lifetimeCapBps: LIFETIME_CAP_BPS,
            bountyBps: BOUNTY_BPS,
            bountyCap: BOUNTY_CAP,
            evidenceWindow: EVIDENCE_WINDOW,
            suffixEvidenceWindow: SUFFIX_EVIDENCE_WINDOW,
            holdNormal: HOLD_NORMAL,
            holdSuffix: HOLD_SUFFIX,
            holdRetirement: HOLD_RETIREMENT,
            timeFloor: TIME_FLOOR
        });
    }
}
