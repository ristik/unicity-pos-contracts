// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Policy} from "./P85Types.sol";

/// @title PolicyBounds
/// @notice The immutable development-profile bounds of design v5 section 6, for the policy fields
/// custody and evidence consume. Governance (PR4) reuses this check at queue, execution, activation
/// and snapshot.
library PolicyBounds {
    error PolicyOutOfBounds(bytes32 field);

    uint16 internal constant MAX_PENALTY_BPS = 200; // 2%
    uint16 internal constant MAX_CAP_BPS = 1_000; // 10%
    uint16 internal constant MAX_BOUNTY_BPS = 2_000; // 20%
    uint128 internal constant MAX_BOUNTY_CAP = 10 ether; // 10 UCT of 10^18 base units
    uint64 internal constant MIN_EVIDENCE = 200;
    uint64 internal constant MAX_EVIDENCE = 10_000;
    uint64 internal constant MIN_HOLD = 400;
    uint64 internal constant MAX_HOLD = 20_000;
    uint64 internal constant MIN_FLOOR = 3_600;
    uint64 internal constant MAX_FLOOR = 604_800;

    function validate(Policy memory p) internal pure {
        if (p.penaltyBps > MAX_PENALTY_BPS) revert PolicyOutOfBounds("penaltyBps");
        if (p.lifetimeCapBps > MAX_CAP_BPS) revert PolicyOutOfBounds("lifetimeCapBps");
        if (p.bountyBps > MAX_BOUNTY_BPS) revert PolicyOutOfBounds("bountyBps");
        if (p.bountyCap > MAX_BOUNTY_CAP) revert PolicyOutOfBounds("bountyCap");
        if (p.evidenceWindow < MIN_EVIDENCE || p.evidenceWindow > MAX_EVIDENCE) {
            revert PolicyOutOfBounds("evidenceWindow");
        }
        if (p.suffixEvidenceWindow < MIN_EVIDENCE || p.suffixEvidenceWindow > MAX_EVIDENCE) {
            revert PolicyOutOfBounds("suffixEvidenceWindow");
        }
        // W_cert (100 rounds) <= the 200-round minimum evidence window, so the range check implies it.
        if (p.holdNormal < MIN_HOLD || p.holdNormal > MAX_HOLD) {
            revert PolicyOutOfBounds("holdNormal");
        }
        if (p.holdSuffix < MIN_HOLD || p.holdSuffix > MAX_HOLD) {
            revert PolicyOutOfBounds("holdSuffix");
        }
        if (p.holdRetirement < MIN_HOLD || p.holdRetirement > MAX_HOLD) {
            revert PolicyOutOfBounds("holdRetirement");
        }
        // each relevant hold is strictly greater than its evidence window
        if (p.holdNormal <= p.evidenceWindow) revert PolicyOutOfBounds("holdNormal<=evidence");
        if (p.holdSuffix <= p.suffixEvidenceWindow) {
            revert PolicyOutOfBounds("holdSuffix<=evidence");
        }
        uint64 widest =
            p.evidenceWindow > p.suffixEvidenceWindow ? p.evidenceWindow : p.suffixEvidenceWindow;
        if (p.holdRetirement <= widest) revert PolicyOutOfBounds("holdRetirement<=evidence");
        if (p.timeFloor < MIN_FLOOR || p.timeFloor > MAX_FLOOR) {
            revert PolicyOutOfBounds("timeFloor");
        }
    }
}
