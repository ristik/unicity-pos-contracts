// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Continuity} from "./Continuity.sol";
import {Selection} from "./Selection.sol";

/// @title SelectionEngine
/// @notice The stateless, pure host of `Selection.select`. It has no storage, no admin and no dependencies; ElectionPolicy calls it
/// (a static call) with the frozen snapshot and takes the result. It is a separate contract only so that ElectionPolicy stays under
/// the contract size limit; its address is pinned by the genesis manifest, whose hash also pins the deployed code.
contract SelectionEngine {
    function select(
        Continuity.Member[] memory o,
        Selection.Entry[] memory e,
        Selection.Config memory cfg
    ) external pure returns (Selection.Reason reason, Continuity.Member[] memory chosen) {
        return Selection.select(o, e, cfg);
    }
}
