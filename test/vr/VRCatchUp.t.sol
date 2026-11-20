// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "./VRBase.sol";
import {VRC} from "../../src/vr/VRConstants.sol";

/// @notice Catch-up throughput at the pinned H (VT-04b, astra's caps ruling: "verify catch-up throughput at the selected H").
/// The root emits at most 32 records per root block (design 4.3), the hook applies `min(H, available)` per EVM block. A backlog of
/// `3H + 7` records, with the Ack as the last record of the first call and its Boundary the first of the second (the pair split
/// across two blocks: the worst placement), must drain exactly H per block with VR Healthy, the pair staged between the blocks and
/// the Boundary's change applied. H is 32 for the PoA build and 16 for the PoS-capable one (`VR_BUILD=pos`).
contract VRCatchUpTest is VRBase {
    function _h() internal view returns (uint32) {
        bool pos = keccak256(bytes(vm.envOr("VR_BUILD", string("")))) == keccak256("pos");
        return uint32(vm.envOr("VR_HOOK_H", pos ? uint256(16) : uint256(32)));
    }

    function test_aBacklogDrainsAtHPerBlock() public {
        uint32 h = _h();
        genesisMaxBatch = h;
        _setUpVR(5, 1, 5, 16);
        uint64 change = _queueScheduled(
            VRC.K_FEE_PARAMS, abi.encode(uint64(2_000_000), uint64(8), address(0xFEE))
        );
        bytes32 rid = _rid("R");
        assertEq(_moduleReserve(rid, true), VRC.ELECT_RESERVED);
        uint256 total = 3 * uint256(h) + 7;
        _advance(1, 1);
        for (uint256 i = 0; i < total; ++i) {
            if (i == h - 1) _recAck(rid);
            else if (i == h) _recBoundary(rid, _nextEpoch(), false, 0);
            else _recClosure(keccak256(abi.encode("backlog", i)));
        }
        assertEq(seal.recordCount(), total);
        uint256 blocks;
        while (vr.recordCursor() < seal.recordCount()) {
            uint64 cursor = vr.recordCursor();
            uint64 n = seal.recordCount() - cursor;
            if (n > h) n = h;
            _apply(uint32(n));
            ++blocks;
            assertEq(vr.recordCursor(), cursor + n, "exactly min(H, available) per block");
            assertEq(vr.health(), VRC.HEALTHY);
            if (blocks == 1) {
                assertEq(vr.pendingPair(), rid, "the Ack staged its pair between the blocks");
                assertEq(_state(rid), VRC.OUT_PUBLISHED, "not finalized until its Boundary");
            }
        }
        assertEq(blocks, 4, "ceil((3H + 7) / H) blocks");
        assertEq(vr.recordCursor(), total);
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
        assertEq(vr.pendingPair(), bytes32(0), "the Boundary completed the pair");
        assertEq(_changeState(change), VRC.CH_ACTIVE, "the Boundary activated its bound change");
    }

    function _recClosure(bytes32 assignment) internal {
        seal.push(
            VRC.REC_CLOSURE,
            abi.encode(
                assignment,
                uint256(1),
                keccak256(abi.encode("h-record", assignment)),
                keccak256("terminal"),
                keccak256("exposure"),
                keccak256("key-history")
            )
        );
    }
}
