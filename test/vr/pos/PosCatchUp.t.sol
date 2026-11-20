// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {RecordKind, ClosureData} from "../../../src/p85/P85Types.sol";

/// @notice Sustained catch-up at the pinned H = 16 of the PoS-capable build (VT-04b, astra #1217 r1 item 3): a root producer and an EVM
/// consumer at the supported cadence over the real PoS stack (VR, the adapter, P85 custody as holder 0).
///
/// The consumer is the hook of every EVM block: `applyRootRecords(min(H, available))`, then `elect(origin)`. The producer starts with
/// an initial backlog of 55 records and a due election, then delivers legal arrivals at the protocol bound: at most 32 records per
/// root block (design 4.3), and per epoch (at least MIN_EPOCH_GAP = 100 progress units apart) at most one handoff's records, which
/// is Ack, Boundary, OutputRejected, SessionClosed, at most 16 Closures (one per member) and at most 16 HolderRetirements: 36 records
/// delivered as a burst of 32 in one root block and the remaining 4 in the next. So arrivals average at most 0.36 per EVM block
/// against a capacity of H = 16: the surplus capacity is positive and a backlog of B drains in ceil(B / H) blocks.
///
/// Recorded per burst: target (the registry's record count), imported (what the block imports, the same log), the VR cursor and the
/// custody cursor. Checked: the election due at the start does not reserve while the cursor is behind and reserves in the block that
/// catches up; after every burst the backlog is back to zero within ceil(32 / H) + 1 blocks; the cursors and the target agree at the end.
contract PosCatchUpTest is PosBase {
    uint32 internal constant H = 16;

    function _foreign(uint256 i) internal {
        pushRecord(
            RecordKind.Closure,
            abi.encode(
                ClosureData(
                    keccak256(abi.encode("a foreign assignment", i)),
                    1,
                    keccak256(abi.encode("h-record", i)),
                    keccak256("terminal"),
                    keccak256("exposure"),
                    keccak256("key-history")
                )
            )
        );
    }

    function test_aBacklogAndContinuingArrivalsConverge() public {
        uint256 produced;
        for (uint256 i = 0; i < 55; ++i) {
            _foreign(produced++);
        }
        _advance(300, 200); // the cadence has passed: an election is due
        uint256 firstReserved = type(uint256).max;
        uint256 worstBacklog = 55;
        uint256 lastBurstDrained;
        uint64 caughtUpAt;
        for (uint256 b = 0; b < 400; ++b) {
            _advance(1, 1);
            if (b > 1 && b % 100 == 0) {
                for (uint256 i = 0; i < 32; ++i) {
                    _foreign(produced++);
                }
                lastBurstDrained = 0;
            } else if (b > 1 && b % 100 == 1) {
                for (uint256 i = 0; i < 4; ++i) {
                    _foreign(produced++);
                }
            }
            uint64 target = roots.recordCount();
            uint64 cursor = vr.recordCursor();
            uint64 backlog = target - cursor;
            if (backlog > worstBacklog) worstBacklog = backlog;
            uint32 n = uint32(backlog > H ? H : backlog);
            if (n != 0) _vrApply(n);
            assertEq(vr.recordCursor(), cursor + n, "exactly min(H, available) per block");
            uint8 o = _vrElect(ORIGIN);
            if (o == VRC.ELECT_RESERVED && firstReserved == type(uint256).max) {
                firstReserved = b;
            }
            if (vr.recordCursor() == target && lastBurstDrained == 0 && b > 1) {
                lastBurstDrained = b;
                caughtUpAt = uint64(b);
            }
            if (b % 100 == 0 || b % 100 == 1 || b == 3) {
                emit log_named_uint("block", b);
                emit log_named_uint("  target", target);
                emit log_named_uint("  imported", roots.recordCount());
                emit log_named_uint("  vr cursor", vr.recordCursor());
                emit log_named_uint("  custody cursor", custody.recordCursor());
                emit log_named_uint("  elect outcome", o);
            }
            if (b % 100 >= 3 && b > 3) {
                assertEq(vr.recordCursor(), target, "caught up within three blocks of a burst");
            }
        }
        assertEq(roots.recordCount(), produced);
        assertEq(vr.recordCursor(), produced, "converged: the VR cursor is the target");
        assertEq(custody.recordCursor(), vr.recordCursor(), "custody is at the VR cursor");
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(firstReserved, (55 + H - 1) / H - 1, "the due election resumes in the block that catches up");
        assertLe(worstBacklog, 55, "legal arrivals never grew the initial backlog");
        assertGt(caughtUpAt, 0);
    }
}
