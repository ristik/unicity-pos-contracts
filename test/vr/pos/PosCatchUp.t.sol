// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {Delegation, DelegationRequest, ElectionParams, RecordKind, BoundaryData, ClosureData, HolderRetirementData} from "../../../src/p85/P85Types.sol";

/// @notice Sustained catch-up at the pinned H = 16 of the PoS-capable build (VT-04b; astra #1217 r1 and r2): a root producer and an EVM
/// consumer over the real PoS stack (VR, the adapter, P85 custody as holder 0), at an explicit testnet operating limit.
///
/// **Protocol bounds.** The root projects at most 32 records per root block; one EVM block imports at most 32 records into the
/// SealRegistry (the per-block import is one root input) and applies at most H = 16 of them (`applyRootRecords(min(H, available))`).
///
/// **Supported rates (testnet operating limit).** EVM blocks are about 10 s apart and a root round about 1 s, so one EVM block spans
/// ROOT_PER_EVM = 10 root blocks. Arrivals per eligible EVM block must stay strictly below 16 on average, with margin: the limit is
/// at most 4 records per EVM block steady (records ordered independently of any handoff: 0.4 per root block), plus one
/// burst root block of 32 projected records in any 10 EVM blocks (3.2 per EVM block): at most 7.2 per EVM block against a service
/// capacity of 16, and at most one burst of 32 accumulated at a time (a backlog never exceeds the import cap plus one burst plus the
/// steady arrivals). This is tight: at 10 root blocks per EVM block, the protocol's 32 per root block can be sustained for only 5% of
/// root blocks, and a steady 1.6 records per root block already saturates the 16 per EVM block.
///
/// The four counters are separate: the root target (records the producer has projected), the SealRegistry imported count
/// (`roots.recordCount()`, at most 32 per EVM block), the VR cursor and the custody cursor. Elections come due on the cadence
/// (200 rounds = 20 EVM blocks at 10 rounds per block); each one is published and acknowledged through the stream.
contract PosCatchUpTest is PosBase {
    uint32 internal constant H = 16;

    /// @dev Churn is not the subject: continuity 1/1 (as the lifecycle test), the profile's committee of at most 5.
    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4, nTarget: 5, nMax: 5, maxM: 4, distNum: 1, distDen: 1, cadenceRounds: 200, cadenceSeconds: 100
        });
    }
    uint256 internal constant IMPORT_CAP = 32;
    uint256 internal constant ROOT_PER_EVM = 10;

    // the producer's projected-record queue (the root target), imported into the registry per EVM block
    RecordKind[] internal qKind;
    bytes[] internal qData;
    uint256 internal target; // root target: records projected
    uint256 internal retirementSeq;

    function _project(RecordKind kind, bytes memory data) internal {
        qKind.push(kind);
        qData.push(data);
        ++target;
    }

    /// @dev Independent arrivals, ordered by the root regardless of any handoff: foreign Closures (a Closure per closed epoch or
    /// assignment of another shard's output; VR and custody apply them as no-ops and advance). Independent HolderRetirements cannot form
    /// a sustained stream in a generation: VR marks one per (holder, identity, generation) and a repeat is an anomaly (health Inconsistent),
    /// custody (holder 0) reverts on one whose identity has not requested retirement, and the PoS profile has at most 8 identities of one
    /// lot, so at most 8 x (generations) legal retirements exist in the generation's lifetime. Their write cost is the retirement batch of
    /// the ureth measurement (`batch32-retire`, the `mixed-*` fillers); their arrival count is bounded by that profile.
    function _projectArrivals(uint256 n) internal {
        for (uint256 i = 0; i < n; ++i) {
            _project(
                RecordKind.Closure,
                abi.encode(
                    ClosureData(
                        keccak256(abi.encode("a foreign assignment", retirementSeq)),
                        1,
                        keccak256(abi.encode("h-record", retirementSeq)),
                        keccak256("terminal"),
                        keccak256("exposure"),
                        keccak256("key-history")
                    )
                )
            );
            ++retirementSeq;
        }
    }

    // ---- exits through catch-up: valid, requested holder-0 retirements of successive identities and generations ----
    //
    // Each cycle: a new identity registers, is elected, requests retirement, is excluded by the next election, its last reference closes,
    // custody imports the HolderRetirement and the lot matures and is claimed (the index slot is free again); three successive identities.
    // A rebond (generation 2 of the same identity) is not exercised: the PoS adapter requires the VR binding generation to equal the custody
    // generation, which needs a VR-side rebinding that this test does not drive. The retirement record is projected inside a 32-record burst, between an
    // election's publication and the next election, while elections keep coming due on the cadence. The live index never exceeds 5 of the
    // profile's 8 and the committee never exceeds 5; the number of retirements in the generation's lifetime is not bounded by the index.
    uint256 internal constant BOND = 1_000 ether;
    Joiner internal jx;
    uint64 internal jxGen;
    uint256 internal jxN; // the registration counter value of jx (its node ids)
    uint256 internal cycle; // 0..2, 3 = done
    uint256 internal stage; // 0 idle, 1 wait elected, 2 wait excluded + closed, 3 wait retirement imported
    uint256 internal retirementsImported;
    uint256 internal retirementBlock;

    function _inCommittee(uint64 id) internal view returns (bool) {
        uint64[] memory ids = vr.committeeIds();
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i] == id) return true;
        }
        return false;
    }

    function _startCycle() internal {
        {
            jx = _joinPos(BOND);
            jxN = joinerCount;
            jxGen = 1;
            evmPkOf[jx.id] = jx.evmPk;
        }
        stage = 1;
    }

    /// @dev One block of the exit state machine, after the block's hooks.
    /// @dev Custody refuses owner operations (`requestRetirement`, `mature`, `bond` of a retiring identity) with `RecordsPending` while it is
    /// behind the registry, so an owner acts only in a block where it has caught up: the operator guidance on pacing.
    function _caughtUp() internal view returns (bool) {
        return custody.recordCursor() == roots.recordCount();
    }

    function _cycleTick() internal {
        if (cycle >= 3 || !_caughtUp()) return;
        if (stage == 0) {
            _startCycle();
        } else if (stage == 1) {
            if (_inCommittee(jx.id)) {
                vm.prank(vm.addr(jx.ownerPk));
                custody.requestRetirement(jx.id);
                requestedSeen[jx.id][jxGen] = true;
                _assertFacts(jx.id, jxGen);
                stage = 2;
            }
        } else if (stage == 2) {
            // excluded by the next election and its last reference closed (the Closure of the assignment it was in has been applied)
            if (!_inCommittee(jx.id) && custody.liveExposures(jx.id, jxGen) == 0
                && progress >= custody.maxLiabilityAnchor(jx.id, jxGen)) {
                // the retirement lands in the middle of a full burst
                _projectArrivals(16);
                _project(
                    RecordKind.HolderRetirement,
                    abi.encode(HolderRetirementData(0, jx.id, jxGen, custody.exposureChain(jx.id, jxGen)))
                );
                _projectArrivals(16);
                retirementBlock = block.number;
                stage = 3;
            }
        } else if (stage == 3) {
            (bool imported,,) = custody.retirements(jx.id, jxGen);
            if (imported) {
                assertTrue(vr.retired(0, jx.id, jxGen), "VR marked the retirement");
                _assertFacts(jx.id, jxGen);
                ++retirementsImported;
                // maturity and claim free the live index slot (and, for a rebond, allow the next generation)
                _advance(100_000, 100_000);
                uint256[] memory lots = custody.generationLots(jx.id, jxGen);
                custody.mature(lots);
                address wd = vm.addr(jx.ownerPk);
                uint256 credit = custody.credit(wd);
                assertEq(credit, BOND, "the bond is claimable");
                vm.prank(wd);
                custody.claim(credit, wd);
                ++cycle;
                stage = 0;
            }
        }
    }

    bytes32 internal open2; // set by the loop once an election of this cycle has been acknowledged-projected

    /// @dev One EVM block's import: up to IMPORT_CAP of the projected records enter the SealRegistry.
    function _import() internal {
        uint256 have = roots.recordCount();
        uint256 n = target - have;
        if (n > IMPORT_CAP) n = IMPORT_CAP;
        for (uint256 i = 0; i < n; ++i) {
            pushRecord(qKind[have + i], qData[have + i]);
        }
    }

    function test_aBacklogAndContinuingIndependentArrivalsConverge() public {
        vm.pauseGasMetering();
        _projectArrivals(55); // the initial backlog
        _advance(300, 200); // the cadence has passed: an election is due at the start
        bytes32 incumbent = GENESIS_ASSIGNMENT;
        uint256[3] memory electionBlock;
        uint256 elections;
        uint256 notReservedWhileDue; // elect attempts that found the cursor behind
        uint256 maxImportLag;
        uint256 maxApplyLag;
        uint256 maxBacklog = target;
        bytes32 open;
        uint256 firstReservedBlock = type(uint256).max;
        for (uint256 b = 0; b < 360; ++b) {
            _advance(uint64(ROOT_PER_EVM), 10);
            if (b < 330) {
                // the producer, per root block of this EVM interval: steady independent retirements, and a burst root block
                _projectArrivals(2); // root block 0
                _projectArrivals(2); // root block 5
                if (b % 10 == 0) _projectArrivals(32); // a full projected block
            }
            if (target - roots.recordCount() > maxImportLag) maxImportLag = target - roots.recordCount();
            _import();
            uint64 imported = roots.recordCount();
            uint64 cursor = vr.recordCursor();
            if (imported - cursor > maxApplyLag) maxApplyLag = imported - cursor;
            uint32 n = uint32(imported - cursor > H ? H : imported - cursor);
            if (n != 0) _vrApply(n);
            assertEq(vr.recordCursor(), cursor + n, "exactly min(H, imported) per block");
            uint8 o = _vrElect(ORIGIN);
            if (target - vr.recordCursor() > maxBacklog) maxBacklog = target - vr.recordCursor();
            if (o == VRC.ELECT_RESERVED) {
                assertEq(vr.recordCursor(), roots.recordCount(), "an election reserves only when VR is caught up with the registry");
                electionBlock[elections < 3 ? elections : 2] = b;
                ++elections;
                emit log_named_uint("election reserved at block", b);
                if (firstReservedBlock == type(uint256).max) firstReservedBlock = b;
                open = vr.openOutput();
                open2 = open;
                assertEq(_publishResult2(open), VRC.PUB_PUBLISHED, "publish");
                uint64 e = vr.config().knownRootEpoch + 1;
                _project(RecordKind.Ack, ackData(open, 150 + progress, 160 + progress, 161 + progress));
                _project(
                    RecordKind.Boundary, abi.encode(BoundaryData(open, e, e, e, 5_000, false, 0))
                );
                // the incumbent assignment closes (the roots project its Closure from the retained bundle)
                _project(RecordKind.Closure, closureData(incumbent, 150 + progress, "closure"));
                incumbent = election.result(open).assignmentID;
            } else if (vr.openOutput() == bytes32(0) && vr.recordCursor() < imported + 0 && imported > cursor + n) {
                ++notReservedWhileDue;
            }
            if (b % 40 == 0 || b == 3) {
                emit log_named_uint("block", b);
                emit log_named_uint("  root target", target);
                emit log_named_uint("  registry imported", roots.recordCount());
                emit log_named_uint("  vr cursor", vr.recordCursor());
                emit log_named_uint("  custody cursor", custody.recordCursor());
                emit log_named_uint("  elections reserved", elections);
            }
            _cycleTick();
            assertEq(vr.health(), VRC.HEALTHY, "healthy");
        }
        // the producer stopped at block 330: everything drained
        assertEq(roots.recordCount(), target, "imported = target");
        assertEq(vr.recordCursor(), target, "VR cursor = target");
        assertEq(custody.recordCursor(), target, "custody cursor = target");
        assertGe(firstReservedBlock, 3, "the election due at the start waits for the catch-up of a 55-record backlog plus the arrivals");
        assertLe(firstReservedBlock, 8, "and resumes within eight blocks");
        assertEq(cycle, 3, "three exits of successive identities completed");
        assertEq(retirementsImported, 3, "custody imported three holder-0 retirements during the run");
        assertGe(elections, 5, "elections keep coming due and completing under the continuing arrivals");
        assertEq(_state(open), VRC.OUT_ACKNOWLEDGED, "the last election's output was acknowledged through the stream");
        assertGt(maxImportLag, 0, "the import lag was observed (target ahead of the registry)");
        assertGt(maxApplyLag, 0, "the apply lag was observed (registry ahead of VR)");
        assertLe(maxBacklog, 3 * IMPORT_CAP + 2 * ROOT_PER_EVM, "the accumulated backlog stays bounded");
        emit log_named_uint("max import lag", maxImportLag);
        emit log_named_uint("max apply lag", maxApplyLag);
        emit log_named_uint("max backlog", maxBacklog);
        emit log_named_uint("elections", elections);
        emit log_named_uint("elect attempts behind", notReservedWhileDue);
    }
}
