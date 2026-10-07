// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {VmSafe} from "forge-std/Vm.sol";
import {B1Entry, B1Member, B1Update} from "../src/B1Layout.sol";
import {SealRegistryB1Helpers} from "./SealRegistryB1.t.sol";

/// @dev Storage-cost calibrator: the same SSTORE/SLOAD rules as the registry runs under, in the same
/// test environment. Its per-operation costs let the insert-only fixture separate storage gas from
/// every other cost without assuming an environment's constants.
contract SlotLoop {
    function set(uint256 from, uint256 n) external {
        for (uint256 i = from; i < from + n; i++) {
            assembly ("memory-safe") {
                sstore(i, 1)
            }
        }
    }

    function read(uint256 from, uint256 n) external view returns (uint256 sum) {
        for (uint256 i = from; i < from + n; i++) {
            assembly ("memory-safe") {
                sum := add(sum, sload(i))
            }
        }
    }
}

/// @notice Gross gas of maximal registry updates at several K_max, and the G_rest bound they prove.
///
/// The system call budget (design v4, "Realizable system metering") is
///   g_sys >= 67536 + 326144*K + 22100*(524*K+4) + 7100*524*K + G_rest(K, C_max),
/// where the SSTORE terms are a conservative rectangle (every addressed write at 22100, every clear at
/// 7100, no refund credit) and G_rest bounds every other cost of open + finalize. The worst entry is
/// 64 members with 128-byte node IDs (523 words); the fixtures are
///   - replace: a full ring of K such entries is deleted and K new ones inserted in one open (p = a = K);
///   - insert:  a ring of one open tail gains K-1 such entries and nothing is deleted (p = 0, a = K-1);
///   - prune:   K-1 such entries are deleted by an update with no new entries (p = K-1, a = 0).
/// Insertion costs are exactly the SSTORE-set price per word, so the insert fixture measures G_rest
/// without any slack from the rectangle; deletion costs are bounded against the rectangle's 7100 per
/// clear (the EVM charges at most 5000). The measured table is emitted by the tests and recorded in
/// docs/b1-registry-gas.md. Gas under forge's test EVM is a measurement of this runtime, not a
/// claim about the final client: the ureth system-integration PR re-measures under the real client.
abstract contract SealRegistryB1GasBase is SealRegistryB1Helpers {
    uint256 internal constant WORD_SSTORE_MAX = 22_100;
    uint256 internal constant WORD_CLEAR_MAX = 7100;
    uint256 internal constant CAL_N = 150;
    uint64 internal constant ORIGIN0 = 1000;

    SlotLoop internal loop;
    uint256 internal cSet; // calibrated zero -> non-zero, cold
    uint256 internal cRead; // calibrated cold SLOAD

    function K() internal pure virtual returns (uint256);

    function setUp() public override {
        wCertFixture = uint64(K() - 1);
        super.setUp();
        seedMaxRing(K());
        loop = new SlotLoop();
    }

    // ---------------------------------------------------------------- fixtures

    /// @dev 64 members with 128-byte IDs in increasing order and full-width keys.
    function maxMembers(uint8 seed) internal pure returns (B1Member[] memory ms) {
        ms = new B1Member[](64);
        for (uint256 j = 0; j < 64; j++) {
            B1Member memory m = member(seed, uint8(j));
            m.nodeIDLength = 128;
            bytes32 low = bytes32(uint256(keccak256(abi.encode(seed, j))) >> 32);
            m.nodeID[0] = bytes32(((uint256(j) + 1) << 240)) | low;
            for (uint256 w = 1; w < 4; w++) {
                m.nodeID[w] = keccak256(abi.encode("id", seed, j, w));
            }
            m.weight = type(uint32).max - uint64(j);
            ms[j] = m;
        }
    }

    function maxEntry(uint64 epoch, uint64 start, uint64 end)
        internal
        pure
        returns (B1Entry memory en)
    {
        en = entry(epoch, start, end, 1);
        en.members = maxMembers(uint8(epoch));
    }

    /// @dev The ring a maximal replacement removes: K maximal entries over [L, O] with one start per
    /// round of the window, O = ORIGIN0. Seeded in setUp so the words are committed state.
    function seedMaxRing(uint256 k) internal {
        uint64 L0 = ORIGIN0 - wCertFixture;
        B1Entry[] memory es = new B1Entry[](k);
        for (uint64 i = 0; i < k; i++) {
            es[i] = maxEntry(i + 1, L0 + i, i == k - 1 ? 0 : L0 + i + 1);
        }
        seedRing(es, 0, ORIGIN0);
    }

    /// @dev Replacement at O' = O + K: the old tip closes at L' (p = K deletions) and K new maximal
    /// intervals are inserted (a = K): the first starts at L', the rest at distinct rounds in (L', O'].
    function replaceArgs(uint256 k) internal view returns (OpenArgs memory a) {
        uint64 O1 = ORIGIN0 + uint64(k);
        uint64 L1 = O1 - wCertFixture;
        B1Update memory u = B1Update({
            priorTipEpoch: uint64(k),
            hasOldTipEnd: true,
            oldTipEnd: L1,
            newEntries: new B1Entry[](k)
        });
        for (uint64 i = 0; i < k; i++) {
            u.newEntries[i] = maxEntry(uint64(k) + 1 + i, L1 + i, i == k - 1 ? 0 : L1 + i + 1);
        }
        a = ackWith(O1, uint64(k), u);
    }

    /// @dev Insert-only: the ring keeps only a maximal open tail (the other seeded entries are
    /// cleared), and K-1 maximal entries are added at O' = O + K - 1 with nothing expiring.
    function insertArgs(uint256 k) internal returns (OpenArgs memory a) {
        for (uint256 e = 1; e < k; e++) {
            clearEntry(e, 64);
        }
        for (uint256 i = 0; i < k; i++) {
            vm.store(A_SR, qSlot(i), bytes32(0));
        }
        B1Entry memory tail = maxEntry(uint64(k), ORIGIN0, 0);
        vm.store(A_SR, qSlot(0), bytes32(uint256(k)));
        vm.store(A_SR, fixedSlot("b1.head"), bytes32(0));
        vm.store(A_SR, fixedSlot("b1.count"), bytes32(uint256(1)));
        storeEntry(tail);
        setWord("assignment.rootEpoch", bytes32(uint256(k)));
        setWord("origin.rootEpoch", bytes32(uint256(k)));

        uint64 O1 = ORIGIN0 + uint64(k) - 1;
        B1Update memory u = B1Update({
            priorTipEpoch: uint64(k),
            hasOldTipEnd: true,
            oldTipEnd: ORIGIN0 + 1,
            newEntries: new B1Entry[](k - 1)
        });
        for (uint64 i = 0; i < k - 1; i++) {
            u.newEntries[i] =
                maxEntry(uint64(k) + 1 + i, ORIGIN0 + 1 + i, i == k - 2 ? 0 : ORIGIN0 + 2 + i);
        }
        a = ackWith(O1, uint64(k - 1), u);
    }

    /// @dev Prune-only: an update with no new entries at the round where all but the tail expire.
    /// The window [L, O] holds the k entries; at O' = O + k - 1, L' = O' - W = O, so every entry
    /// except the tail (whose start is O) has end <= O = L' and is removed.
    function pruneArgs(uint256 k) internal view returns (OpenArgs memory a) {
        a = plainAt(ORIGIN0 + uint64(k) - 1);
    }

    // ---------------------------------------------------------------- measurement

    struct Run {
        uint256 openGross;
        uint256 finalizeGross;
        uint256 nRead;
        uint256 nSet;
        uint256 nOther;
    }

    function run(OpenArgs memory a) internal returns (Run memory r) {
        bytes memory openData = openCalldata(a);
        vm.prank(A_SYS);
        vm.startStateDiffRecording();
        uint256 g0 = gasleft();
        (bool ok, bytes memory ret) = A_SR.call(openData);
        uint256 g1 = gasleft();
        VmSafe.AccountAccess[] memory d = vm.stopAndReturnStateDiff();
        if (!ok) emit log_named_bytes("open reverted", ret);
        assertTrue(ok, "open succeeds");
        r.openGross = g0 - g1;
        for (uint256 i = 0; i < d.length; i++) {
            if (d[i].account != A_SR) continue;
            for (uint256 j = 0; j < d[i].storageAccesses.length; j++) {
                VmSafe.StorageAccess memory sa = d[i].storageAccesses[j];
                if (sa.reverted) continue;
                if (!sa.isWrite) r.nRead++;
                else if (sa.previousValue == bytes32(0) && sa.newValue != bytes32(0)) r.nSet++;
                else r.nOther++;
            }
        }
        bytes memory finData = finalizeCalldata(a.n, keccak256("R"));
        vm.prank(A_SYS);
        g0 = gasleft();
        (ok,) = A_SR.call(finData);
        g1 = gasleft();
        assertTrue(ok, "finalize succeeds");
        r.finalizeGross = g0 - g1;
    }

    /// @dev Marginal per-operation gas of set and cold read: (cost of 150 ops - cost of 50 ops) / 100,
    /// less a 60-gas loop allowance, so storage is under-attributed and the remainder over-attributed.
    function calibrate() internal {
        loop.read(5000, 1); // warm the loop account
        uint256 g0 = gasleft();
        loop.set(2000, 50);
        uint256 a = g0 - gasleft();
        g0 = gasleft();
        loop.set(3000, CAL_N);
        uint256 b = g0 - gasleft();
        cSet = (b - a) / (CAL_N - 50) - 60;
        g0 = gasleft();
        loop.read(7000, 50);
        a = g0 - gasleft();
        g0 = gasleft();
        loop.read(8000, CAL_N);
        b = g0 - gasleft();
        cRead = (b - a) / (CAL_N - 50) - 60;
    }

    /// @dev Spec SSTORE allowance: I = 524a+4 writes at 22100 and D = 524p clears at 7100.
    function allowance(uint256 a, uint256 p) internal pure returns (uint256) {
        return WORD_SSTORE_MAX * (524 * a + 4) + WORD_CLEAR_MAX * 524 * p;
    }

    function report(string memory name, uint256 a, uint256 p, Run memory r) internal {
        emit log_named_string("fixture", name);
        emit log_named_uint("  K_max", K());
        emit log_named_uint("  a (insertions)", a);
        emit log_named_uint("  p (deletions)", p);
        emit log_named_uint("  open gross", r.openGross);
        emit log_named_uint("  finalize gross", r.finalizeGross);
        emit log_named_uint("  SSTORE rectangle", allowance(a, p));
        emit log_named_uint("  G_rest bound", builder.gRestBound(K()));
    }

    // ---------------------------------------------------------------- tests

    /// p = a = K: gross open + finalize stays within the spec rectangle plus the frozen G_rest bound.
    function test_replacementWithinTheEnvelope() public {
        Run memory r = run(replaceArgs(K()));
        report("replace", K(), K(), r);
        assertLe(r.openGross + r.finalizeGross, allowance(K(), K()) + builder.gRestBound(K()));
        assertEq(liveEpochs().length, K());
        assertEntryAbsent(1, 64);
        assertEq(b1Word("b1.count"), K());
    }

    /// p = K-1 deletions and nothing inserted.
    function test_pruneOnlyWithinTheEnvelope() public {
        if (K() == 1) return;
        Run memory r = run(pruneArgs(K()));
        report("prune", 0, K() - 1, r);
        assertLe(r.openGross + r.finalizeGross, allowance(0, K() - 1) + builder.gRestBound(K()));
        assertEq(liveEpochs().length, 1);
    }

    /// p = 0, a = K-1: every addressed write is a fresh zero-to-non-zero set, so the rectangle has no
    /// slack here. Subtracting the calibrated set and read costs leaves G_rest, which must sit within
    /// the frozen bound, and the whole call must sit within rectangle + bound.
    function test_insertOnlyMeasuresGRestWithNoSlack() public {
        if (K() == 1) return;
        calibrate();
        OpenArgs memory a = insertArgs(K());
        Run memory r = run(a);
        report("insert", K() - 1, 0, r);
        uint256 storageGas = r.nSet * cSet + r.nRead * cRead + r.nOther * 5000;
        uint256 total = r.openGross + r.finalizeGross;
        uint256 rest = total > storageGas ? total - storageGas : 0;
        emit log_named_uint("  calibrated cSet", cSet);
        emit log_named_uint("  calibrated cRead", cRead);
        emit log_named_uint("  fresh sets", r.nSet);
        emit log_named_uint("  cold reads", r.nRead);
        emit log_named_uint("  other writes (priced at 5000)", r.nOther);
        emit log_named_uint("  G_rest measured (non-storage)", rest);
        assertLe(rest, builder.gRestBound(K()), "measured G_rest within the frozen bound");
        assertLe(total, allowance(K() - 1, 0) + builder.gRestBound(K()));
        assertEq(liveEpochs().length, K());
    }
}

contract SealRegistryB1GasK1Test is SealRegistryB1GasBase {
    function K() internal pure override returns (uint256) {
        return 1;
    }
}

contract SealRegistryB1GasK2Test is SealRegistryB1GasBase {
    function K() internal pure override returns (uint256) {
        return 2;
    }
}

contract SealRegistryB1GasK4Test is SealRegistryB1GasBase {
    function K() internal pure override returns (uint256) {
        return 4;
    }

    /// Gross metering: deletions' refunds neither lower the system total nor fund the work. A budget
    /// equal to gross minus the maximum refund fails with no state change; a gross budget succeeds.
    function test_deletionRefundsDoNotFundTheCall() public {
        bytes memory data = openCalldata(replaceArgs(4));
        bytes32 before = b1Digest();
        uint256 snap = vm.snapshotState();
        vm.prank(A_SYS);
        uint256 g0 = gasleft();
        (bool ok,) = A_SR.call(data);
        uint256 gross = g0 - gasleft();
        assertTrue(ok);
        assertEntryAbsent(1, 64);
        // 4 deleted entries of 64 members: 4 * 523 entry and member words and 4 queue words.
        uint256 refundIfNetted = (4 * (11 + 8 * 64) + 4) * 4800;
        assertGt(gross, refundIfNetted, "the experiment needs a positive net budget");
        VmSafe.Gas memory lg = vm.lastCallGas();
        assertGt(lg.gasRefunded, 0, "the deletions did earn a refund");
        vm.revertToState(snap);
        assertEq(before, b1Digest());

        vm.prank(A_SYS);
        (bool netOk,) = A_SR.call{gas: gross - refundIfNetted}(data);
        assertFalse(netOk, "a net-of-refund budget is not enough");
        assertEq(before, b1Digest(), "the out-of-gas candidate left no partial write");
        assertEq(ent(1, 0), bytes32(uint256(1)), "old entries are still present");

        vm.prank(A_SYS);
        // A gross budget with headroom for the cheatcode-warmed first run succeeds.
        (bool grossOk,) = A_SR.call{gas: gross + gross / 4}(data);
        assertTrue(grossOk, "the gross budget succeeds");
        assertEntryAbsent(1, 64);
    }

    /// A shortfall of any size discards the whole candidate: nothing earlier survives.
    function test_aBudgetShortOfTheNeededGasDiscardsTheWholeCandidate() public {
        bytes memory data = openCalldata(replaceArgs(4));
        bytes32 before = b1Digest();
        uint256 snap = vm.snapshotState();
        vm.prank(A_SYS);
        uint256 g0 = gasleft();
        (bool ok,) = A_SR.call(data);
        uint256 gross = g0 - gasleft();
        assertTrue(ok);
        vm.revertToState(snap);

        uint256[4] memory shortBy = [uint256(1_000), 30_000, 1_000_000, 20_000_000];
        for (uint256 i = 0; i < shortBy.length; i++) {
            vm.prank(A_SYS);
            (bool shortOk,) = A_SR.call{gas: gross - shortBy[i]}(data);
            assertFalse(shortOk);
            assertEq(before, b1Digest(), "no partial deletion or insertion");
        }
    }
}

contract SealRegistryB1GasK8Test is SealRegistryB1GasBase {
    function K() internal pure override returns (uint256) {
        return 8;
    }
}

contract SealRegistryB1GasK16Test is SealRegistryB1GasBase {
    function K() internal pure override returns (uint256) {
        return 16;
    }
}
