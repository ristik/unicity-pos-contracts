// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {B1Entry, B1Member, B1Update} from "../src/B1Layout.sol";
import {SealRegistryB1Helpers} from "./SealRegistryB1.t.sol";

/// @dev Executes storage operations and reports the gas the EVM charged for the last one, so the
/// Cancun price model below can be checked against the EVM the fixtures run in. The two slot arguments
/// of the paired probes are always equal in the tests; passing them separately stops the optimizer from
/// merging or dropping the first operation, and every result is returned so none is dead code.
contract CostProbe {
    function sstoreOnce(bytes32 slot, uint256 value) external returns (uint256 d) {
        assembly ("memory-safe") {
            let g0 := gas()
            sstore(slot, value)
            d := sub(g0, gas())
        }
    }

    function sstoreTwice(bytes32 s1, bytes32 s2, uint256 v1, uint256 v2)
        external
        returns (uint256 d1, uint256 d2)
    {
        assembly ("memory-safe") {
            let g0 := gas()
            sstore(s1, v1)
            let g1 := gas()
            sstore(s2, v2)
            d2 := sub(g1, gas())
            d1 := sub(g0, g1)
        }
    }

    function sloadTwice(bytes32 s1, bytes32 s2)
        external
        view
        returns (uint256 d1, uint256 d2, uint256 v1, uint256 v2)
    {
        assembly ("memory-safe") {
            let g0 := gas()
            v1 := sload(s1)
            let g1 := gas()
            v2 := sload(s2)
            d2 := sub(g1, gas())
            d1 := sub(g0, g1)
        }
    }

    function readThenClear(bytes32 s1, bytes32 s2)
        external
        returns (uint256 dRead, uint256 dClear, uint256 v)
    {
        assembly ("memory-safe") {
            let g0 := gas()
            v := sload(s1)
            let g1 := gas()
            sstore(s2, 0)
            dClear := sub(g1, gas())
            dRead := sub(g0, g1)
        }
    }

    /// One frame that clears n slots.
    function clearAll(bytes32[] calldata slots) external {
        for (uint256 i = 0; i < slots.length; i++) {
            bytes32 slot = slots[i];
            assembly ("memory-safe") {
                sstore(slot, 0)
            }
        }
    }
}

/// @notice The Cancun storage price model (EIP-2929, EIP-2200 without refunds, EIP-3529). A SLOAD costs
/// 2100 cold and 100 warm. An SSTORE costs 2100 more when its slot is cold, plus 100 if the value does
/// not change or the slot is already dirty, 20000 for a clean zero to non-zero, and 2900 for any other
/// clean change. Refunds do not enter: the registry meters gross (design v4).
abstract contract CancunPrices {
    uint256 internal constant COLD_ACCESS = 2100;
    uint256 internal constant WARM_ACCESS = 100;
    uint256 internal constant SSTORE_SET = 20_000;
    uint256 internal constant SSTORE_RESET = 2900;

    function sloadPrice(bool cold) internal pure returns (uint256) {
        return cold ? COLD_ACCESS : WARM_ACCESS;
    }

    function sstorePrice(uint256 original, uint256 current, uint256 updated, bool cold)
        internal
        pure
        returns (uint256 gas_)
    {
        gas_ = cold ? COLD_ACCESS : 0;
        if (updated == current || current != original) return gas_ + WARM_ACCESS;
        return gas_ + (original == 0 ? SSTORE_SET : SSTORE_RESET);
    }
}

/// @notice The price model against the EVM: a cold slot seeded in setUp (committed state) is charged
/// the cold Cancun prices, which are the prices the fixtures subtract from the measured gross gas.
contract SealRegistryB1GasModelTest is Test, CancunPrices {
    /// The probe itself costs a few gas to wrap each operation (GAS opcode and operand pushes).
    uint256 internal constant WRAP = 16;
    CostProbe internal probe;
    bytes32 internal constant FRESH = keccak256("fresh");
    bytes32 internal constant SEEDED = keccak256("seeded");

    function setUp() public {
        probe = new CostProbe();
        vm.store(address(probe), SEEDED, bytes32(uint256(7)));
    }

    function _near(uint256 measured, uint256 price) internal pure returns (bool) {
        return measured >= price && measured <= price + WRAP;
    }

    function test_coldFreshSetCosts22100() public {
        vm.cool(address(probe));
        uint256 d = probe.sstoreOnce(FRESH, 1);
        assertTrue(_near(d, sstorePrice(0, 0, 1, true)), "cold zero to non-zero");
        assertEq(sstorePrice(0, 0, 1, true), 22_100);
    }

    function test_coldClearOfCommittedStateCosts5000() public {
        vm.cool(address(probe));
        uint256 d = probe.sstoreOnce(SEEDED, 0);
        assertTrue(_near(d, sstorePrice(7, 7, 0, true)), "cold clear");
        assertEq(sstorePrice(7, 7, 0, true), 5000);
    }

    function test_coldOverwriteOfCommittedStateCosts5000() public {
        vm.cool(address(probe));
        uint256 d = probe.sstoreOnce(SEEDED, 9);
        assertTrue(_near(d, sstorePrice(7, 7, 9, true)), "cold non-zero to non-zero");
    }

    function test_aSecondWriteToADirtySlotCosts100() public {
        vm.cool(address(probe));
        (uint256 first, uint256 second) = probe.sstoreTwice(FRESH, FRESH, 1, 2);
        assertTrue(_near(first, sstorePrice(0, 0, 1, true)), "cold set");
        assertTrue(_near(second, sstorePrice(0, 1, 2, false)), "dirty rewrite");
        assertEq(sstorePrice(0, 1, 2, false), 100);
    }

    function test_aRewriteOfTheSameValueCosts100() public {
        vm.cool(address(probe));
        (uint256 first, uint256 second) = probe.sstoreTwice(SEEDED, SEEDED, 7, 7);
        assertTrue(_near(first, sstorePrice(7, 7, 7, true)), "cold no-op write");
        assertTrue(_near(second, sstorePrice(7, 7, 7, false)), "warm no-op write");
        assertEq(sstorePrice(7, 7, 7, true), 2200);
    }

    function test_coldAndWarmReads() public {
        vm.cool(address(probe));
        (uint256 cold, uint256 warm, uint256 v1, uint256 v2) = probe.sloadTwice(SEEDED, SEEDED);
        assertEq(v1, 7);
        assertEq(v2, 7);
        assertTrue(_near(cold, sloadPrice(true)), "cold read");
        assertTrue(_near(warm, sloadPrice(false)), "warm read");
        assertEq(sloadPrice(true), 2100);
    }

    function test_aWriteAfterAColdReadPaysOnlyTheResetOrSet() public {
        vm.cool(address(probe));
        (uint256 read, uint256 clear, uint256 v) = probe.readThenClear(SEEDED, SEEDED);
        assertEq(v, 7);
        assertTrue(_near(read, sloadPrice(true)), "cold read");
        assertTrue(_near(clear, sstorePrice(7, 7, 0, false)), "warm clear");
        assertEq(sstorePrice(7, 7, 0, false), 2900);
    }

    /// The test EVM credits the capped EIP-3529 refund to the call that earned it, so `gasleft()` taken
    /// around a call that clears slots is NET of the refund, while the registry (and the real client)
    /// meters gross (design v4: no refund credit). The fixtures add the credit back: gross = net +
    /// `lastFrameGas().gasRefunded`. Here two calls with the same ABI shape, one that clears committed
    /// slots (earning a refund) and one that rewrites zeros (earning none), calibrate it: the caller-side
    /// overhead of each call is read off the control, and the corrected gross of the clearing call must
    /// match what the same call would cost without the credit.
    function test_theFixturesAddBackTheRefundCreditSoGrossIsMeasured() public {
        uint256 n = 100;
        bytes32[] memory zeros = new bytes32[](n);
        bytes32[] memory live = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            zeros[i] = keccak256(abi.encode("zero", i));
            live[i] = keccak256(abi.encode("live", i));
            vm.store(address(probe), live[i], bytes32(uint256(1)));
        }
        vm.cool(address(probe));
        uint256 g0 = gasleft();
        probe.clearAll(zeros);
        uint256 controlNet = g0 - gasleft();
        assertEq(vm.lastFrameGas().gasRefunded, 0, "the control earns no refund");
        // The control costs n cold zero-over-zero writes (2200 each) plus the overhead W of the call.
        uint256 overhead = controlNet - n * sstorePrice(0, 0, 0, true);

        vm.cool(address(probe));
        g0 = gasleft();
        probe.clearAll(live);
        uint256 net = g0 - gasleft();
        int64 credit = vm.lastFrameGas().gasRefunded;
        assertGt(credit, 0, "the clears earned a refund");
        uint256 gross = net + uint256(uint64(credit));
        uint256 expected = overhead + n * sstorePrice(1, 1, 0, true);
        assertLt(net, expected, "the raw gasleft difference is net of the credit");
        assertApproxEqAbs(gross, expected, 5000, "gross matches the call without the credit");
    }
}

/// @notice Gross gas of maximal registry updates up to the measured genesis K_max cap.
///
/// The system call budget (design v4, "Realizable system metering") is
///   g_sys >= 67536 + 326144*K + 22100*(524*K+4) + 7100*524*K + G_rest(K, C_max),
/// where the two SSTORE terms are a conservative rectangle for the HISTORY writes only (insert, closure,
/// head, count, queue and clears: every addressed write at 22100, every clear at 7100, no refund credit),
/// and G_rest bounds every other cost of open + finalize: SLOADs, hashing, calldata decode, memory,
/// the operational-registry writes and the whole of finalize.
///
/// Method. Each fixture runs the real open and finalize calls against committed, cold state
/// (`vm.cool`, so every first access pays the Cancun cold price), records the storage accesses, and prices
/// every SSTORE with the Cancun model checked against the EVM in SealRegistryB1GasModelTest. Then
///   history  = the exact price of every write to a history slot (these are what the rectangle covers);
///   rest     = gross gas - history  (SLOADs, operational writes, finalize and all other work stay in rest);
///   rest*    = rest with every operational write re-priced at the 22100 worst case (28 writes at most),
///              which is conservative whatever state the operational words are in.
/// The test asserts a 1.5x margin over rest* for each fixture, both for (a, p) and for K_max.
/// The affine allowance is fitted to these measurements, not an instruction-level proof. The
/// structural history-write rectangle and operational-write allowance are checked independently.
/// See docs/b1-registry-gas.md for the coefficient derivation and limits of the evidence.
///
/// Shapes (a = entries inserted, p = entries deleted, every entry 64 members with 128-byte node IDs):
///   replace: a full ring is deleted, K new entries inserted (a = p = K, the former tip is deleted);
///   mixed:   a full ring loses K-1 entries, the surviving tip is closed, K-1 are inserted;
///   insert:  a ring of one open tail gains K-1 entries (p = 0);
///   prune:   an update with no new entries deletes K-1 entries (a = 0).
/// Node ID variants (`_lessThan` and `_checkNodeID` are the only data-dependent code per member):
///   0: members differ in node-ID word 0 (the comparison exits at its first word);
///   1: all members share a 96-byte prefix and differ in word 3 (the comparison runs four words);
///   2: all-zero IDs of increasing length 1..64 (all four words equal, ordered by length).
/// Gas under forge's test EVM is a measurement of this runtime, not a claim about the final client:
/// the ureth system-integration PR re-measures under the real client.
abstract contract SealRegistryB1GasBase is SealRegistryB1Helpers, CancunPrices {
    uint256 internal constant WORD_SSTORE_MAX = 22_100;
    uint256 internal constant WORD_CLEAR_MAX = 7100;
    /// open (acknowledgement path) writes at most 26 operational words, finalize 2.
    uint256 internal constant OPERATIONAL_WRITES_MAX = 28;
    uint64 internal constant ORIGIN0 = 1000;

    uint256 internal constant SHAPE_REPLACE = 0;
    uint256 internal constant SHAPE_MIXED = 1;
    uint256 internal constant SHAPE_INSERT = 2;
    uint256 internal constant SHAPE_PRUNE = 3;

    mapping(bytes32 => bool) internal isOperational;
    mapping(bytes32 => uint256) internal seenInRun;
    mapping(bytes32 => bytes32) internal committedValue;
    uint256 internal runId;

    function K() internal pure virtual returns (uint256);

    /// @dev true: the committed ring holds K maximal entries; false: only a maximal open tail.
    function committedFullRing() internal pure virtual returns (bool);

    function setUp() public virtual override {
        wCertFixture = uint64(K() - 1);
        super.setUp();
        if (committedFullRing()) {
            seedMaxRing(K());
        } else {
            B1Entry[] memory es = new B1Entry[](1);
            es[0] = maxEntry(uint64(K()), ORIGIN0, 0, 0);
            seedRing(es, 0, ORIGIN0);
        }
        string[28] memory names = [
            "genesisCommitment",
            "config.shardConfHash",
            "assignment.epoch",
            "assignment.rootEpoch",
            "assignment.activeConfHash",
            "assignment.spanCommitment",
            "clock.rootRound",
            "origin.rootEpoch",
            "origin.timestamp",
            "origin.treeRoot",
            "origin.identity",
            "origin.trHash",
            "round.authorized",
            "input.commitment",
            "certified.round",
            "certified.stateHash",
            "certified.hasBlockHash",
            "certified.blockHash",
            "phase",
            "outcomes.round",
            "outcomes.commitment",
            "transition.cursor",
            "inbox.consumed",
            "transition.bodyID",
            "transition.genesisID",
            "transition.frozenID",
            "transition.commitID",
            "transition.frozenParent"
        ];
        for (uint256 i = 0; i < names.length; i++) {
            isOperational[fixedSlot(names[i])] = true;
        }
        isOperational[fixedSlot("transition.successorTR")] = true;
    }

    // ---------------------------------------------------------------- fixtures

    /// @dev 64 members with 128-byte IDs (variant 2: lengths 1..64 of zero bytes) in strictly
    /// increasing raw order, with full-width keys and weights.
    function maxMembers(uint8 seed, uint8 variant) internal pure returns (B1Member[] memory ms) {
        ms = new B1Member[](64);
        for (uint256 j = 0; j < 64; j++) {
            B1Member memory m = member(seed, uint8(j));
            if (variant == 2) {
                m.nodeIDLength = uint64(j + 1);
                m.nodeID[0] = bytes32(0);
            } else {
                m.nodeIDLength = 128;
                if (variant == 0) {
                    bytes32 low = bytes32(uint256(keccak256(abi.encode(seed, j))) >> 32);
                    m.nodeID[0] = bytes32(((uint256(j) + 1) << 240)) | low;
                    for (uint256 w = 1; w < 4; w++) {
                        m.nodeID[w] = keccak256(abi.encode("id", seed, j, w));
                    }
                } else {
                    m.nodeID[0] = keccak256(abi.encode("prefix", seed, uint256(0)));
                    m.nodeID[1] = keccak256(abi.encode("prefix", seed, uint256(1)));
                    m.nodeID[2] = keccak256(abi.encode("prefix", seed, uint256(2)));
                    m.nodeID[3] = bytes32(((uint256(j) + 1) << 240))
                        | bytes32(uint256(keccak256(abi.encode(seed, j))) >> 32);
                }
            }
            m.weight = type(uint32).max - uint64(j);
            ms[j] = m;
        }
    }

    function maxEntry(uint64 epoch, uint64 start, uint64 end, uint8 variant)
        internal
        pure
        returns (B1Entry memory en)
    {
        en = entry(epoch, start, end, 1);
        en.members = maxMembers(uint8(epoch), variant);
    }

    /// @dev The ring a maximal replacement removes: K maximal entries over [L, O] with one start per
    /// round of the window, O = ORIGIN0. Written in setUp, so the words are committed state.
    function seedMaxRing(uint256 k) internal {
        uint64 L0 = ORIGIN0 - wCertFixture;
        B1Entry[] memory es = new B1Entry[](k);
        for (uint64 i = 0; i < k; i++) {
            es[i] = maxEntry(i + 1, L0 + i, i == k - 1 ? 0 : L0 + i + 1, 0);
        }
        seedRing(es, 0, ORIGIN0);
    }

    /// @dev Replacement at O' = O + K: the old tip closes at L' (p = K deletions) and K new maximal
    /// intervals are inserted (a = K): the first starts at L', the rest at distinct rounds in (L', O'].
    function replaceArgs(uint256 k, uint8 variant) internal view returns (OpenArgs memory a) {
        uint64 O1 = ORIGIN0 + uint64(k);
        uint64 L1 = O1 - wCertFixture;
        B1Update memory u = B1Update({
            priorTipEpoch: uint64(k),
            hasOldTipEnd: true,
            oldTipEnd: L1,
            newEntries: new B1Entry[](k)
        });
        for (uint64 i = 0; i < k; i++) {
            u.newEntries[i] =
                maxEntry(uint64(k) + 1 + i, L1 + i, i == k - 1 ? 0 : L1 + i + 1, variant);
        }
        a = ackWith(O1, uint64(k), u);
    }

    /// @dev K-1 maximal entries appended behind the tip at O' = O + K - 1, where L' = O: over a full
    /// ring the K-1 older entries expire (mixed: p = a = K-1, the tip survives and is closed); over a
    /// ring of one open tail nothing expires (insert: p = 0, a = K-1).
    function tailArgs(uint256 k, uint8 variant) internal view returns (OpenArgs memory a) {
        uint64 O1 = ORIGIN0 + uint64(k) - 1;
        B1Update memory u = B1Update({
            priorTipEpoch: uint64(k),
            hasOldTipEnd: true,
            oldTipEnd: ORIGIN0 + 1,
            newEntries: new B1Entry[](k - 1)
        });
        for (uint64 i = 0; i < k - 1; i++) {
            u.newEntries[i] = maxEntry(
                uint64(k) + 1 + i, ORIGIN0 + 1 + i, i == k - 2 ? 0 : ORIGIN0 + 2 + i, variant
            );
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

    struct Tally {
        uint256 gross; // open + finalize
        uint256 histCharge; // exact price of every write to a history slot
        uint256 opCharge; // exact price of every write to an operational slot
        uint256 readCharge; // exact price of every SLOAD (stays in G_rest)
        uint256 histWrites; // every write to a history slot
        uint256 histNonzero; // of which the written value is non-zero (inserts, closure, head, count)
        uint256 opWrites;
        uint256 reads;
        uint256 maxNonzeroWrite; // dearest history write of a non-zero value
        uint256 maxZeroWrite; // dearest history write of zero (a clear, or a zero over zero)
    }

    /// @dev Prices one call's recorded accesses with the Cancun model. Every call starts cold.
    function price(VmSafe.AccountAccess[] memory d, Tally memory t) internal {
        runId++;
        for (uint256 i = 0; i < d.length; i++) {
            if (d[i].account != A_SR) continue;
            for (uint256 j = 0; j < d[i].storageAccesses.length; j++) {
                VmSafe.StorageAccess memory sa = d[i].storageAccesses[j];
                if (sa.reverted) continue;
                bool cold = seenInRun[sa.slot] != runId;
                if (cold) {
                    seenInRun[sa.slot] = runId;
                    committedValue[sa.slot] = sa.previousValue;
                }
                if (!sa.isWrite) {
                    t.reads++;
                    t.readCharge += sloadPrice(cold);
                    continue;
                }
                uint256 c = sstorePrice(
                    uint256(committedValue[sa.slot]),
                    uint256(sa.previousValue),
                    uint256(sa.newValue),
                    cold
                );
                if (isOperational[sa.slot]) {
                    t.opWrites++;
                    t.opCharge += c;
                } else {
                    t.histWrites++;
                    if (sa.newValue != bytes32(0)) {
                        t.histNonzero++;
                        if (c > t.maxNonzeroWrite) t.maxNonzeroWrite = c;
                    } else if (c > t.maxZeroWrite) {
                        t.maxZeroWrite = c;
                    }
                    t.histCharge += c;
                }
            }
        }
    }

    /// @dev The test EVM credits the capped refund (at most one fifth of the gas used) to the call that
    /// earned it, so a `gasleft()` difference is net. Gross, which is what the system call is metered
    /// on (design v4: no refund credit), adds the credit back; see
    /// test_theFixturesAddBackTheRefundCreditSoGrossIsMeasured. Call right after the measured call.
    function grossOf(uint256 net) internal view returns (uint256) {
        return net + uint256(uint64(vm.lastFrameGas().gasRefunded));
    }

    function run(OpenArgs memory a) internal returns (Tally memory t) {
        bytes memory openData = openCalldata(a);
        vm.cool(A_SR);
        vm.prank(A_SYS);
        vm.startStateDiffRecording();
        uint256 g0 = gasleft();
        (bool ok, bytes memory ret) = A_SR.call(openData);
        uint256 g1 = gasleft();
        t.gross = grossOf(g0 - g1);
        VmSafe.AccountAccess[] memory d = vm.stopAndReturnStateDiff();
        if (!ok) emit log_named_bytes("open reverted", ret);
        assertTrue(ok, "open succeeds");
        price(d, t);

        bytes memory finData = finalizeCalldata(a.n, keccak256("R"));
        vm.cool(A_SR);
        vm.prank(A_SYS);
        vm.startStateDiffRecording();
        g0 = gasleft();
        (ok,) = A_SR.call(finData);
        g1 = gasleft();
        t.gross += grossOf(g0 - g1);
        d = vm.stopAndReturnStateDiff();
        assertTrue(ok, "finalize succeeds");
        price(d, t);
    }

    /// @dev Spec SSTORE allowance: I = 524a+4 writes at 22100 and D = 524p clears at 7100.
    function allowance(uint256 a, uint256 p) internal pure returns (uint256) {
        return WORD_SSTORE_MAX * (524 * a + 4) + WORD_CLEAR_MAX * 524 * p;
    }

    /// @dev Everything in the call except the history writes, with every operational write re-priced at
    /// its 22100 worst case.
    function restWorst(Tally memory t) internal pure returns (uint256) {
        return t.gross - t.histCharge - t.opCharge + WORD_SSTORE_MAX * OPERATIONAL_WRITES_MAX;
    }

    function check(string memory name, uint256 a, uint256 p, uint8 variant, Tally memory t)
        internal
    {
        uint256 rest = restWorst(t);
        emit log_named_string("fixture", name);
        emit log_named_uint("  K_max", K());
        emit log_named_uint("  nodeID variant", variant);
        emit log_named_uint("  a (insertions)", a);
        emit log_named_uint("  p (deletions)", p);
        emit log_named_uint("  gross (open + finalize)", t.gross);
        emit log_named_uint("  history SSTORE (exact Cancun)", t.histCharge);
        emit log_named_uint("  SSTORE rectangle", allowance(a, p));
        emit log_named_uint("  operational SSTORE (exact)", t.opCharge);
        emit log_named_uint("  SLOAD (exact)", t.readCharge);
        emit log_named_uint("  rest* (worst operational writes)", rest);
        emit log_named_uint("  rest* bound for (a, p)", builder.gRestFor(a, p));
        emit log_named_uint("  G_rest(K_max)", builder.gRestBound(K()));

        // The premises that make the rectangle cover the history writes: a deleted entry writes at most
        // 524 words (11 + 8*64 + queue), an inserted one at most 524 (plus 4 words per update: closure
        // end and flag, head, count); every non-zero write is an insertion-side write priced at most
        // 22100, and a write of zero (a clear, or a no-op over zero) costs at most 5000 <= 7100.
        assertLe(t.histNonzero, 524 * a + 4, "non-zero history writes within I");
        assertLe(t.histWrites, 524 * (a + p) + 4, "history writes within I + D");
        assertLe(t.maxNonzeroWrite, WORD_SSTORE_MAX, "no non-zero write above 22100");
        assertLe(t.maxZeroWrite, 5000, "no write of zero above 5000");
        assertLe(t.histCharge, allowance(a, p), "history SSTOREs within the rectangle");
        assertLe(t.opWrites, OPERATIONAL_WRITES_MAX, "operational writes within 28");
        // Preserve the stated 1.5x safety factor, not just coverage of the measured remainder.
        uint256 withMargin = (3 * rest + 1) / 2;
        assertLe(withMargin, builder.gRestFor(a, p), "rest* has 1.5x margin for (a, p)");
        assertLe(withMargin, builder.gRestBound(K()), "rest* has 1.5x margin for K_max");
        // The design's envelope, end to end, for the shape actually run and for the rectangle at p = a = K.
        assertLe(t.gross, allowance(a, p) + builder.gRestBound(K()), "gross within the envelope");
        assertLe(
            t.gross,
            allowance(K(), K()) + builder.gRestBound(K()),
            "gross within the maximal envelope"
        );
    }

    // ---------------------------------------------------------------- tests

    /// Baseline with no history insertion or deletion, in both full-ring and tail-only state.
    function test_noHistoryChange() public {
        Tally memory t = run(plainAt(ORIGIN0));
        check("unchanged", 0, 0, 0, t);
        assertEq(liveEpochs().length, committedFullRing() ? K() : 1);
    }

    function _replace(uint8 variant) internal {
        if (!committedFullRing()) return;
        Tally memory t = run(replaceArgs(K(), variant));
        check("replace", K(), K(), variant, t);
        assertEq(t.opWrites, OPERATIONAL_WRITES_MAX, "the acknowledgement path writes 28 words");
        assertEq(liveEpochs().length, K());
        assertEntryAbsent(1, 64);
        assertEq(b1Word("b1.count"), K());
    }

    function _mixed(uint8 variant) internal {
        if (!committedFullRing() || K() == 1) return;
        Tally memory t = run(tailArgs(K(), variant));
        check("mixed", K() - 1, K() - 1, variant, t);
        assertEq(liveEpochs().length, K());
    }

    function _insert(uint8 variant) internal {
        if (committedFullRing() || K() == 1) return;
        Tally memory t = run(tailArgs(K(), variant));
        check("insert", K() - 1, 0, variant, t);
        assertEq(liveEpochs().length, K());
    }

    function _prune() internal {
        if (!committedFullRing() || K() == 1) return;
        Tally memory t = run(pruneArgs(K()));
        check("prune", 0, K() - 1, 0, t);
        assertEq(liveEpochs().length, 1);
    }

    /// p = a = K, distinct leading node-ID words.
    function test_replaceVariant0() public {
        _replace(0);
    }

    /// p = a = K, 96-byte common node-ID prefix: every comparison runs four words.
    function test_replaceVariant1() public {
        _replace(1);
    }

    /// p = a = K, equal padded words ordered by length.
    function test_replaceVariant2() public {
        _replace(2);
    }

    /// p = a = K-1 with the surviving tip closed: prune, closure and insert in one call.
    function test_mixedVariant0() public {
        _mixed(0);
    }

    function test_mixedVariant1() public {
        _mixed(1);
    }

    function test_mixedVariant2() public {
        _mixed(2);
    }

    /// p = 0, a = K-1: every history write is a fresh zero-to-non-zero set.
    function test_insertVariant0() public {
        _insert(0);
    }

    function test_insertVariant1() public {
        _insert(1);
    }

    function test_insertVariant2() public {
        _insert(2);
    }

    /// p = K-1 deletions and nothing inserted.
    function test_prune() public {
        _prune();
    }
}

abstract contract FullRing is SealRegistryB1GasBase {
    function committedFullRing() internal pure override returns (bool) {
        return true;
    }
}

abstract contract TailOnly is SealRegistryB1GasBase {
    function committedFullRing() internal pure override returns (bool) {
        return false;
    }
}

contract SealRegistryB1GasK1Test is FullRing {
    function K() internal pure override returns (uint256) {
        return 1;
    }
}

contract SealRegistryB1GasK2Test is FullRing {
    function K() internal pure override returns (uint256) {
        return 2;
    }
}

contract SealRegistryB1GasK2InsertTest is TailOnly {
    function K() internal pure override returns (uint256) {
        return 2;
    }
}

contract SealRegistryB1GasK4Test is FullRing {
    function K() internal pure override returns (uint256) {
        return 4;
    }

    /// Gross metering: deletions' refunds neither lower the system total nor fund the work. A budget
    /// equal to gross minus the maximum refund fails with no state change; a gross budget succeeds.
    function test_deletionRefundsDoNotFundTheCall() public {
        bytes memory data = openCalldata(replaceArgs(4, 0));
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
        VmSafe.Gas memory lg = vm.lastFrameGas();
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
        bytes memory data = openCalldata(replaceArgs(4, 0));
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

contract SealRegistryB1GasK4InsertTest is TailOnly {
    function K() internal pure override returns (uint256) {
        return 4;
    }
}

contract SealRegistryB1GasK8Test is FullRing {
    function K() internal pure override returns (uint256) {
        return 8;
    }
}

contract SealRegistryB1GasK8InsertTest is TailOnly {
    function K() internal pure override returns (uint256) {
        return 8;
    }
}

contract SealRegistryB1GasK16Test is FullRing {
    function K() internal pure override returns (uint256) {
        return 16;
    }
}

contract SealRegistryB1GasK16InsertTest is TailOnly {
    function K() internal pure override returns (uint256) {
        return 16;
    }
}
