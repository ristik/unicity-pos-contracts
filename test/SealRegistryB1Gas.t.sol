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

/// @notice Gross gas of maximal updates of the permanent registry: B = 0, 1 and 2 imported epochs of the 16-member ceiling.
///
/// The system call budget is g_sys >= 155936 + (527344 + 177800*16)*B + G_rest(B), where the SSTORE rectangle covers the HISTORY writes only
/// (per imported epoch 12 + 8*16 = 140 entry words at 22100, the C_e cache word included, plus the former tip's closure (2 words) and the cursor words (importedTipEpoch,
/// originReady), no refund credit and nothing is ever cleared), and G_rest bounds every other cost of open + finalize: SLOADs, hashing, calldata
/// decode, memory, the operational-registry writes and the whole of finalize.
///
/// Method. Each fixture runs the real open and finalize calls against committed, cold state (`vm.cool`, so every first access pays the Cancun
/// cold price), records the storage accesses, and prices every SSTORE with the Cancun model checked against the EVM in
/// SealRegistryB1GasModelTest. Then
///   history  = the exact price of every write to a history slot (these are what the rectangle covers);
///   rest     = gross gas - history  (SLOADs, operational writes, finalize and all other work stay in rest);
///   rest*    = rest with every operational write re-priced at the 22100 worst case (28 writes at most).
/// The test asserts a 1.5x margin over rest* for each fixture. The affine allowance is fitted to these measurements, not an instruction-level
/// proof. Node ID variants: 0 members differ in word 0; 1 all share a 96-byte prefix and differ in word 3; 2 all-zero IDs of increasing length.
/// Gas under forge's test EVM is a measurement of this runtime, not a claim about the final client: the ureth system-integration PR re-measures.
abstract contract SealRegistryB1GasBase is SealRegistryB1Helpers, CancunPrices {
    uint256 internal constant WORD_SSTORE_MAX = 22_100;
    /// open (acknowledgement path) writes at most 26 operational words, finalize 2.
    uint256 internal constant OPERATIONAL_WRITES_MAX = 28;
    uint64 internal constant ORIGIN0 = 1000;
    uint256 internal constant ENTRY_WORDS_MAX = 12 + 8 * 16; // 11 metadata words, the C_e cache word, 8 per member

    mapping(bytes32 => bool) internal isOperational;
    mapping(bytes32 => uint256) internal seenInRun;
    mapping(bytes32 => bytes32) internal committedValue;
    uint256 internal runId;

    function setUp() public virtual override {
        super.setUp();
        // a committed, ready registry with a maximal open tip: epoch 1 (genesis) opened at ORIGIN0
        step(plainAt(ORIGIN0));
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

    /// @dev 16 members with 128-byte IDs in strictly increasing raw order, with full-width keys and weights.
    function maxMembers(uint8 seed, uint8 variant) internal pure returns (B1Member[] memory ms) {
        ms = new B1Member[](16);
        for (uint256 j = 0; j < 16; j++) {
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

    /// @dev `b` consecutive maximal entries ending at origin round O (the i-th starting at O - b + i, the last open).
    function maxAck(uint64 b, uint8 variant) internal view returns (OpenArgs memory a) {
        uint64 tip = tipEpoch();
        uint64 O = ORIGIN0 + 10;
        B1Entry[] memory es = new B1Entry[](b);
        for (uint64 i = 1; i <= b; i++) {
            uint64 start = O - b + i;
            es[i - 1] = entry(tip + i, start, i == b ? 0 : start + 1, 1);
            es[i - 1].members = maxMembers(uint8(tip + i), variant);
        }
        a = ackWith(
            O,
            b,
            B1Update({priorTipEpoch: tip, hasOldTipEnd: true, oldTipEnd: O - b + 1, newEntries: es})
        );
    }

    // ---------------------------------------------------------------- measurement

    struct Tally {
        uint256 gross; // open + finalize
        uint256 histCharge; // exact price of every write to a history slot
        uint256 opCharge; // exact price of every write to an operational slot
        uint256 readCharge; // exact price of every SLOAD (stays in G_rest)
        uint256 histWrites;
        uint256 opWrites;
        uint256 reads;
        uint256 maxWrite; // dearest history write
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
                    t.histCharge += c;
                    if (c > t.maxWrite) t.maxWrite = c;
                }
            }
        }
    }

    /// @dev The test EVM credits the capped refund to the call that earned it, so a `gasleft()` difference is net. Gross, which is what the
    /// system call is metered on (no refund credit), adds the credit back. Nothing in the permanent registry clears a word, so it is 0 here.
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

        importEmptyAsSystem(a.n); // the mandatory import is not part of the finalize measurement
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

    /// @dev The history-write rectangle for `b` imported epochs of the 16-member ceiling: 140 entry words each, the former tip's two closure
    /// words and the two cursor words.
    function allowance(uint256 b) internal pure returns (uint256) {
        return b == 0 ? 0 : WORD_SSTORE_MAX * (ENTRY_WORDS_MAX * b + 4);
    }

    /// @dev Everything in the call except the history writes, with every operational write re-priced at its 22100 worst case.
    function restWorst(Tally memory t) internal pure returns (uint256) {
        return t.gross - t.histCharge - t.opCharge + WORD_SSTORE_MAX * OPERATIONAL_WRITES_MAX;
    }

    function check(string memory name, uint256 b, uint8 variant, Tally memory t) internal {
        uint256 rest = restWorst(t);
        emit log_named_string("fixture", name);
        emit log_named_uint("  B (epochs imported)", b);
        emit log_named_uint("  nodeID variant", variant);
        emit log_named_uint("  gross (open + finalize)", t.gross);
        emit log_named_uint("  history SSTORE (exact Cancun)", t.histCharge);
        emit log_named_uint("  SSTORE rectangle", allowance(b));
        emit log_named_uint("  operational SSTORE (exact)", t.opCharge);
        emit log_named_uint("  SLOAD (exact)", t.readCharge);
        emit log_named_uint("  rest* (worst operational writes)", rest);
        emit log_named_uint("  G_rest(B) allowance", builder.gRestBound(b));

        // The premises that make the rectangle cover the history writes: an imported epoch writes at most 140 words, the update at most 4 more
        // (the former tip's end and flag, importedTipEpoch, originReady), and no write is dearer than a cold set.
        assertLe(
            t.histWrites, ENTRY_WORDS_MAX * b + 4, "history writes within the rectangle's count"
        );
        assertLe(t.maxWrite, WORD_SSTORE_MAX, "no history write above 22100");
        assertLe(t.histCharge, allowance(b), "history SSTOREs within the rectangle");
        assertLe(t.opWrites, OPERATIONAL_WRITES_MAX, "operational writes within 28");
        // Preserve the stated 1.5x safety factor, not just coverage of the measured remainder.
        assertLe((3 * rest + 1) / 2, builder.gRestBound(b), "rest* has 1.5x margin for B");
        assertLe(t.gross, allowance(b) + builder.gRestBound(b), "gross within the envelope");
    }
}

contract SealRegistryB1GasTest is SealRegistryB1GasBase {
    function test_noHistoryChange() public {
        Tally memory t = run(plainAt(ORIGIN0 + 5));
        check("unchanged", 0, 0, t);
        assertEq(t.histWrites, 0);
    }

    function _import(uint64 b, uint8 variant) internal {
        Tally memory t = run(maxAck(b, variant));
        check(b == 1 ? "one epoch" : "two epochs", b, variant, t);
        assertEq(tipEpoch(), 1 + b);
    }

    function test_oneEpochVariant0() public {
        _import(1, 0);
    }

    function test_oneEpochVariant1() public {
        _import(1, 1);
    }

    function test_oneEpochVariant2() public {
        _import(1, 2);
    }

    function test_twoEpochsVariant0() public {
        _import(2, 0);
    }

    function test_twoEpochsVariant1() public {
        _import(2, 1);
    }

    function test_twoEpochsVariant2() public {
        _import(2, 2);
    }

    /// A budget short of the needed gas discards the whole candidate: nothing is half-imported.
    function test_aBudgetShortOfTheNeededGasDiscardsTheWholeCandidate() public {
        OpenArgs memory a = maxAck(2, 0);
        bytes memory data = openCalldata(a);
        bytes32 before = b1Digest();
        vm.prank(A_SYS);
        (bool ok,) = A_SR.call{gas: 2_000_000}(data); // far below what two maximal epochs need
        assertFalse(ok);
        assertEq(b1Digest(), before);
        assertEq(tipEpoch(), 1);
        assertEq(ent(2, 0), bytes32(0));
    }
}
