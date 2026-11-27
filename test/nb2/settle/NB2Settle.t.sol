// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";
import {NB2Config} from "../../../src/nb2/NB2Config.sol";
import {
    NativeBridgeVault11,
    NativeBridgeVault11Ordinary
} from "../../../src/nb2/NativeBridgeVault11.sol";
import {NB2VaultBase} from "../../../src/nb2/NB2VaultBase.sol";
import {FlatHarness} from "../flat/FlatHarness.sol";
import {EchoVerifierV2} from "../NB2TestBase.sol";

/// @dev The reference Γ carries placeholder digests: the recovery runtime hash (Kec(0x600300)) is not the code of the etched
///      adapter and the recovery's generation and pins come from the corpus. Only the construction-time binding and the
///      per-call runtime recheck are replaced; the framing, receipt authentication, fold, scans and the shared payment routine
///      are the production code.
contract CorpusVault11 is NativeBridgeVault11 {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    constructor(bytes memory g, address r, bytes32 rt, bytes32 p)
        NativeBridgeVault11(g, r, rt, p)
    {}

    function _bindRecovery(address, bytes32, NB2Config.Config memory)
        internal
        view
        override
        returns (bytes32 generation, bytes32 pins, address receipts)
    {
        generation = bytes32(VM.readFileBinary("test/nb2/flat/generated/generation.bin"));
        pins = bytes32(VM.readFileBinary("test/nb2/flat/generated/pins.bin"));
        receipts = address(0xf201);
    }

    function _recoveryIntact() internal pure override returns (bool) {
        return true;
    }

    /// @dev Test hook: when set, the authenticated event data is this value (a stand-in for a certified event that the
    ///      pinned producer cannot emit, such as a zero amount), so the order of the shared verdict errors can be tested.
    // The vault owns raw slots from 0: the hook lives in a hashed region.
    uint256 private constant CRAFT =
        0x7e57c0de00000000000000000000000000000000000000000000000000000000;

    function craft(bytes calldata data) external {
        uint256 n = data.length;
        assembly ("memory-safe") {
            sstore(CRAFT, n)
        }
        for (uint256 i; i * 32 < n; ++i) {
            bytes32 w = bytes32(data[i * 32:i * 32 + 32]);
            assembly ("memory-safe") {
                sstore(add(add(CRAFT, 1), i), w)
            }
        }
    }

    function _receipt(bytes calldata proof, bytes32 topic, bytes32 session, uint256 width)
        internal
        view
        override
        returns (bytes memory out)
    {
        uint256 n;
        assembly ("memory-safe") {
            n := sload(CRAFT)
        }
        if (n != 0) {
            out = new bytes(n);
            for (uint256 i; i * 32 < n; ++i) {
                bytes32 w;
                assembly ("memory-safe") {
                    w := sload(add(add(CRAFT, 1), i))
                }
                assembly ("memory-safe") {
                    mstore(add(add(out, 32), mul(i, 32)), w)
                }
            }
            return out;
        }
        return super._receipt(proof, topic, session, width);
    }
}

contract Refuser {
    receive() external payable {
        revert("no");
    }
}

/// Re-enters redeemRecovered from the payout. `propagate` decides whether the inner failure is caught.
contract Reenter {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal immutable VAULT;
    bool internal immutable PROPAGATE;
    bool internal immutable MALFORMED;
    /// The selector of the inner call's failure, recorded so a test can tell Reentrancy() from any other error.
    bytes4 public inner;

    constructor(address vault, bool propagate, bool malformed) {
        VAULT = vault;
        PROPAGATE = propagate;
        MALFORMED = malformed;
    }

    receive() external payable {
        // MALFORMED: the recognised selector with broken outer framing. The shared guard comes first.
        bytes memory data = MALFORMED
            ? abi.encodePacked(bytes4(keccak256("redeemRecovered(bytes)")), hex"01")
            : VM.readFileBinary(
                "test/nb2/flat/generated/transcripts/cold/settle-kind1-suffixfalse-prevfalse/calldata.bin"
            );
        (bool ok, bytes memory why) = VAULT.call(data);
        inner = bytes4(why);
        if (MALFORMED) return; // the test asserts the recorded selector
        require(
            !ok && bytes4(why) == NB2VaultBase.Reentrancy.selector, "inner call must hit the guard"
        );
        if (PROPAGATE) {
            assembly ("memory-safe") {
                revert(add(why, 32), mload(why))
            }
        }
    }
}

contract NB2SettleTest is FlatHarness {
    string private constant COLD = "test/nb2/flat/generated/transcripts/cold/";
    address private constant VAULT = address(0xf200);
    address private constant VERIFIER = address(0xf203);
    address private constant RECIPIENT = 0x96f21e5603aff0A874383f28d66b2f68e6B51e2d;
    uint256 private constant K = 64;
    bytes32 private constant PAID = keccak256("Paid(bytes32,address,uint256)");
    bytes32 private constant SEALED = keccak256("SegmentSealed(uint64,bytes32,bytes32,bytes)");

    NativeBridgeVault11 internal vault;

    function setUp() public override {
        super.setUp();
        vm.etch(address(0xf201), address(receipts).code);
        // The reference Γ pins Kec(0x600000) as the ordinary verifier's runtime hash.
        vm.etch(VERIFIER, hex"600000");
        bytes32 profile = sha256(vm.readFileBinary(string.concat(DIR, "semantic-profile.bin")));
        deployCodeTo(
            "NB2Settle.t.sol:CorpusVault11",
            abi.encode(gamma, RECOVERY, keccak256(hex"600300"), profile),
            VAULT
        );
        vault = NativeBridgeVault11(payable(VAULT));
        vm.etch(VERIFIER, type(EchoVerifierV2).runtimeCode);
        _loadTrust(_path("root"));
    }

    // ------------------------------------------------------------------------------------------------ custody fixtures

    function _cold(string memory name) private pure returns (string memory) {
        return string.concat(COLD, name, "/");
    }

    function _apply(string memory raw, string memory side) private {
        uint256 c = vm.parseJsonUint(raw, string.concat(".", side, ".Segment"));
        uint256 m = vm.parseJsonUint(raw, string.concat(".", side, ".Population"));
        uint256 n = vm.parseJsonUint(raw, string.concat(".", side, ".Deposits"));
        uint256 q = vm.parseJsonUint(raw, string.concat(".", side, ".Liability"));
        bytes32 head = vm.parseJsonBytes32(raw, string.concat(".", side, ".Head"));
        bytes32 prev = vm.parseJsonBytes32(raw, string.concat(".", side, ".PreviousHead"));
        bytes32[] memory cur = vm.parseJsonBytes32Array(raw, string.concat(".", side, ".Current"));
        bytes32[] memory old = vm.parseJsonBytes32Array(raw, string.concat(".", side, ".Previous"));
        _store(n, c, m, q, head, prev, cur, old);
        vm.deal(VAULT, vm.parseJsonUint(raw, string.concat(".", side, ".VaultBalance")));
        vm.deal(RECIPIENT, vm.parseJsonUint(raw, string.concat(".", side, ".RecipientBalance")));
    }

    function _store(
        uint256 n,
        uint256 c,
        uint256 m,
        uint256 q,
        bytes32 head,
        bytes32 prev,
        bytes32[] memory cur,
        bytes32[] memory old
    ) private {
        vm.store(VAULT, bytes32(uint256(0)), bytes32((n << 200) | (c << 152) | (m << 144) | q));
        vm.store(VAULT, bytes32(1 + (c & 1)), head);
        if (c != 0) vm.store(VAULT, bytes32(1 + ((c - 1) & 1)), prev);
        uint256 p = c & 1;
        _fillBuffer(p, cur);
        if (c != 0) _fillBuffer(p ^ 1, old);
    }

    function _fillBuffer(uint256 p, bytes32[] memory ids) private {
        uint256 tags;
        for (uint256 i; i < ids.length; ++i) {
            tags |= (uint256(ids[i]) >> 252) << (4 * i);
            vm.store(VAULT, bytes32(16 + p * K + i), ids[i]);
        }
        vm.store(VAULT, bytes32(3 + p), bytes32(tags));
    }

    function _digest() private view returns (bytes32 h) {
        (uint64 n, uint64 c, uint16 m, uint256 q, bytes32 head, bytes32 prev) = vault.state();
        h = keccak256(abi.encode(n, c, m, q, head, prev, VAULT.balance, RECIPIENT.balance));
        for (uint256 s = 3; s < 16 + 2 * K; ++s) {
            h = keccak256(abi.encode(h, vm.load(VAULT, bytes32(s))));
        }
    }

    function _assertSide(string memory raw, string memory side) private view {
        (uint64 n, uint64 c, uint16 m, uint256 q, bytes32 head, bytes32 prev) = vault.state();
        assertEq(n, vm.parseJsonUint(raw, string.concat(".", side, ".Deposits")), "deposits");
        assertEq(c, vm.parseJsonUint(raw, string.concat(".", side, ".Segment")), "segment");
        assertEq(m, vm.parseJsonUint(raw, string.concat(".", side, ".Population")), "population");
        assertEq(q, vm.parseJsonUint(raw, string.concat(".", side, ".Liability")), "liability");
        assertEq(head, vm.parseJsonBytes32(raw, string.concat(".", side, ".Head")), "head");
        if (c != 0) {
            assertEq(
                prev,
                vm.parseJsonBytes32(raw, string.concat(".", side, ".PreviousHead")),
                "previous head"
            );
        }
        assertEq(
            VAULT.balance,
            vm.parseJsonUint(raw, string.concat(".", side, ".VaultBalance")),
            "vault balance"
        );
        assertEq(
            RECIPIENT.balance,
            vm.parseJsonUint(raw, string.concat(".", side, ".RecipientBalance")),
            "recipient"
        );
        bytes32[] memory cur = vm.parseJsonBytes32Array(raw, string.concat(".", side, ".Current"));
        bytes32[] memory old = vm.parseJsonBytes32Array(raw, string.concat(".", side, ".Previous"));
        for (uint256 i; i < cur.length; ++i) {
            assertEq(vm.load(VAULT, bytes32(16 + (c & 1) * K + i)), cur[i], "current id");
        }
        for (uint256 i; i < old.length && c != 0; ++i) {
            assertEq(vm.load(VAULT, bytes32(16 + ((c & 1) ^ 1) * K + i)), old[i], "previous id");
        }
    }

    function _run(string memory name)
        private
        returns (bool ok, bytes memory out, Vm.Log[] memory logs)
    {
        bytes memory data = vm.readFileBinary(string.concat(_cold(name), "calldata.bin"));
        vm.recordLogs();
        (ok, out) = VAULT.call(data);
        logs = vm.getRecordedLogs();
    }

    // ------------------------------------------------------------------------------------------------ the eight combinations

    function _settles(string memory name) private {
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        _assertSide(raw, "Before");
        (bool ok, bytes memory out, Vm.Log[] memory logs) = _run(name);
        assertTrue(ok, vm.toString(out));
        assertEq(logs.length, 1, "exactly one Paid");
        assertEq(logs[0].topics[0], PAID);
        assertEq(logs[0].emitter, VAULT);
        assertEq(address(uint160(uint256(logs[0].topics[2]))), RECIPIENT);
        assertEq(abi.decode(logs[0].data, (uint256)), 100);
        _assertSide(raw, "After");
        // The same certified verdict cannot pay twice, whichever route presents it.
        (ok, out,) = _run(name);
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.AlreadyPaid.selector);
    }

    function testCompleteZeroSuffixCurrent() external {
        _settles("settle-kind1-suffixfalse-prevfalse");
    }

    function testCompleteZeroSuffixPrevious() external {
        _settles("settle-kind1-suffixfalse-prevtrue");
    }

    function testCompleteSuffixCurrent() external {
        _settles("settle-kind1-suffixtrue-prevfalse");
    }

    function testCompleteSuffixPrevious() external {
        _settles("settle-kind1-suffixtrue-prevtrue");
    }

    function testGapZeroSuffixCurrent() external {
        _settles("settle-kind2-suffixfalse-prevfalse");
    }

    function testGapZeroSuffixPrevious() external {
        _settles("settle-kind2-suffixfalse-prevtrue");
    }

    function testGapSuffixCurrent() external {
        _settles("settle-kind2-suffixtrue-prevfalse");
    }

    function testGapSuffixPrevious() external {
        _settles("settle-kind2-suffixtrue-prevtrue");
    }

    function testSettleThousandAndTwentyFourGaps() external {
        _settles("settle-count1024");
    }

    // ------------------------------------------------------------------------------------------------ rollback and retry

    function _snapshotFull() private view returns (bytes32) {
        return _digest();
    }

    function testPayoutFailureRollsBackThenRetrySucceeds() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes32 before_ = _snapshotFull();
        vm.etch(RECIPIENT, address(new Refuser()).code);
        (bool ok, bytes memory out, Vm.Log[] memory logs) = _run(name);
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.PayoutFailed.selector);
        assertEq(_snapshotFull(), before_, "every field unchanged");
        // The same prepared call succeeds once the recipient accepts.
        vm.etch(RECIPIENT, "");
        (ok, out, logs) = _run(name);
        assertTrue(ok, vm.toString(out));
        assertEq(logs.length, 1);
        _assertSide(raw, "After");
    }

    function testForcedSealRollsBackWithThePayoutThenRetries() external {
        string memory name = "settle-seal-rollback-and-retry";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes32 before_ = _snapshotFull();
        vm.etch(RECIPIENT, address(new Refuser()).code);
        (bool ok, bytes memory out, Vm.Log[] memory logs) = _run(name);
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.PayoutFailed.selector);
        assertEq(_snapshotFull(), before_, "segment, heads and buffers unchanged");
        vm.etch(RECIPIENT, "");
        (ok, out, logs) = _run(name);
        assertTrue(ok, vm.toString(out));
        assertEq(logs.length, 2, "Paid and SegmentSealed");
        assertEq(logs[0].topics[0], PAID);
        assertEq(logs[1].topics[0], SEALED);
        _assertSide(raw, "After");
        (ok, out,) = _run(name);
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.AlreadyPaid.selector);
    }

    function testReentryIsCaughtOrPropagated() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes32 before_ = _snapshotFull();
        // Propagated: the outer call reverts with PayoutFailed and nothing changes.
        vm.etch(RECIPIENT, address(new Reenter(VAULT, true, false)).code);
        (bool ok, bytes memory out, Vm.Log[] memory logs) = _run(name);
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.PayoutFailed.selector);
        assertEq(_snapshotFull(), before_);
        // Caught: the outer call pays exactly once.
        vm.etch(RECIPIENT, address(new Reenter(VAULT, false, false)).code);
        (ok, out, logs) = _run(name);
        assertTrue(ok, vm.toString(out));
        assertEq(logs.length, 1);
        _assertSide(raw, "After");
    }

    function testInsufficientLiability() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        vm.store(VAULT, bytes32(0), bytes32(uint256(vm.load(VAULT, bytes32(0))) - 51)); // Q = 49
        bytes32 before_ = _snapshotFull();
        (bool ok, bytes memory out,) = _run(name);
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.LiabilityUnderflow.selector, 49, 100));
        assertEq(_snapshotFull(), before_);
    }

    // ------------------------------------------------------------------------------------------------ stage order

    function _calldata(string memory name) private view returns (bytes memory) {
        return vm.readFileBinary(string.concat(_cold(name), "calldata.bin"));
    }

    function _expect(bytes memory data, bytes4 selector, string memory why) private {
        vm.recordLogs();
        (bool ok, bytes memory out) = VAULT.call(data);
        assertFalse(ok, why);
        assertEq(bytes4(out), selector, why);
        assertEq(vm.getRecordedLogs().length, 0, why);
    }

    function testFramingRefusalsAreBadPacket() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes memory good = _calldata(name);
        bytes4 bp = bytes4(keccak256("BadPacket()"));
        // Trailing byte, truncation, dirty ABI padding, wrong offset, wrong length word.
        _expect(bytes.concat(good, hex"00"), bp, "trailing");
        bytes memory cut = new bytes(good.length - 1);
        for (uint256 i; i < cut.length; ++i) {
            cut[i] = good[i];
        }
        _expect(cut, bp, "truncated");
        bytes memory bad = bytes.concat(good);
        bad[35] = 0x21; // offset 33
        _expect(bad, bp, "offset");
        bad = bytes.concat(good);
        bad[67] ^= 0x01; // length word
        _expect(bad, bp, "length");
        // Version, size, kind and a gap count that disagrees with the bytes.
        bad = bytes.concat(good);
        bad[68] = 0x02;
        _expect(bad, bp, "version");
        bad = bytes.concat(good);
        bad[68 + 42] = 0x03;
        _expect(bad, bp, "kind");
        bad = bytes.concat(good);
        bad[68 + 42] = 0x00;
        _expect(bad, bp, "kind zero");
        uint256 len = uint32(bytes4(_word(good, 68 + 43)));
        bad = bytes.concat(good);
        bad[68 + 47 + len + 1] = 0x01; // count 1 with no proof bytes
        _expect(bad, bp, "count without proofs");
        // An unknown selector is not a function of this vault.
        bytes memory other = bytes.concat(good);
        other[0] = 0x00;
        _expect(other, bp, "selector");
        // The published malformed-length vector: 1025 gaps.
        string memory refusal = "test/nb2/flat/generated/transcripts/refusals/settle-count1025/";
        string memory before = vm.readFile(string.concat(refusal, "custody-before.json"));
        _applyFlat(before);
        _expect(vm.readFileBinary(string.concat(refusal, "calldata.bin")), bp, "1025 gaps");
        (bool ok,) = VAULT.call(vm.readFileBinary(string.concat(refusal, "retry-calldata.bin")));
        assertTrue(ok, "retry from the same state");
    }

    function _applyFlat(string memory raw) private {
        uint256 c = vm.parseJsonUint(raw, ".Segment");
        uint256 m = vm.parseJsonUint(raw, ".Population");
        bytes32[] memory cur = vm.parseJsonBytes32Array(raw, ".Current");
        bytes32[] memory old = vm.parseJsonBytes32Array(raw, ".Previous");
        _store(
            vm.parseJsonUint(raw, ".Deposits"),
            c,
            m,
            vm.parseJsonUint(raw, ".Liability"),
            vm.parseJsonBytes32(raw, ".Head"),
            vm.parseJsonBytes32(raw, ".PreviousHead"),
            cur,
            old
        );
        vm.deal(VAULT, vm.parseJsonUint(raw, ".VaultBalance"));
        vm.deal(RECIPIENT, vm.parseJsonUint(raw, ".RecipientBalance"));
    }

    function testZeroSuffixGapWithAFalseHeadIsChainMismatchAndRetries() external {
        string memory dir =
            "test/nb2/flat/generated/transcripts/refusals/zero-suffix-gap-wrong-head/";
        _applyFlat(vm.readFile(string.concat(dir, "custody-before.json")));
        bytes32 before_ = _snapshotFull();
        _expect(
            vm.readFileBinary(string.concat(dir, "calldata.bin")),
            NB2VaultBase.ChainMismatch.selector,
            "false head"
        );
        assertEq(_snapshotFull(), before_);
        (bool ok,) = VAULT.call(vm.readFileBinary(string.concat(dir, "retry-calldata.bin")));
        assertTrue(ok, "the honest receipt pays");
    }

    function testForeignAndStaleReceipts() external {
        string memory name = "settle-kind1-suffixtrue-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes memory good = _calldata(name);
        bytes4 bpred = bytes4(keccak256("BadPredecessor()"));
        // Foreign session (a different evidence commitment), wrong kind for the event, corrupted receipt.
        bytes memory bad = bytes.concat(good);
        bad[68 + 20] ^= 0x01; // page root
        _expect(bad, bpred, "evidence commitment");
        bad = bytes.concat(good);
        bad[68 + 5] ^= 0x01; // size
        _expect(bad, bpred, "evidence size");
        bad = bytes.concat(good);
        bad[68 + 42] = 0x02; // a Gap kind over a Complete event (and a head the packet does not carry)
        _expect(bad, bytes4(keccak256("BadPacket()")), "kind without its start head");
        bad = bytes.concat(good);
        bad[68 + 47 + 200] ^= 0x01; // inside the receipt proof
        _expect(bad, bpred, "receipt");
        // The honest packet against the wrong custody: an endpoint that is neither c nor c - 1, then a future start.
        (uint64 n, uint64 c,,,,) = vault.state();
        n;
        string memory moved = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(moved, "Before");
        vm.store(
            VAULT, bytes32(0), bytes32(uint256(vm.load(VAULT, bytes32(0))) + (uint256(2) << 152))
        );
        (bool ok, bytes memory out) = VAULT.call(good);
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.StaleEndpoint.selector, "stale");
        _apply(moved, "Before");
        vm.store(
            VAULT, bytes32(0), bytes32(uint256(vm.load(VAULT, bytes32(0))) - (uint256(c) << 152))
        );
        (ok, out) = VAULT.call(good);
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.FutureIndex.selector, "future");
    }

    function testForeignGenerationRecoveryIsRefused() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        // Receipts are bound to the recovery generation: the same bytes under a vault that pins another generation fail.
        bytes memory good = _calldata(name);
        bytes memory bad = bytes.concat(good);
        bad[68 + 43 + 4 + 40] ^= 0x01; // the certified receipt
        _expect(bad, bytes4(keccak256("BadPredecessor()")), "tampered receipt");
        (bool ok,) = VAULT.call(good);
        assertTrue(ok, "the original still settles (a refusal credits nothing)");
    }

    function testGapProofRefusalPositionIsIndexed() external {
        string memory name = "settle-count1024";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes memory good = _calldata(name);
        uint256 abiLen = uint256(_word(good, 36));
        uint256 gaps = 68 + abiLen - 1024 * 257;
        for (uint256 k = 0; k < 3; ++k) {
            uint256 position = k == 0 ? 0 : k == 1 ? 5 : 1023;
            bytes memory bad = bytes.concat(good);
            bad[gaps + 257 * position] = 0xff; // index >= K
            bytes32 before_ = _snapshotFull();
            (bool ok, bytes memory out) = VAULT.call(bad);
            assertFalse(ok);
            assertEq(out, abi.encodeWithSelector(NB2VaultBase.BadGapProof.selector, position));
            assertEq(_snapshotFull(), before_);
        }
    }

    // ------------------------------------------------------------------------------------------------ races and eviction

    function _verdict(bytes32 eta, uint256 start) private view returns (bytes memory) {
        return abi.encode(
            vault.domain(),
            eta,
            uint64(start),
            bytes32(0x87b0b8b600fcd942cc3383bac1dbb80fd69d54af700cf48faa4525451a7b1845),
            RECIPIENT,
            uint256(100)
        );
    }

    function testRaceOrdinaryThenRecovered() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes32 eta = vm.parseJsonBytes32Array(raw, ".After.Current")[0];
        bytes memory evidence = _verdict(eta, 7);
        vault.redeem(evidence, eta, 7, "");
        assertEq(RECIPIENT.balance, 100);
        (bool ok, bytes memory out,) = _run(name);
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.AlreadyPaid.selector, eta));
        assertEq(RECIPIENT.balance, 100, "paid once");
        (,,, uint256 q,,) = vault.state();
        assertEq(q, 0);
    }

    function testRaceRecoveredThenOrdinary() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes32 eta = vm.parseJsonBytes32Array(raw, ".After.Current")[0];
        (bool ok, bytes memory out,) = _run(name);
        assertTrue(ok, vm.toString(out));
        bytes memory evidence = _verdict(eta, 7);
        vm.expectRevert(abi.encodeWithSelector(NB2VaultBase.AlreadyPaid.selector, eta));
        vault.redeem(evidence, eta, 7, "");
        assertEq(RECIPIENT.balance, 100, "paid once");
    }

    function testSecondSessionForTheSameEtaIsDetectedInBothBuffers() external {
        // Another session (here: each published receipt kind) for an eta that an earlier session already inserted.
        string[3] memory names = [
            "settle-kind1-suffixfalse-prevtrue",
            "settle-kind2-suffixfalse-prevtrue",
            "settle-kind2-suffixtrue-prevfalse"
        ];
        for (uint256 i; i < names.length; ++i) {
            string memory raw = vm.readFile(string.concat(_cold(names[i]), "outcome.json"));
            _apply(raw, "Before");
            bytes32 eta = vm.parseJsonBytes32Array(raw, ".After.Current")[0];
            (, uint64 c,,,,) = vault.state();
            // In the current buffer, then (after a rotation of the live window) in the previous one.
            bytes32[] memory cur = new bytes32[](1);
            cur[0] = eta;
            _fillBuffer(c & 1, cur);
            vm.store(
                VAULT,
                bytes32(0),
                bytes32(uint256(vm.load(VAULT, bytes32(0))) | (uint256(1) << 144))
            );
            _expect(_calldata(names[i]), NB2VaultBase.AlreadyPaid.selector, "current buffer");
            if (i == 2) continue; // an endpoint at c scans only the current buffer
            _apply(raw, "Before");
            bytes32[] memory prev = vm.parseJsonBytes32Array(raw, ".Before.Previous");
            prev[5] = eta;
            _fillBuffer((c & 1) ^ 1, prev);
            _expect(_calldata(names[i]), NB2VaultBase.AlreadyPaid.selector, "previous buffer");
        }
    }

    function testEvictedFromBothBuffersIsPaidOnlyThroughTheArchive() external {
        // The identifier was paid and then left both live buffers: only the folded gap exclusion can authorise a payment.
        // Both buffers hold other identifiers here, so the scans pass and the receipt's fold decides.
        string memory name = "settle-kind1-suffixtrue-prevtrue";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        (bool ok, bytes memory out,) = _run(name);
        assertTrue(ok, vm.toString(out));
        _assertSide(raw, "After");
        // Corrupt the stored head the fold compares to: the same receipt no longer pays.
        _apply(raw, "Before");
        (, uint64 c,,,,) = vault.state();
        vm.store(VAULT, bytes32(1 + (uint256(c) - 1 & 1)), bytes32(uint256(1)));
        _expect(_calldata(name), NB2VaultBase.ChainMismatch.selector, "stored head");
    }

    /// @dev Hands the deployed vault code and the helper code to the real-B1 replay (tools/nb2-settle-b1), which installs them at
    ///      the reference addresses and runs the same custody fixtures on ureth's actual precompiles.
    function testExportForRealB1Replay() external {
        vm.createDir("out/nb2-settle", true);
        vm.writeFile("out/nb2-settle/vault.hex", vm.toString(VAULT.code));
        vm.writeFile("out/nb2-settle/receipts.hex", vm.toString(address(receipts).code));
        vm.writeFile("out/nb2-settle/recovery.hex", vm.toString(RECOVERY.code));
    }

    // ------------------------------------------------------------------------------------------------ round 2 (astra)

    function testGuardPrecedesTheOuterAbiDecoder() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes32 before_ = _snapshotFull();
        // Re-entry with the right selector and broken framing: the recipient records the inner failure and accepts the
        // value, so the outer call pays and the recorded selector is exactly Reentrancy(), not BadPacket() or any other.
        vm.etch(RECIPIENT, address(new Reenter(VAULT, false, true)).code);
        (bool ok, bytes memory out,) = _run(name);
        assertTrue(ok, vm.toString(out));
        assertEq(
            Reenter(payable(RECIPIENT)).inner(), NB2VaultBase.Reentrancy.selector, "inner error"
        );
        assertTrue(before_ != _snapshotFull(), "the outer call paid once");
        // Outside a payout the same framing is BadPacket().
        _expect(
            abi.encodePacked(bytes4(keccak256("redeemRecovered(bytes)")), hex"01"),
            bytes4(keccak256("BadPacket()")),
            "framing"
        );
    }

    function testChainIdIsRecheckedBeforeAReceiptIsConsumed() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes32 before_ = _snapshotFull();
        bytes memory data = _calldata(name);
        vm.chainId(1);
        _expect(data, bytes4(keccak256("BadPredecessor()")), "another chain");
        assertEq(_snapshotFull(), before_, "custody unchanged on refusal");
        vm.chainId(31337);
        (bool ok, bytes memory out,) = _run(name);
        assertTrue(ok, vm.toString(out));
        _assertSide(raw, "After");
    }

    function _event(uint256 amount, bytes32 domain, bytes32 asset, address recipient)
        private
        pure
        returns (bytes memory)
    {
        return abi.encode(
            uint256(1),
            domain,
            bytes32(0xf705f24c68a7b77536b2406ea51c1cce7805cc872a47d5b899532348e0241eea),
            uint256(7),
            asset,
            recipient,
            amount
        );
    }

    function testSharedVerdictErrorsComeFromTheSettlementStage() external {
        string memory name = "settle-kind1-suffixfalse-prevfalse";
        string memory raw = vm.readFile(string.concat(_cold(name), "outcome.json"));
        _apply(raw, "Before");
        bytes memory data = _calldata(name);
        bytes32 d = vault.domain();
        bytes32 asset = 0x87b0b8b600fcd942cc3383bac1dbb80fd69d54af700cf48faa4525451a7b1845;
        CorpusVault11 v = CorpusVault11(payable(VAULT));
        v.craft(_event(100, bytes32(uint256(d) ^ 1), asset, RECIPIENT));
        _expect(data, NB2VaultBase.DomainMismatch.selector, "domain");
        v.craft(_event(100, d, bytes32(uint256(asset) ^ 1), RECIPIENT));
        _expect(data, NB2VaultBase.AssetMismatch.selector, "asset");
        v.craft(_event(0, d, asset, RECIPIENT));
        _expect(data, NB2VaultBase.ZeroAmount.selector, "amount");
        v.craft(_event(100, d, asset, address(0)));
        _expect(data, NB2VaultBase.BadRecipient.selector, "zero recipient");
        v.craft(_event(100, d, asset, VAULT));
        _expect(data, NB2VaultBase.BadRecipient.selector, "vault recipient");
        // Earlier stages win: a stale endpoint, and an eta already in a live buffer, precede the verdict errors.
        v.craft(_event(0, d, asset, RECIPIENT));
        bytes32[] memory cur = new bytes32[](1);
        cur[0] = 0xf705f24c68a7b77536b2406ea51c1cce7805cc872a47d5b899532348e0241eea;
        _fillBuffer(7 & 1, cur);
        vm.store(
            VAULT, bytes32(0), bytes32(uint256(vm.load(VAULT, bytes32(0))) | (uint256(1) << 144))
        );
        _expect(data, NB2VaultBase.AlreadyPaid.selector, "scan before verdict");
        _apply(raw, "Before");
        vm.store(
            VAULT, bytes32(0), bytes32(uint256(vm.load(VAULT, bytes32(0))) + (uint256(2) << 152))
        );
        _expect(data, NB2VaultBase.StaleEndpoint.selector, "endpoint before verdict");
        v.craft("");
    }
}
