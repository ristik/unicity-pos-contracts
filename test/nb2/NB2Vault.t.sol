// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Test.sol";
import {NB2VaultBase} from "../../src/nb2/NB2VaultBase.sol";
import {NB2Config} from "../../src/nb2/NB2Config.sol";
import {NativeBridgeVaultV2Test} from "../../src/nb2/NativeBridgeVaultV2Test.sol";
import {
    INB2Vault,
    MockVerifierV2,
    NB2Ref,
    NB2TestBase,
    ReenteringRecipient,
    RevertingRecipient
} from "./NB2TestBase.sol";

/// A verifier that returns or reverts with 512 KiB of data from any call.
contract ReturnBomb {
    bool internal immutable REVERTS;

    constructor(bool reverts) {
        REVERTS = reverts;
    }

    fallback() external {
        bool r = REVERTS;
        assembly ("memory-safe") {
            if r { revert(0, 524288) }
            return(0, 524288)
        }
    }
}

/// The vault's rules one by one (bft-core docs/design/native-bridge-v2.md sections 5, 9 to 11 and 13; NB2-04 #1100):
/// every rejection with its exact revert data, rotation at K = 4 and K = 8, rollback, packing boundaries, K = 64 seals,
/// the storage-write bound and the CI gas ceilings.
contract NB2VaultTest is NB2TestBase {
    uint256 internal constant QMAX = 1e30;

    function setUp() public {
        vm.deal(address(this), 0);
    }

    // -------------------------------------------------------------------------------------------- helpers

    function _redeem(World memory w, bytes32 eta, uint256 a, bytes memory h, bytes memory evidence)
        internal
        returns (bool ok, bytes memory ret)
    {
        (ok, ret) =
            address(w.v).call(abi.encodeCall(INB2Vault.redeem, (evidence, eta, uint64(a), h)));
    }

    function _redeemOk(World memory w, bytes32 eta, uint256 a, bytes memory h) internal {
        (bool ok, bytes memory ret) = _redeem(w, eta, a, h, verdict(w, eta, a, RECIPIENT, 1));
        assertTrue(ok, vm.toString(ret));
        mirrorPaid(w, eta);
    }

    function _expect(World memory w, bytes32 eta, uint256 a, bytes memory h, bytes memory want)
        internal
    {
        _expectEv(w, eta, a, h, verdict(w, eta, a, RECIPIENT, 1), want);
    }

    function _expectEv(
        World memory w,
        bytes32 eta,
        uint256 a,
        bytes memory h,
        bytes memory ev,
        bytes memory want
    ) internal {
        bytes32 a0 = vm.load(address(w.v), bytes32(0));
        (bool ok, bytes memory ret) = _redeem(w, eta, a, h, ev);
        assertFalse(ok, "expected a revert");
        assertEq(ret, want);
        assertEq(vm.load(address(w.v), bytes32(0)), a0, "state unchanged");
    }

    function _q(World memory w) internal view returns (uint256 q) {
        (,,, q,,) = w.v.state();
    }

    // -------------------------------------------------------------------------------------------- deposit rules

    function test_deposit_ok() public {
        World memory w = deploy(4, 2, QMAX);
        vm.deal(address(this), 10);
        vm.recordLogs();
        w.v.deposit{value: 7}(owner(), bytes32(uint256(5)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], TOPIC_DEPOSITED);
        assertEq(logs[0].topics[1], bytes32(uint256(1)), "deposit numbers start at 1");
        assertEq(logs[0].data, abi.encode(w.d, uint256(7), bytes32(uint256(5)), owner()));
        assertEq(logs[0].data.length, 224);
        (uint64 n,,, uint256 q,,) = w.v.state();
        assertEq(n, 1);
        assertEq(q, 7);
        assertEq(address(w.v).balance, 7);
    }

    function test_deposit_ZeroValue() public {
        World memory w = deploy(4, 2, QMAX);
        vm.expectRevert(abi.encodeWithSignature("ZeroValue()"));
        w.v.deposit(owner(), bytes32(0));
    }

    function test_deposit_BadFirstOwner() public {
        World memory w = deploy(4, 2, QMAX);
        vm.deal(address(this), 10);
        bytes memory good = owner();
        bytes[5] memory bad = [
            bytes.concat(hex"d9987883014101582104", keccak256("k")), // 0x04 prefix
            bytes.concat(hex"d99878830141015821", hex"02", bytes31(keccak256("k"))), // 41 bytes
            bytes.concat(good, hex"00"), // 43 bytes
            bytes.concat(hex"d9987883014102582102", keccak256("k")), // burn predicate code
            bytes.concat(hex"d9987883014101582003", keccak256("k")) // 32-byte key head
        ];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(abi.encodeWithSignature("BadFirstOwner()"));
            w.v.deposit{value: 1}(bad[i], bytes32(0));
        }
        w.v.deposit{value: 1}(bytes.concat(hex"d9987883014101582103", keccak256("k")), bytes32(0));
    }

    function test_deposit_LiabilityCap() public {
        World memory w = deploy(4, 2, 100);
        vm.deal(address(this), 1000);
        w.v.deposit{value: 60}(owner(), 0);
        vm.expectRevert(
            abi.encodeWithSignature("LiabilityCap(uint256,uint256,uint256)", 60, 41, 100)
        );
        w.v.deposit{value: 41}(owner(), 0);
        w.v.deposit{value: 40}(owner(), 0);
        assertEq(_q(w), 100);
    }

    function test_deposit_DepositCounterExhausted() public {
        World memory w = deploy(4, 2, QMAX);
        vm.deal(address(this), 10);
        // n = 2^56 - 2 with c = 5, m = 3, Q = 9: the last number is allocated, then the counter refuses
        uint256 acc = (((1 << 56) - 2) << 200) | (5 << 152) | (3 << 144) | 9;
        vm.store(address(w.v), bytes32(0), bytes32(acc));
        w.v.deposit{value: 1}(owner(), 0);
        (uint64 n, uint64 c, uint16 m, uint256 q,,) = w.v.state();
        assertEq(n, (1 << 56) - 1);
        assertEq(c, 5);
        assertEq(m, 3);
        assertEq(q, 10);
        vm.expectRevert(abi.encodeWithSignature("DepositCounterExhausted()"));
        w.v.deposit{value: 1}(owner(), 0);
    }

    function test_deposit_noReceiveNoFallback() public {
        World memory w = deploy(4, 2, QMAX);
        vm.deal(address(this), 10);
        (bool ok,) = address(w.v).call{value: 1}("");
        assertFalse(ok, "no receive");
        (ok,) = address(w.v).call{value: 1}(hex"12345678");
        assertFalse(ok, "no fallback");
        // forced value (SELFDESTRUCT, coinbase) is surplus: it never raises Q
        vm.deal(address(w.v), 5);
        assertEq(_q(w), 0);
    }

    // -------------------------------------------------------------------------------------------- redeem rules

    function test_redeem_ok() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        bytes32 eta = nextEta(w, 99);
        vm.recordLogs();
        w.v.redeem(verdict(w, eta, 0, RECIPIENT, 30), eta, 0, "");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], TOPIC_PAID);
        assertEq(logs[0].topics[1], eta);
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(RECIPIENT))));
        assertEq(logs[0].data, abi.encode(uint256(30)));
        assertEq(RECIPIENT.balance, 30);
        assertEq(_q(w), 70);
        assertEq(address(w.v).balance, 70);
    }

    function test_redeem_BadHistoryLength() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 10);
        uint256 plen = 65 + 32 * 2;
        uint256[5] memory lens = [uint256(1), 31, 32, 32 + plen - 1, 32 + 2 * plen + 1];
        for (uint256 i = 0; i < lens.length; i++) {
            _expect(
                w,
                nextEta(w, 9),
                0,
                new bytes(lens[i]),
                abi.encodeWithSignature("BadHistoryLength(uint256)", lens[i])
            );
        }
    }

    function test_redeem_FutureIndex() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 10);
        bytes32 eta = nextEta(w, 9);
        _expect(
            w,
            eta,
            1,
            "",
            abi.encodeWithSignature("FutureIndex(uint64,uint64)", uint64(1), uint64(0))
        );
        _expect(
            w,
            eta,
            type(uint64).max,
            new bytes(32 + 129),
            abi.encodeWithSignature("FutureIndex(uint64,uint64)", type(uint64).max, uint64(0))
        );
    }

    function test_redeem_StaleEndpoint() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        fill(w, 8, 9); // c = 2
        _expect(
            w,
            nextEta(w, 9),
            0,
            "",
            abi.encodeWithSignature("StaleEndpoint(uint64,uint64)", uint64(0), uint64(2))
        );
        // at c = 0 the only endpoint is 0
        World memory w0 = deploy(4, 2, QMAX);
        fund(w0, 10);
        _expect(
            w0,
            nextEta(w0, 9),
            0,
            new bytes(32 + 129),
            abi.encodeWithSignature("StaleEndpoint(uint64,uint64)", 1, 0)
        );
    }

    function test_redeem_BadGapProof() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        fill(w, 8, 9); // two sealed segments
        bytes32 eta = nextEta(w, 9);
        (, bytes memory h) = history(w, eta, 0, 2);
        // proof 1's index set to K
        bytes memory bad = bytes.concat(h);
        bad[32 + 129] = bytes1(uint8(4));
        _expect(w, eta, 0, bad, abi.encodeWithSignature("BadGapProof(uint256)", 1));
        // an identifier paid in segment 1 has no gap there: a valid gap of another identifier does not contain it
        bytes32 paid = w.segs[1][1];
        (, bytes memory hp) = history(w, paid, 0, 1);
        _expect(
            w,
            paid,
            0,
            bytes.concat(hp, _gapFor(w, 1, paid)),
            abi.encodeWithSignature("BadGapProof(uint256)", 1)
        );
        _redeemOk(w, eta, 0, h);
    }

    function test_redeem_ChainMismatch() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        fill(w, 4, 9);
        bytes32 eta = nextEta(w, 9);
        (, bytes memory h) = history(w, eta, 0, 1);
        bytes memory wrong = bytes.concat(h);
        wrong[0] ^= 0x01; // wrong start head
        _expect(w, eta, 0, wrong, abi.encodeWithSignature("ChainMismatch()"));
        bytes memory sib = bytes.concat(h);
        sib[32 + 65] ^= 0x01; // tampered sibling
        _expect(w, eta, 0, sib, abi.encodeWithSignature("ChainMismatch()"));
        // repairable without a new burn: the honest history pays
        _redeemOk(w, eta, 0, h);
    }

    function test_redeem_AlreadyPaid() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        bytes32 eta = nextEta(w, 9);
        _redeemOk(w, eta, 0, "");
        _expect(w, eta, 0, "", abi.encodeWithSignature("AlreadyPaid(bytes32)", eta));
    }

    function test_redeem_VerifierRefused() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        bytes32 eta = nextEta(w, 9);
        bytes memory reason = abi.encodeWithSignature("SplitSum()");
        w.mock.set(true, reason);
        _expect(w, eta, 0, "", abi.encodeWithSignature("VerifierRefused(bytes)", reason));
        w.mock.set(true, "");
        _expect(w, eta, 0, "", abi.encodeWithSignature("VerifierRefused(bytes)", ""));
    }

    /// Revert data is copied into VerifierRefused only up to 1024 bytes; larger is VerifierBadReturn, decided before any
    /// copy, so a huge revert that fits the verifier's gas cannot exhaust the vault's (section 11.1 step 5).
    function test_redeem_verifierRevertBounded() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        bytes32 eta = nextEta(w, 9);
        bytes memory r1024 = new bytes(1024);
        r1024[0] = 0x6a;
        w.mock.set(true, r1024);
        _expect(w, eta, 0, "", abi.encodeWithSignature("VerifierRefused(bytes)", r1024));
        w.mock.set(true, new bytes(1025));
        _expect(w, eta, 0, "", abi.encodeWithSignature("VerifierBadReturn()"));
        // a verifier that reverts with 512 KiB: the callee has the gas for it, the vault's remainder must suffice
        address bomb = address(new ReturnBomb(true));
        vm.etch(address(w.mock), bomb.code);
        bytes memory cd = abi.encodeCall(
            INB2Vault.redeem, (verdict(w, eta, 0, RECIPIENT, 1), eta, uint64(0), bytes(""))
        );
        (bool ok, bytes memory ret) = address(w.v).call{gas: 1_000_000}(cd);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSignature("VerifierBadReturn()"));
        // the same for oversized success data
        bomb = address(new ReturnBomb(false));
        vm.etch(address(w.mock), bomb.code);
        (ok, ret) = address(w.v).call{gas: 1_000_000}(cd);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSignature("VerifierBadReturn()"));
        assertEq(_q(w), 100);
    }

    function test_redeem_VerifierBadReturn() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        bytes32 eta = nextEta(w, 9);
        bytes memory good = verdict(w, eta, 0, RECIPIENT, 1);
        bytes memory bad = abi.encodeWithSignature("VerifierBadReturn()");
        _expectEv(w, eta, 0, "", "", bad);
        _expectEv(w, eta, 0, "", bytes.concat(good, hex"00"), bad);
        bytes memory short = new bytes(191);
        for (uint256 i = 0; i < 191; i++) {
            short[i] = good[i];
        }
        _expectEv(w, eta, 0, "", short, bad);
        bytes memory hiMin = bytes.concat(good);
        hiMin[64] = 0x01; // minSegment word with a high byte set
        _expectEv(w, eta, 0, "", hiMin, bad);
        bytes memory hiRcp = bytes.concat(good);
        hiRcp[128] = 0x01; // recipient word with a high byte set
        _expectEv(w, eta, 0, "", hiRcp, bad);
        // the verifier address without code: an empty successful return
        vm.etch(address(w.mock), "");
        _expectEv(w, eta, 0, "", good, bad);
    }

    function test_redeem_verdictChecks() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        bytes32 eta = nextEta(w, 9);
        _expectEv(
            w,
            eta,
            0,
            "",
            abi.encode(keccak256("other D"), eta, uint64(0), ASSET_UCT, RECIPIENT, 1),
            abi.encodeWithSignature("DomainMismatch()")
        );
        _expectEv(
            w,
            eta,
            0,
            "",
            abi.encode(w.d, eta, uint64(0), keccak256("ERC20"), RECIPIENT, 1),
            abi.encodeWithSignature("AssetMismatch()")
        );
        _expectEv(
            w,
            eta,
            0,
            "",
            verdict(w, nextEta(w, 9), 0, RECIPIENT, 1),
            abi.encodeWithSignature("ClaimMismatch()")
        );
        fill(w, 4, 9); // c = 1: a claimed start 1 against a verdict of 0, and the reverse
        _expectEv(
            w,
            eta,
            1,
            "",
            verdict(w, eta, 0, RECIPIENT, 1),
            abi.encodeWithSignature("ClaimMismatch()")
        );
        (, bytes memory h) = history(w, eta, 0, 1);
        _expectEv(
            w,
            eta,
            0,
            h,
            verdict(w, eta, 1, RECIPIENT, 1),
            abi.encodeWithSignature("ClaimMismatch()")
        );
        _expectEv(
            w,
            eta,
            1,
            "",
            verdict(w, eta, 1, address(0), 1),
            abi.encodeWithSignature("BadRecipient()")
        );
        _expectEv(
            w,
            eta,
            1,
            "",
            verdict(w, eta, 1, address(w.v), 1),
            abi.encodeWithSignature("BadRecipient()")
        );
        _expectEv(
            w, eta, 1, "", verdict(w, eta, 1, RECIPIENT, 0), abi.encodeWithSignature("ZeroAmount()")
        );
        uint256 q = _q(w);
        _expectEv(
            w,
            eta,
            1,
            "",
            verdict(w, eta, 1, RECIPIENT, q + 1),
            abi.encodeWithSignature("LiabilityUnderflow(uint256,uint256)", q, q + 1)
        );
        // the whole liability can be paid
        (bool ok,) = _redeem(w, eta, 1, "", verdict(w, eta, 1, RECIPIENT, q));
        assertTrue(ok);
        assertEq(_q(w), 0);
    }

    /// A forged claimed identifier passes the gap proofs and the scan; the verdict's identifier differs: nothing granted.
    function test_redeem_forgedClaimPassesEarlyChecks() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        fill(w, 4, 9);
        bytes32 real = w.segs[0][2]; // paid in segment 0
        bytes32 forged = nextEta(w, 9);
        (, bytes memory h) = history(w, forged, 0, 1);
        _expectEv(
            w,
            forged,
            0,
            h,
            verdict(w, real, 0, RECIPIENT, 1),
            abi.encodeWithSignature("ClaimMismatch()")
        );
    }

    function test_redeem_SegmentCounterExhausted() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        // c = 2^48 - 2: the seal to 2^48 - 1 works, the next one is refused
        uint256 acc = (1 << 200) | (((1 << 48) - 2) << 152) | 100;
        vm.store(address(w.v), bytes32(0), bytes32(acc));
        vm.store(address(w.v), bytes32(uint256(1)), w.heads[0]);
        for (uint256 i = 0; i < 4; i++) {
            bytes32 eta = nextEta(w, 9);
            w.v.redeem(verdict(w, eta, (1 << 48) - 2, RECIPIENT, 1), eta, uint64((1 << 48) - 2), "");
        }
        (, uint64 c, uint16 m,,,) = w.v.state();
        assertEq(c, (1 << 48) - 1);
        assertEq(m, 0);
        for (uint256 i = 0; i < 3; i++) {
            bytes32 eta = nextEta(w, 9);
            w.v.redeem(verdict(w, eta, c, RECIPIENT, 1), eta, c, "");
        }
        bytes32 last = nextEta(w, 9);
        _expect(w, last, c, "", abi.encodeWithSignature("SegmentCounterExhausted()"));
        // the refused sealing payment leaves the K - 1 payments as they were
        (, uint64 c2, uint16 m2, uint256 q,,) = w.v.state();
        assertEq(c2, c);
        assertEq(m2, 3);
        assertEq(q, 93);
    }

    function test_redeem_PayoutFailed() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        address bad = address(new RevertingRecipient());
        bytes32 eta = nextEta(w, 9);
        _expectEv(
            w, eta, 0, "", verdict(w, eta, 0, bad, 1), abi.encodeWithSignature("PayoutFailed()")
        );
    }

    // -------------------------------------------------------------------------------------------- rollback and reentrancy

    /// A reverting recipient on the sealing payment: the seal, its log, the payment and every buffer write revert.
    function test_rollback_revertingRecipientOnSeal() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        fill(w, 7, 9); // c = 1, m = 3
        bytes32[8] memory before = _snapshotSlots(w);
        address bad = address(new RevertingRecipient());
        bytes32 eta = nextEta(w, 9);
        vm.recordLogs();
        (bool ok, bytes memory ret) = _redeem(w, eta, 1, "", verdict(w, eta, 1, bad, 1));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSignature("PayoutFailed()"));
        _assertSlots(w, before);
        checkState(w);
        // the same claim pays a good recipient afterwards: the seal happens then
        _redeemOk(w, eta, 1, "");
        checkState(w);
    }

    /// Out of gas inside the sealing work: the whole call reverts and a retry with enough gas seals.
    function test_rollback_outOfGasInSeal() public {
        World memory w = deploy(64, 16, QMAX);
        fund(w, 1000);
        fill(w, 127, 99); // c = 1, m = 63
        bytes32[8] memory before = _snapshotSlots(w);
        bytes32 eta = nextEta(w, 99);
        bytes memory cd = abi.encodeCall(
            INB2Vault.redeem, (verdict(w, eta, 1, RECIPIENT, 1), eta, uint64(1), bytes(""))
        );
        uint256 snap = vm.snapshotState();
        uint256 g0 = gasleft();
        (bool ok,) = address(w.v).call(cd);
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        vm.revertToStateAndDelete(snap);
        // the seal is most of this call and comes just before the payout: 100k short runs out inside it
        (ok,) = address(w.v).call{gas: used - 100_000}(cd);
        assertFalse(ok);
        _assertSlots(w, before);
        checkState(w);
        (ok,) = address(w.v).call{gas: 1_000_000}(cd);
        assertTrue(ok);
        mirrorPaid(w, eta);
        checkState(w);
    }

    function test_reentrancy_throughRedeemAndDeposit() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 100);
        for (uint256 viaDeposit = 0; viaDeposit < 2; viaDeposit++) {
            ReenteringRecipient r = new ReenteringRecipient(w.v, viaDeposit == 1);
            bytes32 eta = nextEta(w, 9);
            w.v.redeem(verdict(w, eta, 0, address(r), 5), eta, 0, "");
            mirrorPaid(w, eta);
            assertEq(r.inner(), abi.encodeWithSignature("Reentrancy()"), "inner call refused");
            assertEq(address(r).balance, 5, "outer payout succeeded");
        }
        (uint64 n,,, uint256 q,,) = w.v.state();
        assertEq(n, 1, "the inner deposit did not count");
        assertEq(q, 90);
        // the guard is released after the call
        fund(w, 1);
    }

    function _snapshotSlots(World memory w) internal view returns (bytes32[8] memory s) {
        uint256[8] memory slots = [uint256(0), 1, 2, 3, 4, 16, 16 + w.k, 16 + 2 * w.k - 1];
        for (uint256 i = 0; i < 8; i++) {
            s[i] = vm.load(address(w.v), bytes32(slots[i]));
        }
    }

    function _assertSlots(World memory w, bytes32[8] memory s) internal view {
        bytes32[8] memory now_ = _snapshotSlots(w);
        for (uint256 i = 0; i < 8; i++) {
            assertEq(now_[i], s[i], "slot rolled back");
        }
        uint256 p = (w.c & 1);
        for (uint256 i = 0; i < w.k; i++) {
            if (i >= w.cur.length) continue;
            assertEq(vm.load(address(w.v), bytes32(16 + p * w.k + i)), w.cur[i]);
        }
    }

    // -------------------------------------------------------------------------------------------- rotation (K = 4, K = 8)

    function test_rotation_k4() public {
        _rotation(4, 2);
    }

    function test_rotation_k8() public {
        _rotation(8, 4);
    }

    function _rotation(uint256 k, uint256 b) internal {
        World memory w = deploy(k, b, QMAX);
        fund(w, 1e6);
        // same-block duplicate: two calls in one transaction context
        bytes32 x = nextEta(w, 99);
        _redeemOk(w, x, 0, "");
        _expect(w, x, 0, "", abi.encodeWithSignature("AlreadyPaid(bytes32)", x));
        fill(w, k - 1, 99); // seals segment 0 (x in it): c = 1
        // replay after one rollover: the previous buffer at e = c - 1, and the sealed segment at e = c
        _expect(w, x, 0, "", abi.encodeWithSignature("AlreadyPaid(bytes32)", x));
        _expect(
            w,
            x,
            0,
            abi.encodePacked(w.heads[0], _gapFor(w, 0, x)),
            abi.encodeWithSignature("BadGapProof(uint256)", 0)
        );
        // a witness prepared at c = 1 for a fresh y survives one more seal (e = c - 1)
        bytes32 y = nextEta(w, 99);
        (, bytes memory hy) = history(w, y, 0, 1);
        fill(w, k, 99); // c = 2
        _redeemOk(w, y, 0, hy);
        // replay after eviction (c = 3: segment 0 is no longer buffered) with a fresh witness: the gap proof refuses
        fill(w, k - 1, 99); // c = 3
        assertEq(w.c, 3);
        (, bytes memory p1) = NB2Ref.proof(w.segs[1], x);
        _expect(
            w,
            x,
            0,
            abi.encodePacked(w.heads[0], _gapFor(w, 0, x), p1),
            abi.encodeWithSignature("BadGapProof(uint256)", 0)
        );
        // y replayed: the honest history to e = 2 = c - 1 reaches the previous buffer, which holds y
        (, bytes memory hy2) = history(w, y, 0, 2);
        _expect(w, y, 0, hy2, abi.encodeWithSignature("AlreadyPaid(bytes32)", y));
        // stale endpoint refusal and refresh: a witness to e = 1 is two seals old
        bytes32 z = nextEta(w, 99);
        (, bytes memory hz) = history(w, z, 0, 1);
        _expect(
            w,
            z,
            0,
            hz,
            abi.encodeWithSignature("StaleEndpoint(uint64,uint64)", uint64(1), uint64(3))
        );
        (, bytes memory fresh) = history(w, z, 0, 3);
        _redeemOk(w, z, 0, fresh);
        checkState(w);
    }

    function _gapFor(World memory w, uint256 j, bytes32 eta)
        internal
        pure
        returns (bytes memory p)
    {
        // the gap proof of the gap just below eta's position in segment j (a valid gap of its neighbour)
        bytes32[] memory z = w.segs[j];
        bytes32 probe = bytes32(uint256(z[0]) + 1);
        if (z[0] == eta) probe = bytes32(uint256(z[1]) + 1);
        (, p) = NB2Ref.proof(z, probe);
    }

    // -------------------------------------------------------------------------------------------- packing boundaries

    function test_packing_liabilityAtTheCap() public {
        uint256 cap = (1 << 144) - 1;
        World memory w = deploy(4, 2, cap);
        vm.deal(address(this), cap + 1);
        w.v.deposit{value: cap}(owner(), 0);
        bytes32 a0 = vm.load(address(w.v), bytes32(0));
        assertEq(uint256(a0), (1 << 200) | cap, "Q fills its field, nothing carries");
        vm.expectRevert(
            abi.encodeWithSignature("LiabilityCap(uint256,uint256,uint256)", cap, 1, cap)
        );
        w.v.deposit{value: 1}(owner(), 0);
        bytes32 eta = nextEta(w, 9);
        w.v.redeem(verdict(w, eta, 0, RECIPIENT, cap), eta, 0, "");
        assertEq(
            uint256(vm.load(address(w.v), bytes32(0))), (1 << 200) | (1 << 144), "no borrow into m"
        );
    }

    /// Staged constructor validation (section 4.1): the array, then the fields 0..18 in index order, then the deployment
    /// checks asset (10), ty (11), aid (12), vault (9), chainId (5), verifier code hash (15). Multi-fault Γ report the
    /// first failure of that order.
    function test_constructor_precedence() public {
        MockVerifierV2 mock = new MockVerifierV2();
        address addr = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        GammaFields memory f = fields(addr, address(mock), 4, 2, QMAX);
        // wrong chainId (5) and wrong asset (10): 10
        GammaFields memory g = fields(addr, address(mock), 4, 2, QMAX);
        g.chainId = 1;
        g.asset = keccak256("x");
        _ctorExpect(g, 10);
        // wrong vault (9) and wrong ty (11): 11
        g = fields(address(0xdead), address(mock), 4, 2, QMAX);
        g.ty = keccak256("x");
        _ctorExpect(g, 11);
        // a decode fault (7) and a wrong asset (10): 7
        g = fields(addr, address(mock), 4, 2, QMAX);
        g.evmShard = "";
        g.asset = keccak256("x");
        _ctorExpect(g, 7);
        // a Γ self-consistent for chain 1 (ty and aid derived for it) deployed on 31337, with a wrong code hash: 5
        vm.chainId(1);
        g = fields(addr, address(mock), 4, 2, QMAX);
        g.verifierCodeHash = keccak256("other");
        vm.chainId(31337);
        _ctorExpect(g, 5);
        f.verifierCodeHash = keccak256("other");
        _ctorExpect(f, 15);
    }

    function _ctorExpect(GammaFields memory g, uint256 field) internal {
        bytes memory gamma = encodeGamma(g);
        vm.expectRevert(abi.encodeWithSelector(NB2Config.BadConfig.selector, field));
        new NativeBridgeVaultV2Test(gamma);
    }

    function test_packing_qmaxBound() public {
        // Qmax = 2^144 is refused at construction (field 18)
        MockVerifierV2 mock = new MockVerifierV2();
        address addr = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        bytes memory gamma = encodeGamma(fields(addr, address(mock), 4, 2, 1 << 144));
        vm.expectRevert(abi.encodeWithSelector(NB2Config.BadConfig.selector, 18));
        new NativeBridgeVaultV2Test(gamma);
    }

    /// Stale cells and tags beyond the population are ignored and overwritten with masked tag updates.
    function test_packing_tagWordReuseWithStaleCells() public {
        World memory w = deploy(4, 2, QMAX);
        fund(w, 1e6);
        // segment 0: tags 1, 1, 1, 1 (all bucket 1)
        for (uint256 i = 0; i < 4; i++) {
            pay(w, nextEta(w, 1));
        }
        fill(w, 4, 0); // segment 1 in buffer 1, all bucket 0; c = 2, buffer 0 is current again
        assertEq(
            uint256(vm.load(address(w.v), bytes32(uint256(3)))) & 0xf, 0xf, "stale tags in buffer 0"
        );
        // a bucket-0 identifier at position 0 clears only its own tag bit
        bytes32 e0 = nextEta(w, 0);
        pay(w, e0);
        assertEq(
            uint256(vm.load(address(w.v), bytes32(uint256(3)))) & 0xf, 0xe, "masked tag update"
        );
        // a stale cell (position 1 still holds a segment-0 identifier) is not a live entry: its identifier is judged by
        // history, not by the stale cell
        bytes32 stale = vm.load(address(w.v), bytes32(uint256(16 + 1)));
        assertEq(stale, w.segs[0][_indexOf(w.segs[0], stale)]);
        (bool paid,) = history(w, stale, 0, 2);
        assertTrue(paid);
        // with a start at the current segment (a burn signed after segment 1), only live positions are scanned
        (bool ok, bytes memory ret) = _redeem(w, stale, 2, "", verdict(w, stale, 2, RECIPIENT, 1));
        assertTrue(ok, vm.toString(ret));
        assertEq(vm.load(address(w.v), bytes32(uint256(16 + 1))), stale);
        assertEq(
            uint256(vm.load(address(w.v), bytes32(uint256(3)))) & 0xf, 0xe, "tag 1 rewritten as 1"
        );
    }

    function _indexOf(bytes32[] memory a, bytes32 x) internal pure returns (uint256) {
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i] == x) return i;
        }
        revert("not found");
    }

    // -------------------------------------------------------------------------------------------- K = 64 seals

    function test_k64_sealUniform() public {
        _sealK64(99);
    }

    function test_k64_sealOneBucket() public {
        _sealK64(5);
    }

    function _sealK64(uint256 bkt) internal {
        World memory w = deploy(64, 16, QMAX);
        fund(w, 1e6);
        fill(w, 63, bkt);
        bytes32 last = nextEta(w, bkt);
        vm.recordLogs();
        w.v.redeem(verdict(w, last, 0, RECIPIENT, 1), last, 0, "");
        mirrorPaid(w, last);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        assertEq(logs[0].topics[0], TOPIC_PAID);
        assertEq(logs[1].topics[0], TOPIC_SEALED);
        assertEq(logs[1].topics[1], bytes32(0));
        bytes memory ids;
        for (uint256 i = 0; i < 64; i++) {
            ids = bytes.concat(ids, w.segs[0][i]);
        }
        assertEq(
            logs[1].data,
            abi.encode(w.heads[0], w.heads[1], ids),
            "sorted identifiers and both heads"
        );
        assertEq(logs[1].data.length, 128 + 32 * 64);
        checkState(w);
        // every identifier of the segment is refused through the sealed segment, a fresh one passes
        (bool paid,) = history(w, w.segs[0][17], 0, 1);
        assertTrue(paid);
        bytes32 fresh = nextEta(w, bkt);
        (, bytes memory h) = history(w, fresh, 0, 1);
        assertEq(h.length, 32 + 65 + 32 * 6, "257-byte proof at K = 64");
        _redeemOk(w, fresh, 0, h);
    }

    // -------------------------------------------------------------------------------------------- storage-write bound

    /// Section 9: a full cycle of two segments writes exactly 2K + 5 distinct words (A, both heads, both tag words, 2K
    /// identifiers); an ordinary payment writes 3, a sealing payment 4, a deposit 1; after the first two segments no call
    /// writes a new word.
    function test_storageWriteBound() public {
        _writeBound(4, 2);
        _writeBound(8, 4);
        _writeBound(64, 16);
    }

    function _writeBound(uint256 k, uint256 b) internal {
        World memory w = deploy(k, b, QMAX);
        address v = address(w.v);
        vm.deal(address(this), 1000);
        vm.record();
        w.v.deposit{value: 1000}(owner(), 0);
        (, bytes32[] memory wr) = vm.accesses(v);
        assertEq(_distinct(wr).length, 1, "deposit writes A only");
        bytes32[] memory all = new bytes32[](0);
        for (uint256 i = 0; i < 2 * k; i++) {
            vm.record();
            bytes32 eta = nextEta(w, 99);
            w.v.redeem(verdict(w, eta, w.c, RECIPIENT, 1), eta, uint64(w.c), "");
            (, wr) = vm.accesses(v);
            bytes32[] memory d = _distinct(wr);
            assertEq(d.length, (i + 1) % k == 0 ? 4 : 3, "writes per payment");
            all = _union(all, d);
            mirrorPaid(w, eta);
        }
        assertEq(all.length, 2 * k + 5, "distinct words of a two-segment cycle");
        for (uint256 i = 0; i < 2 * k; i++) {
            vm.record();
            bytes32 eta = nextEta(w, 99);
            w.v.redeem(verdict(w, eta, w.c, RECIPIENT, 1), eta, uint64(w.c), "");
            (, wr) = vm.accesses(v);
            assertEq(
                _union(all, _distinct(wr)).length, all.length, "no new word after two segments"
            );
            mirrorPaid(w, eta);
        }
    }

    function _distinct(bytes32[] memory a) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](0);
        return _union(out, a);
    }

    function _union(bytes32[] memory a, bytes32[] memory b)
        internal
        pure
        returns (bytes32[] memory out)
    {
        out = a;
        for (uint256 i = 0; i < b.length; i++) {
            bool seen = false;
            for (uint256 j = 0; j < out.length; j++) {
                if (out[j] == b[i]) {
                    seen = true;
                    break;
                }
            }
            if (!seen) out = push(out, b[i]);
        }
    }

    // -------------------------------------------------------------------------------------------- views

    function test_views() public {
        World memory w = deploy(8, 4, QMAX);
        assertEq(
            keccak256(w.v.config()),
            keccak256(encodeGamma(fields(address(w.v), address(w.mock), 8, 4, QMAX)))
        );
        (uint64 n, uint64 c, uint16 m, uint256 q, bytes32 h, bytes32 ph) = w.v.state();
        assertEq(n, 0);
        assertEq(c, 0);
        assertEq(m, 0);
        assertEq(q, 0);
        assertEq(h, NB2Ref.genesis(w.d, 8));
        assertEq(ph, bytes32(0), "previousHead is zero at c = 0");
        fund(w, 100);
        fill(w, 11, 99);
        checkState(w);
    }
}
