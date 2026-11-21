// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {NativeBridgeVault11} from "../../../src/nb2/NativeBridgeVault11.sol";
import {NB2VaultBase} from "../../../src/nb2/NB2VaultBase.sol";
import {EchoVerifierV2, NB2Ref} from "../NB2TestBase.sol";
import {FlatHarness} from "../flat/FlatHarness.sol";
import {CorpusVault11} from "./NB2Settle.t.sol";

/// @notice Custody through a real funded flow (no storage injection): deposits, ordinary payments rotating the segments, and
///         the certified T1 receipt for the target eta presented through the cold route. The target is actually paid, then
///         rotated out of both live buffers; only the sealed archive can then prevent a second debit.
contract NB2SettleHistoryTest is FlatHarness {
    address private constant VAULT = address(0xf200);
    address private constant VERIFIER = address(0xf203);
    address private constant RECIPIENT = 0x96f21e5603aff0A874383f28d66b2f68e6B51e2d;
    bytes32 private constant ASSET =
        0x87b0b8b600fcd942cc3383bac1dbb80fd69d54af700cf48faa4525451a7b1845;
    /// The eta of the published Complete and Gap events (signed start a = 7).
    bytes32 private constant TARGET =
        0xf705f24c68a7b77536b2406ea51c1cce7805cc872a47d5b899532348e0241eea;
    uint256 private constant K = 64;
    uint256 private constant LOW = (1 << 252) - 1;
    string private constant COMPLETE =
        "test/nb2/flat/generated/transcripts/cold/settle-kind1-suffixfalse-prevfalse/calldata.bin";
    string private constant GAP =
        "test/nb2/flat/generated/transcripts/cold/settle-kind2-suffixfalse-prevtrue/calldata.bin";

    NativeBridgeVault11 private vault;
    bytes32 private d;
    // The test's mirror of what the vault has paid, built only from the payments made.
    uint256 private c;
    bytes32[] private cur;
    bytes32[][] private segs;
    bytes32[] private heads;
    uint256 private counter;
    bool private low;

    function setUp() public override {
        super.setUp();
        vm.etch(address(0xf201), address(receipts).code);
        vm.etch(VERIFIER, hex"600000");
        bytes32 profile = sha256(vm.readFileBinary(string.concat(DIR, "semantic-profile.bin")));
        deployCodeTo(
            "NB2Settle.t.sol:CorpusVault11",
            abi.encode(gamma, RECOVERY, keccak256(hex"600300"), profile),
            VAULT
        );
        vault = NativeBridgeVault11(payable(VAULT));
        vm.etch(VERIFIER, type(EchoVerifierV2).runtimeCode);
        d = vault.domain();
        heads.push(NB2Ref.genesis(d, K));
        _loadTrust(_path("root"));
        // Fund the vault through the deposit entry point.
        vm.deal(address(this), 10_000_000);
        bytes memory owner =
            bytes.concat(hex"d99878830141015821", hex"02", bytes32(uint256(0x1234)));
        vault.deposit{value: 10_000_000}(owner, bytes32(uint256(5)));
    }

    // ------------------------------------------------------------------------------------------------ real flow

    function _id() private returns (bytes32 id) {
        id = keccak256(abi.encode("background", counter++));
        if (low) id = bytes32(uint256(id) & LOW); // every identifier below the target: the wraparound gap
    }

    function _pay(bytes32 eta) private {
        vault.redeem(
            abi.encode(d, eta, uint64(c), ASSET, RECIPIENT, uint256(100)), eta, uint64(c), ""
        );
        cur.push(eta);
        if (cur.length == K) {
            segs.push(NB2Ref.sorted(cur));
            heads.push(NB2Ref.step(d, c, heads[c], NB2Ref.root(segs[c])));
            ++c;
            delete cur;
        }
    }

    function _payMany(uint256 n) private {
        for (uint256 i; i < n; ++i) {
            _pay(_id());
        }
    }

    function _checkMirror() private view {
        (, uint64 sc, uint16 m,, bytes32 head,) = vault.state();
        assertEq(sc, c);
        assertEq(m, cur.length);
        assertEq(head, heads[c], "the mirrored head chain is the vault's");
    }

    function _digest() private view returns (bytes32 h) {
        (uint64 n, uint64 sc, uint16 m, uint256 q, bytes32 head, bytes32 prev) = vault.state();
        h = keccak256(abi.encode(n, sc, m, q, head, prev, VAULT.balance, RECIPIENT.balance));
        for (uint256 s = 3; s < 16 + 2 * K; ++s) {
            h = keccak256(abi.encode(h, vm.load(VAULT, bytes32(s))));
        }
    }

    // ------------------------------------------------------------------------------------------------ calls

    function _gaps(bytes32 eta, uint256 from, uint256 to)
        private
        view
        returns (bool paid, bytes memory p)
    {
        for (uint256 j = from; j < to; ++j) {
            (bool hit, bytes memory one) = NB2Ref.proof(segs[j], eta);
            if (hit) {
                // No exclusion proof exists for a paid identifier: present the closest bytes, an invalid proof.
                paid = true;
                one = new bytes(65 + 6 * 32);
            }
            p = bytes.concat(p, one);
        }
    }

    /// The published Complete receipt (a = 7) with this suffix; the start head is the vault's own archive head H_7.
    function _cold(uint256 count, bytes memory gaps) private view returns (bytes memory) {
        bytes memory base = vm.readFileBinary(COMPLETE);
        uint256 prefix = 47 + uint32(bytes4(_word(base, 68 + 43)));
        bytes memory body = new bytes(prefix);
        for (uint256 i; i < prefix; ++i) {
            body[i] = base[68 + i];
        }
        body = bytes.concat(
            body, bytes2(uint16(count)), count == 0 ? bytes("") : bytes.concat(heads[7]), gaps
        );
        return bytes.concat(
            bytes4(keccak256("redeemRecovered(bytes)")),
            bytes32(uint256(32)),
            bytes32(body.length),
            body,
            new bytes((32 - body.length % 32) % 32)
        );
    }

    function _ordinary(bytes32 eta, uint256 start, bytes memory history)
        private
        view
        returns (bytes memory)
    {
        return abi.encodeWithSignature(
            "redeem(bytes,bytes32,uint64,bytes)",
            abi.encode(d, eta, uint64(start), ASSET, RECIPIENT, uint256(100)),
            eta,
            uint64(start),
            history
        );
    }

    function _history(uint256 from, bytes memory gaps) private view returns (bytes memory) {
        return bytes.concat(heads[from], gaps);
    }

    // ------------------------------------------------------------------------------------------------ the target is paid

    function _toSegmentSeven() private {
        low = true;
        _payMany(7 * K);
        _checkMirror();
        assertEq(c, 7);
    }

    function testPaidTargetRotatedOutOfBothBuffersCannotBeDebitedAgain() external {
        vm.pauseGasMetering();
        _toSegmentSeven();
        // The ordinary route pays the target in segment 7 (signed start 7), then the history rotates twice.
        _pay(TARGET);
        assertEq(RECIPIENT.balance, 7 * K * 100 + 100);
        _payMany(K - 1); // seals segment 7, which holds the target
        _payMany(K); // seals segment 8
        _payMany(1);
        _checkMirror();
        assertEq(c, 9);
        // Neither live buffer holds the target any more.
        for (uint256 i; i < cur.length; ++i) {
            assertTrue(cur[i] != TARGET);
        }
        for (uint256 i; i < segs[8].length; ++i) {
            assertTrue(segs[8][i] != TARGET);
        }
        bool inSeven;
        for (uint256 i; i < segs[7].length; ++i) {
            inSeven = inSeven || segs[7][i] == TARGET;
        }
        assertTrue(inSeven, "the target is in the sealed archive");

        bytes32 before_ = _digest();
        // Cold, e = c: honest proofs for segments 7 and 8 exist only for the unpaid one.
        (bool paid, bytes memory gaps) = _gaps(TARGET, 7, 9);
        assertTrue(paid);
        (bool ok, bytes memory out) = VAULT.call(_cold(2, gaps));
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.BadGapProof.selector, 0));
        // Cold, e = c - 1.
        (, gaps) = _gaps(TARGET, 7, 8);
        (ok, out) = VAULT.call(_cold(1, gaps));
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.BadGapProof.selector, 0));
        // The ordinary route with the same archive evidence.
        (, gaps) = _gaps(TARGET, 7, 9);
        (ok, out) = VAULT.call(_ordinary(TARGET, 7, _history(7, gaps)));
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.BadGapProof.selector, 0));
        // Skipping the archive is not possible either: a is signed, so a zero suffix is a stale endpoint; a Gap receipt
        // carries the heads of its own chain and cannot reach this vault's stored head.
        (ok, out) = VAULT.call(_cold(0, ""));
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.StaleEndpoint.selector);
        (ok, out) = VAULT.call(vm.readFileBinary(GAP));
        assertFalse(ok);
        assertEq(bytes4(out), NB2VaultBase.ChainMismatch.selector);
        assertEq(
            _digest(),
            before_,
            "balances, Q, nonce, heads, buffers and logs unchanged by every refusal"
        );
        (uint64 n,,, uint256 q,,) = vault.state();
        assertEq(n, 1);
        assertEq(
            q,
            10_000_000 - (7 * K + 1 + (K - 1) + K + 1) * 100,
            "Q is the deposit less exactly the payments made"
        );
    }

    // ------------------------------------------------------------------------------------------------ unpaid controls

    function _controlSettlesThroughTheColdRoute(bool wrap) internal {
        vm.pauseGasMetering();
        low = wrap;
        _payMany(7 * K);
        _payMany(2 * K + 1); // segments 7 and 8 sealed, none containing the target
        _checkMirror();
        assertEq(c, 9);
        (bool paid, bytes memory gaps) = _gaps(TARGET, 7, 9);
        assertFalse(paid);
        if (wrap) {
            // Every identifier is below the target: the proof is the wraparound pair (index K - 1).
            assertEq(uint8(gaps[0]), K - 1);
        }
        uint256 balance = RECIPIENT.balance;
        (,,, uint256 q0,,) = vault.state();
        vm.recordLogs();
        (bool ok, bytes memory out) = VAULT.call(_cold(2, gaps));
        assertTrue(ok, vm.toString(out));
        assertEq(RECIPIENT.balance, balance + 100);
        (,,, uint256 q1,,) = vault.state();
        assertEq(q1, q0 - 100);
        cur.push(TARGET);
        _checkMirror();
        // The same receipt cannot pay again while the target is live, nor through the ordinary route.
        bytes32 before_ = _digest();
        (ok, out) = VAULT.call(_cold(2, gaps));
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.AlreadyPaid.selector, TARGET));
        (ok, out) = VAULT.call(_ordinary(TARGET, 7, _history(7, gaps)));
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.AlreadyPaid.selector, TARGET));
        assertEq(_digest(), before_);
        // Rotate the now-paid target out of both live buffers: the archive refuses its second debit, with position 2 (the
        // segment that holds it) in the history of either route.
        _payMany(K - 1); // seals segment 9
        _payMany(K); // seals segment 10
        _payMany(1);
        assertEq(c, 11);
        before_ = _digest();
        (paid, gaps) = _gaps(TARGET, 7, 11);
        assertTrue(paid);
        (ok, out) = VAULT.call(_cold(4, gaps));
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.BadGapProof.selector, 2));
        (ok, out) = VAULT.call(_ordinary(TARGET, 7, _history(7, gaps)));
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(NB2VaultBase.BadGapProof.selector, 2));
        assertEq(_digest(), before_, "no second debit");
    }

    function testUnpaidTargetSettlesThroughTheWraparoundGap() external {
        _controlSettlesThroughTheColdRoute(true);
    }

    function testUnpaidTargetSettlesThroughARegularGap() external {
        _controlSettlesThroughTheColdRoute(false);
    }
}
