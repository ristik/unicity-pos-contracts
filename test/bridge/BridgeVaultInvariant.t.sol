// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {VaultHarness, Payee} from "./VaultHarness.sol";
import {BridgeVault} from "../../src/bridge/BridgeVault.sol";
import {KernelResult} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice Drives the vault with random locks, redemptions (including replays, conflicting burns,
///         wrong amounts and unknown nonces), claims (to EOAs, to a reverting payee and to a reentrant
///         payee), donations and forced value, and checks the accounting identities after every step.
///         The verifier is a TEST DOUBLE; every expected refusal is matched by selector, so a handler
///         step that refuses for another reason fails the run (`fail_on_revert` is on and unexpected
///         outcomes assert).
contract VaultHandler is VaultHarness {
    address[] internal users;
    Payee[] internal payees;
    address[] public recipients; // every address that can hold credit

    mapping(uint256 => uint256) public lockAmount;
    mapping(uint256 => bytes32) public firstEta;
    mapping(uint256 => bool) public redeemed;

    uint256 public ghostLocked;
    uint256 public ghostCredited;
    uint256 public ghostPaid;
    uint256 public ghostExtra;
    uint256 public locks;
    uint256 public okRedeems;
    uint256 public refusedReplays;
    uint256 public okClaims;
    uint256 public failedPayouts;

    constructor() {
        _setUpVault();
        users.push(ALICE);
        users.push(BOB);
        users.push(CAROL);
        recipients.push(ALICE);
        recipients.push(BOB);
        recipients.push(CAROL);
        Payee.Mode[3] memory modes =
            [Payee.Mode.Accept, Payee.Mode.Revert, Payee.Mode.ReenterSwallow];
        for (uint256 i = 0; i < 3; ++i) {
            Payee p = new Payee();
            p.set(vault, modes[i]);
            payees.push(p);
            recipients.push(address(p));
        }
    }

    function getVault() external view returns (BridgeVault) {
        return vault;
    }

    function recipientCount() external view returns (uint256) {
        return recipients.length;
    }

    function lock(uint256 amountSeed, uint256 userSeed) external {
        uint256 amount = bound(amountSeed, 1, 100 ether);
        address who = users[userSeed % users.length];
        uint256 n = vault.lastNonce() + 1;
        vd.setPrepare(_prepareResult(n, amount));
        vm.deal(who, who.balance + amount);
        vm.prank(who);
        vault.lock{value: amount}(hex"d9");
        lockAmount[n] = amount;
        ghostLocked += amount;
        ++locks;
    }

    function redeem(uint256 nSeed, uint256 recSeed, uint256 etaSeed) external {
        uint256 last = vault.lastNonce();
        if (last == 0) return;
        uint256 n = bound(nSeed, 1, last);
        address to = recipients[recSeed % recipients.length];
        bytes32 eta = keccak256(abi.encode(etaSeed)) | bytes32(uint256(1));
        vd.setReturn(_returnResult(n, lockAmount[n], to, eta));
        (bool ok, bytes memory err) =
            address(vault).call(abi.encodeCall(BridgeVault.redeem, (hex"")));
        if (redeemed[n]) {
            assertFalse(ok, "replay accepted");
            assertEq(bytes4(err), AlreadyRedeemed.selector, "replay refused for another reason");
            ++refusedReplays;
        } else {
            assertTrue(ok, "first redemption refused");
            redeemed[n] = true;
            firstEta[n] = eta;
            ghostCredited += lockAmount[n];
            ++okRedeems;
        }
    }

    function redeemWrongAmount(uint256 nSeed, uint256 deltaSeed) external {
        uint256 last = vault.lastNonce();
        if (last == 0) return;
        uint256 n = bound(nSeed, 1, last);
        uint256 wrong = lockAmount[n] + bound(deltaSeed, 1, 10 ether);
        vd.setReturn(_returnResult(n, wrong, ALICE, _eta(n, 99)));
        (bool ok, bytes memory err) =
            address(vault).call(abi.encodeCall(BridgeVault.redeem, (hex"")));
        assertFalse(ok, "wrong amount accepted");
        // the digest binds the amount, and is checked before the spent word
        assertEq(bytes4(err), LockDigestMismatch.selector);
    }

    function redeemUnknown(uint256 nSeed) external {
        uint256 n = vault.lastNonce() + 1 + bound(nSeed, 0, 1000);
        vd.setReturn(_returnResult(n, 1 ether, ALICE, _eta(n, 1)));
        (bool ok, bytes memory err) =
            address(vault).call(abi.encodeCall(BridgeVault.redeem, (hex"")));
        assertFalse(ok);
        assertEq(bytes4(err), UnknownLock.selector);
    }

    function claim(uint256 recSeed, uint256 amountSeed, uint256 toSeed) external {
        address holder = recipients[recSeed % recipients.length];
        uint256 have = vault.claimable(holder);
        if (have == 0) return;
        uint256 amount = bound(amountSeed, 1, have);
        address to = recipients[toSeed % recipients.length];
        bool isPayee = false;
        for (uint256 i = 0; i < payees.length; ++i) {
            if (address(payees[i]) == holder) isPayee = true;
        }
        bool ok;
        bytes memory err;
        if (isPayee) {
            (ok, err) = holder.call(abi.encodeCall(Payee.claim, (amount, to)));
        } else {
            vm.prank(holder);
            (ok, err) = address(vault).call(abi.encodeCall(BridgeVault.claim, (amount, to)));
        }
        if (ok) {
            ghostPaid += amount;
            ++okClaims;
        } else {
            // the only legitimate refusal here is the payout itself failing, and it restores everything
            assertEq(bytes4(err), PayoutFailed.selector, "claim refused for another reason");
            ++failedPayouts;
        }
    }

    function donate(uint256 amountSeed) external {
        uint256 amount = bound(amountSeed, 1, 10 ether);
        vm.deal(DONOR, amount);
        vm.prank(DONOR);
        (bool ok,) = address(vault).call{value: amount}("");
        assertTrue(ok);
        ghostExtra += amount;
    }

    function force(uint256 amountSeed) external {
        uint256 amount = bound(amountSeed, 1, 10 ether);
        vm.deal(address(vault), address(vault).balance + amount);
        ghostExtra += amount;
    }

    address internal constant DONOR = address(0xD0A);
}

contract BridgeVaultInvariantTest is VaultHarness {
    VaultHandler internal h;
    BridgeVault internal v;

    function setUp() public {
        h = new VaultHandler();
        v = h.getVault();
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](7);
        sel[0] = VaultHandler.lock.selector;
        sel[1] = VaultHandler.redeem.selector;
        sel[2] = VaultHandler.redeemWrongAmount.selector;
        sel[3] = VaultHandler.redeemUnknown.selector;
        sel[4] = VaultHandler.claim.selector;
        sel[5] = VaultHandler.donate.selector;
        sel[6] = VaultHandler.force.selector;
        targetSelector(FuzzSelector({addr: address(h), selectors: sel}));
    }

    function invariant_paidLeCreditedLeLocked() public view {
        assertLe(v.paid(), v.credited());
        assertLe(v.credited(), v.locked());
    }

    function invariant_claimableSumsToCreditedMinusPaid() public view {
        uint256 sum;
        for (uint256 i = 0; i < h.recipientCount(); ++i) {
            sum += v.claimable(h.recipients(i));
        }
        assertEq(sum, v.credited() - v.paid());
        assertEq(sum, v.pendingClaims());
    }

    function invariant_balanceIdentity() public view {
        assertEq(address(v).balance, v.locked() - v.paid() + h.ghostExtra());
        assertEq(v.unexpectedValue(), h.ghostExtra());
        assertEq(v.outstanding(), v.locked() - v.credited());
    }

    function invariant_countersMatchTheGhostModel() public view {
        assertEq(v.locked(), h.ghostLocked());
        assertEq(v.credited(), h.ghostCredited());
        assertEq(v.paid(), h.ghostPaid());
        assertEq(v.lastNonce(), h.locks());
    }

    function invariant_everyNonceIsSpentAtMostOnceWithItsFirstNullifier() public view {
        uint256 last = v.lastNonce();
        uint256 redeemedSum;
        for (uint256 n = 1; n <= last; ++n) {
            if (h.redeemed(n)) {
                assertEq(v.spentNullifier(n), h.firstEta(n));
                redeemedSum += h.lockAmount(n);
            } else {
                assertEq(v.spentNullifier(n), bytes32(0));
            }
            assertTrue(v.lockDigest(n) != bytes32(0), "digest is permanent");
        }
        assertEq(redeemedSum, v.credited(), "credited is exactly the redeemed locks");
    }

    function invariant_guardIsReleased() public view {
        assertEq(uint256(vm.load(address(v), bytes32(uint256(4)))), 0);
    }

    /// @dev A long run exercised what it claims to: redemptions, refused replays, paid claims and
    ///      failed payouts all happened. (Foundry also calls this hook on runs with too few calls.)
    function afterInvariant() public view {
        if (h.locks() < 100) return;
        assertGt(h.okRedeems(), 0, "redemptions");
        assertGt(h.refusedReplays(), 0, "refused replays");
        assertGt(h.okClaims(), 0, "paid claims");
        assertGt(h.failedPayouts(), 0, "failed payouts");
    }
}
