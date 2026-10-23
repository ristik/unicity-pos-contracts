// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {VaultHarness} from "./VaultHarness.sol";
import {BridgeVault} from "../../src/bridge/BridgeVault.sol";
import {KernelResult} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice Split redemption (protocol 6): one lock, redeemed in whole parts. The verifier is a TEST DOUBLE returning the result
///         the native composition would (root identity plus the redeemed part); the real verifier's parsing of the oracle's
///         bytes is `SplitVerifier.t.sol`.
contract BridgeVaultSplitTest is VaultHarness {
    event RedemptionCredited(
        uint256 indexed nonce,
        bytes32 indexed partId,
        address indexed recipient,
        bytes32 nullifier,
        uint256 amount,
        uint256 remaining
    );

    bytes32 internal constant X = keccak256("part-x");
    bytes32 internal constant Y = keccak256("part-y");
    bytes32 internal constant Z = keccak256("part-z");

    function setUp() public {
        _setUpVault();
    }

    function _setPart(uint256 n, uint256 lockAmt, bytes32 id, uint256 amt, address to, bytes32 eta)
        internal
    {
        vd.setReturn(_partResult(n, lockAmt, id, amt, 1, to, eta));
    }

    function _redeemPart(
        uint256 n,
        uint256 lockAmt,
        bytes32 id,
        uint256 amt,
        address to,
        bytes32 eta
    ) internal {
        vd.setReturn(_partResult(n, lockAmt, id, amt, 1, to, eta));
        vault.redeem("");
    }

    /// 100 locked, split 40 + 60: each sibling redeems once, independently, and together exactly the lock.
    function test_siblingsRedeemIndependentlyAndCompleteTheLock() public {
        _lock(ALICE, 100 ether);
        assertEq(vault.lockedAmount(1), 100 ether);
        _setPart(1, 100 ether, X, 40 ether, BOB, _eta(1, 0));
        vm.expectEmit(true, true, true, true, address(vault));
        emit RedemptionCredited(1, X, BOB, _eta(1, 0), 40 ether, 60 ether);
        vault.redeem("");
        assertEq(vault.redeemedAmount(1), 40 ether);
        assertEq(vault.remaining(1), 60 ether);
        assertFalse(vault.lockComplete(1), "one sibling does not close the lock");
        assertEq(vault.spentPart(1, X), _eta(1, 0));
        assertEq(vault.spentPart(1, Y), bytes32(0));
        assertEq(vault.claimable(BOB), 40 ether);

        _setPart(1, 100 ether, Y, 60 ether, CAROL, _eta(1, 1));
        vm.expectEmit(true, true, true, true, address(vault));
        emit RedemptionCredited(1, Y, CAROL, _eta(1, 1), 60 ether, 0);
        vault.redeem("");
        assertTrue(vault.lockComplete(1));
        assertEq(vault.remaining(1), 0);
        assertEq(vault.credited(), 100 ether);
        assertEq(vault.outstanding(), 0);
        assertEq(vault.claimable(CAROL), 60 ether);
        assertEq(address(vault).balance, 100 ether, "redeem pays nothing");
    }

    /// The same part is paid once, whatever burn, recipient, depth or witnesses it is presented with.
    function test_aPartIsPaidOnce() public {
        _lock(ALICE, 100 ether);
        _redeemPart(1, 100 ether, X, 40 ether, BOB, _eta(1, 0));
        _setPart(1, 100 ether, X, 40 ether, BOB, _eta(1, 0));
        vm.expectRevert(abi.encodeWithSelector(PartAlreadyRedeemed.selector, 1, X));
        vault.redeem("");
        _setPart(1, 100 ether, X, 40 ether, CAROL, _eta(1, 9));
        vm.expectRevert(abi.encodeWithSelector(PartAlreadyRedeemed.selector, 1, X));
        vault.redeem("");
        vd.setReturn(_partResult(1, 100 ether, X, 40 ether, 5, BOB, _eta(1, 0))); // another lineage depth
        vm.expectRevert(abi.encodeWithSelector(PartAlreadyRedeemed.selector, 1, X));
        vault.redeem(hex"01");
        assertEq(vault.spentPart(1, X), _eta(1, 0), "the first nullifier stays");
        assertEq(vault.credited(), 40 ether);
        assertEq(vault.claimable(CAROL), 0);
    }

    /// A part never takes more than the lock has left: the parent's whole return after a child was paid, an inflated part,
    /// and any part of a complete lock.
    function test_aPartNeverExceedsWhatTheLockHasLeft() public {
        _lock(ALICE, 100 ether);
        _redeemPart(1, 100 ether, X, 40 ether, BOB, _eta(1, 0));
        // the root itself (depth 0) after a part was paid: 100 > 60 left
        vd.setReturn(_returnResult(1, 100 ether, CAROL, _eta(1, 1)));
        vm.expectRevert(
            abi.encodeWithSelector(PartExceedsRemaining.selector, 1, 60 ether, 100 ether)
        );
        vault.redeem("");
        _setPart(1, 100 ether, Y, 61 ether, CAROL, _eta(1, 2));
        vm.expectRevert(
            abi.encodeWithSelector(PartExceedsRemaining.selector, 1, 60 ether, 61 ether)
        );
        vault.redeem("");
        _redeemPart(1, 100 ether, Y, 60 ether, CAROL, _eta(1, 3));
        _setPart(1, 100 ether, Z, 1, CAROL, _eta(1, 4));
        vm.expectRevert(abi.encodeWithSelector(PartExceedsRemaining.selector, 1, 0, 1));
        vault.redeem("");
        assertEq(vault.credited(), 100 ether);
    }

    /// The lock's identity is the root's: its stored amount and digest, never a part's.
    function test_theRootIdentityMustMatchTheLock() public {
        _lock(ALICE, 100 ether);
        // the root amount of the result is the part's (a kernel that forgot the root): refused by the digest first
        KernelResult memory r = _partResult(1, 40 ether, X, 40 ether, 1, BOB, _eta(1, 0));
        vd.setReturn(r);
        vm.expectRevert(abi.encodeWithSelector(LockDigestMismatch.selector, 1));
        vault.redeem("");
        // the real digest with a part amount as the root amount
        r.lockDigest = vault.lockDigest(1);
        vd.setReturn(r);
        vm.expectRevert(
            abi.encodeWithSelector(KernelRootAmountMismatch.selector, 100 ether, 40 ether)
        );
        vault.redeem("");
        // another lock's digest
        _lock(ALICE, 100 ether);
        r = _partResult(1, 100 ether, X, 40 ether, 1, BOB, _eta(1, 0));
        r.lockDigest = vault.lockDigest(2);
        vd.setReturn(r);
        vm.expectRevert(abi.encodeWithSelector(LockDigestMismatch.selector, 1));
        vault.redeem("");
    }

    function test_zeroPartIsRefused() public {
        _lock(ALICE, 10 ether);
        KernelResult memory r = _partResult(1, 10 ether, X, 0, 1, BOB, _eta(1, 0));
        vd.setReturn(r);
        vm.expectRevert(abi.encodeWithSelector(ZeroAmount.selector));
        vault.redeem("");
        r = _partResult(1, 10 ether, bytes32(0), 5 ether, 1, BOB, _eta(1, 0));
        vd.setReturn(r);
        vm.expectRevert(abi.encodeWithSelector(ZeroAmount.selector));
        vault.redeem("");
    }

    /// Parts of different locks are independent even if a part ID were to repeat across locks.
    function test_partIdsAreScopedToTheirLock() public {
        _lock(ALICE, 10 ether);
        _lock(ALICE, 10 ether);
        _redeemPart(1, 10 ether, X, 10 ether, BOB, _eta(1, 0));
        _redeemPart(2, 10 ether, X, 10 ether, BOB, _eta(2, 0));
        assertEq(vault.credited(), 20 ether);
    }

    /// The mint view stays valid while any of the lock is unredeemed and closes with the last part.
    function test_mintViewClosesWhenTheLockIsComplete() public {
        _lock(ALICE, 100 ether);
        vd.setMint(_prepareResult(1, 100 ether));
        assertEq(vault.verifyMint(""), 1);
        _redeemPart(1, 100 ether, X, 40 ether, BOB, _eta(1, 0));
        assertEq(vault.verifyMint(""), 1, "a partly redeemed lock still has a valid mint");
        _redeemPart(1, 100 ether, Y, 60 ether, BOB, _eta(1, 1));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, 1));
        vault.verifyMint("");
    }

    /// Credit is claimable part by part; paid never exceeds credited.
    function test_claimsFollowTheCreditedParts() public {
        _lock(ALICE, 100 ether);
        _redeemPart(1, 100 ether, X, 40 ether, BOB, _eta(1, 0));
        vm.prank(BOB);
        vault.claim(25 ether, BOB);
        assertEq(vault.paid(), 25 ether);
        assertEq(vault.pendingClaims(), 15 ether);
        _redeemPart(1, 100 ether, Y, 60 ether, BOB, _eta(1, 1));
        vm.prank(BOB);
        vault.claim(75 ether, BOB);
        assertEq(vault.paid(), 100 ether);
        assertLe(vault.paid(), vault.credited());
        assertLe(vault.credited(), vault.locked());
        assertEq(address(vault).balance, 0);
    }

    /// Any partition of a lock into parts redeems to exactly the lock, in any order, and nothing more.
    function testFuzz_anyPartitionRedeemsExactlyTheLock(uint96 lockAmount, uint256 seed) public {
        uint256 total = bound(uint256(lockAmount), 2, 1_000_000 ether);
        _lock(ALICE, total);
        uint256 left = total;
        uint256 i;
        while (left > 0) {
            uint256 part = i >= 7 ? left : bound(uint256(keccak256(abi.encode(seed, i))), 1, left);
            vd.setReturn(
                _partResult(
                    1, total, keccak256(abi.encode("p", i)), part, 1 + (i % 4), BOB, _eta(1, i)
                )
            );
            vault.redeem("");
            left -= part;
            ++i;
            assertEq(vault.remaining(1), left);
            assertEq(vault.credited(), total - left);
        }
        assertTrue(vault.lockComplete(1));
        vd.setReturn(_partResult(1, total, keccak256("extra"), 1, 1, BOB, _eta(1, 99)));
        vm.expectRevert(abi.encodeWithSelector(PartExceedsRemaining.selector, 1, 0, 1));
        vault.redeem("");
        assertEq(vault.credited(), vault.locked());
    }
}
