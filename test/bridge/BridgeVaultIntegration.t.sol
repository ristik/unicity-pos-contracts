// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BridgeBase} from "./BridgeBase.sol";
import {BridgeVault} from "../../src/bridge/BridgeVault.sol";
import {TokenVerifier} from "../../src/bridge/TokenVerifier.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {BridgeProfile} from "../../src/bridge/BridgeProfile.sol";
import {Deployment, KernelResult} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice Vault + real `TokenVerifier` end to end. The 0x0104 kernel and the 0x0105 composition are TEST DOUBLES
///         (`vm.mockCall` over reverting code), here answering by default; the exact request bytes are pinned in
///         `TokenVerifier.t.sol`. These tests show the wiring: what the vault passes, what bubbles up, and that verification
///         alone moves no state.
contract BridgeVaultIntegrationTest is BridgeBase {
    BridgeVault internal vault;
    TokenVerifier internal verifier;

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);

    function setUp() public {
        _loadGolden();
        _etchDoubles();
        verifier = new TokenVerifier();
        vault = _deployVault(keccak256("execution-genesis"));
    }

    function _deployVault(bytes32 executionGenesis) internal returns (BridgeVault) {
        return new BridgeVault(
            Deployment({
                network: 3,
                rootGenesis: keccak256("root-genesis"),
                executionGenesis: executionGenesis,
                evmPartition: 7,
                evmShard: hex"80",
                semanticProfileHash: keccak256("semantic"),
                tokenVerifier: address(verifier),
                tokenVerifierCodeHash: address(verifier).codehash,
                b1ProfileHash: keccak256("b1"),
                policyBody: _policyV2(11)
            })
        );
    }

    // ---- kernel results for this vault ---------------------------------------------------------

    function _digest(uint256 n, uint256 amount) internal pure returns (bytes32) {
        return keccak256(abi.encode("digest", n, amount));
    }

    function _prepare(BridgeVault v, uint256 n, uint256 amount)
        internal
        view
        returns (KernelResult memory r)
    {
        r.cfg = v.CFG();
        r.nonce = n;
        r.amount = amount;
        r.tokenId = keccak256(abi.encode("id", n));
        r.salt = keccak256(abi.encode("salt", n));
        r.firstPredicateHash = keccak256(abi.encode("rcpt", n));
        r.lockDigest = _digest(n, amount);
    }

    function _ret(BridgeVault v, uint256 n, uint256 amount, address to, bytes32 eta)
        internal
        view
        returns (KernelResult memory r)
    {
        r = _prepare(v, n, amount);
        r.releaseTo = to;
        r.nullifier = eta;
        r.leafCount = 3;
    }

    function _mint(BridgeVault v, uint256 n, uint256 amount)
        internal
        view
        returns (KernelResult memory r)
    {
        r = _prepare(v, n, amount);
        r.leafCount = 1;
    }

    function _kernelDefault(KernelResult memory r) internal {
        _progDefault(B1Calls.KERNEL, _kernelOut(true, r));
    }

    /// @dev The composition answers every redemption with `r` (status 0) or with the refusal `status`.
    function _composeDefault(KernelResult memory r) internal {
        _progDefault(B1Calls.COMPOSE, _composeOut(0, r));
    }

    function _composeRefuses(uint256 status) internal {
        KernelResult memory none;
        _progDefault(B1Calls.COMPOSE, _composeOut(status, none));
    }

    function _lock(BridgeVault v, address who, uint256 amount) internal returns (uint256 n) {
        n = v.lastNonce() + 1;
        _kernelDefault(_prepare(v, n, amount));
        vm.deal(who, who.balance + amount);
        vm.expectCall(
            B1Calls.KERNEL,
            _kernelInput(0, v.cfgBytes(), BridgeProfile.preparePayload(n, amount, hex"d9aabb"))
        );
        vm.prank(who);
        assertEq(v.lock{value: amount}(hex"d9aabb"), n);
    }

    /// @dev A proof for the vault's policy: golden policy body, anchors and three leaf paths (opaque to the contract).
    function _proof(bytes memory history) internal view returns (bytes memory) {
        return
            abi.encode(
                _policyV2(11), history, _goldenAnchors("return"), _goldenLeafProofs("return")
            );
    }

    function _mintProof(bytes memory history) internal view returns (bytes memory) {
        return abi.encode(_policyV2(11), history, _goldenAnchors("mint"), _goldenLeafProofs("mint"));
    }

    // ---------------------------------------------------------------------------------------------

    function test_roundTrip_lockMintRedeemClaim() public {
        uint256 n = _lock(vault, ALICE, 5 ether);
        // verifyMint is a view: it checks the lock exists and is unspent
        _composeDefault(_mint(vault, n, 5 ether));
        assertEq(vault.verifyMint(_mintProof("mint-history")), n);
        // redeem: the burn's recipient is credited, anyone may submit; one native call carries the whole relation (two redeems
        // below: this one and the refused repeat)
        _composeDefault(_ret(vault, n, 5 ether, BOB, keccak256("eta")));
        vm.expectCall(B1Calls.COMPOSE, _composeInput(2, vault.cfgBytes(), _proof(hex"aabbcc")), 2);
        vault.redeem(_proof(hex"aabbcc"));
        assertEq(vault.claimable(BOB), 5 ether);
        assertEq(vault.spentNullifier(n), keccak256("eta"));
        vm.prank(BOB);
        vault.claim(5 ether, BOB);
        assertEq(BOB.balance, 5 ether);
        assertEq(address(vault).balance, 0);
        // the lock cannot mint or redeem again
        _composeDefault(_mint(vault, n, 5 ether));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, n));
        vault.verifyMint(_mintProof("mint-history"));
        _composeDefault(_ret(vault, n, 5 ether, BOB, keccak256("eta")));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, n));
        vault.redeem(_proof(hex"aabbcc"));
    }

    /// Every native refusal bubbles with its status before any vault state moves: the anchor table not authenticated (61), a
    /// leaf not included (62), an anchor of another partition (22).
    function test_redeem_aNativeRefusalBubblesBeforeAnyStateChange() public {
        uint256 n = _lock(vault, ALICE, 1 ether);
        uint256[3] memory statuses = [uint256(61), 62, 22];
        for (uint256 i = 0; i < 3; ++i) {
            _composeRefuses(statuses[i]);
            vm.expectRevert(abi.encodeWithSelector(BridgeRejected.selector, statuses[i]));
            vault.redeem(_proof(hex"aabbcc"));
            assertEq(vault.credited(), 0);
            assertEq(vault.spentNullifier(n), bytes32(0));
            assertEq(vault.claimable(BOB), 0);
        }
    }

    /// A halted composition (out of gas, malformed input) is a failure, never a result.
    function test_redeem_aHaltedCompositionIsAFailure() public {
        _lock(vault, ALICE, 1 ether);
        _progDefaultRevert(B1Calls.COMPOSE);
        vm.expectRevert(abi.encodeWithSelector(PrecompileFailed.selector, B1Calls.COMPOSE));
        vault.redeem(_proof(hex"aabbcc"));
        assertEq(vault.credited(), 0);
    }

    function test_redeem_aproofForAnotherVaultsCfgIsRefused() public {
        // A second deployment with another execution genesis has another cfg. The kernel result
        // carrying vault A's cfg is not accepted by vault B: B calls the verifier with its own Cfg.
        BridgeVault other = _deployVault(keccak256("other-execution-genesis"));
        assertTrue(other.CFG() != vault.CFG());
        uint256 n = _lock(vault, ALICE, 1 ether);
        _lock(other, ALICE, 1 ether);
        _composeDefault(_ret(vault, n, 1 ether, BOB, keccak256("eta")));
        vm.expectRevert(
            abi.encodeWithSelector(KernelCfgMismatch.selector, other.CFG(), vault.CFG())
        );
        other.redeem(_proof(hex"aabbcc"));
        assertEq(other.credited(), 0);
    }

    function test_directVerifierCallAuthorizesNothing() public {
        uint256 n = _lock(vault, ALICE, 1 ether);
        KernelResult memory r = _ret(vault, n, 1 ether, BOB, keccak256("eta"));
        _composeDefault(r);
        // Anyone can run the relation against the vault's cfg; it changes no vault state.
        KernelResult memory out = verifier.verifyReturn(vault.cfgBytes(), _proof(hex"aabbcc"));
        assertEq(out.nonce, n);
        assertEq(vault.credited(), 0);
        assertEq(vault.claimable(BOB), 0);
        assertEq(vault.spentNullifier(n), bytes32(0));
    }

    function test_redeem_unknownLockAfterAValidRelation() public {
        _lock(vault, ALICE, 1 ether);
        _composeDefault(_ret(vault, 9, 1 ether, BOB, keccak256("eta")));
        vm.expectRevert(abi.encodeWithSelector(UnknownLock.selector, 9));
        vault.redeem(_proof(hex"aabbcc"));
    }

    function test_redeem_digestOfADifferentLockAmount() public {
        uint256 n = _lock(vault, ALICE, 1 ether);
        _composeDefault(_ret(vault, n, 2 ether, BOB, keccak256("eta"))); // digest binds the amount
        vm.expectRevert(abi.encodeWithSelector(LockDigestMismatch.selector, n));
        vault.redeem(_proof(hex"aabbcc"));
    }

    function test_lock_kernelRejectionBubbles() public {
        vm.deal(ALICE, 1 ether);
        _progDefault(B1Calls.KERNEL, _b(".invalidOutput"));
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(KernelRejected.selector));
        vault.lock{value: 1 ether}(hex"d9aabb");
        assertEq(vault.lastNonce(), 0);
        assertEq(address(vault).balance, 0);
    }

    function test_lock_inactiveKernelRefusesEveryLock() public {
        vm.etch(B1Calls.KERNEL, "");
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(KernelBadOutput.selector));
        vault.lock{value: 1 ether}(hex"d9aabb");
    }

    function test_lock_mismatchedKernelResultIsRefusedByTheVerifier() public {
        // The kernel answers for another amount: the verifier's cfg check passes, the vault's amount check fails.
        _kernelDefault(_prepare(vault, 1, 2 ether));
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(KernelAmountMismatch.selector, 1 ether, 2 ether));
        vault.lock{value: 1 ether}(hex"d9aabb");
    }

    // ---- the same state IDs proved before and after a topology change ----------------------------

    /// @notice "Re-proving a state after a topology change creates no second spend", at the vault: two different proofs of one
    ///         return (under the parent shard, and under its children; the composition proves either natively, ureth
    ///         `reth-unicity-bridge`) give the same relation result, so the same burn nullifier; the vault credits one of them,
    ///         stores that one nullifier against the nonce, and refuses the other, in either order.
    function test_topologyChange_sameResultKeepsOneNullifierAndOneRelease() public {
        bytes memory before_ = abi.encode(_policyV2(11), hex"aabbcc", "parent-shard anchors");
        bytes memory after_ = abi.encode(_policyV2(11), hex"aabbcc", "child-shard anchors");
        uint256 n = _lock(vault, ALICE, 5 ether);
        _composeDefault(_ret(vault, n, 5 ether, BOB, keccak256("eta-topology")));
        KernelResult memory rb = verifier.verifyReturn(vault.cfgBytes(), before_);
        KernelResult memory ra = verifier.verifyReturn(vault.cfgBytes(), after_);
        assertEq(rb.nullifier, ra.nullifier, "one nullifier");
        vault.redeem(after_);
        assertEq(vault.spentNullifier(n), keccak256("eta-topology"));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, n));
        vault.redeem(before_);
        assertEq(vault.claimable(BOB), 5 ether, "credited once");
        uint256 m = _lock(vault, ALICE, 5 ether);
        _composeDefault(_ret(vault, m, 5 ether, BOB, keccak256("eta-topology")));
        vault.redeem(before_);
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, m));
        vault.redeem(after_);
        assertEq(vault.claimable(BOB), 10 ether, "two locks, one credit each");
    }
}
