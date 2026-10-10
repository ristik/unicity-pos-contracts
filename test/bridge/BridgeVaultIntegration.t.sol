// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BridgeBase} from "./BridgeBase.sol";
import {BridgeVault} from "../../src/bridge/BridgeVault.sol";
import {TokenVerifier} from "../../src/bridge/TokenVerifier.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {BridgeProfile} from "../../src/bridge/BridgeProfile.sol";
import {Anchor, Deployment, KernelResult, Leaf, LeafProof} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice Vault + real `TokenVerifier` end to end. The B1 precompiles and the 0x0104 kernel are TEST
///         DOUBLES (`vm.mockCall` over reverting code), here answering by default; the exact request bytes are pinned
///         in `TokenVerifier.t.sol`. These tests show the wiring: what the vault passes, what bubbles
///         up, and that verification alone moves no state. They do not close B4.
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
        _progDefault(B1Calls.UC_VERIFIER, TRUE_OUT);
        _progDefault(B1Calls.RSMT_VERIFIER, TRUE_OUT);
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
                policyBody: _b(".policy.bytes")
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
        r.leaves = new Leaf[](0);
    }

    function _ret(BridgeVault v, uint256 n, uint256 amount, address to, bytes32 eta)
        internal
        view
        returns (KernelResult memory r)
    {
        r = _prepare(v, n, amount);
        r.releaseTo = to;
        r.nullifier = eta;
        r.leaves = new Leaf[](3);
        // The golden state IDs: the golden anchors certify exactly these shards.
        KernelResult memory g = _goldenResult(".return.result");
        for (uint256 i = 0; i < 3; ++i) {
            r.leaves[i] = Leaf({
                sid: g.leaves[i].sid,
                txHash: keccak256(abi.encode("tx", n, i)),
                referenceTime: uint64(1_700_000_000 + i),
                leafValue: keccak256(abi.encode("value", n, i))
            });
        }
    }

    function _mint(BridgeVault v, uint256 n, uint256 amount)
        internal
        view
        returns (KernelResult memory r)
    {
        r = _prepare(v, n, amount);
        r.leaves = new Leaf[](1);
        r.leaves[0] = Leaf({
            sid: _goldenResult(".mint.result").leaves[0].sid,
            txHash: keccak256("mint-tx"),
            referenceTime: 1_700_000_000,
            leafValue: keccak256("mint-value")
        });
    }

    function _kernelDefault(KernelResult memory r) internal {
        _progDefault(B1Calls.KERNEL, _kernelOut(true, r));
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

    /// @dev A proof for the vault's policy: golden policy body, anchor and three leaf paths.
    function _proof(bytes memory history) internal view returns (bytes memory) {
        return abi.encode(
            _b(".policy.bytes"), history, _goldenAnchors("return"), _goldenLeafProofs("return")
        );
    }

    function _mintProof(bytes memory history) internal view returns (bytes memory) {
        return
            abi.encode(
                _b(".policy.bytes"), history, _goldenAnchors("mint"), _goldenLeafProofs("mint")
            );
    }

    // ---------------------------------------------------------------------------------------------

    function test_roundTrip_lockMintRedeemClaim() public {
        uint256 n = _lock(vault, ALICE, 5 ether);
        // verifyMint is a view: it checks the lock exists and is unspent
        _kernelDefault(_mint(vault, n, 5 ether));
        assertEq(vault.verifyMint(_mintProof("mint-history")), n);
        // redeem: the burn's recipient is credited, anyone may submit
        _kernelDefault(_ret(vault, n, 5 ether, BOB, keccak256("eta")));
        vm.expectCall(B1Calls.KERNEL, _kernelInput(2, vault.cfgBytes(), hex"aabbcc"), 2);
        vault.redeem(_proof(hex"aabbcc"));
        assertEq(vault.claimable(BOB), 5 ether);
        assertEq(vault.spentNullifier(n), keccak256("eta"));
        vm.prank(BOB);
        vault.claim(5 ether, BOB);
        assertEq(BOB.balance, 5 ether);
        assertEq(address(vault).balance, 0);
        // the lock cannot mint or redeem again
        _kernelDefault(_mint(vault, n, 5 ether));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, n));
        vault.verifyMint(_mintProof("mint-history"));
        _kernelDefault(_ret(vault, n, 5 ether, BOB, keccak256("eta")));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, n));
        vault.redeem(_proof(hex"aabbcc"));
    }

    function test_redeem_everyB1CallRunsBeforeAnyStateChange() public {
        uint256 n = _lock(vault, ALICE, 1 ether);
        _kernelDefault(_ret(vault, n, 1 ether, BOB, keccak256("eta")));
        _progDefault(B1Calls.UC_VERIFIER, FALSE_OUT);
        vm.expectRevert(abi.encodeWithSelector(UCRejected.selector));
        vault.redeem(_proof(hex"aabbcc"));
        assertEq(vault.credited(), 0);
        assertEq(vault.spentNullifier(n), bytes32(0));
        assertEq(vault.claimable(BOB), 0);
    }

    function test_redeem_leafNotIncludedBubblesFromTheVerifier() public {
        uint256 n = _lock(vault, ALICE, 1 ether);
        KernelResult memory r = _ret(vault, n, 1 ether, BOB, keccak256("eta"));
        _kernelDefault(r);
        LeafProof memory p = _goldenLeafProofs("return")[1];
        bytes memory req = _expectedRSMT(
            _goldenAnchors("return")[p.anchorIndex].expectedStateRoot,
            r.leaves[1].sid,
            r.leaves[1].leafValue,
            p
        );
        _prog(B1Calls.RSMT_VERIFIER, req, FALSE_OUT);
        vm.expectRevert(abi.encodeWithSelector(LeafNotIncluded.selector, 1));
        vault.redeem(_proof(hex"aabbcc"));
        assertEq(vault.credited(), 0);
    }

    function test_redeem_policyOfAnotherPartitionIsRefused() public {
        uint256 n = _lock(vault, ALICE, 1 ether);
        _kernelDefault(_ret(vault, n, 1 ether, BOB, keccak256("eta")));
        Anchor[] memory a = _goldenAnchors("return");
        a[0].partition = 12;
        bytes memory proof =
            abi.encode(_b(".policy.bytes"), hex"aabbcc", a, _goldenLeafProofs("return"));
        vm.expectRevert(abi.encodeWithSelector(PolicyTupleMismatch.selector));
        vault.redeem(proof);
    }

    function test_redeem_aproofForAnotherVaultsCfgIsRefused() public {
        // A second deployment with another execution genesis has another cfg. The kernel result
        // carrying vault A's cfg is not accepted by vault B: B calls the verifier with its own Cfg.
        BridgeVault other = _deployVault(keccak256("other-execution-genesis"));
        assertTrue(other.CFG() != vault.CFG());
        uint256 n = _lock(vault, ALICE, 1 ether);
        _lock(other, ALICE, 1 ether);
        _kernelDefault(_ret(vault, n, 1 ether, BOB, keccak256("eta")));
        vm.expectRevert(
            abi.encodeWithSelector(KernelCfgMismatch.selector, other.CFG(), vault.CFG())
        );
        other.redeem(_proof(hex"aabbcc"));
        assertEq(other.credited(), 0);
    }

    function test_directVerifierCallAuthorizesNothing() public {
        uint256 n = _lock(vault, ALICE, 1 ether);
        KernelResult memory r = _ret(vault, n, 1 ether, BOB, keccak256("eta"));
        _kernelDefault(r);
        // Anyone can run the relation against the vault's cfg; it changes no vault state.
        KernelResult memory out = verifier.verifyReturn(vault.cfgBytes(), _proof(hex"aabbcc"));
        assertEq(out.nonce, n);
        assertEq(vault.credited(), 0);
        assertEq(vault.claimable(BOB), 0);
        assertEq(vault.spentNullifier(n), bytes32(0));
    }

    function test_redeem_unknownLockAfterAValidRelation() public {
        _lock(vault, ALICE, 1 ether);
        _kernelDefault(_ret(vault, 9, 1 ether, BOB, keccak256("eta")));
        vm.expectRevert(abi.encodeWithSelector(UnknownLock.selector, 9));
        vault.redeem(_proof(hex"aabbcc"));
    }

    function test_redeem_digestOfADifferentLockAmount() public {
        uint256 n = _lock(vault, ALICE, 1 ether);
        _kernelDefault(_ret(vault, n, 2 ether, BOB, keccak256("eta"))); // digest binds the amount
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
}
