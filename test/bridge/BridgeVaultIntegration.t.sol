// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {TopologyFixtures} from "./TopologyFixtures.sol";
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
contract BridgeVaultIntegrationTest is TopologyFixtures {
    BridgeVault internal vault;
    TokenVerifier internal verifier;

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);

    function setUp() public {
        _loadGolden();
        _etchDoubles();
        verifier = new TokenVerifier();
        vault = _deployVault(keccak256("execution-genesis"));
        _progDefault(B1Calls.CERT_BATCH, BATCH_TRUE);
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
        _progDefault(B1Calls.CERT_BATCH, BATCH_FALSE);
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
        bytes memory proof = abi.encode(_policyV2(11), hex"aabbcc", a, _goldenLeafProofs("return"));
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

    // ---- the same state IDs proved before and after a topology change ----------------------------

    /// @dev One return, three state IDs, two proofs: BEFORE the change the shard `1` (one parent) certified all three; AFTER it the
    ///      children `10` and `11` certify them, in two anchors. The kernel result, and so the burn nullifier, is the same for both.
    function _topologyProofs(bytes memory history)
        internal
        pure
        returns (bytes memory before_, bytes memory after_, bytes32[3] memory sids)
    {
        bytes memory parent = _shardId(1, 1);
        bytes memory left = _shardId(2, 2);
        bytes memory right = _shardId(2, 3);
        sids[0] = _sidIn(left, 0);
        sids[1] = _sidIn(left, 1);
        sids[2] = _sidIn(right, 2);
        Anchor[] memory a1 = new Anchor[](1);
        a1[0] = _synthAnchor(parent, 0, 3, hex"00");
        Anchor[] memory a2 = new Anchor[](2);
        a2[0] = _synthAnchor(left, 1, 3, hex"00");
        a2[1] = _synthAnchor(right, 2, 3, hex"00");
        LeafProof[] memory p1 = new LeafProof[](3);
        LeafProof[] memory p2 = new LeafProof[](3);
        for (uint256 i = 0; i < 3; ++i) {
            p1[i] = LeafProof({anchorIndex: 0, bitmap: bytes32(0), siblings: new bytes32[](0)});
            p2[i] = LeafProof({
                anchorIndex: uint16(i == 2 ? 1 : 0), bitmap: bytes32(0), siblings: new bytes32[](0)
            });
        }
        before_ = abi.encode(_policyV2(11), history, a1, p1);
        after_ = abi.encode(_policyV2(11), history, a2, p2);
    }

    function _topologyResult(uint256 n, bytes32[3] memory sids)
        internal
        view
        returns (KernelResult memory r)
    {
        r = _ret(vault, n, 5 ether, BOB, keccak256("eta-topology"));
        for (uint256 i = 0; i < 3; ++i) {
            r.leaves[i].sid = sids[i];
        }
    }

    /// @notice The claim "re-proving a state after a topology change creates no second spend", as one test: the same SIDs proved under the
    ///         parent shard and under its children give the verifier the same kernel result, so the same burn nullifier; the vault credits
    ///         one of the two proofs, stores that one nullifier against the nonce, and refuses the other (in either order).
    function test_topologyChange_sameSidsKeepOneNullifierAndOneRelease() public {
        bytes memory history = hex"aabbcc";
        (bytes memory before_, bytes memory after_, bytes32[3] memory sids) =
            _topologyProofs(history);
        uint256 n = _lock(vault, ALICE, 5 ether);
        KernelResult memory r = _topologyResult(n, sids);
        _kernelDefault(r);
        // both proofs verify, to the same relation and the same nullifier (the nullifier excludes paths and anchors)
        KernelResult memory rb = verifier.verifyReturn(vault.cfgBytes(), before_);
        KernelResult memory ra = verifier.verifyReturn(vault.cfgBytes(), after_);
        assertEq(rb.nullifier, ra.nullifier, "one nullifier");
        assertEq(rb.nullifier, keccak256("eta-topology"));
        assertEq(rb.nonce, ra.nonce);
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(rb.leaves[i].sid, ra.leaves[i].sid, "same state IDs");
        }
        // the proof from after the change redeems; the one from before is then refused: the nonce is spent, the nullifier unchanged
        vault.redeem(after_);
        assertEq(vault.spentNullifier(n), keccak256("eta-topology"));
        assertEq(vault.claimable(BOB), 5 ether);
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, n));
        vault.redeem(before_);
        assertEq(vault.spentNullifier(n), keccak256("eta-topology"));
        assertEq(vault.claimable(BOB), 5 ether, "credited once");

        // the other order, on a fresh lock: the parent-era proof redeems, the child-era proof is refused
        uint256 m = _lock(vault, ALICE, 5 ether);
        _kernelDefault(_topologyResult(m, sids));
        vault.redeem(before_);
        assertEq(vault.spentNullifier(m), keccak256("eta-topology"));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, m));
        vault.redeem(after_);
        assertEq(vault.claimable(BOB), 10 ether, "two locks, one credit each");
    }
}
