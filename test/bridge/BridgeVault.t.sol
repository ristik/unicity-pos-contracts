// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {stdError} from "forge-std/StdError.sol";
import {VaultHarness, VerifierDouble, Payee} from "./VaultHarness.sol";
import {BridgeVault} from "../../src/bridge/BridgeVault.sol";
import {TokenVerifier} from "../../src/bridge/TokenVerifier.sol";
import {BridgeProfile} from "../../src/bridge/BridgeProfile.sol";
import {Cfg, Deployment, KernelResult, Leaf} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice Vault state machine and storage tests. The verifier is a TEST DOUBLE (`VerifierDouble`) so
///         each vault guard is exercised on its own; the real verifier is covered by
///         `TokenVerifier.t.sol` and `BridgeVaultIntegration.t.sol`.
contract BridgeVaultTest is VaultHarness {
    event Configured(bytes32 indexed cfg, bytes cfgBytes);
    event Locked(
        uint256 indexed nonce,
        address indexed depositor,
        bytes32 digest,
        address zeroAddress,
        bytes32 ty,
        bytes32 aid,
        uint256 amount,
        bytes32 tokenId,
        bytes32 salt,
        bytes32 rcpt,
        bytes p0
    );
    event RedemptionCredited(
        uint256 indexed nonce, bytes32 indexed nullifier, address indexed recipient, uint256 amount
    );
    event Claimed(address indexed recipient, address indexed to, uint256 amount);
    event Received(address indexed from, uint256 amount);

    Payee internal payee;

    function setUp() public {
        _setUpVault();
        payee = new Payee();
    }

    // ---------------------------------------------------------------------------------------------
    // Construction
    // ---------------------------------------------------------------------------------------------

    function _expectedCfg(address verifier) internal view returns (Cfg memory c) {
        c = Cfg({
            network: NETWORK,
            rootGenesis: ROOT_GENESIS,
            chainId: uint64(block.chainid),
            executionGenesis: EXEC_GENESIS,
            evmPartition: EVM_PARTITION,
            evmShard: hex"80",
            vault: address(vault),
            zeroAddress: address(0),
            ty: BridgeProfile.deriveType(
                NETWORK, ROOT_GENESIS, EXEC_GENESIS, uint64(block.chainid)
            ),
            aid: BridgeProfile.deriveAsset(
                    NETWORK, ROOT_GENESIS, EXEC_GENESIS, uint64(block.chainid)
                ),
            semanticProfileHash: keccak256("semantic"),
            tokenVerifier: verifier,
            tokenVerifierCodeHash: verifier.codehash,
            b1ProfileHash: keccak256("b1"),
            aggregatorPolicyHash: sha256(POLICY)
        });
    }

    function test_constructor_configuration() public view {
        Cfg memory c = _expectedCfg(address(vd));
        bytes memory raw = BridgeProfile.encodeCfg(c);
        assertEq(vault.cfgBytes(), raw);
        assertEq(vault.CFG(), sha256(raw));
        assertEq(vault.TYPE_ID(), c.ty);
        assertEq(vault.ASSET_ID(), c.aid);
        assertEq(address(vault.VERIFIER()), address(vd));
        Cfg memory d = BridgeProfile.decodeCfg(vault.cfgBytes());
        assertEq(d.vault, address(vault));
        assertEq(d.zeroAddress, address(0));
        assertEq(d.chainId, block.chainid);
        assertEq(d.aggregatorPolicyHash, sha256(POLICY));
    }

    function test_constructor_emitsConfigured() public {
        // The vault address is the next CREATE address; compute the expected Cfg for it.
        address next = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        Cfg memory c = _expectedCfg(address(vd));
        c.vault = next;
        bytes memory raw = BridgeProfile.encodeCfg(c);
        vm.expectEmit(true, false, false, true, next);
        emit Configured(sha256(raw), raw);
        new BridgeVault(_deployment(address(vd)));
    }

    // ---- unicity-native identifiers: derived from the deployment, never from the vault ----------

    function test_constructor_identifiersMatchTheOracleFamily() public {
        string memory g = vm.readFile("test/bridge/golden.json");
        Deployment memory d = _deployment(address(vd));
        d.network = uint16(vm.parseJsonUint(g, ".cfg.network"));
        d.rootGenesis = vm.parseJsonBytes32(g, ".cfg.rootGenesis");
        d.executionGenesis = vm.parseJsonBytes32(g, ".cfg.executionGenesis");
        assertEq(block.chainid, vm.parseJsonUint(g, ".cfg.chainId"), "oracle chain id");
        BridgeVault v = new BridgeVault(d);
        assertEq(v.TYPE_ID(), vm.parseJsonBytes32(g, ".cfg.ty"), "ty");
        assertEq(v.ASSET_ID(), vm.parseJsonBytes32(g, ".cfg.aid"), "aid");
    }

    function test_constructor_replacementVaultSharesTheAssetButNotTheConfig() public {
        BridgeVault other = new BridgeVault(_deployment(address(vd)));
        assertTrue(address(other) != address(vault));
        assertEq(other.TYPE_ID(), vault.TYPE_ID(), "same ty");
        assertEq(other.ASSET_ID(), vault.ASSET_ID(), "same aid");
        assertTrue(other.CFG() != vault.CFG(), "its own cfg");
        assertTrue(keccak256(other.cfgBytes()) != keccak256(vault.cfgBytes()));
        assertEq(BridgeProfile.decodeCfg(other.cfgBytes()).vault, address(other));
    }

    function test_constructor_everyIdentityComponentChangesBothIdentifiers() public {
        Deployment memory d = _deployment(address(vd));
        // network
        d.network = NETWORK + 1;
        BridgeVault a = new BridgeVault(d);
        assertTrue(a.TYPE_ID() != vault.TYPE_ID() && a.ASSET_ID() != vault.ASSET_ID(), "network");
        // root genesis
        d = _deployment(address(vd));
        d.rootGenesis = keccak256("another root");
        a = new BridgeVault(d);
        assertTrue(a.TYPE_ID() != vault.TYPE_ID() && a.ASSET_ID() != vault.ASSET_ID(), "root");
        // execution genesis
        d = _deployment(address(vd));
        d.executionGenesis = keccak256("another exec");
        a = new BridgeVault(d);
        assertTrue(a.TYPE_ID() != vault.TYPE_ID() && a.ASSET_ID() != vault.ASSET_ID(), "exec");
        // chain id: a private deployment that reuses the genesis hashes on another chain
        vm.chainId(4242);
        a = new BridgeVault(_deployment(address(vd)));
        assertTrue(a.TYPE_ID() != vault.TYPE_ID() && a.ASSET_ID() != vault.ASSET_ID(), "chain");
        assertEq(BridgeProfile.decodeCfg(a.cfgBytes()).chainId, 4242);
        assertEq(
            a.TYPE_ID(),
            BridgeProfile.deriveType(NETWORK, ROOT_GENESIS, EXEC_GENESIS, 4242),
            "ty by chain"
        );
    }

    function test_constructor_typeAndAssetAreDistinct() public view {
        assertTrue(vault.TYPE_ID() != vault.ASSET_ID());
    }

    function test_constructor_rootGenesisZero() public {
        Deployment memory d = _deployment(address(vd));
        d.rootGenesis = 0;
        vm.expectRevert(abi.encodeWithSelector(ZeroConfig.selector));
        new BridgeVault(d);
    }

    function test_constructor_executionGenesisZero() public {
        Deployment memory d = _deployment(address(vd));
        d.executionGenesis = 0;
        vm.expectRevert(abi.encodeWithSelector(ZeroConfig.selector));
        new BridgeVault(d);
    }

    function test_constructor_semanticProfileZero() public {
        Deployment memory d = _deployment(address(vd));
        d.semanticProfileHash = 0;
        vm.expectRevert(abi.encodeWithSelector(ZeroConfig.selector));
        new BridgeVault(d);
    }

    function test_constructor_b1ProfileZero() public {
        Deployment memory d = _deployment(address(vd));
        d.b1ProfileHash = 0;
        vm.expectRevert(abi.encodeWithSelector(ZeroConfig.selector));
        new BridgeVault(d);
    }

    function test_constructor_evmShardEmpty() public {
        Deployment memory d = _deployment(address(vd));
        d.evmShard = "";
        vm.expectRevert(abi.encodeWithSelector(BadEvmShard.selector));
        new BridgeVault(d);
    }

    function test_constructor_evmShardTooLong() public {
        Deployment memory d = _deployment(address(vd));
        d.evmShard = new bytes(34);
        vm.expectRevert(abi.encodeWithSelector(BadEvmShard.selector));
        new BridgeVault(d);
    }

    function test_constructor_evmShardLongestAccepted() public {
        Deployment memory d = _deployment(address(vd));
        d.evmShard = new bytes(33);
        new BridgeVault(d);
    }

    function test_constructor_verifierCodeHashPin() public {
        Deployment memory d = _deployment(address(vd));
        d.tokenVerifierCodeHash = keccak256("other code");
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierCodeHashMismatch.selector, keccak256("other code"), address(vd).codehash
            )
        );
        new BridgeVault(d);
    }

    function test_constructor_verifierMissing() public {
        Deployment memory d = _deployment(address(vd));
        d.tokenVerifier = address(0x1234);
        d.tokenVerifierCodeHash = bytes32(0);
        vm.expectRevert(
            abi.encodeWithSelector(VerifierCodeHashMismatch.selector, bytes32(0), bytes32(0))
        );
        new BridgeVault(d);
    }

    function test_constructor_verifierWithoutCode() public {
        // an existing account without code is not a verifier, even when its hash is "pinned"
        Deployment memory d = _deployment(address(vd));
        vm.deal(address(0x1234), 1);
        d.tokenVerifier = address(0x1234);
        d.tokenVerifierCodeHash = keccak256("");
        vm.expectRevert(
            abi.encodeWithSelector(VerifierCodeHashMismatch.selector, keccak256(""), keccak256(""))
        );
        new BridgeVault(d);
    }

    function test_constructor_policyMalformed() public {
        Deployment memory d = _deployment(address(vd));
        d.policyBody = bytes.concat(POLICY, hex"00");
        vm.expectRevert(abi.encodeWithSelector(PolicyMalformed.selector));
        new BridgeVault(d);
    }

    function test_constructor_policyPartitionIsEvmPartition() public {
        Deployment memory d = _deployment(address(vd));
        d.evmPartition = 11; // equals the policy's aggregator partition
        vm.expectRevert(abi.encodeWithSelector(PolicyPartitionIsEvm.selector));
        new BridgeVault(d);
    }

    // ---------------------------------------------------------------------------------------------
    // Layout
    // ---------------------------------------------------------------------------------------------

    function test_layout_compilerSlots() public view {
        string memory j = vm.readFile("out/BridgeVault.sol/BridgeVault.json");
        string[8] memory labels = [
            "lastNonce",
            "locked",
            "credited",
            "paid",
            "entered",
            "lockDigest",
            "spentNullifier",
            "claimable"
        ];
        for (uint256 i = 0; i < 8; ++i) {
            string memory p = string.concat(".storageLayout.storage[", vm.toString(i), "]");
            assertEq(vm.parseJsonString(j, string.concat(p, ".label")), labels[i]);
            assertEq(vm.parseJsonString(j, string.concat(p, ".slot")), vm.toString(i));
            assertEq(vm.parseJsonString(j, string.concat(p, ".offset")), "0");
        }
        // exactly eight storage variables: configuration lives in immutables and a code-only contract
        assertEq(vm.keyExistsJson(j, ".storageLayout.storage[8]"), false);
    }

    function test_layout_lockedStateInTheDeclaredSlots() public {
        _lock(ALICE, 5 ether);
        _lock(BOB, 7 ether);
        _redeem(1, 5 ether, CAROL, _eta(1, 0));
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(0)))), 2, "lastNonce");
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(1)))), 12 ether, "locked");
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(2)))), 5 ether, "credited");
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(3)))), 0, "paid");
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(4)))), 0, "entered is released");
        // logical slot keccak256(abi.encode(key, base)), full word values
        assertEq(
            vm.load(address(vault), keccak256(abi.encode(uint256(1), uint256(5)))),
            _digest(1, 5 ether)
        );
        assertEq(
            vm.load(address(vault), keccak256(abi.encode(uint256(2), uint256(5)))),
            _digest(2, 7 ether)
        );
        assertEq(vm.load(address(vault), keccak256(abi.encode(uint256(1), uint256(6)))), _eta(1, 0));
        assertEq(vm.load(address(vault), keccak256(abi.encode(uint256(2), uint256(6)))), bytes32(0));
        assertEq(
            uint256(vm.load(address(vault), keccak256(abi.encode(CAROL, uint256(7))))),
            5 ether,
            "claimable"
        );
    }

    function test_layout_matchesOracleSlotAndTrieKeys() public view {
        string memory g = vm.readFile("test/bridge/golden.json");
        // oracle LockDigestSlot/SpentSlot at n=1 and u64 max, then their trie keys keccak256(slot)
        bytes32 s1 = keccak256(abi.encode(uint256(1), uint256(5)));
        bytes32 sMax = keccak256(abi.encode(uint256(type(uint64).max), uint256(5)));
        assertEq(s1, vm.parseJsonBytes32(g, ".derivations[0].lockSlot"));
        assertEq(sMax, vm.parseJsonBytes32(g, ".derivations[1].lockSlot"));
        assertEq(keccak256(abi.encode(s1)), vm.parseJsonBytes32(g, ".derivations[0].lockTrieKey"));
        assertEq(keccak256(abi.encode(sMax)), vm.parseJsonBytes32(g, ".derivations[1].lockTrieKey"));
        assertEq(
            keccak256(abi.encode(uint256(1), uint256(6))),
            vm.parseJsonBytes32(g, ".derivations[0].spentSlot")
        );
        assertEq(
            keccak256(abi.encode(uint256(type(uint64).max), uint256(6))),
            vm.parseJsonBytes32(g, ".derivations[1].spentSlot")
        );
        address a = vm.parseJsonAddress(g, ".claimable.address");
        bytes32 cs = keccak256(abi.encode(a, uint256(7)));
        assertEq(cs, vm.parseJsonBytes32(g, ".claimable.slot"));
        assertEq(keccak256(abi.encode(cs)), vm.parseJsonBytes32(g, ".claimable.trieKey"));
    }

    function test_layout_u64MaxNonceSlotHoldsTheDigest() public {
        vm.store(address(vault), bytes32(uint256(0)), bytes32(uint256(type(uint64).max) - 1));
        uint256 n = _lock(ALICE, 1 ether);
        assertEq(n, type(uint64).max);
        bytes32 slot = keccak256(abi.encode(uint256(type(uint64).max), uint256(5)));
        assertEq(vm.load(address(vault), slot), _digest(n, 1 ether));
    }

    function test_layout_rlpOfLeadingZeroDigest() public view {
        // A lock digest with leading zero bytes is stored as a full word and its trie value is the
        // minimal RLP integer; padding back to 32 bytes recovers it (oracle vectors).
        string memory g = vm.readFile("test/bridge/golden.json");
        for (uint256 i = 0; i < 4; ++i) {
            string memory p = string.concat(".rlp[", vm.toString(i), "]");
            bytes32 value = vm.parseJsonBytes32(g, string.concat(p, ".value"));
            bytes memory rlp = vm.parseJsonBytes(g, string.concat(p, ".rlp"));
            assertEq(_rlpWord(value), rlp, "rlp encode");
            assertEq(_unrlpWord(rlp), value, "left-padded recovery");
        }
    }

    function _rlpWord(bytes32 v) internal pure returns (bytes memory) {
        uint256 i = 0;
        while (i < 32 && v[i] == 0) ++i;
        bytes memory s = new bytes(32 - i);
        for (uint256 j = 0; j < s.length; ++j) {
            s[j] = v[i + j];
        }
        if (s.length == 1 && uint8(s[0]) < 0x80) return s;
        if (s.length <= 55) return bytes.concat(bytes1(uint8(0x80 + s.length)), s);
        return bytes.concat(hex"b8", bytes1(uint8(s.length)), s);
    }

    function _unrlpWord(bytes memory r) internal pure returns (bytes32 out) {
        uint256 start;
        uint256 len;
        if (uint8(r[0]) < 0x80) {
            start = 0;
            len = 1;
        } else if (uint8(r[0]) <= 0xb7) {
            start = 1;
            len = uint8(r[0]) - 0x80;
        } else {
            start = 2;
            len = uint8(r[1]);
        }
        uint256 acc;
        for (uint256 j = 0; j < len; ++j) {
            acc = (acc << 8) | uint8(r[start + j]);
        }
        out = bytes32(acc);
    }

    // ---------------------------------------------------------------------------------------------
    // Lock
    // ---------------------------------------------------------------------------------------------

    function test_lock_recordsDigestAndEmitsTheCompleteRecord() public {
        KernelResult memory r = _prepareResult(1, 3 ether);
        vd.setPrepare(r);
        vm.deal(ALICE, 3 ether);
        vm.expectEmit(true, true, false, true, address(vault));
        emit Locked(
            1,
            ALICE,
            r.lockDigest,
            address(0),
            vault.TYPE_ID(),
            vault.ASSET_ID(),
            3 ether,
            r.tokenId,
            r.salt,
            r.firstPredicateHash,
            hex"d9"
        );
        vm.prank(ALICE);
        uint256 n = vault.lock{value: 3 ether}(hex"d9");
        assertEq(n, 1);
        assertEq(vault.lastNonce(), 1);
        assertEq(vault.locked(), 3 ether);
        assertEq(vault.lockDigest(1), r.lockDigest);
        assertEq(address(vault).balance, 3 ether);
        assertEq(vault.outstanding(), 3 ether);
    }

    function test_lock_callsTheVerifierWithTheVaultsOwnValues() public {
        vd.setPrepare(_prepareResult(1, 2 ether));
        vm.deal(ALICE, 2 ether);
        vm.expectCall(
            address(vd),
            abi.encodeCall(TokenVerifier.prepareLock, (vault.cfgBytes(), 1, 2 ether, hex"d9aa"))
        );
        vm.prank(ALICE);
        vault.lock{value: 2 ether}(hex"d9aa");
    }

    function test_lock_nonceIncrementsOnlyOnSuccess() public {
        _lock(ALICE, 1 ether);
        vd.setFailure(abi.encodeWithSelector(KernelRejected.selector));
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(KernelRejected.selector));
        vault.lock{value: 1 ether}(hex"d9");
        assertEq(vault.lastNonce(), 1, "rolled back");
        assertEq(vault.locked(), 1 ether);
        vd.setFailure("");
        assertEq(_lock(BOB, 1 ether), 2, "the failed attempt did not consume nonce 2");
    }

    function test_lock_zeroValue() public {
        vd.setPrepare(_prepareResult(1, 1));
        vm.expectRevert(abi.encodeWithSelector(ZeroAmount.selector));
        vault.lock(hex"d9");
    }

    function test_lock_kernelCfgMismatch() public {
        KernelResult memory r = _prepareResult(1, 1 ether);
        r.cfg = keccak256("other");
        vd.setPrepare(r);
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(KernelCfgMismatch.selector, cfgHash, r.cfg));
        vault.lock{value: 1 ether}(hex"d9");
    }

    function test_lock_kernelNonceMismatch() public {
        KernelResult memory r = _prepareResult(5, 1 ether);
        vd.setPrepare(r);
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(KernelNonceMismatch.selector, 1, 5));
        vault.lock{value: 1 ether}(hex"d9");
    }

    function test_lock_kernelAmountMismatch() public {
        KernelResult memory r = _prepareResult(1, 2 ether);
        vd.setPrepare(r);
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(KernelAmountMismatch.selector, 1 ether, 2 ether));
        vault.lock{value: 1 ether}(hex"d9");
    }

    function test_lock_zeroDigestRejected() public {
        KernelResult memory r = _prepareResult(1, 1 ether);
        r.lockDigest = 0;
        vd.setPrepare(r);
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(LockDigestZero.selector));
        vault.lock{value: 1 ether}(hex"d9");
    }

    function test_lock_nonceExhaustedAtU64Max() public {
        vm.store(address(vault), bytes32(uint256(0)), bytes32(uint256(type(uint64).max)));
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(NonceExhausted.selector));
        vault.lock{value: 1 ether}(hex"d9");
    }

    function test_lock_lockedOverflowReverts() public {
        vm.store(address(vault), bytes32(uint256(1)), bytes32(type(uint256).max));
        vd.setPrepare(_prepareResult(1, 1));
        vm.deal(ALICE, 1);
        vm.prank(ALICE);
        vm.expectRevert(stdError.arithmeticError);
        vault.lock{value: 1}(hex"d9");
    }

    function test_lock_digestNeverOverwritten() public {
        _lock(ALICE, 1 ether);
        bytes32 d1 = vault.lockDigest(1);
        _lock(BOB, 2 ether);
        assertEq(vault.lockDigest(1), d1);
        _redeem(1, 1 ether, CAROL, _eta(1, 0));
        assertEq(vault.lockDigest(1), d1, "redemption keeps the digest");
    }

    // ---------------------------------------------------------------------------------------------
    // verifyMint (view)
    // ---------------------------------------------------------------------------------------------

    function test_verifyMint_acceptsAnExistingUnspentLock() public {
        _lock(ALICE, 1 ether);
        KernelResult memory r = _prepareResult(1, 1 ether);
        r.leaves = new Leaf[](1);
        vd.setMint(r);
        assertEq(vault.verifyMint(""), 1);
    }

    function test_verifyMint_unknownLock() public {
        _lock(ALICE, 1 ether);
        KernelResult memory r = _prepareResult(2, 1 ether);
        vd.setMint(r);
        vm.expectRevert(abi.encodeWithSelector(UnknownLock.selector, 2));
        vault.verifyMint("");
        r = _prepareResult(0, 1 ether);
        vd.setMint(r);
        vm.expectRevert(abi.encodeWithSelector(UnknownLock.selector, 0));
        vault.verifyMint("");
    }

    function test_verifyMint_digestMismatch() public {
        _lock(ALICE, 1 ether);
        KernelResult memory r = _prepareResult(1, 1 ether);
        r.lockDigest = keccak256("another lock");
        vd.setMint(r);
        vm.expectRevert(abi.encodeWithSelector(LockDigestMismatch.selector, 1));
        vault.verifyMint("");
    }

    function test_verifyMint_alreadyRedeemed() public {
        _lock(ALICE, 1 ether);
        _redeem(1, 1 ether, BOB, _eta(1, 0));
        vd.setMint(_prepareResult(1, 1 ether));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, 1));
        vault.verifyMint("");
    }

    function test_verifyMint_cfgMismatch() public {
        _lock(ALICE, 1 ether);
        KernelResult memory r = _prepareResult(1, 1 ether);
        r.cfg = keccak256("other");
        vd.setMint(r);
        vm.expectRevert(abi.encodeWithSelector(KernelCfgMismatch.selector, cfgHash, r.cfg));
        vault.verifyMint("");
    }

    // ---------------------------------------------------------------------------------------------
    // Redeem
    // ---------------------------------------------------------------------------------------------

    function test_redeem_creditsTheBurnRecipientNotTheSubmitter() public {
        _lock(ALICE, 4 ether);
        vd.setReturn(_returnResult(1, 4 ether, BOB, _eta(1, 0)));
        vm.expectEmit(true, true, true, true, address(vault));
        emit RedemptionCredited(1, _eta(1, 0), BOB, 4 ether);
        vm.prank(CAROL); // an arbitrary submitter
        assertEq(vault.redeem("hex"), 1);
        assertEq(vault.claimable(BOB), 4 ether);
        assertEq(vault.claimable(CAROL), 0);
        assertEq(vault.credited(), 4 ether);
        assertEq(vault.spentNullifier(1), _eta(1, 0));
        assertEq(address(vault).balance, 4 ether, "redeem pays nothing");
        assertEq(vault.paid(), 0);
        assertEq(vault.outstanding(), 0);
        assertEq(vault.pendingClaims(), 4 ether);
    }

    function test_redeem_callsTheVerifierWithTheVaultsCfgAndTheProof() public {
        _lock(ALICE, 1 ether);
        vd.setReturn(_returnResult(1, 1 ether, BOB, _eta(1, 0)));
        vm.expectCall(
            address(vd), abi.encodeCall(TokenVerifier.verifyReturn, (vault.cfgBytes(), hex"c0ffee"))
        );
        vault.redeem(hex"c0ffee");
    }

    function test_redeem_sameProofTwice() public {
        _lock(ALICE, 1 ether);
        _redeem(1, 1 ether, BOB, _eta(1, 0));
        vd.setReturn(_returnResult(1, 1 ether, BOB, _eta(1, 0)));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, 1));
        vault.redeem("");
        assertEq(vault.claimable(BOB), 1 ether);
        assertEq(vault.credited(), 1 ether);
    }

    function test_redeem_conflictingBurnWithDifferentNullifierSameNonce() public {
        _lock(ALICE, 1 ether);
        _redeem(1, 1 ether, BOB, _eta(1, 0));
        // a second certified history of the same lock, with another eta and another recipient
        vd.setReturn(_returnResult(1, 1 ether, CAROL, _eta(1, 1)));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, 1));
        vault.redeem("");
        assertEq(vault.spentNullifier(1), _eta(1, 0), "the first nullifier stays");
        assertEq(vault.claimable(CAROL), 0);
    }

    function test_redeem_refreshedWitnessCannotReopenTheNonce() public {
        // The kernel result is independent of witness bytes; only the proof argument differs.
        _lock(ALICE, 1 ether);
        vd.setReturn(_returnResult(1, 1 ether, BOB, _eta(1, 0)));
        vault.redeem(hex"01");
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, 1));
        vault.redeem(hex"0202");
    }

    function test_redeem_unrelatedNoncesAreIndependent() public {
        _lock(ALICE, 1 ether);
        _lock(ALICE, 2 ether);
        _lock(ALICE, 3 ether);
        _redeem(2, 2 ether, BOB, _eta(2, 0));
        _redeem(3, 3 ether, CAROL, _eta(3, 0));
        _redeem(1, 1 ether, BOB, _eta(1, 0));
        assertEq(vault.claimable(BOB), 3 ether);
        assertEq(vault.claimable(CAROL), 3 ether);
        assertEq(vault.credited(), 6 ether);
    }

    function test_redeem_unknownNonce() public {
        _lock(ALICE, 1 ether);
        vd.setReturn(_returnResult(2, 1 ether, BOB, _eta(2, 0)));
        vm.expectRevert(abi.encodeWithSelector(UnknownLock.selector, 2));
        vault.redeem("");
        vd.setReturn(_returnResult(0, 1 ether, BOB, _eta(0, 0)));
        vm.expectRevert(abi.encodeWithSelector(UnknownLock.selector, 0));
        vault.redeem("");
    }

    function test_redeem_digestMismatch() public {
        _lock(ALICE, 1 ether);
        KernelResult memory r = _returnResult(1, 1 ether, BOB, _eta(1, 0));
        r.lockDigest = _digest(1, 2 ether);
        vd.setReturn(r);
        vm.expectRevert(abi.encodeWithSelector(LockDigestMismatch.selector, 1));
        vault.redeem("");
    }

    function test_redeem_digestOfAnotherNonce() public {
        _lock(ALICE, 1 ether);
        _lock(ALICE, 1 ether);
        KernelResult memory r = _returnResult(1, 1 ether, BOB, _eta(1, 0));
        r.lockDigest = vault.lockDigest(2);
        vd.setReturn(r);
        vm.expectRevert(abi.encodeWithSelector(LockDigestMismatch.selector, 1));
        vault.redeem("");
    }

    function test_redeem_cfgMismatch() public {
        _lock(ALICE, 1 ether);
        KernelResult memory r = _returnResult(1, 1 ether, BOB, _eta(1, 0));
        r.cfg = keccak256("other");
        vd.setReturn(r);
        vm.expectRevert(abi.encodeWithSelector(KernelCfgMismatch.selector, cfgHash, r.cfg));
        vault.redeem("");
    }

    function test_redeem_zeroNullifier() public {
        _lock(ALICE, 1 ether);
        vd.setReturn(_returnResult(1, 1 ether, BOB, bytes32(0)));
        vm.expectRevert(abi.encodeWithSelector(ZeroNullifier.selector));
        vault.redeem("");
    }

    function test_redeem_badRecipients() public {
        _lock(ALICE, 1 ether);
        vd.setReturn(_returnResult(1, 1 ether, address(0), _eta(1, 0)));
        vm.expectRevert(abi.encodeWithSelector(BadRecipient.selector));
        vault.redeem("");
        vd.setReturn(_returnResult(1, 1 ether, address(vault), _eta(1, 0)));
        vm.expectRevert(abi.encodeWithSelector(BadRecipient.selector));
        vault.redeem("");
    }

    function test_redeem_creditNeverExceedsLockedPerLock() public {
        _lock(ALICE, 1 ether);
        KernelResult memory r = _returnResult(1, 2 ether, BOB, _eta(1, 0));
        r.lockDigest = vault.lockDigest(1); // digest of the real lock, inflated amount
        vd.setReturn(r);
        vm.expectRevert(abi.encodeWithSelector(CreditExceedsLocked.selector, 0, 2 ether, 1 ether));
        vault.redeem("");
    }

    function test_redeem_creditNeverExceedsLockedCumulatively() public {
        _lock(ALICE, 1 ether);
        _lock(ALICE, 1 ether);
        // a kernel bug inflating lock 1 passes the global bound once, then lock 2 hits it
        KernelResult memory r = _returnResult(1, 2 ether, BOB, _eta(1, 0));
        r.lockDigest = vault.lockDigest(1);
        vd.setReturn(r);
        vault.redeem("");
        r = _returnResult(2, 1 ether, BOB, _eta(2, 0));
        vd.setReturn(r);
        vm.expectRevert(
            abi.encodeWithSelector(CreditExceedsLocked.selector, 2 ether, 1 ether, 2 ether)
        );
        vault.redeem("");
    }

    function test_redeem_verifierFailureBubblesUnchanged() public {
        _lock(ALICE, 1 ether);
        vd.setFailure(abi.encodeWithSelector(PolicyTupleMismatch.selector));
        vm.expectRevert(abi.encodeWithSelector(PolicyTupleMismatch.selector));
        vault.redeem("");
        assertEq(vault.credited(), 0);
        vd.setFailure(abi.encodeWithSelector(LeafNotIncluded.selector, 7));
        vm.expectRevert(abi.encodeWithSelector(LeafNotIncluded.selector, 7));
        vault.redeem("");
        assertEq(vault.spentNullifier(1), bytes32(0));
    }

    // ---------------------------------------------------------------------------------------------
    // Claim
    // ---------------------------------------------------------------------------------------------

    function _credited(address who, uint256 amount) internal returns (uint256 n) {
        n = _lock(ALICE, amount);
        _redeem(n, amount, who, _eta(n, 0));
    }

    function test_claim_paysAndAccounts() public {
        _credited(BOB, 5 ether);
        vm.expectEmit(true, true, false, true, address(vault));
        emit Claimed(BOB, CAROL, 5 ether);
        vm.prank(BOB);
        vault.claim(5 ether, CAROL);
        assertEq(CAROL.balance, 5 ether);
        assertEq(vault.claimable(BOB), 0);
        assertEq(vault.paid(), 5 ether);
        assertEq(address(vault).balance, 0);
        assertEq(vault.pendingClaims(), 0);
    }

    function test_claim_partial() public {
        _credited(BOB, 5 ether);
        vm.prank(BOB);
        vault.claim(2 ether, BOB);
        assertEq(vault.claimable(BOB), 3 ether);
        assertEq(vault.paid(), 2 ether);
        vm.prank(BOB);
        vault.claim(3 ether, BOB);
        assertEq(vault.paid(), 5 ether);
    }

    function test_claim_onlyTheCreditedRecipientCanRedirect() public {
        _credited(BOB, 5 ether);
        vm.prank(CAROL);
        vm.expectRevert(abi.encodeWithSelector(InsufficientCredit.selector, 0, 1 ether));
        vault.claim(1 ether, CAROL);
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(InsufficientCredit.selector, 5 ether, 5 ether + 1));
        vault.claim(5 ether + 1, BOB);
    }

    function test_claim_zeroAndBadDestination() public {
        _credited(BOB, 1 ether);
        vm.startPrank(BOB);
        vm.expectRevert(abi.encodeWithSelector(ZeroAmount.selector));
        vault.claim(0, BOB);
        vm.expectRevert(abi.encodeWithSelector(BadRecipient.selector));
        vault.claim(1, address(0));
        vm.expectRevert(abi.encodeWithSelector(BadRecipient.selector));
        vault.claim(1, address(vault));
        vm.stopPrank();
    }

    function test_claim_revertingPayeeRestoresEverything() public {
        _credited(address(payee), 3 ether);
        payee.set(vault, Payee.Mode.Revert);
        uint256 bal = address(vault).balance;
        vm.expectRevert(abi.encodeWithSelector(PayoutFailed.selector));
        payee.claim(3 ether, address(payee));
        assertEq(vault.claimable(address(payee)), 3 ether, "credit restored");
        assertEq(vault.paid(), 0, "P restored");
        assertEq(address(vault).balance, bal);
        // and the payee can still be paid to a working address
        payee.claim(3 ether, ALICE);
        assertEq(ALICE.balance, 3 ether);
    }

    function test_claim_reentrantPayeeIsBlockedOnEveryEntryPoint() public {
        _credited(address(payee), 3 ether);
        payee.set(vault, Payee.Mode.ReenterSwallow);
        payee.claim(2 ether, address(payee));
        assertEq(payee.received(), 2 ether);
        assertEq(payee.errorCount(), 3);
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(payee.errors(i), Reentrancy.selector, "claim, redeem and lock all refused");
        }
        // checks and effects preceded the call
        assertEq(payee.seenClaimable(), 1 ether);
        assertEq(payee.seenPaid(), 2 ether);
        assertEq(vault.claimable(address(payee)), 1 ether);
        assertEq(vault.paid(), 2 ether);
    }

    function test_claim_reentrantPayeeThatPropagatesFailsTheClaim() public {
        _credited(address(payee), 3 ether);
        payee.set(vault, Payee.Mode.ReenterPropagateClaim);
        vm.expectRevert(abi.encodeWithSelector(PayoutFailed.selector));
        payee.claim(2 ether, address(payee));
        assertEq(vault.claimable(address(payee)), 3 ether);
        assertEq(vault.paid(), 0);
    }

    function test_claim_badPayeeDoesNotBlockSeparateUsers() public {
        _credited(address(payee), 1 ether);
        payee.set(vault, Payee.Mode.Revert);
        vm.expectRevert(abi.encodeWithSelector(PayoutFailed.selector));
        payee.claim(1 ether, address(payee));
        // an unrelated lock, redemption and claim all go through
        uint256 n = _lock(ALICE, 2 ether);
        _redeem(n, 2 ether, BOB, _eta(n, 0));
        vm.prank(BOB);
        vault.claim(2 ether, BOB);
        assertEq(BOB.balance, 2 ether);
        assertEq(vault.claimable(address(payee)), 1 ether);
    }

    // ---------------------------------------------------------------------------------------------
    // Shared guard
    // ---------------------------------------------------------------------------------------------

    function test_guard_lockRedeemClaimRefuseWhileEntered() public {
        vm.store(address(vault), bytes32(uint256(4)), bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(Reentrancy.selector));
        vault.lock(hex"d9");
        vm.expectRevert(abi.encodeWithSelector(Reentrancy.selector));
        vault.redeem("");
        vm.expectRevert(abi.encodeWithSelector(Reentrancy.selector));
        vault.claim(1, BOB);
    }

    function test_guard_releasedAfterEveryCall() public {
        _credited(BOB, 1 ether);
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(4)))), 0);
        vm.prank(BOB);
        vault.claim(1 ether, BOB);
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(4)))), 0);
    }

    // ---------------------------------------------------------------------------------------------
    // Donations and forced value
    // ---------------------------------------------------------------------------------------------

    function test_donation_changesOnlyUnexpectedValue() public {
        _credited(BOB, 2 ether);
        vm.deal(ALICE, 1 ether);
        vm.expectEmit(true, false, false, true, address(vault));
        emit Received(ALICE, 1 ether);
        vm.prank(ALICE);
        (bool ok,) = address(vault).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(vault.lastNonce(), 1, "a plain transfer is not a lock");
        assertEq(vault.locked(), 2 ether);
        assertEq(vault.credited(), 2 ether);
        assertEq(vault.paid(), 0);
        assertEq(vault.unexpectedValue(), 1 ether);
    }

    function test_forcedValue_isOnlyUnexpected_andCannotBeClaimed() public {
        _credited(BOB, 2 ether);
        vm.deal(address(vault), address(vault).balance + 5 ether); // models a forced transfer
        assertEq(vault.unexpectedValue(), 5 ether);
        vm.prank(BOB);
        vault.claim(2 ether, BOB);
        // nothing but the credited amount can leave: the surplus is stuck, not spendable
        assertEq(address(vault).balance, 5 ether);
        assertEq(vault.unexpectedValue(), 5 ether);
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(InsufficientCredit.selector, 0, 1));
        vault.claim(1, BOB);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(InsufficientCredit.selector, 0, 1));
        vault.claim(1, ALICE);
    }

    function test_noFallbackAndNoOtherEntryPoint() public {
        (bool ok,) = address(vault).call(abi.encodeWithSignature("sweep(address)", ALICE));
        assertFalse(ok);
        (ok,) = address(vault).call(hex"deadbeef");
        assertFalse(ok);
    }

    // ---------------------------------------------------------------------------------------------
    // Fuzz
    // ---------------------------------------------------------------------------------------------

    function testFuzz_lockRedeemClaimKeepsAccounting(
        uint96 a1,
        uint96 a2,
        uint96 donate,
        bool claimFirst
    ) public {
        a1 = uint96(bound(a1, 1, 1_000_000 ether));
        a2 = uint96(bound(a2, 1, 1_000_000 ether));
        donate = uint96(bound(donate, 0, 1_000_000 ether));
        _lock(ALICE, a1);
        _lock(BOB, a2);
        if (donate != 0) {
            vm.deal(CAROL, donate);
            vm.prank(CAROL);
            (bool ok,) = address(vault).call{value: donate}("");
            assertTrue(ok);
        }
        _redeem(2, a2, CAROL, _eta(2, 0));
        if (claimFirst) {
            vm.prank(CAROL);
            vault.claim(a2, CAROL);
        }
        _redeem(1, a1, CAROL, _eta(1, 0));
        assertLe(vault.paid(), vault.credited());
        assertLe(vault.credited(), vault.locked());
        assertEq(vault.claimable(CAROL), vault.credited() - vault.paid());
        assertEq(address(vault).balance, vault.locked() - vault.paid() + donate);
        assertEq(vault.unexpectedValue(), donate);
    }

    function testFuzz_replayNeverCreditsTwice(bytes32 eta1, bytes32 eta2, address r2, uint96 amount)
        public
    {
        vm.assume(eta1 != 0 && eta2 != 0 && r2 != address(0) && r2 != address(vault));
        amount = uint96(bound(amount, 1, 1_000_000 ether));
        _lock(ALICE, amount);
        _redeem(1, amount, BOB, eta1);
        vd.setReturn(_returnResult(1, amount, r2, eta2));
        vm.expectRevert(abi.encodeWithSelector(AlreadyRedeemed.selector, 1));
        vault.redeem("");
        assertEq(vault.spentNullifier(1), eta1);
        assertEq(vault.credited(), amount);
    }

    function testFuzz_redeemUsesOnlyKernelFields(
        address submitter,
        address to,
        bytes32 eta,
        uint96 amount
    ) public {
        vm.assume(to != address(0) && to != address(vault) && eta != 0);
        amount = uint96(bound(amount, 1, 1_000_000 ether));
        _lock(ALICE, amount);
        vd.setReturn(_returnResult(1, amount, to, eta));
        vm.prank(submitter);
        vault.redeem("");
        assertEq(vault.claimable(to), amount);
        if (submitter != to) assertEq(vault.claimable(submitter), 0);
    }
}
