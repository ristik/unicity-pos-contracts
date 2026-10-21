// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BridgeBase} from "./BridgeBase.sol";
import {TokenVerifier} from "../../src/bridge/TokenVerifier.sol";
import {Cbor} from "../../src/bridge/Cbor.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {BridgeBounds} from "../../src/bridge/BridgeBounds.sol";
import {BridgeProfile} from "../../src/bridge/BridgeProfile.sol";
import {Anchor, Cfg, KernelResult, LeafProof, Policy} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice Verifier tests of the B7 direct path: the configuration binding, the forwarded call to the native composition
///         (0x0105) and the result checks, plus `prepareLock` against the 0x0104 kernel. The Cfg, policy, histories, anchors and
///         results are the golden bundles of the Go oracle, regenerated with script/bridge-golden. The 0x0104 kernel and 0x0105
///         composition are TEST DOUBLES that answer only the exact expected request bytes (`vm.mockCall` over reverting code);
///         the composed relation itself is tested natively (ureth `reth-unicity-bridge` replays the oracle's `native-compose`
///         corpus).
contract TokenVerifierTest is BridgeBase {
    TokenVerifier internal v;
    bytes internal cfgB;

    /// @dev One complete verifyReturn/verifyMint input and the doubles' answers.
    struct Scenario {
        uint8 op;
        bytes cfgB;
        bytes policyBody;
        bytes history;
        Anchor[] anchors;
        LeafProof[] paths;
        KernelResult result;
        uint256 status; // the composition's status; 0 holds
    }

    function setUp() public {
        _loadGolden();
        _etchDoubles();
        address verifierAddr = _a(".cfg.tokenVerifier");
        vm.etch(verifierAddr, address(new TokenVerifier()).code);
        v = TokenVerifier(verifierAddr);
        cfgB = _b(".cfg.bytes");
        assertEq(block.chainid, 31337, "fixture chain id");
    }

    // ---------------------------------------------------------------------------------------------
    // Scenario plumbing
    // ---------------------------------------------------------------------------------------------

    function _returnScenario() internal view returns (Scenario memory s) {
        s.op = 2;
        s.cfgB = cfgB;
        s.policyBody = _b(".policy.bytes");
        s.history = _b(".return.history");
        s.anchors = _goldenAnchors("return");
        s.paths = _goldenLeafProofs("return");
        s.result = _goldenResult(".return.result");
    }

    function _mintScenario() internal view returns (Scenario memory s) {
        s.op = 1;
        s.cfgB = cfgB;
        s.policyBody = _b(".policy.bytes");
        s.history = _b(".mint.history");
        s.anchors = _goldenAnchors("mint");
        s.paths = _goldenLeafProofs("mint");
        s.result = _goldenResult(".mint.result");
    }

    function _proof(Scenario memory s) internal pure returns (bytes memory) {
        return abi.encode(s.policyBody, s.history, s.anchors, s.paths);
    }

    /// @dev Programs the composition double for exactly this scenario's input: the 384-byte result of `s.result` and `s.status`.
    function _arm(Scenario memory s) internal {
        _prog(
            B1Calls.COMPOSE, _composeInput(s.op, s.cfgB, _proof(s)), _composeOut(s.status, s.result)
        );
    }

    function _call(Scenario memory s) internal view returns (KernelResult memory) {
        bytes memory proof = _proof(s);
        return s.op == 1 ? v.verifyMint(s.cfgB, proof) : v.verifyReturn(s.cfgB, proof);
    }

    function _run(Scenario memory s) internal returns (KernelResult memory) {
        _arm(s);
        return _call(s);
    }

    /// @dev Arms the scenario and expects the call to revert with exactly `err`.
    function _rejects(Scenario memory s, bytes memory err) internal {
        _arm(s);
        bytes memory proof = _proof(s);
        vm.expectRevert(err);
        if (s.op == 1) v.verifyMint(s.cfgB, proof);
        else v.verifyReturn(s.cfgB, proof);
    }

    function _sameResult(KernelResult memory a, KernelResult memory b)
        internal
        pure
        returns (bool)
    {
        return keccak256(abi.encode(a)) == keccak256(abi.encode(b));
    }

    function _cfgBytes(Cfg memory c) internal pure returns (bytes memory) {
        return BridgeProfile.encodeCfg(c);
    }

    function _setWord(bytes memory b, uint256 off, uint256 val)
        internal
        pure
        returns (bytes memory out)
    {
        out = b;
        assembly ("memory-safe") {
            mstore(add(add(out, 32), off), val)
        }
    }

    function _copy(bytes memory b) internal pure returns (bytes memory out) {
        out = new bytes(b.length);
        for (uint256 i = 0; i < b.length; ++i) {
            out[i] = b[i];
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Golden conformance: exact bytes of the oracle
    // ---------------------------------------------------------------------------------------------

    function test_golden_cfgEncodesToOracleBytes() public view {
        Cfg memory c = _goldenCfg();
        assertEq(BridgeProfile.encodeCfg(c), _b(".cfg.bytes"));
        assertEq(BridgeProfile.cfgHash(_b(".cfg.bytes")), _b32(".cfg.hash"));
    }

    function test_golden_cfgDecodesAndReencodes() public view {
        Cfg memory c = BridgeProfile.decodeCfg(_b(".cfg.bytes"));
        assertEq(keccak256(abi.encode(c)), keccak256(abi.encode(_goldenCfg())));
    }

    function test_golden_policyBytesAndHash() public view {
        Policy memory p = Policy({partition: uint32(vm.parseJsonUint(G, ".policy.partition"))});
        assertEq(p.partition, 11);
        assertEq(BridgeProfile.encodePolicy(p), _b(".policy.bytes"));
        assertEq(
            BridgeProfile.encodePolicy(p),
            _policyV2(11),
            "the independent byte-by-byte builder agrees"
        );
        assertEq(sha256(_b(".policy.bytes")), _b32(".policy.hash"));
        assertEq(_b32(".policy.hash"), _goldenCfg().aggregatorPolicyHash);
        assertEq(BridgeProfile.decodePolicy(_b(".policy.bytes")).partition, 11);
    }

    function test_golden_typeAndAssetDerivations() public view {
        Cfg memory c = _goldenCfg();
        assertEq(
            BridgeProfile.deriveType(c.network, c.rootGenesis, c.executionGenesis, c.chainId), c.ty
        );
        assertEq(
            BridgeProfile.deriveAsset(c.network, c.rootGenesis, c.executionGenesis, c.chainId),
            c.aid
        );
        assertEq(
            string(
                BridgeProfile.identityD(c.network, c.rootGenesis, c.executionGenesis, c.chainId)
            ),
            vm.parseJsonString(G, ".cfg.identityD")
        );
    }

    /// @dev Every component of D changes both identifiers; the vault is not a component.
    function test_golden_identityFamilyVectors() public view {
        for (uint256 i = 0; i < 7; ++i) {
            string memory p = string.concat(".identities[", vm.toString(i), "]");
            uint16 net = uint16(vm.parseJsonUint(G, string.concat(p, ".network")));
            bytes32 root = _b32(string.concat(p, ".rootGenesis"));
            bytes32 exec = _b32(string.concat(p, ".executionGenesis"));
            uint64 chain = uint64(_u(string.concat(p, ".chainId")));
            assertEq(
                string(BridgeProfile.identityD(net, root, exec, chain)),
                vm.parseJsonString(G, string.concat(p, ".d")),
                "D"
            );
            assertEq(
                BridgeProfile.deriveType(net, root, exec, chain),
                _b32(string.concat(p, ".ty")),
                "ty"
            );
            assertEq(
                BridgeProfile.deriveAsset(net, root, exec, chain),
                _b32(string.concat(p, ".aid")),
                "aid"
            );
        }
    }

    function test_golden_preparePayloadAndKernelInputs() public view {
        assertEq(
            BridgeProfile.preparePayload(
                _u(".prepare.n"), _u(".prepare.amount"), _b(".prepare.p0")
            ),
            _b(".prepare.payload")
        );
        assertEq(_kernelInput(0, cfgB, _b(".prepare.payload")), _b(".prepare.kernelInput"));
        assertEq(_kernelInput(1, cfgB, _b(".mint.history")), _b(".mint.kernelInput"));
        assertEq(_kernelInput(2, cfgB, _b(".return.history")), _b(".return.kernelInput"));
    }

    function test_golden_preparePayloadLargeAmountAndNonce() public pure {
        // 2^255 is a 32-byte minimal big-endian amount: bstr head 58 20 then 80 00..00.
        bytes memory p = BridgeProfile.preparePayload(type(uint64).max, 1 << 255, hex"d9");
        assertEq(
            p,
            bytes.concat(
                hex"83", hex"1bffffffffffffffff", hex"5820", hex"80", new bytes(31), hex"d9"
            )
        );
        // The smallest amount is one byte; the nonce one is a single-byte uint.
        assertEq(BridgeProfile.preparePayload(1, 1, hex"d9"), hex"83014101d9");
    }

    function _slice(bytes memory b, uint256 start, uint256 len)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) {
            out[i] = b[start + i];
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Accepting paths
    // ---------------------------------------------------------------------------------------------

    function test_prepareLock_golden() public {
        _prog(B1Calls.KERNEL, _b(".prepare.kernelInput"), _b(".prepare.kernelOutput"));
        KernelResult memory r =
            v.prepareLock(cfgB, _u(".prepare.n"), _u(".prepare.amount"), _b(".prepare.p0"));
        assertTrue(_sameResult(r, _goldenResult(".prepare.result")));
    }

    function test_verifyMint_golden() public {
        Scenario memory s = _mintScenario();
        vm.expectCall(B1Calls.COMPOSE, _composeInput(1, s.cfgB, _proof(s)), 1);
        KernelResult memory r = _run(s);
        assertTrue(_sameResult(r, s.result));
        assertEq(r.leafCount, 1);
    }

    /// One native call for the whole redemption, with exactly `abi.encode(op, cfg, proof)`; the fixed result is the oracle's.
    function test_verifyReturn_golden_oneNativeCall() public {
        Scenario memory s = _returnScenario();
        assertEq(s.anchors.length, 2, "the DN-B topology puts the leaves under two UCs");
        assertEq(s.result.leafCount, 3);
        vm.expectCall(B1Calls.COMPOSE, _composeInput(2, s.cfgB, _proof(s)), 1);
        vm.expectCall(B1Calls.KERNEL, bytes(""), 0);
        assertTrue(_sameResult(_run(s), s.result));
    }

    // ---------------------------------------------------------------------------------------------
    // Configuration and environment
    // ---------------------------------------------------------------------------------------------

    function test_cfg_wrongVerifierAddress() public {
        Cfg memory c = _goldenCfg();
        c.tokenVerifier = address(0xBEEF);
        Scenario memory s = _returnScenario();
        s.cfgB = _cfgBytes(c);
        _rejects(s, abi.encodeWithSelector(WrongVerifier.selector, address(0xBEEF), address(v)));
    }

    function test_cfg_chainIdMismatch() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        bytes memory proof = _proof(s);
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(ChainIdMismatch.selector, 31337, 1));
        v.verifyReturn(cfgB, proof);
    }

    function test_cfg_malformedVariants() public {
        Scenario memory s = _returnScenario();
        bytes memory good = cfgB;
        // trailing byte
        s.cfgB = bytes.concat(good, hex"00");
        _rejects(s, abi.encodeWithSelector(CfgMalformed.selector));
        // truncated
        s.cfgB = _slice(good, 0, good.length - 1);
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        // wrong domain byte
        bytes memory b = _copy(good);
        b[2] = 0x58;
        s.cfgB = b;
        _rejects(s, abi.encodeWithSelector(CfgMalformed.selector));
        // non-shortest network integer: 03 -> 18 03 (array head and every other item unchanged)
        s.cfgB = bytes.concat(_slice(good, 0, 16), hex"1803", _slice(good, 17, good.length - 17));
        _rejects(s, abi.encodeWithSelector(CfgMalformed.selector));
    }

    function test_cfg_everyPrefixIsRefusedWithANamedError() public view {
        Scenario memory s = _returnScenario();
        bytes memory good = cfgB;
        for (uint256 i = 0; i < good.length; ++i) {
            s.cfgB = _slice(good, 0, i);
            bytes memory proof = _proof(s);
            try v.verifyReturn(s.cfgB, proof) {
                revert("prefix accepted");
            } catch (bytes memory err) {
                bytes4 sel = bytes4(err);
                assertTrue(
                    sel == CborMalformed.selector || sel == CfgMalformed.selector, "named cfg error"
                );
            }
        }
    }

    function test_cfg_reservedAdditionalInformationIsCborMalformed() public {
        // network `03` replaced by an item with additional information 28 (reserved) and by the
        // indefinite marker 31
        Scenario memory s = _returnScenario();
        bytes memory good = cfgB;
        s.cfgB = bytes.concat(
            _slice(good, 0, 16), hex"1c", new bytes(15), hex"03", _slice(good, 17, good.length - 17)
        );
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        s.cfgB = bytes.concat(_slice(good, 0, 16), hex"1f", _slice(good, 17, good.length - 17));
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
    }

    function test_cfg_decodeRejectsEmptyAndOversizeShard() public {
        Cfg memory c = _goldenCfg();
        Scenario memory s = _returnScenario();
        c.evmShard = "";
        s.cfgB = _cfgBytes(c);
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        c.evmShard = new bytes(34);
        s.cfgB = _cfgBytes(c);
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
    }

    function test_cfg_oversizeIsBudget() public {
        // rejected before the calldata is copied into memory
        Scenario memory s = _returnScenario();
        s.cfgB = bytes.concat(cfgB, new bytes(1025 - cfgB.length));
        _rejects(s, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_cfg_wrongMajorTypesAndWidths() public {
        Scenario memory s = _returnScenario();
        bytes memory good = cfgB;
        uint256 tail = good.length - 17;
        // network as a byte string (major 2) instead of an unsigned integer
        s.cfgB = bytes.concat(_slice(good, 0, 16), hex"4103", _slice(good, 17, tail));
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        // an empty byte string `40` has argument 0, the same as an unsigned zero
        s.cfgB = bytes.concat(_slice(good, 0, 16), hex"40", _slice(good, 17, tail));
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        // network above uint16: 1a 00011170 (70000), same width as the cast would truncate
        s.cfgB = bytes.concat(_slice(good, 0, 16), hex"1a00011170", _slice(good, 17, tail));
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        // rootGenesis (bytes 17..51) as 31 and as 33 bytes
        bytes memory head = _slice(good, 0, 17);
        bytes memory rest = _slice(good, 17 + 34, good.length - 17 - 34);
        s.cfgB = bytes.concat(head, hex"581f", new bytes(31), rest);
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        s.cfgB = bytes.concat(head, hex"5821", new bytes(33), rest);
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        // rootGenesis head as an unsigned integer 32 (`18 20`) over the same 32 bytes
        s.cfgB = bytes.concat(head, hex"1820", _slice(good, 19, good.length - 19));
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        // rootGenesis as an unsigned integer
        s.cfgB = bytes.concat(head, hex"00", rest);
        _rejects(s, abi.encodeWithSelector(CborMalformed.selector));
        // chainId above uint64 is not encodable; uint32 evmPartition above its range
        // (1b ffffffffffffffff = 2^64-1 fits uint64 but not uint32)
    }

    /// @dev A policy body assembled from raw parts: array(3), the 24-byte domain as a byte string, the version item, the partition item.
    function _rawPolicy(bytes memory domain, bytes memory version, bytes memory partition)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(hex"83", hex"5818", domain, version, partition);
    }

    function test_policy_theIndependentBuilderIsTheCanonicalBody() public pure {
        assertEq(_rawPolicy("UNICITY_BR_AGG_PARTITION", hex"02", hex"0b"), _policyV2(11));
        assertEq(_policyV2(11), hex"835818554e49434954595f42525f4147475f504152544954494f4e020b");
    }

    function test_kernel_cfgHashMismatch() public {
        Scenario memory s = _returnScenario();
        s.result.cfg = keccak256("other cfg");
        _rejects(s, abi.encodeWithSelector(KernelCfgMismatch.selector, sha256(cfgB), s.result.cfg));
    }

    function test_shape_nonceZero() public {
        Scenario memory s = _returnScenario();
        s.result.nonce = 0;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_nonceAboveU64() public {
        Scenario memory s = _returnScenario();
        s.result.nonce = uint256(type(uint64).max) + 1;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_nonceU64MaxAccepted() public {
        Scenario memory s = _returnScenario();
        s.result.nonce = type(uint64).max;
        assertEq(_run(s).nonce, type(uint64).max);
    }

    function test_shape_amountZero() public {
        Scenario memory s = _returnScenario();
        s.result.amount = 0;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_lockDigestZero() public {
        Scenario memory s = _returnScenario();
        s.result.lockDigest = 0;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_returnNullifierZero() public {
        Scenario memory s = _returnScenario();
        s.result.nullifier = 0;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_returnReleaseToZero() public {
        Scenario memory s = _returnScenario();
        s.result.releaseTo = address(0);
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_returnReleaseToVault() public {
        Scenario memory s = _returnScenario();
        s.result.releaseTo = _goldenCfg().vault;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_returnNeedsMintAndBurnAtLeast() public {
        Scenario memory s = _returnScenario();
        s.result.leafCount = 1;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_returnLeafCountIsTheCompositions() public {
        Scenario memory s = _returnScenario();
        s.result.leafCount = 1000; // no Solidity leaf bound: the native composition bounds and proves the leaves
        assertEq(_run(s).leafCount, 1000);
    }

    function test_shape_mintWithTwoLeaves() public {
        Scenario memory s = _mintScenario();
        s.result.leafCount = 2;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_mintWithReleaseFields() public {
        Scenario memory s = _mintScenario();
        s.result.releaseTo = address(0xCAFE);
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
        s = _mintScenario();
        s.result.nullifier = bytes32(uint256(1));
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_prepareWithLeavesOrRelease() public {
        _prog(B1Calls.KERNEL, _b(".prepare.kernelInput"), _b(".prepare.kernelOutput"));
        KernelResult memory r = _goldenResult(".prepare.result");
        r.leafCount = 1;
        _prog(B1Calls.KERNEL, _b(".prepare.kernelInput"), _kernelOut(true, r));
        // a prepare result has no leaves: anything longer than the fixed result is refused before it is copied
        vm.expectRevert(abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.KERNEL));
        v.prepareLock(cfgB, _u(".prepare.n"), _u(".prepare.amount"), _b(".prepare.p0"));
        r = _goldenResult(".prepare.result");
        r.releaseTo = address(1);
        _prog(B1Calls.KERNEL, _b(".prepare.kernelInput"), _kernelOut(true, r));
        vm.expectRevert(abi.encodeWithSelector(KernelResultShape.selector));
        v.prepareLock(cfgB, _u(".prepare.n"), _u(".prepare.amount"), _b(".prepare.p0"));
    }

    function test_prepare_p0OverCapIsBudget() public {
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        v.prepareLock(cfgB, 1, 1, new bytes(BridgeBounds.MAX_SEMANTIC_BYTES + 1));
    }

    function test_prepare_cfgMismatchInResult() public {
        KernelResult memory r = _goldenResult(".prepare.result");
        r.cfg = bytes32(uint256(7));
        _prog(B1Calls.KERNEL, _b(".prepare.kernelInput"), _kernelOut(true, r));
        vm.expectRevert(abi.encodeWithSelector(KernelCfgMismatch.selector, sha256(cfgB), r.cfg));
        v.prepareLock(cfgB, _u(".prepare.n"), _u(".prepare.amount"), _b(".prepare.p0"));
    }

    /// @dev A mutated Cfg either fails to decode or is a different configuration (different hash),
    ///      never the same one in another encoding.
    function testFuzz_cfgByteFlipNeverAliasesTheHash(uint256 pos, uint8 flip) public view {
        bytes memory good = _b(".cfg.bytes");
        bytes memory b = _copy(good);
        pos = bound(pos, 0, b.length - 1);
        flip = uint8(bound(flip, 1, 255));
        b[pos] = bytes1(uint8(b[pos]) ^ flip);
        try this.decodeCfg(b) returns (Cfg memory c) {
            assertEq(keccak256(BridgeProfile.encodeCfg(c)), keccak256(b), "decode is canonical");
            assertTrue(sha256(b) != sha256(good));
        } catch {}
    }

    function decodeCfg(bytes memory b) external pure returns (Cfg memory) {
        return BridgeProfile.decodeCfg(b);
    }

    function testFuzz_policyDecodeIsCanonical(bytes memory b) public view {
        try this.decodePolicy(b) returns (Policy memory p) {
            assertEq(keccak256(BridgeProfile.encodePolicy(p)), keccak256(b));
        } catch {}
    }

    function decodePolicy(bytes memory b) external pure returns (Policy memory) {
        return BridgeProfile.decodePolicy(b);
    }

    /// The deployed code has to fit EIP-170 (24,576 bytes). It is close: the number is published so a change that eats the headroom is seen.
    // ---- the prepare kernel's output ------------------------------------------------------------------------------------

    function _prepareRejects(bytes memory kernelOutput, bytes memory err) internal {
        _prog(B1Calls.KERNEL, _b(".prepare.kernelInput"), kernelOutput);
        vm.expectRevert(err);
        v.prepareLock(cfgB, _u(".prepare.n"), _u(".prepare.amount"), _b(".prepare.p0"));
    }

    /// The prepare result is exactly the 448-byte canonical layout: a valid word other than a bool, a moved Result or leaf
    /// array offset, or a dirty address word is a bad output.
    function test_prepare_everyNoncanonicalKernelOutputIsBad() public {
        bytes memory good = _b(".prepare.kernelOutput");
        // ... and a leaf count other than zero in exactly 448 bytes
        uint256[5] memory word = [uint256(32), 64, 384, 320, 416];
        uint256[5] memory value = [uint256(2), 0x80, 0x160, uint256(1) << 160, 1];
        for (uint256 i = 0; i < 5; ++i) {
            _prepareRejects(
                _setWord(_copy(good), word[i], value[i]),
                abi.encodeWithSelector(KernelBadOutput.selector)
            );
        }
    }

    function test_prepare_anInvalidResultIsKernelRejected() public {
        bytes memory o = _setWord(_copy(_b(".prepare.kernelOutput")), 32, 0);
        _prepareRejects(o, abi.encodeWithSelector(KernelRejected.selector));
    }

    function test_prepare_aKernelHaltIsPrecompileFailed() public {
        _progRevert(B1Calls.KERNEL, _b(".prepare.kernelInput"));
        vm.expectRevert(abi.encodeWithSelector(PrecompileFailed.selector, B1Calls.KERNEL));
        v.prepareLock(cfgB, _u(".prepare.n"), _u(".prepare.amount"), _b(".prepare.p0"));
    }

    /// The kernel is forwarded exactly its charge for the request, so a late failure cannot consume the transaction.
    function test_prepare_theKernelIsForwardedExactlyItsCharge() public {
        bytes memory input = _b(".prepare.kernelInput");
        _prog(B1Calls.KERNEL, input, _b(".prepare.kernelOutput"));
        uint64 charge = uint64(26_000 + 20 * input.length);
        vm.expectCall(B1Calls.KERNEL, 0, charge, input);
        v.prepareLock(cfgB, _u(".prepare.n"), _u(".prepare.amount"), _b(".prepare.p0"));
    }

    /// The deployment's policy body decodes strictly: shortest heads, the exact domain, version 2, a nonzero partition, no trailing
    /// byte (`BridgeProfile.decodePolicy`, which the vault runs at construction).
    function test_policy_decodeIsStrict() public {
        bytes[6] memory bad = [
            _rawPolicy("UNICITY_BR_AGG_PARTITION", hex"02", hex"00"),
            bytes.concat(_policyV2(11), hex"00"),
            _rawPolicy("UNICITY_BR_AGG_PARTITION", hex"02", hex"180b"),
            _rawPolicy("UNICITY_BR_AGG_PARTITIOX", hex"02", hex"0b"),
            _rawPolicy("UNICITY_BR_AGG_PARTITION", hex"01", hex"0b"),
            _rawPolicy("UNICITY_BR_AGG_PARTITION", hex"03", hex"0b")
        ];
        for (uint256 i = 0; i < bad.length; ++i) {
            // version 3 is above the reader's bound; every other case fails the policy's own checks
            vm.expectRevert(
                i == 5
                    ? abi.encodeWithSelector(CborMalformed.selector)
                    : abi.encodeWithSelector(PolicyMalformed.selector)
            );
            this.decodePolicy(bad[i]);
        }
        assertEq(this.decodePolicy(_policyV2(11)).partition, 11);
    }

    // ---- the native composition's result -------------------------------------------------------------------------------

    /// A nonzero status is the native refusal, named by its code; nothing of the result is read.
    function test_compose_aNonzeroStatusIsBridgeRejected() public {
        uint256[4] memory statuses = [uint256(1), 22, 61, 62];
        for (uint256 i = 0; i < 4; ++i) {
            Scenario memory s = _returnScenario();
            s.status = statuses[i];
            _rejects(s, abi.encodeWithSelector(BridgeRejected.selector, statuses[i]));
        }
    }

    /// A halt (out of gas, non-canonical input) is a failure, never a result.
    function test_compose_aHaltIsPrecompileFailed() public {
        Scenario memory s = _returnScenario();
        _progRevert(B1Calls.COMPOSE, _composeInput(2, s.cfgB, _proof(s)));
        vm.expectRevert(abi.encodeWithSelector(PrecompileFailed.selector, B1Calls.COMPOSE));
        v.verifyReturn(s.cfgB, _proof(s));
    }

    /// An inactive address answers nothing: an empty success is a bad return, never a result.
    function test_compose_theInactiveAddressIsABadReturn() public {
        vm.etch(B1Calls.COMPOSE, "");
        Scenario memory s = _returnScenario();
        vm.expectRevert(abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.COMPOSE));
        v.verifyReturn(s.cfgB, _proof(s));
    }

    /// Exactly 384 bytes under the marker, and the address word clean: any other shape is a bad return.
    function test_compose_everyOtherResultShapeIsABadReturn() public {
        Scenario memory s = _returnScenario();
        bytes memory good = _composeOut(0, s.result);
        bytes[4] memory bad;
        bad[0] = _slice(good, 0, 383);
        bad[1] = bytes.concat(good, bytes32(0));
        bad[2] = _copy(good);
        bad[2][0] = 0x00; // marker
        bad[3] = _copy(good);
        bad[3][288 + 11] = 0x01; // releaseTo with a high bit set
        for (uint256 i = 0; i < 4; ++i) {
            _prog(B1Calls.COMPOSE, _composeInput(2, s.cfgB, _proof(s)), bad[i]);
            vm.expectRevert(abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.COMPOSE));
            v.verifyReturn(s.cfgB, _proof(s));
        }
    }

    /// The configuration is bound before the native call: a Cfg naming another verifier never reaches 0x0105.
    function test_compose_theCfgIsBoundBeforeTheNativeCall() public {
        Cfg memory c = _goldenCfg();
        c.tokenVerifier = address(0xBEEF);
        Scenario memory s = _returnScenario();
        s.cfgB = _cfgBytes(c);
        vm.expectCall(B1Calls.COMPOSE, bytes(""), 0);
        vm.expectRevert(abi.encodeWithSelector(WrongVerifier.selector, address(0xBEEF), address(v)));
        v.verifyReturn(s.cfgB, _proof(s));
    }

    function test_theVerifierFitsTheContractSizeLimit() public {
        uint256 size = address(v).code.length;
        emit log_named_uint("TokenVerifier runtime bytes", size);
        emit log_named_uint("headroom to EIP-170", 24_576 - size);
        assertLe(size, 24_576);
    }
}
