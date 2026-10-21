// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {TopologyFixtures} from "./TopologyFixtures.sol";
import {TokenVerifier} from "../../src/bridge/TokenVerifier.sol";
import {Cbor} from "../../src/bridge/Cbor.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {BridgeBounds} from "../../src/bridge/BridgeBounds.sol";
import {CertGroups} from "../../src/bridge/CertGroups.sol";
import {BridgeProfile} from "../../src/bridge/BridgeProfile.sol";
import {Anchor, Cfg, KernelResult, Leaf, LeafProof, Policy} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice Composing-verifier tests of bridge protocol 4 (any-age verification). The anchors, leaves, history, Cfg, policy and gate
///         components are the golden bundles of the protocol-4 Go oracle (bft-core bridgeprofile #610: real UCs, real kernel results),
///         regenerated with script/bridge-golden. The batch precompile (0x0100), the RSMT call (0x0102) and the 0x0104 kernel are TEST DOUBLES that answer only the exact expected request bytes
///         (`vm.mockCall` over reverting code); they are not the native code.
contract TokenVerifierTest is TopologyFixtures {
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
        bytes kernelOut; // empty: derive from `result`
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

    /// @dev The authenticated state root of the anchor that serves leaf `i`.
    function _rootOf(Scenario memory s, uint256 i) internal pure returns (bytes32) {
        return s.anchors[s.paths[i].anchorIndex].expectedStateRoot;
    }

    function _proof(Scenario memory s) internal pure returns (bytes memory) {
        return abi.encode(s.policyBody, s.history, s.anchors, s.paths);
    }

    /// @dev Programs the doubles for exactly this scenario: kernel by exact input, UC by the exact
    ///      expected request, one RSMT answer per leaf by the exact expected request.
    function _arm(Scenario memory s) internal {
        _armExcept(s, address(0));
    }

    /// @dev `_arm` without the answers of one native address (an inactive address answers nothing).
    function _armExcept(Scenario memory s, address skip) internal {
        bytes memory kout = s.kernelOut.length != 0 ? s.kernelOut : _kernelOut(true, s.result);
        if (skip != B1Calls.KERNEL) {
            _prog(B1Calls.KERNEL, _kernelInput(s.op, s.cfgB, s.history), kout);
        }
        if (s.anchors.length != 0) {
            if (skip != B1Calls.CERT_BATCH) {
                _prog(B1Calls.CERT_BATCH, _expectedBatch(s.anchors), BATCH_TRUE);
            }
            for (uint256 i = 0; i < s.result.leaves.length && i < s.paths.length; ++i) {
                if (skip == B1Calls.RSMT_VERIFIER) break;
                uint256 ai = s.paths[i].anchorIndex < s.anchors.length ? s.paths[i].anchorIndex : 0;
                bytes memory req = _expectedRSMT(
                    s.anchors[ai].expectedStateRoot,
                    s.result.leaves[i].sid,
                    s.result.leaves[i].leafValue,
                    s.paths[i]
                );
                _prog(B1Calls.RSMT_VERIFIER, req, TRUE_OUT);
            }
        }
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

    function _rejectsRaw(Scenario memory s, bytes memory proof, bytes memory err) internal {
        _arm(s);
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

    function _getWord(bytes memory b, uint256 off) internal pure returns (uint256 val) {
        assembly ("memory-safe") {
            val := mload(add(add(b, 32), off))
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

    function test_golden_envelopeAbiLayout() public view {
        Scenario memory s = _returnScenario();
        assertEq(_proof(s), _b(".return.envelope.bytes"));
        assertEq(s.paths.length, 3);
        Scenario memory m = _mintScenario();
        assertEq(_proof(m), _b(".mint.envelope.bytes"));
        assertEq(m.paths.length, 1);
    }

    function test_golden_batchRequestsMatchTheOracle() public view {
        Scenario memory s = _returnScenario();
        bytes memory want = _b(".return.envelope.batch.request");
        assertEq(B1Calls.batchRequest(s.anchors), want);
        assertEq(_expectedBatch(s.anchors), want);
        assertEq(_b(".return.envelope.batch.result"), BATCH_TRUE);
        Scenario memory m = _mintScenario();
        assertEq(B1Calls.batchRequest(m.anchors), _b(".mint.envelope.batch.request"));
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

    function test_golden_kernelOutputAbiLayout() public view {
        assertEq(_kernelOut(true, _goldenResult(".prepare.result")), _b(".prepare.kernelOutput"));
        assertEq(_kernelOut(true, _goldenResult(".mint.result")), _b(".mint.kernelOutput"));
        assertEq(_kernelOut(true, _goldenResult(".return.result")), _b(".return.kernelOutput"));
        KernelResult memory z;
        z.leaves = new Leaf[](0);
        assertEq(_kernelOut(false, z), _b(".invalidOutput"));
    }

    function test_golden_rsmtRequestsMatchTheB1Manifest() public view {
        string memory b1v = vm.readFile(B1V_PATH);
        string[4] memory ids =
            ["rsmt.single-leaf.ok", "rsmt.small.ok", "rsmt.small.leaf0.ok", "rsmt.small.leaf8.ok"];
        for (uint256 i = 0; i < ids.length; ++i) {
            bytes memory req =
                vm.parseJsonBytes(b1v, string.concat('.vectors["', ids[i], '"].request'));
            bytes32 root = bytes32(_slice(req, 4, 32));
            bytes32 key = bytes32(_slice(req, 36, 32));
            uint256 vlen = uint32(bytes4(_slice(req, 68, 4)));
            bytes memory value = _slice(req, 72, vlen);
            bytes32 bitmap = bytes32(_slice(req, 72 + vlen, 32));
            uint256 n = (req.length - 104 - vlen) / 32;
            bytes32[] memory sibs = new bytes32[](n);
            for (uint256 j = 0; j < n; ++j) {
                sibs[j] = bytes32(_slice(req, 104 + vlen + 32 * j, 32));
            }
            assertEq(B1Calls.memberRequest(root, key, value, bitmap, sibs), req, ids[i]);
        }
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
        vm.expectCall(B1Calls.CERT_BATCH, _expectedBatch(s.anchors), 1);
        vm.expectCall(B1Calls.RSMT_VERIFIER, hex"01000001", 1);
        assertTrue(_sameResult(_run(s), s.result));
    }

    function test_verifyReturn_golden_everyLeafOnceInOrder() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        assertEq(s.anchors.length, 2, "the DN-B topology puts the leaves under two UCs");
        vm.expectCall(B1Calls.CERT_BATCH, _expectedBatch(s.anchors), 1); // ONE batch call for the whole table
        for (uint256 i = 0; i < 3; ++i) {
            bytes memory req = _expectedRSMT(
                s.anchors[s.paths[i].anchorIndex].expectedStateRoot,
                s.result.leaves[i].sid,
                s.result.leaves[i].leafValue,
                s.paths[i]
            );
            vm.expectCall(B1Calls.RSMT_VERIFIER, req, 1);
        }
        assertTrue(_sameResult(_call(s), s.result));
        assertEq(s.result.leaves.length, 3);
    }

    function test_verifyReturn_leafOrderIsKernelOrder() public {
        // Swapping two paths keeps the call well formed but hands each leaf the other's path: the
        // exact-request doubles refuse it, so a leaf is never checked against another leaf's path.
        Scenario memory s = _returnScenario();
        _arm(s);
        LeafProof memory t = s.paths[0];
        s.paths[0] = s.paths[1];
        s.paths[1] = t;
        bytes memory proof = _proof(s);
        vm.expectRevert(abi.encodeWithSelector(PrecompileFailed.selector, B1Calls.RSMT_VERIFIER));
        v.verifyReturn(cfgB, proof);
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

    // ---------------------------------------------------------------------------------------------
    // Envelope framing and bounds
    // ---------------------------------------------------------------------------------------------

    function test_envelope_trailingWordRejected() public {
        Scenario memory s = _returnScenario();
        _rejectsRaw(
            s, bytes.concat(_proof(s), bytes32(0)), abi.encodeWithSelector(EnvelopeFraming.selector)
        );
    }

    function test_envelope_truncatedRejected() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _proof(s);
        _rejectsRaw(
            s, _slice(p, 0, p.length - 32), abi.encodeWithSelector(EnvelopeFraming.selector)
        );
    }

    function test_envelope_unalignedLengthRejected() public {
        Scenario memory s = _returnScenario();
        _rejectsRaw(
            s, bytes.concat(_proof(s), hex"00"), abi.encodeWithSelector(EnvelopeFraming.selector)
        );
    }

    function _framingRejects(bytes memory p) internal {
        Scenario memory s = _returnScenario();
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    function test_envelope_dirtyPaddingOfEveryBytesFieldIsFraming() public {
        Scenario memory s = _returnScenario();
        bytes memory good = _proof(s);
        // the policy body, history, and an anchor's shard, uc and inputRecord each end in padding
        uint256 offAnchors = _getWord(good, 64);
        uint256 t = offAnchors + 32 + _getWord(good, offAnchors + 32);
        uint256[5] memory lens = [
            _getWord(good, _getWord(good, 0)),
            _getWord(good, _getWord(good, 32)),
            _getWord(good, t + _getWord(good, t + 32)),
            _getWord(good, t + _getWord(good, t + 160)),
            _getWord(good, t + _getWord(good, t + 192))
        ];
        uint256[5] memory offs = [
            _getWord(good, 0),
            _getWord(good, 32),
            t + _getWord(good, t + 32),
            t + _getWord(good, t + 160),
            t + _getWord(good, t + 192)
        ];
        for (uint256 i = 0; i < 5; ++i) {
            uint256 len = lens[i];
            if (len % 32 == 0) continue; // no padding to dirty
            bytes memory bad = _copy(good);
            bad[offs[i] + 32 + len] = 0x01; // first padding byte
            _framingRejects(bad);
        }
    }

    function test_envelope_aLeafProofOffsetOutOfPlaceIsFraming() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        uint256 offLeaves = _getWord(p, 96);
        // swap the first two leaf-proof offsets: a permutation the ABI decoder accepts
        uint256 a = _getWord(p, offLeaves + 32);
        uint256 b = _getWord(p, offLeaves + 64);
        p = _setWord(p, offLeaves + 32, b);
        p = _setWord(p, offLeaves + 64, a);
        _framingRejects(p);
    }

    function test_envelope_anAnchorOffsetOutOfPlaceIsFraming() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        uint256 offAnchors = _getWord(p, 64);
        uint256 a = _getWord(p, offAnchors + 32);
        uint256 b = _getWord(p, offAnchors + 64);
        p = _setWord(p, offAnchors + 32, b);
        p = _setWord(p, offAnchors + 64, a);
        _framingRejects(p);
    }

    function test_envelope_everyTupleOffsetWordMustBeCanonical() public {
        Scenario memory s = _returnScenario();
        bytes memory good = _proof(s);
        uint256 offAnchors = _getWord(good, 64);
        uint256 t = offAnchors + 32 + _getWord(good, offAnchors + 32);
        uint256[3] memory anchorWords = [t + 32, t + 160, t + 192];
        for (uint256 i = 0; i < 3; ++i) {
            bytes memory bad =
                _setWord(_copy(good), anchorWords[i], _getWord(good, anchorWords[i]) + 32);
            _framingRejects(bad);
        }
        uint256 offLeaves = _getWord(good, 96);
        uint256 l = offLeaves + 32 + _getWord(good, offLeaves + 32);
        _framingRejects(_setWord(_copy(good), l + 64, _getWord(good, l + 64) + 32));
        _framingRejects(_setWord(_copy(good), 0, 160));
        // the three body offsets of the head, each moved one word
        for (uint256 w = 32; w <= 96; w += 32) {
            _framingRejects(_setWord(_copy(good), w, _getWord(good, w) + 32));
        }
    }

    function test_envelope_aliasedAnchorFieldOffsetsAreFraming() public {
        Scenario memory s = _returnScenario();
        s.paths[0].bitmap = bytes32(uint256(3)); // a small word, so an aliased sibling count passes the bounds
        bytes memory good = _proof(s);
        uint256 offAnchors = _getWord(good, 64);
        uint256 t = offAnchors + 32 + _getWord(good, offAnchors + 32);
        // the certificate and the opening each aliased to the shard's (one-byte) data: in every bound
        _framingRejects(_setWord(_copy(good), t + 160, _getWord(good, t + 32)));
        _framingRejects(_setWord(_copy(good), t + 192, _getWord(good, t + 32)));
        // the shard aliased to the opening
        _framingRejects(_setWord(_copy(good), t + 32, _getWord(good, t + 192)));
        // the history aliased to the policy body, and the siblings of the first leaf to its bitmap word
        _framingRejects(_setWord(_copy(good), 32, _getWord(good, 0)));
        uint256 offLeaves = _getWord(good, 96);
        uint256 l = offLeaves + 32 + _getWord(good, offLeaves + 32);
        _framingRejects(_setWord(_copy(good), l + 64, 64));
    }

    function test_envelope_aReadPastTheEndAfterAValidHeadIsFraming() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _setWord(new bytes(128), 0, 128); // a canonical first word, then no room for the body
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    function test_envelope_aHugeLengthWordIsFramingNotAnArithmeticPanic() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _setWord(_copy(_proof(s)), 128, type(uint256).max);
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
        p = _setWord(_copy(_proof(s)), 128, 1 << 64);
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    function test_envelope_tooShortRejected() public {
        Scenario memory s = _returnScenario();
        _rejectsRaw(s, new bytes(96), abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    function test_envelope_noncanonicalOffsetRejected() public {
        // Move the history offset by one word, leaving a padding word between the bodies: the ABI
        // decoder accepts it, the re-encode comparison does not.
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        uint256 policyLen = s.policyBody.length;
        uint256 policyWords = (policyLen + 31) / 32;
        uint256 histOff = _getWord(p, 32);
        // insert a padding word before the history body and shift every later offset by 32
        bytes memory q =
            bytes.concat(_slice(p, 0, histOff), bytes32(0), _slice(p, histOff, p.length - histOff));
        q = _setWord(q, 32, histOff + 32);
        q = _setWord(q, 64, _getWord(p, 64) + 32);
        q = _setWord(q, 96, _getWord(p, 96) + 32);
        assertEq(policyWords > 0, true);
        _rejectsRaw(s, q, abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    function test_envelope_aliasedOffsetRejected() public {
        // Point the anchors and leaf proofs offsets at the same array: an alias the decoder would
        // follow, which cannot re-encode to the input.
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        p = _setWord(p, 96, _getWord(p, 64));
        _arm(s);
        vm.expectRevert(abi.encodeWithSelector(EnvelopeFraming.selector));
        v.verifyReturn(cfgB, p);
    }

    function test_envelope_offsetAtTheEndIsFraming() public {
        // The offset equals the length: in range for a naive bound, but no word can be read there.
        Scenario memory s = _returnScenario();
        bytes memory p = _setWord(_copy(_proof(s)), 64, _proof(s).length);
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
        p = _setWord(_copy(_proof(s)), 96, _proof(s).length - 31);
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    function test_envelope_countLargerThanTheDataIsFramingNotBudget() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        p = _setWord(p, _getWord(p, 64), 1 << 40);
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
        p = _setWord(_copy(_proof(s)), _getWord(p, 96), 1 << 40);
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    function test_envelope_hugeWordIsFraming() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _setWord(_copy(_proof(s)), 64, type(uint256).max);
        _rejectsRaw(s, p, abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    function test_envelope_tooManyAnchorsIsBudget() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        uint256 offAnchors = _getWord(p, 64);
        p = _setWord(p, offAnchors, BridgeBounds.MAX_ANCHORS + 1);
        _rejectsRaw(s, p, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_envelope_tooManyLeafProofsIsBudget() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        uint256 offLeaves = _getWord(p, 96);
        p = _setWord(p, offLeaves, BridgeBounds.MAX_LEAVES + 1);
        _rejectsRaw(s, p, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_envelope_aPathOverThePerLeafSiblingBoundIsBudget() public {
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        uint256 offLeaves = _getWord(p, 96);
        uint256 rel = _getWord(p, offLeaves + 32);
        uint256 t = offLeaves + 32 + rel;
        uint256 sOff = t + _getWord(p, t + 64);
        // One path over the per-leaf sibling bound is a budget refusal.
        p = _setWord(p, sOff, 33);
        _rejectsRaw(s, p, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_envelope_twoPathsOverThePerLeafSiblingBound() public {
        // Two paths each far over the per-leaf sibling bound.
        Scenario memory s = _returnScenario();
        bytes memory p = _copy(_proof(s));
        uint256 offLeaves = _getWord(p, 96);
        for (uint256 i = 0; i < 2; ++i) {
            uint256 rel = _getWord(p, offLeaves + 32 + 32 * i);
            uint256 t = offLeaves + 32 + rel;
            p = _setWord(p, t + _getWord(p, t + 64), 1025);
        }
        _rejectsRaw(s, p, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_envelope_oversizeIsBudget() public {
        Scenario memory s = _returnScenario();
        bytes memory p = new bytes(BridgeBounds.MAX_ENVELOPE_BYTES + 32);
        _rejectsRaw(s, p, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_envelope_atTheCapIsNotBudget() public {
        // MAX_ENVELOPE_BYTES (512 KiB) exactly is within the bound; it then fails as framing, not as a budget error.
        Scenario memory s = _returnScenario();
        assertEq(BridgeBounds.MAX_ENVELOPE_BYTES, 512 * 1024);
        _rejectsRaw(
            s,
            new bytes(BridgeBounds.MAX_ENVELOPE_BYTES),
            abi.encodeWithSelector(EnvelopeFraming.selector)
        );
    }

    function test_envelope_historyOverCapIsBudget() public {
        Scenario memory s = _returnScenario();
        s.history = new bytes(BridgeBounds.MAX_SEMANTIC_BYTES + 1);
        // the kernel never runs; the cap is checked on the opened history
        _rejects(s, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_envelope_historyAtTheSemanticCapReachesTheKernel() public {
        // 16 KiB exactly is within budget; the double answers the
        // golden result for exactly these bytes, so the whole relation completes.
        Scenario memory s = _returnScenario();
        s.history = new bytes(16 * 1024);
        assertTrue(_sameResult(_run(s), s.result));
    }

    // ---------------------------------------------------------------------------------------------
    // Policy carrier
    // ---------------------------------------------------------------------------------------------

    function test_policy_hashMismatch() public {
        Scenario memory s = _returnScenario();
        bytes memory body = _copy(s.policyBody);
        body[body.length - 1] = body[body.length - 1] ^ 0x01;
        s.policyBody = body;
        _rejects(
            s,
            abi.encodeWithSelector(
                PolicyHashMismatch.selector, _goldenCfg().aggregatorPolicyHash, sha256(body)
            )
        );
    }

    /// @dev The scenario with another policy body: the Cfg pins its SHA-256 (so only strict decoding can refuse it) and the kernel
    ///      result names the new Cfg's hash.
    function _withPolicyBody(Scenario memory s, bytes memory body) internal view {
        Cfg memory c = _goldenCfg();
        c.aggregatorPolicyHash = sha256(body);
        s.cfgB = BridgeProfile.encodeCfg(c);
        s.policyBody = body;
        s.result.cfg = BridgeProfile.cfgHash(s.cfgB);
    }

    /// @dev A policy body assembled from raw parts: array(3), the 24-byte domain as a byte string, the version item, the partition item.
    function _rawPolicy(bytes memory domain, bytes memory version, bytes memory partition)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(hex"83", hex"5818", domain, version, partition);
    }

    function _rejectsPolicy(bytes memory body, bytes memory err) internal {
        Scenario memory s = _returnScenario();
        _withPolicyBody(s, body);
        _rejects(s, err);
    }

    function test_policy_theIndependentBuilderIsTheCanonicalBody() public pure {
        assertEq(_rawPolicy("UNICITY_BR_AGG_PARTITION", hex"02", hex"0b"), _policyV2(11));
        assertEq(_policyV2(11), hex"835818554e49434954595f42525f4147475f504152544954494f4e020b");
    }

    function test_policy_nonShortestPartitionWithMatchingHash() public {
        _rejectsPolicy(
            _rawPolicy("UNICITY_BR_AGG_PARTITION", hex"02", hex"180b"),
            abi.encodeWithSelector(PolicyMalformed.selector)
        );
    }

    function test_policy_wrongDomainWithMatchingHash() public {
        _rejectsPolicy(
            _rawPolicy("UNICITY_BR_AGG_PARTITIOX", hex"02", hex"0b"),
            abi.encodeWithSelector(PolicyMalformed.selector)
        );
        // the protocol-3 sharded domain, even at the right length, is no policy of this protocol
        _rejectsPolicy(
            _rawPolicy("UNICITY_BR_AGG_SHARDED\x00\x00", hex"02", hex"0b"),
            abi.encodeWithSelector(PolicyMalformed.selector)
        );
    }

    function test_policy_versionsOtherThanTwoAreRefused() public {
        // version 1 passes the reader's bound and fails the canonical comparison; version 3 is above the reader's bound
        _rejectsPolicy(
            _rawPolicy("UNICITY_BR_AGG_PARTITION", hex"01", hex"0b"),
            abi.encodeWithSelector(PolicyMalformed.selector)
        );
        _rejectsPolicy(
            _rawPolicy("UNICITY_BR_AGG_PARTITION", hex"03", hex"0b"),
            abi.encodeWithSelector(CborMalformed.selector)
        );
    }

    function test_policy_partitionZero() public {
        _rejectsPolicy(
            _rawPolicy("UNICITY_BR_AGG_PARTITION", hex"02", hex"00"),
            abi.encodeWithSelector(PolicyMalformed.selector)
        );
    }

    function test_policy_aLegacyShardedBodyIsRefused() public {
        // the protocol-3 body: five items with a depth and a row table
        _rejectsPolicy(
            hex"8556554e49434954595f42525f4147475f53484152444544010b0081824180582000000000000000000000000000000000000000000000000000000000000000ff",
            abi.encodeWithSelector(CborMalformed.selector)
        );
    }

    function test_policy_missingBody() public {
        Scenario memory s = _returnScenario();
        s.policyBody = "";
        _rejects(
            s,
            abi.encodeWithSelector(
                PolicyHashMismatch.selector, _goldenCfg().aggregatorPolicyHash, sha256("")
            )
        );
    }

    function test_policy_oversizeBody() public {
        Scenario memory s = _returnScenario();
        s.policyBody = new bytes(513);
        _rejects(s, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_policy_trailingByteWithMatchingHash() public {
        // The hash opens correctly, so only strict decoding can refuse it.
        Scenario memory s = _returnScenario();
        _withPolicyBody(s, bytes.concat(s.policyBody, hex"00"));
        _rejects(s, abi.encodeWithSelector(PolicyMalformed.selector));
    }

    function test_policy_partitionEqualToEvmPartition() public {
        Scenario memory s = _returnScenario();
        Policy memory p = BridgeProfile.decodePolicy(s.policyBody);
        p.partition = 7; // Cfg.evmPartition
        _withPolicyBody(s, BridgeProfile.encodePolicy(p));
        _rejects(s, abi.encodeWithSelector(PolicyPartitionIsEvm.selector));
    }

    function test_policy_anchorCountZero() public {
        Scenario memory s = _returnScenario();
        s.anchors = new Anchor[](0);
        _rejects(s, abi.encodeWithSelector(PolicyAnchorCount.selector, 0));
    }

    function test_policy_anchorCountOverTheProfileBound() public {
        Scenario memory s = _returnScenario();
        Anchor[] memory five = new Anchor[](BridgeBounds.MAX_ANCHORS + 1);
        for (uint256 j = 0; j < five.length; ++j) {
            five[j] = s.anchors[j % 2];
        }
        s.anchors = five;
        // Refused from the envelope's declared count, before anything is allocated.
        _rejects(s, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    function test_policy_moreAnchorsThanLeaves() public {
        Scenario memory s = _mintScenario();
        Anchor[] memory two = new Anchor[](2);
        two[0] = s.anchors[0];
        two[1] = s.anchors[0];
        s.anchors = two;
        _rejects(s, abi.encodeWithSelector(PolicyAnchorCount.selector, 2));
    }

    function test_policy_identicalUcBytesAreOneAnchorNeverTwo() public {
        Scenario memory s = _returnScenario();
        s.anchors[1] = s.anchors[0];
        _rejects(s, abi.encodeWithSelector(PolicyAnchorDuplicate.selector, 1));
    }

    function testFuzz_popcountIsTheNumberOfSetBits(uint256 x) public pure {
        uint256 n;
        for (uint256 y = x; y != 0; y &= y - 1) {
            ++n;
        }
        assertEq(BridgeBounds.popcount(x), n);
        assertEq(BridgeBounds.popcount(type(uint256).max), 256);
        assertEq(BridgeBounds.popcount(0), 0);
    }

    function test_policy_leafCountMismatch() public {
        Scenario memory s = _returnScenario();
        LeafProof[] memory two = new LeafProof[](2);
        two[0] = s.paths[0];
        two[1] = s.paths[1];
        s.paths = two;
        _rejects(s, abi.encodeWithSelector(PolicyLeafCount.selector, 3, 2));
    }

    function test_policy_extraLeafProof() public {
        Scenario memory s = _returnScenario();
        LeafProof[] memory four = new LeafProof[](4);
        for (uint256 i = 0; i < 3; ++i) {
            four[i] = s.paths[i];
        }
        four[3] = s.paths[0];
        s.paths = four;
        _rejects(s, abi.encodeWithSelector(PolicyLeafCount.selector, 3, 4));
    }

    function test_policy_leafNamesAnAnchorOfAnotherShard() public {
        Scenario memory s = _returnScenario();
        s.paths[2].anchorIndex = 0; // leaf 2 belongs to the second anchor's shard
        _rejects(s, abi.encodeWithSelector(PolicyLeafIndex.selector, 2, 0));
    }

    function test_policy_leafIndexOutOfRange() public {
        Scenario memory s = _returnScenario();
        s.paths[2].anchorIndex = 2;
        _rejects(s, abi.encodeWithSelector(PolicyLeafIndex.selector, 2, 2));
    }

    function test_policy_anchorsNotInFirstUseOrder() public {
        Scenario memory s = _returnScenario();
        Anchor memory t = s.anchors[0];
        s.anchors[0] = s.anchors[1];
        s.anchors[1] = t;
        s.paths[0].anchorIndex = 1;
        s.paths[1].anchorIndex = 1;
        s.paths[2].anchorIndex = 0;
        _rejects(s, abi.encodeWithSelector(PolicyLeafIndex.selector, 0, 1));
    }

    /// @dev The kernel double lets a test choose the leaf shards: all three leaves in the first
    ///      anchor's shard, so the second anchor (a different UC of the same shard) is never used.
    function _sameShardScenario() internal view returns (Scenario memory s) {
        s = _returnScenario();
        uint256 row0 = uint8(s.anchors[0].shard[0]) >> 7;
        for (uint256 i = 0; i < 3; ++i) {
            bytes32 sid = s.result.leaves[i].sid;
            s.result.leaves[i].sid =
                row0 == 1 ? sid | bytes32(uint256(1) << 255) : sid & ~bytes32(uint256(1) << 255);
            s.paths[i].anchorIndex = 0;
        }
        // the second golden anchor stays as it is (a valid UC of the other shard) and no leaf names it: it is unused
    }

    /// @dev The return relation under one anchor: every leaf in the first anchor's shard. The
    ///      InputRecord and time tests vary that single anchor.
    function _oneAnchorReturn() internal view returns (Scenario memory s) {
        s = _sameShardScenario();
        Anchor[] memory one = new Anchor[](1);
        one[0] = s.anchors[0];
        s.anchors = one;
    }

    function test_policy_aLeafIndexPastTheLastAnchorIsRefusedEvenWhenAllAreUsed() public {
        // One anchor, every leaf under it, then a leaf naming index 1 = the table length.
        Scenario memory s = _oneAnchorReturn();
        s.paths[2].anchorIndex = 1;
        _rejects(s, abi.encodeWithSelector(PolicyLeafIndex.selector, 2, 1));
    }

    function test_policy_unusedAnchorIsRefused() public {
        Scenario memory s = _sameShardScenario();
        _rejects(s, abi.encodeWithSelector(PolicyAnchorUnused.selector, 1));
    }

    function test_policy_mintNeedsExactlyOnePath() public {
        Scenario memory s = _mintScenario();
        LeafProof[] memory none = new LeafProof[](0);
        s.paths = none;
        _rejects(s, abi.encodeWithSelector(PolicyLeafCount.selector, 1, 0));
    }

    // ---------------------------------------------------------------------------------------------
    // Kernel output and result shape
    // ---------------------------------------------------------------------------------------------

    function test_kernel_inactiveAddressEmptyOutput() public {
        Scenario memory s = _returnScenario();
        vm.etch(B1Calls.KERNEL, "");
        vm.expectRevert(abi.encodeWithSelector(KernelBadOutput.selector));
        v.verifyReturn(cfgB, _proof(s));
    }

    function test_kernel_revertIsPrecompileFailed() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        _progRevert(B1Calls.KERNEL, _kernelInput(2, cfgB, s.history));
        vm.expectRevert(abi.encodeWithSelector(PrecompileFailed.selector, B1Calls.KERNEL));
        v.verifyReturn(cfgB, _proof(s));
    }

    function test_kernel_exactInputBytes() public {
        // Programmed only for the oracle's input bytes: a different cfg/history/op would revert.
        Scenario memory s = _returnScenario();
        _arm(s);
        vm.expectCall(B1Calls.KERNEL, _b(".return.kernelInput"), 1);
        _call(s);
    }

    function _kernelRejects(Scenario memory s, bytes memory out, bytes memory err) internal {
        s.kernelOut = out;
        _rejects(s, err);
    }

    function test_kernel_wrongMarker() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _copy(_b(".return.kernelOutput"));
        o[0] = 0x00;
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
    }

    function test_kernel_invalidIsRejectedNotBad() public {
        Scenario memory s = _returnScenario();
        _kernelRejects(s, _b(".invalidOutput"), abi.encodeWithSelector(KernelRejected.selector));
    }

    function test_kernel_validWordNotBool() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _setWord(_copy(_b(".return.kernelOutput")), 32, 2);
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
    }

    function test_kernel_resultOffsetNotCanonical() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _setWord(_copy(_b(".return.kernelOutput")), 64, 0x80);
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
    }

    function test_kernel_leavesOffsetNotCanonical() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _setWord(_copy(_b(".return.kernelOutput")), 384, 0x160);
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
    }

    function test_kernel_leafCountDisagreesWithLength() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _setWord(_copy(_b(".return.kernelOutput")), 416, 2);
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
    }

    function test_kernel_leafCountOverCap() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _setWord(_copy(_b(".return.kernelOutput")), 416, 66);
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
    }

    function test_kernel_hugeLeafCountDoesNotOverflow() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _setWord(_copy(_b(".return.kernelOutput")), 416, type(uint256).max);
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
        o = _setWord(_copy(_b(".return.kernelOutput")), 416, 1 << 250);
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
    }

    function test_kernel_everyTruncationIsBadOutput() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        bytes memory o = _b(".return.kernelOutput");
        bytes memory kin = _kernelInput(2, cfgB, s.history);
        for (uint256 i = 0; i < o.length; i += 17) {
            _prog(B1Calls.KERNEL, kin, _slice(o, 0, i));
            vm.expectRevert(abi.encodeWithSelector(KernelBadOutput.selector));
            v.verifyReturn(cfgB, _proof(s));
        }
    }

    function test_kernel_extraTrailingWord() public {
        Scenario memory s = _returnScenario();
        _kernelRejects(
            s,
            bytes.concat(_b(".return.kernelOutput"), bytes32(0)),
            abi.encodeWithSelector(KernelBadOutput.selector)
        );
    }

    function test_kernel_shortOutput() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _b(".return.kernelOutput");
        _kernelRejects(
            s, _slice(o, 0, o.length - 32), abi.encodeWithSelector(KernelBadOutput.selector)
        );
    }

    function test_kernel_unalignedOutput() public {
        Scenario memory s = _returnScenario();
        _kernelRejects(
            s,
            bytes.concat(_b(".return.kernelOutput"), hex"00"),
            abi.encodeWithSelector(KernelBadOutput.selector)
        );
    }

    function test_kernel_releaseToHighBitsDirty() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _setWord(
            _copy(_b(".return.kernelOutput")), 320, (1 << 160) | uint160(s.result.releaseTo)
        );
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
    }

    function test_kernel_oversizeReturndataIsBoundedBeforeCopy() public {
        Scenario memory s = _returnScenario();
        _kernelRejects(
            s,
            new bytes(448 + 128 * 65 + 32),
            abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.KERNEL)
        );
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
        Leaf[] memory one = new Leaf[](1);
        one[0] = s.result.leaves[0];
        s.result.leaves = one;
        LeafProof[] memory p = new LeafProof[](1);
        p[0] = s.paths[0];
        s.paths = p;
        _rejects(s, abi.encodeWithSelector(KernelResultShape.selector));
    }

    function test_shape_returnOverLeafCap() public {
        Scenario memory s = _returnScenario();
        s.result.leaves = new Leaf[](66);
        _rejects(s, abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.KERNEL));
    }

    function test_shape_mintWithTwoLeaves() public {
        Scenario memory s = _mintScenario();
        Leaf[] memory two = new Leaf[](2);
        two[0] = s.result.leaves[0];
        two[1] = s.result.leaves[0];
        s.result.leaves = two;
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
        r.leaves = new Leaf[](1);
        _prog(B1Calls.KERNEL, _b(".prepare.kernelInput"), _kernelOut(true, r));
        vm.expectRevert(abi.encodeWithSelector(KernelResultShape.selector));
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

    // ---------------------------------------------------------------------------------------------
    // B1 outcomes
    // ---------------------------------------------------------------------------------------------

    function _b1Rejects(Scenario memory s, address target, bytes memory out, bytes memory err)
        internal
    {
        _arm(s);
        if (target == B1Calls.CERT_BATCH) {
            _prog(target, _expectedBatch(s.anchors), out);
        }
        vm.expectRevert(err);
        v.verifyReturn(s.cfgB, _proof(s));
    }

    function test_b1_inactiveRsmtAddressIsBadReturn() public {
        Scenario memory s = _returnScenario();
        _armExcept(s, B1Calls.RSMT_VERIFIER);
        vm.etch(B1Calls.RSMT_VERIFIER, "");
        vm.expectRevert(abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.RSMT_VERIFIER));
        v.verifyReturn(cfgB, _proof(s));
    }

    function test_b1_rsmtFalseNamesTheLeaf() public {
        for (uint256 k = 0; k < 3; ++k) {
            Scenario memory s = _returnScenario();
            _arm(s);
            bytes memory req = _expectedRSMT(
                _rootOf(s, k), s.result.leaves[k].sid, s.result.leaves[k].leafValue, s.paths[k]
            );
            _prog(B1Calls.RSMT_VERIFIER, req, FALSE_OUT);
            vm.expectRevert(abi.encodeWithSelector(LeafNotIncluded.selector, k));
            v.verifyReturn(cfgB, _proof(s));
        }
    }

    function test_b1_rsmtBadReturnShapes() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        bytes memory req = _expectedRSMT(
            _rootOf(s, 1), s.result.leaves[1].sid, s.result.leaves[1].leafValue, s.paths[1]
        );
        bytes[4] memory bad = [
            bytes(""),
            abi.encode(uint256(1)),
            bytes.concat(TRUE_OUT, hex"00"),
            abi.encode(uint256(3), true)
        ];
        for (uint256 i = 0; i < bad.length; ++i) {
            _prog(B1Calls.RSMT_VERIFIER, req, bad[i]);
            vm.expectRevert(
                abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.RSMT_VERIFIER)
            );
            v.verifyReturn(cfgB, _proof(s));
        }
    }

    function test_b1_rsmtHaltIsFailureNotFalse() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        bytes memory req = _expectedRSMT(
            _rootOf(s, 0), s.result.leaves[0].sid, s.result.leaves[0].leafValue, s.paths[0]
        );
        _progRevert(B1Calls.RSMT_VERIFIER, req);
        vm.expectRevert(abi.encodeWithSelector(PrecompileFailed.selector, B1Calls.RSMT_VERIFIER));
        v.verifyReturn(cfgB, _proof(s));
    }

    function test_b1_rsmtUsesTheAnchorStateRootNotAnotherRoot() public {
        // Every RSMT path is verified under the UC's authenticated shard state root. A double that
        // knows only a request with another root is never reached: the real request is unprogrammed.
        Scenario memory s = _returnScenario();
        _arm(s);
        bytes memory req = _expectedRSMT(
            _rootOf(s, 0), s.result.leaves[0].sid, s.result.leaves[0].leafValue, s.paths[0]
        );
        _progRevert(B1Calls.RSMT_VERIFIER, req);
        bytes memory other = _expectedRSMT(
            keccak256("other root"),
            s.result.leaves[0].sid,
            s.result.leaves[0].leafValue,
            s.paths[0]
        );
        _prog(B1Calls.RSMT_VERIFIER, other, TRUE_OUT);
        vm.expectRevert(abi.encodeWithSelector(PrecompileFailed.selector, B1Calls.RSMT_VERIFIER));
        v.verifyReturn(cfgB, _proof(s));
    }

    // ---- gas gate and forwarded gas --------------------------------------------------------------

    // The former `test_gas_worstBundleVerifierOverheadFitsTheReserve` (a bundle at every cap) is gone: after the repricing the gate
    // prices that bundle out (9.9M, see `test_gate_twoMaximumAnchorBundleAtEveryCapIsPricedOutToTheOracleUnit`), and the union test
    // above measures the verifier's overhead on the largest bundle the gate admits.

    function test_gate_bitmapPopcountMustEqualTheSiblingCount() public {
        Scenario memory s = _returnScenario();
        s.paths[1].bitmap = bytes32(uint256(s.paths[1].bitmap) | 1 << 255 | 1);
        _rejects(s, abi.encodeWithSelector(PathBitmapMismatch.selector, 1));
    }

    // ---------------------------------------------------------------------------------------------
    // Fuzz
    // ---------------------------------------------------------------------------------------------

    /// @dev Every single-byte change to a valid envelope is refused: all of its bytes are canonical
    ///      and each reaches the kernel, the policy or an exact B1 request.
    function testFuzz_anyEnvelopeByteFlipIsRefused(uint256 pos, uint8 flip) public {
        Scenario memory s = _returnScenario();
        _arm(s);
        bytes memory p = _copy(_proof(s));
        pos = bound(pos, 0, p.length - 1);
        flip = uint8(bound(flip, 1, 255));
        p[pos] = bytes1(uint8(p[pos]) ^ flip);
        try v.verifyReturn(cfgB, p) {
            revert("mutated envelope accepted");
        } catch (bytes memory err) {
            assertTrue(
                _isNamedError(bytes4(err)),
                "refused with a named error, not a panic or empty revert"
            );
        }
    }

    /// @dev Every error the verifier can raise; a Panic or an empty revert is not among them.
    function _isNamedError(bytes4 sel) internal pure returns (bool) {
        return sel == CborMalformed.selector || sel == CfgMalformed.selector
            || sel == PolicyMalformed.selector || sel == EnvelopeFraming.selector
            || sel == BudgetExceeded.selector || sel == KernelBadOutput.selector
            || sel == ChainIdMismatch.selector || sel == WrongVerifier.selector
            || sel == KernelCfgMismatch.selector || sel == PolicyHashMismatch.selector
            || sel == PolicyAnchorCount.selector || sel == PolicyTupleMismatch.selector
            || sel == PolicyLeafCount.selector || sel == PolicyLeafIndex.selector
            || sel == PolicyPartitionIsEvm.selector || sel == KernelRejected.selector
            || sel == KernelResultShape.selector || sel == PrecompileFailed.selector
            || sel == PrecompileBadReturn.selector || sel == UCRejected.selector
            || sel == LeafNotIncluded.selector || sel == IRBadOpening.selector
            || sel == IRMalformed.selector || sel == IRStateMismatch.selector
            || sel == IRTimeAfterAnchor.selector || sel == PolicyAnchorDuplicate.selector
            || sel == PolicyAnchorUnused.selector || sel == UCScanRejected.selector
            || sel == PathBitmapMismatch.selector;
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

    // ---------------------------------------------------------------------------------------------
    // InputRecord opening and the reference-time comparison (SDK 3.0.1)
    // ---------------------------------------------------------------------------------------------

    /// @dev Installs `ir` as the anchor's opening, with its hash as the anchor's expected IR hash, so
    ///      the opening is internally consistent and only the check under test can refuse it.
    function _withIR(Scenario memory s, bytes memory ir) internal pure {
        s.anchors[0].inputRecord = ir;
        s.anchors[0].expectedIRHash = sha256(ir);
    }

    /// @dev A well-formed opening of the anchor's state root at timestamp `ts`.
    function _irAt(Scenario memory s, uint256 ts) internal pure returns (bytes memory) {
        bytes[10] memory p = _parts();
        p[4] = _h32(s.anchors[0].expectedStateRoot);
        p[6] = _uint(ts);
        return _build(TAG_ARRAY10, p);
    }

    function _latest(Scenario memory s) internal pure returns (uint64 m) {
        for (uint256 i = 0; i < s.result.leaves.length; ++i) {
            if (s.result.leaves[i].referenceTime > m) m = s.result.leaves[i].referenceTime;
        }
    }

    function test_ir_goldenOpeningIsTheOracleCertifiedOne() public view {
        // The anchors carry the oracle's real InputRecord: its hash is the anchor's IR hash, its
        // state hash the anchor's state root, and its time the one the oracle certified at.
        string[2] memory ops = ["mint", "return"];
        for (uint256 i = 0; i < 2; ++i) {
            Anchor[] memory as_ = _goldenAnchors(ops[i]);
            for (uint256 j = 0; j < as_.length; ++j) {
                assertEq(sha256(as_[j].inputRecord), as_[j].expectedIRHash, "hash");
                assertGt(as_[j].inputRecord.length, 0);
                assertLe(as_[j].inputRecord.length, 512);
            }
        }
        Scenario memory s = _oneAnchorReturn();
        assertEq(
            uint256(_latest(s)) + 5, vm.parseJsonUint(G, ".return.envelope.irTime"), "return time"
        );
        assertEq(_latest(s), vm.parseJsonUint(G, ".return.maxReferenceTime"));
    }

    function test_ir_eachLeafIsBoundedByItsOwnAnchorsTime() public {
        // Leaf 2 is served by the second anchor: its time bounds it, not the first anchor's.
        Scenario memory s = _returnScenario();
        uint64 late = _latest(s);
        s.anchors[0].inputRecord = _irFor(s.anchors[0], late);
        s.anchors[0].expectedIRHash = sha256(s.anchors[0].inputRecord);
        s.anchors[1].inputRecord = _irFor(s.anchors[1], late - 1);
        s.anchors[1].expectedIRHash = sha256(s.anchors[1].inputRecord);
        _rejects(s, abi.encodeWithSelector(IRTimeAfterAnchor.selector, 2, late, late - 1));
        // and the converse: a late second anchor does not excuse an early first one
        s = _returnScenario();
        s.anchors[0].inputRecord = _irFor(s.anchors[0], s.result.leaves[0].referenceTime - 1);
        s.anchors[0].expectedIRHash = sha256(s.anchors[0].inputRecord);
        s.anchors[1].inputRecord = _irFor(s.anchors[1], late);
        s.anchors[1].expectedIRHash = sha256(s.anchors[1].inputRecord);
        _rejects(
            s,
            abi.encodeWithSelector(
                IRTimeAfterAnchor.selector,
                0,
                s.result.leaves[0].referenceTime,
                s.result.leaves[0].referenceTime - 1
            )
        );
    }

    function test_ir_timeEqualToTheLatestLeafIsAccepted() public {
        Scenario memory s = _oneAnchorReturn();
        _withIR(s, _irAt(s, _latest(s)));
        assertTrue(_sameResult(_run(s), s.result));
        Scenario memory m = _mintScenario();
        _withIR(m, _irAt(m, _latest(m)));
        assertTrue(_sameResult(_run(m), m.result));
    }

    function test_ir_timeOneBelowTheLatestLeafIsRejected() public {
        Scenario memory s = _oneAnchorReturn();
        uint64 t = _latest(s);
        _withIR(s, _irAt(s, t - 1));
        // leaves are certified at BaseTime + 10 i; the third one is the latest
        _rejects(s, abi.encodeWithSelector(IRTimeAfterAnchor.selector, 2, t, t - 1));
        Scenario memory m = _mintScenario();
        uint64 tm = _latest(m);
        _withIR(m, _irAt(m, tm - 1));
        _rejects(m, abi.encodeWithSelector(IRTimeAfterAnchor.selector, 0, tm, tm - 1));
    }

    function test_ir_theFirstViolatingLeafIsNamed() public {
        for (uint256 k = 0; k < 3; ++k) {
            Scenario memory s = _oneAnchorReturn();
            uint64 ts = 1_000;
            for (uint256 i = 0; i < 3; ++i) {
                s.result.leaves[i].referenceTime = i < k ? ts : (i == k ? ts + 1 : ts + 7);
            }
            _withIR(s, _irAt(s, ts));
            if (k == 0) {
                _rejects(s, abi.encodeWithSelector(IRTimeAfterAnchor.selector, 0, ts + 1, ts));
            } else {
                // leaves before k sit exactly at the bound; leaf k is the first past it
                _rejects(s, abi.encodeWithSelector(IRTimeAfterAnchor.selector, k, ts + 1, ts));
            }
        }
    }

    function test_ir_leafTimesBelowTheBoundAreAccepted() public {
        Scenario memory s = _oneAnchorReturn();
        s.result.leaves[0].referenceTime = 0;
        s.result.leaves[1].referenceTime = 1;
        s.result.leaves[2].referenceTime = 2;
        _withIR(s, _irAt(s, 2));
        assertTrue(_sameResult(_run(s), s.result));
    }

    function test_ir_u64Extremes() public {
        Scenario memory s = _oneAnchorReturn();
        for (uint256 i = 0; i < 3; ++i) {
            s.result.leaves[i].referenceTime = type(uint64).max;
        }
        _withIR(s, _irAt(s, type(uint64).max));
        assertTrue(_sameResult(_run(s), s.result));
        Scenario memory t = _oneAnchorReturn();
        t.result.leaves[2].referenceTime = type(uint64).max;
        _withIR(t, _irAt(t, type(uint64).max - 1));
        _rejects(
            t,
            abi.encodeWithSelector(
                IRTimeAfterAnchor.selector, 2, type(uint64).max, type(uint64).max - 1
            )
        );
    }

    function test_ir_noRsmtCallBeforeTheTimeCheck() public {
        Scenario memory s = _oneAnchorReturn();
        _withIR(s, _irAt(s, _latest(s) - 1));
        _arm(s);
        vm.expectCall(B1Calls.RSMT_VERIFIER, hex"01000001", 0);
        vm.expectRevert(
            abi.encodeWithSelector(IRTimeAfterAnchor.selector, 2, _latest(s), _latest(s) - 1)
        );
        v.verifyReturn(cfgB, _proof(s));
    }

    /// @dev The bound is exactly `t <= IR.timestamp` for every leaf, and the first violator is named.
    function testFuzz_ir_theTimeBoundIsExactlyLeafTimeAtMostAnchorTime(
        uint64 ts,
        uint64 t0,
        uint64 t1,
        uint64 t2
    ) public {
        Scenario memory s = _oneAnchorReturn();
        s.result.leaves[0].referenceTime = t0;
        s.result.leaves[1].referenceTime = t1;
        s.result.leaves[2].referenceTime = t2;
        _withIR(s, _irAt(s, ts));
        _arm(s);
        uint256 bad = type(uint256).max;
        if (t0 > ts) bad = 0;
        else if (t1 > ts) bad = 1;
        else if (t2 > ts) bad = 2;
        if (bad == type(uint256).max) {
            assertTrue(_sameResult(_call(s), s.result));
        } else {
            bytes memory proof = _proof(s);
            vm.expectRevert(
                abi.encodeWithSelector(
                    IRTimeAfterAnchor.selector, bad, s.result.leaves[bad].referenceTime, ts
                )
            );
            v.verifyReturn(cfgB, proof);
        }
    }

    function test_ir_aStaleOpeningIsRefusedByTimeNotAcceptedByAge() public {
        // An opening far in the past of every leaf: refused. The check is the authenticated time
        // against t, never the current block time.
        Scenario memory s = _oneAnchorReturn();
        vm.warp(type(uint40).max);
        _withIR(s, _irAt(s, 1));
        _rejects(
            s,
            abi.encodeWithSelector(
                IRTimeAfterAnchor.selector, 0, s.result.leaves[0].referenceTime, 1
            )
        );
    }

    // ---- the opening carries weight only after B1 0x0100 -----------------------------------------

    // ---- the binding of the opening to the authenticated pair ------------------------------------

    function test_ir_aTimestampLieWithTheSameHashIsBadOpening() public {
        // The anchor's hash is the real one; the prover offers an opening with a far-future time.
        Scenario memory s = _oneAnchorReturn();
        bytes memory real = s.anchors[0].inputRecord;
        bytes[10] memory p = _parts();
        p[4] = _h32(s.anchors[0].expectedStateRoot);
        p[6] = _uint(1 << 60);
        s.anchors[0].inputRecord = _build(TAG_ARRAY10, p);
        assertEq(s.anchors[0].expectedIRHash, sha256(real));
        _rejects(s, abi.encodeWithSelector(IRBadOpening.selector));
    }

    function test_ir_aHashThatIsNotTheOpeningsIsBadOpening() public {
        Scenario memory s = _oneAnchorReturn();
        s.anchors[0].expectedIRHash = keccak256("another hash");
        _rejects(s, abi.encodeWithSelector(IRBadOpening.selector));
        // the same opening, one byte changed
        Scenario memory t = _oneAnchorReturn();
        t.anchors[0].inputRecord[t.anchors[0].inputRecord.length - 2] ^= 0x01;
        _rejects(t, abi.encodeWithSelector(IRBadOpening.selector));
    }

    function test_ir_theOpenedStateMustBeTheExpectedStateRoot() public {
        Scenario memory s = _oneAnchorReturn();
        bytes[10] memory p = _parts();
        bytes32 other = keccak256("another state");
        p[4] = _h32(other);
        p[6] = _uint(_latest(s));
        _withIR(s, _build(TAG_ARRAY10, p));
        _rejects(
            s,
            abi.encodeWithSelector(IRStateMismatch.selector, s.anchors[0].expectedStateRoot, other)
        );
    }

    function test_ir_missingOpeningIsMalformed() public {
        Scenario memory s = _oneAnchorReturn();
        _withIR(s, hex"");
        _rejects(s, abi.encodeWithSelector(IRMalformed.selector));
        Scenario memory m = _mintScenario();
        _withIR(m, hex"");
        _rejects(m, abi.encodeWithSelector(IRMalformed.selector));
    }

    function test_ir_malformedOpeningWithMatchingHashIsMalformed() public {
        Scenario memory s = _oneAnchorReturn();
        bytes memory ok = _irAt(s, _latest(s));
        _withIR(s, bytes.concat(ok, hex"00")); // trailing byte
        _rejects(s, abi.encodeWithSelector(IRMalformed.selector));
        Scenario memory t = _oneAnchorReturn();
        bytes[10] memory p = _parts();
        p[4] = _h32(t.anchors[0].expectedStateRoot);
        p[6] = hex"1800"; // not shortest
        _withIR(t, _build(TAG_ARRAY10, p));
        _rejects(t, abi.encodeWithSelector(IRMalformed.selector));
    }

    function test_ir_boundIsReadBeforeAnythingIsAllocated() public {
        // 512 bytes is within budget and fails as an opening; 513 is over budget.
        Scenario memory s = _oneAnchorReturn();
        s.anchors[0].inputRecord = new bytes(512);
        _rejects(s, abi.encodeWithSelector(IRBadOpening.selector));
        Scenario memory t = _oneAnchorReturn();
        t.anchors[0].inputRecord = new bytes(513);
        _rejects(t, abi.encodeWithSelector(BudgetExceeded.selector));
        // A declared length far beyond the data is read from the head words and refused as budget,
        // before the ABI decoder could be asked to allocate it.
        Scenario memory u = _oneAnchorReturn();
        bytes memory proof = _proof(u);
        uint256 offAnchors = _getWord(proof, 64);
        uint256 tuple = offAnchors + 32 + _getWord(proof, offAnchors + 32);
        uint256 lenWord = tuple + _getWord(proof, tuple + 192);
        proof = _setWord(proof, lenWord, 1 << 40);
        _rejectsRaw(u, proof, abi.encodeWithSelector(BudgetExceeded.selector));
        proof = _setWord(_proof(u), lenWord, 1 << 70);
        _rejectsRaw(u, proof, abi.encodeWithSelector(EnvelopeFraming.selector));
    }

    // ---- 0x0102 takes the raw leaf value ---------------------------------------------------------

    function test_member_theValueIsTheRawLeafValueNotTheTxHash() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        for (uint256 i = 0; i < 3; ++i) {
            string memory p = string.concat(".return.envelope.members[", vm.toString(i), "]");
            bytes memory real = _b(string.concat(p, ".request"));
            bytes memory old = _b(string.concat(p, ".txHashRequest"));
            // the verifier's request is the oracle's, and is not the request for the txHash
            assertEq(
                _expectedRSMT(
                    _rootOf(s, i), s.result.leaves[i].sid, s.result.leaves[i].leafValue, s.paths[i]
                ),
                real
            );
            assertTrue(keccak256(real) != keccak256(old));
            // the reference B1 refuses the old value, and the verifier never sends it
            _prog(B1Calls.RSMT_VERIFIER, old, FALSE_OUT);
            vm.expectCall(B1Calls.RSMT_VERIFIER, old, 0);
            vm.expectCall(B1Calls.RSMT_VERIFIER, real, 1);
        }
        _call(s);
    }

    // ---- kernel output stride 128 ----------------------------------------------------------------

    function test_kernel_strideIsFourWordsPerLeaf() public view {
        // golden outputs are 448 + 128 m bytes for m = 0, 1, 3
        assertEq(_b(".prepare.kernelOutput").length, 448);
        assertEq(_b(".mint.kernelOutput").length, 448 + 128);
        assertEq(_b(".return.kernelOutput").length, 448 + 128 * 3);
    }

    function test_kernel_oldStrideOutputIsRefused() public {
        // Three leaves in the pre-3.0.1 two-word layout: count 3, 448 + 64*3 bytes.
        Scenario memory s = _returnScenario();
        bytes memory o = _slice(_b(".return.kernelOutput"), 0, 448 + 64 * 3);
        _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
        // and one leaf in the old layout under a count of one
        Scenario memory m = _mintScenario();
        _kernelRejects(
            m,
            _slice(_b(".mint.kernelOutput"), 0, 448 + 64),
            abi.encodeWithSelector(KernelBadOutput.selector)
        );
    }

    function test_kernel_aPartialLeafIsRefused() public {
        Scenario memory s = _returnScenario();
        bytes memory o = _b(".return.kernelOutput");
        for (uint256 cut = 32; cut < 128; cut += 32) {
            _kernelRejects(
                s, _slice(o, 0, o.length - cut), abi.encodeWithSelector(KernelBadOutput.selector)
            );
        }
    }

    function test_kernel_referenceTimeWordNeedsZeroHighBits() public {
        Scenario memory s = _returnScenario();
        for (uint256 i = 0; i < 3; ++i) {
            uint256 pos = 448 + 128 * i + 64;
            bytes memory o = _copy(_b(".return.kernelOutput"));
            uint256 t = _getWord(o, pos);
            o = _setWord(o, pos, t | (uint256(1) << 64));
            _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
            o = _setWord(_copy(_b(".return.kernelOutput")), pos, t | (uint256(1) << 255));
            _kernelRejects(s, o, abi.encodeWithSelector(KernelBadOutput.selector));
        }
    }

    function test_kernel_referenceTimeIsReadFromTheThirdWordAndValueFromTheFourth() public {
        // the result carries the kernel's time and value words verbatim
        Scenario memory s = _returnScenario();
        KernelResult memory r = _run(s);
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(r.leaves[i].referenceTime, s.result.leaves[i].referenceTime);
            assertEq(r.leaves[i].leafValue, s.result.leaves[i].leafValue);
            assertEq(r.leaves[i].txHash, s.result.leaves[i].txHash);
            assertEq(r.leaves[i].sid, s.result.leaves[i].sid);
        }
    }

    function test_kernel_theMaximumProfileOutputIsAccepted() public {
        // MAX_LEAVES leaves, each with its own exact RSMT request, under the two anchors.
        Scenario memory s = _returnScenario();
        uint256 n = BridgeBounds.MAX_LEAVES;
        Leaf[] memory ls = new Leaf[](n);
        LeafProof[] memory ps = new LeafProof[](n);
        for (uint256 i = 0; i < n; ++i) {
            ps[i] = s.paths[i % 3];
            ls[i] = Leaf({
                sid: _sidInRow(
                    keccak256(abi.encode("sid", i)),
                    uint8(s.anchors[ps[i].anchorIndex].shard[0]) >> 7
                ),
                txHash: keccak256(abi.encode("tx", i)),
                referenceTime: uint64(1_700_000_000 + i),
                leafValue: keccak256(abi.encode("v", i))
            });
        }
        s.result.leaves = ls;
        s.paths = ps;
        _withIR(s, _irAt(s, 1_700_000_064));
        s.anchors[1].inputRecord = _irFor(s.anchors[1], 1_700_000_064);
        s.anchors[1].expectedIRHash = sha256(s.anchors[1].inputRecord);
        KernelResult memory got = _run(s);
        assertEq(got.leaves.length, n);
        assertEq(_kernelOut(true, s.result).length, 448 + 128 * n);
    }

    /// The profile's leaf bound is the kernel's own (owner §36): a result above it does not fit the returndata buffer and is refused as a
    /// bad return, never truncated.
    function test_kernel_aResultOverTheKernelLeafBoundIsABadReturn() public {
        assertEq(BridgeBounds.MAX_LEAVES, BridgeBounds.KERNEL_MAX_LEAVES);
        Scenario memory s = _returnScenario();
        uint256 n = BridgeBounds.MAX_LEAVES + 1;
        Leaf[] memory ls = new Leaf[](n);
        for (uint256 i = 0; i < n; ++i) {
            ls[i] = s.result.leaves[i % 3];
        }
        s.result.leaves = ls;
        _rejects(s, abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.KERNEL));
    }

    function _sidInRow(bytes32 sid, uint256 row) internal pure returns (bytes32) {
        bytes32 top = bytes32(uint256(1) << 255);
        return row == 1 ? sid | top : sid & ~top;
    }

    function _irFor(Anchor memory a, uint256 ts) internal pure returns (bytes memory) {
        bytes[10] memory p = _parts();
        p[4] = _h32(a.expectedStateRoot);
        p[6] = _uint(ts);
        return _build(TAG_ARRAY10, p);
    }

    function testFuzz_kernelOutputWordFlipIsRefusedOrDifferent(uint256 pos, uint8 flip) public {
        // A flipped byte of the kernel output either breaks the canonical layout or changes a field;
        // it is never silently the same result.
        Scenario memory s = _returnScenario();
        bytes memory o = _copy(_b(".return.kernelOutput"));
        pos = bound(pos, 0, o.length - 1);
        flip = uint8(bound(flip, 1, 255));
        o[pos] = bytes1(uint8(o[pos]) ^ flip);
        s.kernelOut = o;
        _arm(s);
        try this.runReturn(s.cfgB, _proof(s)) returns (KernelResult memory r) {
            assertFalse(_sameResult(r, s.result));
        } catch (bytes memory err) {
            assertTrue(_isNamedError(bytes4(err)), "named error");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Any-age: topology, leaf-to-anchor coverage, the Solidity preflight, the gate and the batch call
    // ---------------------------------------------------------------------------------------------

    /// @dev A return bundle over the given shards: one distinct synthetic anchor per shard (first-use order), one leaf per anchor with a
    ///      state ID in that shard, the golden Cfg, policy and kernel result shape, every native answer a double.
    function _topology(bytes[] memory shards) internal view returns (Scenario memory s) {
        uint256 n = shards.length;
        s = _returnScenario();
        s.history = hex"aabbcc";
        s.anchors = new Anchor[](n);
        s.paths = new LeafProof[](n);
        s.result.leaves = new Leaf[](n);
        for (uint256 i = 0; i < n; ++i) {
            s.anchors[i] = _synthAnchor(shards[i], i, 3, hex"00");
            s.paths[i] =
                LeafProof({anchorIndex: uint16(i), bitmap: bytes32(0), siblings: new bytes32[](0)});
            s.result.leaves[i] = Leaf({
                sid: _sidIn(shards[i], i),
                txHash: keccak256(abi.encode("tx", i)),
                referenceTime: 1_700_000_000,
                leafValue: keccak256(abi.encode("leaf", i))
            });
        }
    }

    function _uniform(uint256 d) internal pure returns (bytes[] memory shards) {
        shards = new bytes[](uint256(1) << d);
        for (uint256 k = 0; k < shards.length; ++k) {
            shards[k] = _shardId(d, k);
        }
    }

    function _noNativeCalls() internal {
        vm.expectCall(B1Calls.KERNEL, bytes(""), 0);
        vm.expectCall(B1Calls.CERT_BATCH, bytes(""), 0);
        vm.expectCall(B1Calls.RSMT_VERIFIER, bytes(""), 0);
    }

    function test_shardIdBuilderMatchesTheNativeEncoding() public pure {
        // d = 0: 0x80; d = 1: 0x40 and 0xc0; d = 2: 0x20 0x60 0xa0 0xe0; d = 8 needs a second byte
        assertEq(_shardId(0, 0), hex"80");
        assertEq(_shardId(1, 0), hex"40");
        assertEq(_shardId(1, 1), hex"c0");
        assertEq(_shardId(2, 2), hex"a0");
        assertEq(_shardId(7, 0x7f), hex"ff");
        assertEq(_shardId(8, 0xff), hex"ff80");
        for (uint256 d = 0; d < 9; ++d) {
            assertEq(CertGroups.shardDepth(_shardId(d, (uint256(1) << d) - 1)), d);
        }
    }

    // ---- topologies: 1, 2, 4, 8 and 16 uniform shards, uneven trees, a historical change -----------

    function test_topology_uniformShardCountsAreVerifiedByOneBatch() public {
        for (uint256 d = 1; d <= 4; ++d) {
            Scenario memory s = _topology(_uniform(d));
            assertEq(s.anchors.length, uint256(1) << d);
            _arm(s);
            vm.expectCall(B1Calls.CERT_BATCH, _expectedBatch(s.anchors), 1);
            assertTrue(_sameResult(_call(s), s.result), "2, 4, 8 and 16 shards");
        }
    }

    function test_topology_moreThanEightShardsOfAnUnevenTree() public {
        // a complete binary tree of ten shards: 000 001 010 011 100 101 and 1100 1101 1110 1111
        bytes[] memory shards = new bytes[](10);
        for (uint256 k = 0; k < 6; ++k) {
            shards[k] = _shardId(3, k);
        }
        for (uint256 k = 0; k < 4; ++k) {
            shards[6 + k] = _shardId(4, 12 + k);
        }
        Scenario memory s = _topology(shards);
        assertEq(s.anchors.length, 10);
        assertTrue(_sameResult(_run(s), s.result));
    }

    function test_topology_aHistoricalChangeMixesAParentAndItsChildren() public {
        // before the change '1' was one shard (0xc0); after it '10' and '11'. A token's history carries UCs of both.
        bytes[] memory shards = new bytes[](4);
        shards[0] = _shardId(1, 0);
        shards[1] = _shardId(1, 1);
        shards[2] = _shardId(2, 2);
        shards[3] = _shardId(2, 3);
        Scenario memory s = _topology(shards);
        assertTrue(_sameResult(_run(s), s.result));
        // a leaf in '10' may be served by the parent '1' or by the child '10': both carry its prefix
        s.paths[2].anchorIndex = 1;
        s.paths[1].anchorIndex = 1;
        s.paths[3].anchorIndex = 3;
        s.result.leaves[2].sid = _sidIn(shards[2], 2);
        // anchors must be used in first-use order and all used: leaf 2 now names anchor 1, leaf 3 anchor 3, so anchor 2 is skipped
        _rejects(s, abi.encodeWithSelector(PolicyLeafIndex.selector, 3, 3));
    }

    function test_topology_aLeafOutsideItsAnchorsPrefixIsRefusedAtEveryDepth() public {
        for (uint256 d = 1; d <= 4; ++d) {
            Scenario memory s = _topology(_uniform(d));
            uint256 last = s.anchors.length - 1;
            // flip the last bit of the anchor's prefix in the leaf's state ID: it now belongs to the sibling shard
            bytes memory raw = abi.encodePacked(s.result.leaves[last].sid);
            raw[(d - 1) / 8] = bytes1(uint8(raw[(d - 1) / 8]) ^ uint8(0x80 >> ((d - 1) % 8)));
            s.result.leaves[last].sid = bytes32(raw);
            _rejects(s, abi.encodeWithSelector(PolicyLeafIndex.selector, last, last));
        }
    }

    function test_topology_theDepthComesFromTheAnchorsOwnShardNotFromAPolicy() public {
        // one table with depths 1, 2 and 3 at once: a policy-wide depth would refuse all but one
        bytes[] memory shards = new bytes[](3);
        shards[0] = _shardId(1, 0);
        shards[1] = _shardId(2, 2);
        shards[2] = _shardId(3, 7);
        Scenario memory s = _topology(shards);
        assertTrue(_sameResult(_run(s), s.result));
    }

    function test_topology_anAnchorOutsideThePoliciesPartitionIsRefused() public {
        Scenario memory s = _topology(_uniform(2));
        s.anchors[3].partition = 12;
        _rejects(s, abi.encodeWithSelector(PolicyTupleMismatch.selector));
    }

    function test_topology_aMalformedShardIsRefusedBeforeAnyNativeCall() public {
        Scenario memory s = _topology(_uniform(2));
        s.anchors[1].shard = hex"ff00"; // last byte zero: no terminator
        _noNativeCalls();
        vm.expectRevert(abi.encodeWithSelector(UCScanRejected.selector));
        v.verifyReturn(s.cfgB, _proof(s));
    }

    function test_topology_deepShardsCompareWholeBytesThenTheRemainingBits() public {
        // depths 8, 9 and 12: the prefix spans one whole byte and then 0, 1 and 4 bits of the next
        uint256[3] memory depths = [uint256(8), 9, 12];
        for (uint256 j = 0; j < depths.length; ++j) {
            uint256 d = depths[j];
            bytes[] memory shards = new bytes[](3);
            shards[0] = _shardId(d, 0x5a5 & ((uint256(1) << d) - 1));
            shards[1] = _shardId(d, 0xa5a & ((uint256(1) << d) - 1));
            shards[2] = _shardId(d, 0xff3 & ((uint256(1) << d) - 1));
            Scenario memory s = _topology(shards);
            assertTrue(_sameResult(_run(s), s.result), "deep shards are admitted");
            // a flipped bit in the first byte, and one in the last prefix bit, each break the coverage
            uint256[2] memory bits = [uint256(0), d - 1];
            for (uint256 b = 0; b < 2; ++b) {
                Scenario memory bad = _topology(shards);
                bytes memory raw = abi.encodePacked(bad.result.leaves[1].sid);
                raw[bits[b] / 8] = bytes1(uint8(raw[bits[b] / 8]) ^ uint8(0x80 >> (bits[b] % 8)));
                bad.result.leaves[1].sid = bytes32(raw);
                _rejects(bad, abi.encodeWithSelector(PolicyLeafIndex.selector, 1, 1));
            }
        }
    }

    /// Depth-200 certificates are 200 siblings of 34 bytes each: there is no cumulative step budget and no gas ceiling (owner §36), so the
    /// bundle is admitted and verified whenever the envelope fits its ingress bound. It never half-runs.
    function test_bounds_deepShardsAreBoundedOnlyByTheEnvelope() public {
        for (uint256 k = 7; k <= 8; ++k) {
            bytes[] memory shards = new bytes[](k);
            for (uint256 i = 0; i < k; ++i) {
                shards[i] = new bytes(26);
                shards[i][0] = bytes1(uint8(0x10 * (i + 1)));
                shards[i][25] = 0x80; // 200 prefix bits, then the terminator
            }
            Scenario memory s = _topology(shards);
            if (_proof(s).length <= BridgeBounds.MAX_ENVELOPE_BYTES) {
                assertTrue(_sameResult(_run(s), s.result), "inside the envelope bound");
            } else {
                _arm(s);
                vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
                v.verifyReturn(s.cfgB, _proof(s));
            }
        }
    }

    function test_envelope_anAnchorUcOverTheByteCapIsBudget() public {
        Scenario memory s = _returnScenario();
        s.anchors[0].uc = new bytes(BridgeBounds.MAX_ANCHOR_UC_BYTES + 1);
        _rejects(s, abi.encodeWithSelector(BudgetExceeded.selector));
    }

    // ---- the Solidity CBOR preflight: the native batch's bounds, before any native call -----------------

    function _denseSlot(uint256 k) internal pure returns (bytes memory) {
        return bytes.concat(Cbor.head(4, k), _fill(k, 0));
    }

    /// @dev Two anchors whose input-record slots hold `k` one-byte items each.
    function _denseTwo(uint256 k) internal view returns (Scenario memory s) {
        bytes[] memory shards = _uniform(1);
        s = _topology(shards);
        for (uint256 i = 0; i < 2; ++i) {
            s.anchors[i] = _synthAnchor(shards[i], i, 3, _denseSlot(k));
        }
    }

    function _itemsOf(Scenario memory s) internal pure returns (uint256) {
        return CertGroups.measure(s.anchors).items;
    }

    /// There is no shared bridge item budget (owner §36): two anchors whose UCs carry far more than the former 4,096 items, with the Cfg,
    /// policy and IR openings on top, are admitted and charged.
    function test_preflight_itemsAreChargedNotBudgeted() public {
        Scenario memory s = _denseTwo(3000);
        assertGt(_itemsOf(s), 4096);
        assertTrue(_sameResult(_run(s), s.result), "over the former budget");
    }

    /// A slot that declares more children than the native batch's item bound has left is refused by its declared length before any
    /// native call.
    function test_preflight_aDenseCertificateIsRefusedByItsDeclaredLengthBeforeAnyNativeCall()
        public
    {
        // eight anchors of 7,000 dense items each: the fifth crosses the native 32,768 and is refused at its declared length
        bytes[] memory shards = _uniform(3);
        Scenario memory s = _topology(shards);
        for (uint256 i = 0; i < 8; ++i) {
            s.anchors[i] = _synthAnchor(shards[i], i, 3, _denseSlot(7000));
        }
        _noNativeCalls();
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        v.verifyReturn(s.cfgB, _proof(s));
    }

    /// The deployed code has to fit EIP-170 (24,576 bytes). It is close: the number is published so a change that eats the headroom is seen.
    function test_theVerifierFitsTheContractSizeLimit() public {
        uint256 size = address(v).code.length;
        emit log_named_uint("TokenVerifier runtime bytes", size);
        emit log_named_uint("headroom to EIP-170", 24_576 - size);
        assertLe(size, 24_576);
    }

    /// The gate's constants (80 per byte, 1,000 per item, the reserve) were measured with the size-first profile (arch's ruling of 2026-10-14):
    /// the verifier must be built with `optimizer_runs = 1`, as `foundry.toml` restricts `src/bridge/**`. A build under another profile
    /// would silently invalidate the measured allowance.
    function test_theVerifierIsBuiltWithTheMeasuredProfile() public view {
        string memory art = vm.readFile("out/TokenVerifier.sol/TokenVerifier.json");
        assertEq(vm.parseJsonUint(art, ".metadata.settings.optimizer.runs"), 1, "optimizer runs");
        assertTrue(vm.parseJsonBool(art, ".metadata.settings.optimizer.enabled"), "optimizer");
        assertTrue(vm.parseJsonBool(art, ".metadata.settings.viaIR"), "via IR");
        assertEq(vm.parseJsonString(art, ".metadata.settings.evmVersion"), "cancun", "evm");
        assertEq(
            keccak256(vm.parseJsonBytes(art, ".deployedBytecode.object")),
            address(v).codehash,
            "the artifact is the deployed code"
        );
    }

    // ---- the batch call: outcomes, shapes, forwarded gas ----------------------------------------------

    function _batchRejects(bytes memory out, bytes memory err) internal {
        Scenario memory s = _returnScenario();
        _arm(s);
        _prog(B1Calls.CERT_BATCH, _expectedBatch(s.anchors), out);
        vm.expectRevert(err);
        v.verifyReturn(s.cfgB, _proof(s));
    }

    function test_batch_falseIsRejectedAndNeverReachesRsmt() public {
        vm.expectCall(B1Calls.RSMT_VERIFIER, bytes(""), 0);
        _batchRejects(BATCH_FALSE, abi.encodeWithSelector(UCRejected.selector));
    }

    function test_batch_aHaltIsAFailureNotAFalse() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        _progRevert(B1Calls.CERT_BATCH, _expectedBatch(s.anchors));
        vm.expectRevert(abi.encodeWithSelector(PrecompileFailed.selector, B1Calls.CERT_BATCH));
        v.verifyReturn(s.cfgB, _proof(s));
    }

    function test_batch_everyWrongReturnShapeIsRejected() public {
        bytes[6] memory wrong = [
            TRUE_OUT, // the RSMT version-1 shape is not a batch verdict
            abi.encode(uint256(3), true),
            abi.encode(uint256(2), uint256(2)), // flag above 1
            hex"", // an empty success, as an unregistered address answers
            abi.encode(uint256(2)), // one word
            bytes.concat(BATCH_TRUE, bytes32(0)) // three words
        ];
        for (uint256 i = 0; i < wrong.length; ++i) {
            _batchRejects(
                wrong[i], abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.CERT_BATCH)
            );
        }
    }

    function test_batch_theInactiveAddressIsABadReturnNotAVerdict() public {
        Scenario memory s = _returnScenario();
        _armExcept(s, B1Calls.CERT_BATCH);
        vm.etch(B1Calls.CERT_BATCH, "");
        vm.expectRevert(abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.CERT_BATCH));
        v.verifyReturn(s.cfgB, _proof(s));
    }

    function test_batch_theSharedSealAddressIsNeverCalled() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        vm.expectCall(address(0x0101), bytes(""), 0);
        _call(s);
    }

    function test_batch_onlyAfterTheVerdictDoesTheOpeningCarryWeight() public {
        Scenario memory s = _returnScenario();
        s.anchors[0].inputRecord = hex"00"; // a malformed opening
        _arm(s);
        _prog(B1Calls.CERT_BATCH, _expectedBatch(s.anchors), BATCH_FALSE);
        vm.expectRevert(abi.encodeWithSelector(UCRejected.selector)); // the verdict is read first: not IRMalformed
        v.verifyReturn(s.cfgB, _proof(s));
    }

    // ---- the gas estimate: components against the oracle, no ceiling, forwarded gas --------------------

    /// @dev The fixed-shape items the verifier opens itself: Cfg, policy and one IR opening per anchor (part of J, never budgeted).
    function _spentItems(uint256 anchors) internal pure returns (uint256) {
        return BridgeBounds.CFG_ITEMS + BridgeBounds.POLICY_ITEMS + BridgeBounds.IR_ITEMS * anchors;
    }

    function _gateOfScenario(Scenario memory s)
        internal
        pure
        returns (uint256 total, uint256 batch, uint256 rsmt)
    {
        batch = CertGroups.batchGas(CertGroups.measure(s.anchors));
        for (uint256 i = 0; i < s.paths.length; ++i) {
            rsmt += BridgeBounds.rsmtGas(s.paths[i].siblings.length);
        }
        total = BridgeBounds.intrinsicGas(s.cfgB.length, _proof(s).length)
            + BridgeBounds.b2Gas(
                BridgeBounds.kernelRequestBytes(s.cfgB.length, s.history.length),
                s.result.leaves.length
            ) + batch + rsmt + BridgeBounds.ITEM_GAS * _items(s) + BridgeBounds.GAS_RESERVE;
    }

    /// @dev `J`: Cfg, policy, one IR opening per anchor and every UC occurrence's items.
    function _items(Scenario memory s) internal pure returns (uint256) {
        return _spentItems(s.anchors.length) + CertGroups.measure(s.anchors).items;
    }

    function test_gate_everyGoldenComponentEqualsTheOracleGate() public view {
        string[2] memory ops = ["mint", "return"];
        for (uint256 o = 0; o < 2; ++o) {
            Scenario memory s = o == 0 ? _mintScenario() : _returnScenario();
            string memory g = string.concat(".", ops[o], ".envelope.gate");
            CertGroups.Counts memory n = CertGroups.measure(s.anchors);
            assertEq(
                BridgeBounds.intrinsicGas(s.cfgB.length, _proof(s).length),
                vm.parseJsonUint(G, string.concat(g, ".intrinsic")),
                "intrinsic"
            );
            assertEq(
                BridgeBounds.b2Gas(
                    BridgeBounds.kernelRequestBytes(s.cfgB.length, s.history.length),
                    s.result.leaves.length
                ),
                vm.parseJsonUint(G, string.concat(g, ".b2")),
                "kernel"
            );
            assertEq(
                CertGroups.batchGas(n), vm.parseJsonUint(G, string.concat(g, ".batch")), "batch"
            );
            (uint256 total,, uint256 rsmt) = _gateOfScenario(s);
            assertEq(rsmt, vm.parseJsonUint(G, string.concat(g, ".rsmt")), "leaves");
            assertEq(total, vm.parseJsonUint(G, string.concat(g, ".total")), "total");
            assertEq(n.p, vm.parseJsonUint(G, string.concat(g, ".grouping.p")), "P");
            assertEq(n.k, vm.parseJsonUint(G, string.concat(g, ".grouping.k")), "K");
            assertEq(n.e, vm.parseJsonUint(G, string.concat(g, ".grouping.e")), "E");
            assertEq(n.s, vm.parseJsonUint(G, string.concat(g, ".grouping.s")), "S");
            assertEq(n.q, vm.parseJsonUint(G, string.concat(g, ".grouping.q")), "Q");
            assertEq(n.a, vm.parseJsonUint(G, string.concat(g, ".grouping.a")), "A");
            assertEq(n.c, vm.parseJsonUint(G, string.concat(g, ".grouping.c")), "C");
            assertEq(vm.parseJsonUint(G, string.concat(g, ".reserve")), BridgeBounds.GAS_RESERVE);
        }
    }

    function test_gas_everyNativeCallIsForwardedExactlyItsCharge() public {
        Scenario memory s = _returnScenario();
        _arm(s);
        uint64 batch = uint64(vm.parseJsonUint(G, ".return.envelope.gate.batch"));
        vm.expectCall(B1Calls.CERT_BATCH, 0, batch, _expectedBatch(s.anchors));
        for (uint256 i = 0; i < s.result.leaves.length; ++i) {
            bytes memory req = _expectedRSMT(
                s.anchors[s.paths[i].anchorIndex].expectedStateRoot,
                s.result.leaves[i].sid,
                s.result.leaves[i].leafValue,
                s.paths[i]
            );
            vm.expectCall(
                B1Calls.RSMT_VERIFIER,
                0,
                uint64(BridgeBounds.rsmtGas(s.paths[i].siblings.length)),
                req
            );
        }
        vm.expectCall(
            B1Calls.KERNEL,
            0,
            uint64(
                BridgeBounds.b2Gas(
                    BridgeBounds.kernelRequestBytes(s.cfgB.length, s.history.length),
                    BridgeBounds.KERNEL_MAX_LEAVES
                )
            ),
            _kernelInput(s.op, s.cfgB, s.history)
        );
        _call(s);
    }

    /// @dev The synthetic return bundle of `k` anchors of depth 1..4 with `sigs` signatures each and `pad` extra history bytes.
    function _heavy(uint256 k, uint256 sigs, uint256 pad)
        internal
        view
        returns (Scenario memory s)
    {
        s = _topology(_uniform(4)); // 16 anchors, then cut to k
        Anchor[] memory as_ = new Anchor[](k);
        LeafProof[] memory ps = new LeafProof[](k);
        Leaf[] memory ls = new Leaf[](k);
        for (uint256 i = 0; i < k; ++i) {
            as_[i] = _synthAnchor(_shardId(4, i), i, sigs, hex"00");
            ps[i] = s.paths[i];
            ls[i] = s.result.leaves[i];
        }
        s.anchors = as_;
        s.paths = ps;
        s.result.leaves = ls;
        s.history = new bytes(pad + 3);
    }

    function _total(Scenario memory s, uint256 pad) internal pure returns (uint256 t) {
        s.history = new bytes(pad + 3);
        (t,,) = _gateOfScenario(s);
    }

    /// No ceiling (owner §36): sixteen 16-signature anchors with the largest history are estimated far above the former 7,000,000 and
    /// are admitted and verified; the estimate only tells the caller how much gas to give.
    function test_gate_anEstimateAboveTheFormerCeilingIsAdmitted() public {
        Scenario memory s = _heavy(16, 16, 0);
        uint256 t = _total(s, BridgeBounds.MAX_SEMANTIC_BYTES - 3);
        assertGt(t, 7_000_000);
        s.history = new bytes(BridgeBounds.MAX_SEMANTIC_BYTES);
        assertTrue(_sameResult(_run(s), s.result), "admitted above the former ceiling");
    }

    function test_gate_sixteenSignatureAnchorsAreAlwaysAdmitted() public {
        for (uint256 k = 2; k <= 16; ++k) {
            Scenario memory s = _heavy(k, 16, 0);
            _arm(s);
            assertTrue(_sameResult(_call(s), s.result));
        }
    }

    // ---- margin: the composing verifier's own execution against 80 per envelope byte plus the reserve --

    function _measure(string memory label, Scenario memory s)
        internal
        returns (uint256 used, uint256 allowance)
    {
        _arm(s);
        bytes memory proof = _proof(s);
        uint256 g0 = gasleft();
        if (s.op == 1) v.verifyMint(s.cfgB, proof);
        else v.verifyReturn(s.cfgB, proof);
        used = g0 - gasleft();
        (uint256 total, uint256 batch, uint256 rsmt) = _gateOfScenario(s);
        // everything the gate prices as native work is charged to the natives, which the doubles do not spend; what is left of the gate
        // after them, minus the calldata the transaction itself pays for, is the composing verifier's allowance
        uint256 natives = batch + rsmt
            + BridgeBounds.b2Gas(
                BridgeBounds.kernelRequestBytes(s.cfgB.length, s.history.length),
                s.result.leaves.length
            );
        allowance = total - natives - BridgeBounds.INTRINSIC_BASE - BridgeBounds.PER_BYTE
            * BridgeBounds.maxCalldata(s.cfgB.length, proof.length);
        emit log_named_string("composition", label);
        emit log_named_uint("  envelope bytes", proof.length);
        emit log_named_uint("  anchors", s.anchors.length);
        emit log_named_uint("  leaves", s.result.leaves.length);
        emit log_named_uint("  gate total", total);
        emit log_named_uint("  natives priced (batch + leaves + kernel)", natives);
        emit log_named_uint("  verifier execution measured (natives mocked)", used);
        emit log_named_uint("  allowance 80*B_env + 1000*J + reserve", allowance);
        emit log_named_int("  margin", int256(allowance) - int256(used));
    }

    function test_margin_goldenBundlesAndSyntheticTopologies() public {
        (uint256 u1, uint256 a1) = _measure("golden mint (1 anchor)", _mintScenario());
        (uint256 u2, uint256 a2) = _measure("golden return (2 anchors, depth 1)", _returnScenario());
        (uint256 u3, uint256 a3) = _measure("4 shards", _topology(_uniform(2)));
        (uint256 u4, uint256 a4) = _measure("8 shards", _topology(_uniform(3)));
        (uint256 u5, uint256 a5) = _measure("16 shards", _topology(_uniform(4)));
        assertLe(u1, a1);
        assertLe(u2, a2);
        assertLe(u3, a3);
        assertLe(u4, a4);
        assertLe(u5, a5);
        // the heaviest signature-bound shape: sixteen 16-signature anchors
        (uint256 u6, uint256 a6) = _measure("sixteen 16-signature anchors", _heavy(16, 16, 0));
        assertLe(u6, a6);
        // the compact dense shape arch asked to see published: two anchors with dense input-record slots near the UC byte cap. Its
        // allowance is small (few bytes), its scan is not: the margin may be negative, which is a finding, not a failure of the fixture.
        Scenario memory dense = _denseTwo(7000);
        emit log_named_uint("dense: items traversed by the UC scan", _itemsOf(dense));
        emit log_named_uint(
            "dense: items in total (with Cfg, policy, IR openings)",
            _itemsOf(dense) + _spentItems(2)
        );
        (uint256 u7, uint256 a7) = _measure("two dense anchors near the UC byte cap", dense);
        emit log_named_uint("dense: used / allowance (permille)", u7 * 1000 / a7);
    }

    function runReturn(bytes memory c, bytes memory proof)
        external
        view
        returns (KernelResult memory)
    {
        return v.verifyReturn(c, proof);
    }
}
