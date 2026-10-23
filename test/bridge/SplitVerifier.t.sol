// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BridgeBase} from "./BridgeBase.sol";
import {TokenVerifier} from "../../src/bridge/TokenVerifier.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {KernelResult} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice The protocol 6 result of the composing verifier against the ORACLE's bytes: every case of `split-golden.json` is the
///         compose input and the 480-byte output the Go oracle's `NativeComposeV2` produced for a real split lineage (extracted by
///         script/bridge-golden/split-golden.py from the pinned bft-core commit). The 0x0105 double answers only the exact input
///         bytes; the composed relation itself is replayed natively in ureth against the same corpus.
contract SplitVerifierTest is BridgeBase {
    TokenVerifier internal v;
    bytes internal cfgB;
    string internal S;

    function setUp() public {
        _loadGolden();
        S = vm.readFile("test/bridge/split-golden.json");
        _etchDoubles();
        address verifierAddr = _a(".cfg.tokenVerifier");
        vm.etch(verifierAddr, address(new TokenVerifier()).code);
        v = TokenVerifier(verifierAddr);
        cfgB = _b(".cfg.bytes");
        // the split corpus is built on the same DEV fixture Cfg as the whole-token golden
        assertEq(vm.parseJsonBytes(S, ".cfg"), cfgB, "same fixture Cfg");
    }

    // ---- oracle cases -------------------------------------------------------------------------

    function _idx(string memory id) internal view returns (uint256) {
        for (uint256 i = 0; i < 64; ++i) {
            string memory p = string.concat(".cases[", vm.toString(i), "].id");
            if (!vm.keyExistsJson(S, p)) break;
            if (keccak256(bytes(vm.parseJsonString(S, p))) == keccak256(bytes(id))) return i;
        }
        revert("no such case");
    }

    function _f(uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "].", f);
    }

    /// @dev Arms the double with the case's exact input and output; returns the proof (the envelope) and the operation.
    function _arm(string memory id) internal returns (uint256 i, bytes memory proof) {
        i = _idx(id);
        bytes memory input = vm.parseJsonBytes(S, _f(i, "input"));
        (uint8 op, bytes memory cfg, bytes memory env) = abi.decode(input, (uint8, bytes, bytes));
        assertEq(op, 2);
        assertEq(cfg, cfgB);
        _prog(B1Calls.COMPOSE, input, vm.parseJsonBytes(S, _f(i, "output")));
        proof = env;
    }

    function _checkSuccess(string memory id) internal {
        (uint256 i, bytes memory proof) = _arm(id);
        KernelResult memory r = v.verifyReturn(cfgB, proof);
        string memory p = string.concat(".cases[", vm.toString(i), "].result.");
        assertEq(
            r.nonce, vm.parseUint(vm.parseJsonString(S, string.concat(p, "nonce"))), "root nonce"
        );
        assertEq(r.tokenId, vm.parseJsonBytes32(S, string.concat(p, "tokenId")), "root token");
        assertEq(
            r.lockDigest, vm.parseJsonBytes32(S, string.concat(p, "lockDigest")), "root digest"
        );
        assertEq(r.releaseTo, vm.parseJsonAddress(S, string.concat(p, "releaseTo")), "recipient");
        assertEq(r.nullifier, vm.parseJsonBytes32(S, string.concat(p, "nullifier")), "nullifier");
        assertEq(r.partTokenId, vm.parseJsonBytes32(S, string.concat(p, "partTokenId")), "part");
        // amounts are minimal big-endian hex in the corpus
        assertEq(
            r.amount,
            uint256(bytes32(_left(vm.parseJsonBytes(S, string.concat(p, "amount"))))),
            "root amount"
        );
        assertEq(
            r.partAmount,
            uint256(bytes32(_left(vm.parseJsonBytes(S, string.concat(p, "partAmount"))))),
            "part amount"
        );
        assertEq(
            r.splitDepth, vm.parseUint(vm.parseJsonString(S, string.concat(p, "depth"))), "depth"
        );
        assertEq(r.leafCount, vm.parseJsonUint(S, string.concat(p, "leaves")), "leaves");
        assertEq(
            r.cfg,
            vm.parseJsonBytes32(S, string.concat(".cases[", vm.toString(i), "].result.cfg")),
            "cfg"
        );
    }

    function _left(bytes memory b) internal pure returns (bytes memory out) {
        out = new bytes(32);
        for (uint256 k = 0; k < b.length; ++k) {
            out[32 - b.length + k] = b[k];
        }
    }

    function test_oracle_depthZeroIsTheWholeToken() public {
        _checkSuccess("lineage-depth-0");
    }

    function test_oracle_siblingsShareOneLock() public {
        _checkSuccess("lineage-depth-1-part-40");
        (uint256 a,) = _arm("lineage-depth-1-part-40");
        KernelResult memory r40 = v.verifyReturn(cfgB, _proofOf("lineage-depth-1-part-40"));
        _checkSuccess("lineage-depth-1-part-60");
        KernelResult memory r60 = v.verifyReturn(cfgB, _proofOf("lineage-depth-1-part-60"));
        assertEq(r40.lockDigest, r60.lockDigest, "one lock");
        assertEq(r40.nonce, r60.nonce);
        assertEq(r40.amount, 100, "the lock is 100");
        assertEq(r40.amount, r60.amount);
        assertEq(r40.partAmount + r60.partAmount, 100, "the parts add up to the lock");
        assertTrue(r40.partTokenId != r60.partTokenId);
        assertTrue(r40.nullifier != r60.nullifier);
        a;
    }

    function _proofOf(string memory id) internal returns (bytes memory proof) {
        (, proof) = _arm(id);
    }

    function test_oracle_nestedAndFanOut() public {
        _checkSuccess("lineage-depth-1-part-40-real-proofs");
        _checkSuccess("lineage-depth-2");
        _checkSuccess("lineage-depth-3");
        _checkSuccess("lineage-depth-8");
        _checkSuccess("lineage-fanout-16");
    }

    function test_oracle_refreshedWitnessesGiveTheSameNullifier() public {
        KernelResult memory a = v.verifyReturn(cfgB, _proofOf("lineage-depth-1-part-40"));
        KernelResult memory b = v.verifyReturn(cfgB, _proofOf("lineage-refreshed-witnesses"));
        assertEq(a.nullifier, b.nullifier);
        assertEq(a.partTokenId, b.partTokenId);
        assertEq(a.lockDigest, b.lockDigest);
    }

    /// Every native refusal of the split relation reaches the caller as BridgeRejected(status) with the oracle's code.
    function test_oracle_splitRefusalsCarryTheirStatus() public {
        string[8] memory ids = [
            "lineage-neg-tree-total-under",
            "lineage-neg-tree-understates-part",
            "lineage-neg-parent-not-burned",
            "lineage-neg-not-a-manifest",
            "lineage-neg-partial-part-return",
            "lineage-neg-repeated-token-id",
            "lineage-neg-ancestor-certificate-outside-codec",
            "lineage-neg-ancestor-signature-width"
        ];
        for (uint256 k = 0; k < ids.length; ++k) {
            (uint256 i, bytes memory proof) = _arm(ids[k]);
            uint256 status = uint256(vm.parseJsonInt(S, _f(i, "status")));
            assertTrue(status != 0, "a refusal");
            vm.expectRevert(abi.encodeWithSelector(BridgeRejected.selector, status));
            v.verifyReturn(cfgB, proof);
        }
        // the split statuses are the appended codes 63..71
        (uint256 j,) = _arm("lineage-neg-tree-total-under");
        assertEq(vm.parseJsonString(S, _f(j, "statusName")), "ErrSplitSum");
        assertEq(uint256(vm.parseJsonInt(S, _f(j, "status"))), 69);
    }

    // ---- shape checks on the part (crafted outputs) -------------------------------------------

    function _base() internal returns (KernelResult memory r, bytes memory proof) {
        bytes memory out;
        uint256 i;
        (i, proof) = _arm("lineage-depth-1-part-40");
        out = vm.parseJsonBytes(S, _f(i, "output"));
        r = v.verifyReturn(cfgB, proof);
        out;
    }

    function _setOut(bytes memory proof, KernelResult memory r) internal {
        _prog(B1Calls.COMPOSE, _composeInput(2, cfgB, proof), _composeOut(0, r));
    }

    function test_shape_roundTripOfTheOraclesResult() public {
        (KernelResult memory r, bytes memory proof) = _base();
        // our own encoding of the decoded result is the oracle's output
        _setOut(proof, r);
        KernelResult memory again = v.verifyReturn(cfgB, proof);
        assertEq(keccak256(abi.encode(again)), keccak256(abi.encode(r)));
    }

    function _rejectsShape(KernelResult memory r, bytes memory proof) internal {
        _setOut(proof, r);
        vm.expectRevert(abi.encodeWithSelector(KernelResultShape.selector));
        v.verifyReturn(cfgB, proof);
    }

    function test_shape_partLargerThanTheLock() public {
        (KernelResult memory r, bytes memory proof) = _base();
        r.partAmount = r.amount + 1;
        _rejectsShape(r, proof);
    }

    function test_shape_partAmountZero() public {
        (KernelResult memory r, bytes memory proof) = _base();
        r.partAmount = 0;
        _rejectsShape(r, proof);
    }

    function test_shape_partTokenIdZero() public {
        (KernelResult memory r, bytes memory proof) = _base();
        r.partTokenId = bytes32(0);
        _rejectsShape(r, proof);
    }

    function test_shape_depthZeroPartIsTheRoot() public {
        (KernelResult memory r, bytes memory proof) = _base();
        r.splitDepth = 0; // a split part claiming depth 0
        _rejectsShape(r, proof);
        // and the converse: the root claiming a deeper lineage
        r.partTokenId = r.tokenId;
        r.partAmount = r.amount;
        r.splitDepth = 1;
        _rejectsShape(r, proof);
    }

    function test_shape_depthNeedsItsLeaves() public {
        (KernelResult memory r, bytes memory proof) = _base();
        // 2(d+1) leaves at least: this lineage has 6, so depth 3 would need 8
        r.splitDepth = 3;
        _rejectsShape(r, proof);
        r.splitDepth = 2; // 6 leaves hold depth 2
        _setOut(proof, r);
        assertEq(v.verifyReturn(cfgB, proof).splitDepth, 2);
    }

    function test_shape_depthAboveU64IsABadReturn() public {
        (KernelResult memory r, bytes memory proof) = _base();
        r.splitDepth = uint256(type(uint64).max) + 1;
        _setOut(proof, r);
        vm.expectRevert(abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.COMPOSE));
        v.verifyReturn(cfgB, proof);
    }

    function test_shape_aV1Result480OrMarkerIsRefused() public {
        (KernelResult memory r, bytes memory proof) = _base();
        bytes memory good = _composeOut(0, r);
        // the protocol 5 marker
        bytes memory bad = good;
        bad[24] = "1"; // ...COMPOSE_V1 (the marker's last character is byte 24)
        _prog(B1Calls.COMPOSE, _composeInput(2, cfgB, proof), bad);
        vm.expectRevert(abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.COMPOSE));
        v.verifyReturn(cfgB, proof);
        // the 384-byte V1 length
        bytes memory short_ = new bytes(384);
        for (uint256 k = 0; k < 384; ++k) {
            short_[k] = good[k];
        }
        _prog(B1Calls.COMPOSE, _composeInput(2, cfgB, proof), short_);
        vm.expectRevert(abi.encodeWithSelector(PrecompileBadReturn.selector, B1Calls.COMPOSE));
        v.verifyReturn(cfgB, proof);
    }

    function test_shape_aMintIsTheRootAtDepthZero() public {
        KernelResult memory r = _goldenResult(".mint.result");
        bytes memory proof = abi.encode(
            _b(".policy.bytes"),
            _b(".mint.history"),
            _goldenAnchors("mint"),
            _goldenLeafProofs("mint")
        );
        _prog(B1Calls.COMPOSE, _composeInput(1, cfgB, proof), _composeOut(0, r));
        assertEq(v.verifyMint(cfgB, proof).partTokenId, r.tokenId);
        // a mint carrying a split lineage is not a mint: each of the three fields alone refuses it
        KernelResult memory m = abi.decode(abi.encode(r), (KernelResult));
        m.splitDepth = 1;
        _prog(B1Calls.COMPOSE, _composeInput(1, cfgB, proof), _composeOut(0, m));
        vm.expectRevert(abi.encodeWithSelector(KernelResultShape.selector));
        v.verifyMint(cfgB, proof);
        m = abi.decode(abi.encode(r), (KernelResult));
        m.partTokenId = keccak256("part");
        _prog(B1Calls.COMPOSE, _composeInput(1, cfgB, proof), _composeOut(0, m));
        vm.expectRevert(abi.encodeWithSelector(KernelResultShape.selector));
        v.verifyMint(cfgB, proof);
        r.partAmount = r.amount - 1;
        _prog(B1Calls.COMPOSE, _composeInput(1, cfgB, proof), _composeOut(0, r));
        vm.expectRevert(abi.encodeWithSelector(KernelResultShape.selector));
        v.verifyMint(cfgB, proof);
    }
}
