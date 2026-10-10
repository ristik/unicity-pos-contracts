// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {TokenVerifier} from "../../src/bridge/TokenVerifier.sol";
import {BridgeVault} from "../../src/bridge/BridgeVault.sol";
import {B1Calls} from "../../src/bridge/B1Calls.sol";
import {BridgeProfile} from "../../src/bridge/BridgeProfile.sol";
import {Cbor} from "../../src/bridge/Cbor.sol";
import {
    Anchor,
    Cfg,
    Deployment,
    KernelResult,
    Leaf,
    LeafProof
} from "../../src/bridge/BridgeTypes.sol";

/// @notice Shared fixture: the golden vectors of the merged Go oracle, the precompile doubles, and
///         builders that are written independently of the library under test.
abstract contract BridgeBase is Test {
    // The precompile doubles. B1 0x0100/0x0102 and the B2 kernel 0x0104 are NOT the native
    // implementation (B1 ships in ureth, inactive here); they are `vm.mockCall` answers keyed by the
    // exact request bytes, over code that reverts. An unprogrammed input therefore reverts, so a test
    // that programs only the exact expected bytes proves the caller built exactly those bytes. Mocks
    // cost no EVM gas: the verifier forwards each native call exactly its computed charge (a single
    // RSMT member call is about six thousand gas), which a storage-backed double cannot meet.
    bytes internal constant REVERT_CODE = hex"5f5ffd"; // PUSH0 PUSH0 REVERT

    bytes32 internal constant MARKER = bytes32("UNICITY_TOKEN_SEMANTICS");

    string internal G;
    string internal B1V;

    function _loadGolden() internal {
        G = vm.readFile("test/bridge/golden.json");
        B1V = vm.readFile("test/bridge/b1-vectors.json");
    }

    function _etchDoubles() internal {
        address[3] memory targets = [B1Calls.UC_VERIFIER, B1Calls.RSMT_VERIFIER, B1Calls.KERNEL];
        for (uint256 i = 0; i < targets.length; ++i) {
            vm.etch(targets[i], REVERT_CODE);
        }
    }

    /// @dev The mock selector of a target's default answer: the first four bytes of its requests.
    function _selectorOf(address target) internal pure returns (bytes4) {
        return target == B1Calls.KERNEL ? bytes4(0) : bytes4(0x01000001);
    }

    function _prog(address target, bytes memory req, bytes memory out) internal {
        vm.mockCall(target, req, out);
    }

    function _progRevert(address target, bytes memory req) internal {
        vm.mockCallRevert(target, req, "");
    }

    function _progDefault(address target, bytes memory out) internal {
        vm.mockCall(target, _selectorOf(target), out);
    }

    function _progDefaultRevert(address target) internal {
        vm.mockCallRevert(target, _selectorOf(target), "");
    }

    // ---- golden accessors ---------------------------------------------------------------------

    function _b(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(G, key);
    }

    function _b32(string memory key) internal view returns (bytes32) {
        return vm.parseJsonBytes32(G, key);
    }

    function _a(string memory key) internal view returns (address) {
        return vm.parseJsonAddress(G, key);
    }

    function _u(string memory key) internal view returns (uint256) {
        return vm.parseUint(vm.parseJsonString(G, key));
    }

    function _goldenCfg() internal view returns (Cfg memory c) {
        c.network = uint16(vm.parseJsonUint(G, ".cfg.network"));
        c.rootGenesis = _b32(".cfg.rootGenesis");
        c.chainId = uint64(vm.parseJsonUint(G, ".cfg.chainId"));
        c.executionGenesis = _b32(".cfg.executionGenesis");
        c.evmPartition = uint32(vm.parseJsonUint(G, ".cfg.evmPartition"));
        c.evmShard = _b(".cfg.evmShard");
        c.vault = _a(".cfg.vault");
        c.zeroAddress = _a(".cfg.zeroAddress");
        c.ty = _b32(".cfg.ty");
        c.aid = _b32(".cfg.aid");
        c.semanticProfileHash = _b32(".cfg.semanticProfileHash");
        c.tokenVerifier = _a(".cfg.tokenVerifier");
        c.tokenVerifierCodeHash = _b32(".cfg.tokenVerifierCodeHash");
        c.b1ProfileHash = _b32(".cfg.b1ProfileHash");
        c.aggregatorPolicyHash = _b32(".cfg.aggregatorPolicyHash");
    }

    function _goldenResult(string memory prefix) internal view returns (KernelResult memory r) {
        r.cfg = _b32(string.concat(prefix, ".cfg"));
        r.nonce = _u(string.concat(prefix, ".nonce"));
        r.amount = _u(string.concat(prefix, ".amount"));
        r.tokenId = _b32(string.concat(prefix, ".tokenId"));
        r.salt = _b32(string.concat(prefix, ".salt"));
        r.firstPredicateHash = _b32(string.concat(prefix, ".firstPredicateHash"));
        r.lockDigest = _b32(string.concat(prefix, ".lockDigest"));
        r.releaseTo = _a(string.concat(prefix, ".releaseTo"));
        r.nullifier = _b32(string.concat(prefix, ".nullifier"));
        uint256 n = 0;
        while (vm.keyExistsJson(G, string.concat(prefix, ".leaves[", vm.toString(n), "]"))) ++n;
        r.leaves = new Leaf[](n);
        for (uint256 i = 0; i < n; ++i) {
            string memory p = string.concat(prefix, ".leaves[", vm.toString(i), "]");
            r.leaves[i] = Leaf({
                sid: _b32(string.concat(p, ".sid")),
                txHash: _b32(string.concat(p, ".txHash")),
                // forge-lint: disable-next-line(unsafe-typecast)
                referenceTime: uint64(_u(string.concat(p, ".referenceTime"))),
                leafValue: _b32(string.concat(p, ".leafValue"))
            });
        }
    }

    /// @dev Paths of the golden envelope of `op` ("mint" or "return"), one per exported leaf.
    function _goldenLeafProofs(string memory op) internal view returns (LeafProof[] memory lp) {
        uint256 n = vm.parseJsonUint(G, string.concat(".", op, ".envelope.leaves"));
        lp = new LeafProof[](n);
        for (uint256 i = 0; i < n; ++i) {
            string memory p = string.concat(".", op, ".envelope.members[", vm.toString(i), "]");
            lp[i].anchorIndex = uint16(vm.parseJsonUint(G, string.concat(p, ".anchorIndex")));
            lp[i].bitmap = _b32(string.concat(p, ".bitmap"));
            lp[i].siblings = vm.parseJsonBytes32Array(G, string.concat(p, ".siblings"));
        }
    }

    /// @dev The real certified anchors of the golden envelope of `op` (one per distinct UC, first-use
    ///      leaf order), each with its native InputRecord.
    function _goldenAnchors(string memory op) internal view returns (Anchor[] memory as_) {
        uint256 n = 0;
        while (vm.keyExistsJson(
                G, string.concat(".", op, ".envelope.anchors[", vm.toString(n), "]")
            )) ++n;
        as_ = new Anchor[](n);
        for (uint256 i = 0; i < n; ++i) {
            string memory p = string.concat(".", op, ".envelope.anchors[", vm.toString(i), "]");
            as_[i].partition = uint32(vm.parseJsonUint(G, string.concat(p, ".partition")));
            as_[i].shard = _b(string.concat(p, ".shard"));
            as_[i].shardConfHash = _b32(string.concat(p, ".conf"));
            as_[i].expectedStateRoot = _b32(string.concat(p, ".stateRoot"));
            as_[i].expectedIRHash = _b32(string.concat(p, ".irHash"));
            as_[i].uc = _b(string.concat(p, ".uc"));
            as_[i].inputRecord = _b(string.concat(p, ".inputRecord"));
        }
    }

    /// @dev The first anchor of the golden envelope of `op`.
    function _goldenAnchor(string memory op) internal view returns (Anchor memory) {
        return _goldenAnchors(op)[0];
    }

    // SHA-256 of the labels the oracle's generator uses for the "all-set" opening (golden .inputRecords[0]).
    bytes32 internal constant STATE =
        0x91ae5c284aae6c453b68a3ca740bddd48a744f5d9abd219f6cf856eba48f6b41; // sha256("ir-state")
    bytes32 internal constant IR_PREV =
        0x0a3d611baad100dbb3fa683023777ce19341f15902032af1c86d4d52055e9dd0; // sha256("ir-prev")
    bytes32 internal constant IR_BLOCK =
        0x935aaea6cb67711c949b02be9aaecfa42522fbb10c5dcd9573525f71eb8c84de; // sha256("ir-block")
    bytes32 internal constant IR_ET =
        0x74d10f34253c2fd416330be4db5c182e63efbe88f2e25ce755209c464429be42; // sha256("ir-et")

    // ---- independent InputRecord builder (no use of the library under test) ---------------------

    /// @dev Shortest-form unsigned CBOR, written without the library under test.
    function _uint(uint256 v) internal pure returns (bytes memory) {
        if (v < 24) return abi.encodePacked(uint8(v));
        if (v < 1 << 8) return abi.encodePacked(uint8(0x18), uint8(v));
        if (v < 1 << 16) return abi.encodePacked(uint8(0x19), uint16(v));
        if (v < 1 << 32) return abi.encodePacked(uint8(0x1a), uint32(v));
        return abi.encodePacked(uint8(0x1b), uint64(v));
    }

    function _h32(bytes32 h) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"5820", h);
    }

    bytes internal constant NULL = hex"f6";

    /// @dev The ten fields of a well-formed opening; a test overrides one.
    function _parts() internal pure returns (bytes[10] memory p) {
        p[0] = _uint(1);
        p[1] = _uint(100);
        p[2] = _uint(3);
        p[3] = _h32(IR_PREV);
        p[4] = _h32(STATE);
        p[5] = hex"47" // 7-byte summary
            hex"73756d6d617279";
        p[6] = _uint(1_700_000_100);
        p[7] = _h32(IR_BLOCK);
        p[8] = _uint(55);
        p[9] = _h32(IR_ET);
    }

    function _build(bytes memory tagAndArray, bytes[10] memory p)
        internal
        pure
        returns (bytes memory out)
    {
        out = tagAndArray;
        for (uint256 i = 0; i < 10; ++i) {
            out = bytes.concat(out, p[i]);
        }
    }

    bytes internal constant TAG_ARRAY10 = hex"d9985a8a";

    function _ok() internal pure returns (bytes memory) {
        return _build(TAG_ARRAY10, _parts());
    }

    // ---- independently written expected bytes --------------------------------------------------

    /// @dev Kernel input `abi.encode(uint8 op, bytes Cfg, bytes payload)`.
    function _kernelInput(uint8 op, bytes memory cfgBytes, bytes memory payload)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(op, cfgBytes, payload);
    }

    function _kernelOut(bool valid, KernelResult memory r) internal pure returns (bytes memory) {
        return abi.encode(MARKER, valid, r);
    }

    /// @dev UC request for one claim, written byte by byte rather than through the library.
    function _expectedUC(Anchor memory a) internal pure returns (bytes memory) {
        return bytes.concat(
            hex"0100",
            hex"0001",
            bytes4(a.partition),
            bytes2(uint16(a.shard.length)),
            a.shard,
            a.shardConfHash,
            a.expectedStateRoot,
            a.expectedIRHash,
            bytes4(uint32(a.uc.length)),
            a.uc
        );
    }

    /// @dev RSMT request with the raw 32-byte leaf value `v = H(C(b(txHash), t))`.
    function _expectedRSMT(bytes32 root, bytes32 sid, bytes32 leafValue, LeafProof memory p)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(hex"01000001", root, sid, hex"00000020", leafValue, p.bitmap);
        for (uint256 i = 0; i < p.siblings.length; ++i) {
            out = bytes.concat(out, p.siblings[i]);
        }
    }

    bytes internal constant TRUE_OUT = abi.encode(uint256(1), true);
    bytes internal constant FALSE_OUT = abi.encode(uint256(1), false);
}
