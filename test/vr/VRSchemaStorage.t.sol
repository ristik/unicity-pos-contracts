// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {VRLayout} from "../../src/vr/VRLayout.sol";
import {VRLiability} from "../../src/vr/VRLiability.sol";

/// @notice The ValidatorRegistry schema v1 storage layout (bft-core docs/design/validator-registry/schema-v1.md section 2) as the
/// production code declares it: `src/vr/VRLayout.sol` (VR, at V) and `src/vr/VRLiability.sol` (every liability holder, at B). Since
/// VT-02 the fixture writes the frozen scenarios through those production structs, so the slots and words below come from the same
/// declarations ValidatorRegistry and the holders compile against.
library VRSchemaLayout {
    // aliases, so the scenario writer below reads as the schema text
    function fees(uint64 floor_, uint64 denominator, address collector)
        internal
        pure
        returns (VRLayout.Fees memory)
    {
        return VRLayout.Fees(floor_, denominator, collector);
    }
}

contract VRLayoutFixture {
    bytes32 internal constant B =
        0xb2905100cfe7c1af5dee2b1b6726fdfd755820e0f51ef675ed653be4f1102d00;

    function _vr(bytes32 ns) internal pure returns (VRLayout.VRStorage storage $) {
        assembly {
            $.slot := ns
        }
    }

    function _lia() internal pure returns (VRLiability.LiabilityStorage storage $) {
        assembly {
            $.slot := B
        }
    }

    function writeVR(bytes32 ns) external {
        VRLayout.VRStorage storage $ = _vr(ns);
        bytes32 r = keccak256("result/R");
        bytes32 n = keccak256("result/N");
        address module = 0xA000000000000000000000000000000000000001;
        address other = 0xb000000000000000000000000000000000000002;
        address sender = 0xC000000000000000000000000000000000000003;
        uint64 max = type(uint64).max;
        $.network = keccak256("unicity.vr.schema.test-network");
        $.openOutput = r;
        $.lastAcked = keccak256("unicity.vr.genesis-result.v1");
        $.committeeLimits = VRLayout.CommitteeLimits(4, 5, 7);
        $.hookLimits = VRLayout.HookLimits(16, 8, 8, 32);
        $.status = VRLayout.Status(1, 5, 42, 2, 1);
        $.activeModule = module;
        $.activeModuleCodeHash = keccak256("module-code");
        $.governor = other;
        $.counters = VRLayout.Counters(10, 5, 2);
        $.feesPrevious = VRSchemaLayout.fees(1_000_000, 8, other);
        $.feesCurrent = VRSchemaLayout.fees(uint64(1) << 62, 4, sender);
        $.feesEffectiveBlock = 101;
        $.outputs[r] = VRLayout.Output({
            state: 2,
            attempt: 7,
            reservedProgress: 10_000,
            expiresAtProgress: 10_000 + 16_384,
            predecessor: keccak256("unicity.vr.genesis-result.v1"),
            sourceModule: module,
            native: false,
            moduleTag: keccak256("unicity.vr.poa.v1"),
            membersDigest: keccak256("members-digest"),
            kDigest: keccak256("k-digest"),
            changesDigest: keccak256("changes"),
            snapshotDigest: keccak256("snapshot"),
            policyDigest: keccak256("policy"),
            outputCommit: keccak256("commit"),
            invalidReason: 0,
            invalidAtProgress: 0
        });
        VRLayout.Output storage o = $.outputs[n];
        o.state = 3;
        o.attempt = max;
        o.reservedProgress = max - 16_384;
        o.expiresAtProgress = max;
        o.predecessor = r;
        o.native = true;
        o.moduleTag = keccak256("unicity.vr.registry-native.v1");
        o.invalidReason = 2;
        o.invalidAtProgress = max - 1;
        bytes memory limits = abi.encode(uint32(4), uint32(5), uint32(7));
        $.changes[3] = VRLayout.Change(
            4, 3, 0, 2000, 3600, 0, keccak256(limits), r, 2100, uint32(limits.length)
        );
        $.changePayload[3] = limits;
        bytes memory fr = abi.encode(uint64(2));
        $.changes[max] =
            VRLayout.Change(10, 5, 1, max, max, max, keccak256(fr), r, max, uint32(fr.length));
        $.changePayload[max] = fr;
        $.changePayload[0] = bytes("short-payload");
        $.activations[0] =
            VRLayout.Activation(keccak256("unicity.rule/a"), keccak256("1"), 7, 5000, 2, 4);
        $.activations[1] =
            VRLayout.Activation(keccak256("unicity.rule/a"), keccak256("2"), 9, 6000, 3, 6);
        $.holders[0] = VRLayout.Holder(other, 3, keccak256("holder-code"), module);
        $.retired[0][7][1] = true;
        $.retired[7][max][max] = true;
    }

    function writeLiability() external {
        VRLiability.LiabilityStorage storage $ = _lia();
        uint64 max = type(uint64).max;
        $.cursor = 40;
        $.facts[0][0] = VRLiability.Facts(true, 1, 2, 3, keccak256("ref-0-0"));
        $.facts[1][1] = VRLiability.Facts(true, 0, 0, 900, keccak256("ref-1-1"));
        $.facts[max][max] =
            VRLiability.Facts(true, type(uint32).max, type(uint32).max, max, keccak256("ref-max"));
        $.facts[7][max] = VRLiability.Facts(false, 5, 0, 0, keccak256("ref-7"));
        // raw words a typed writer cannot produce: a nonzero reserved byte, and requested = 2
        _raw(9, 1, bytes32(uint256(1) | (uint256(1) << 248)), keccak256("ref-reserved"));
        _raw(9, 2, bytes32(uint256(2)), keccak256("ref-two"));
    }

    function _raw(uint64 id, uint64 gen, bytes32 w0, bytes32 w1) internal {
        VRLiability.Facts storage f = _lia().facts[id][gen];
        assembly {
            sstore(f.slot, w0)
            sstore(add(f.slot, 1), w1)
        }
    }
}

/// @notice Writes the schema v1 storage scenarios through the typed layout and checks every slot and word against the shared vectors
/// (testvectors/validator-registry/storage-flat.json, generated by bft-core vrschema); the written slots are also dumped to
/// test/vr/fixtures/storage-forge.json, which bft-core's reader test consumes. Regenerate the dump with VR_WRITE_FIXTURES=true.
contract VRSchemaStorageTest is Test {
    string internal constant FLAT = "/test/vr/fixtures/storage-flat.json";
    string internal constant DUMP = "/test/vr/fixtures/storage-forge.json";
    address internal constant VR = 0xFF00000000000000000000000000000000000003;
    address internal constant HOLDER = 0xcC0000000000000000000000000000000000000c;

    function _ns(string memory id) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(keccak256(bytes(id))) - 1)) & ~bytes32(uint256(0xff));
    }

    /// distinct written slots, in first-write order
    function _written(address a, function() internal write)
        internal
        returns (bytes32[] memory out)
    {
        vm.record();
        write();
        (, bytes32[] memory writes) = vm.accesses(a);
        bytes32[] memory uniq = new bytes32[](writes.length);
        uint256 n;
        for (uint256 i; i < writes.length; ++i) {
            bool seen;
            for (uint256 j; j < n; ++j) {
                if (uniq[j] == writes[i]) seen = true;
            }
            if (!seen) uniq[n++] = writes[i];
        }
        out = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = uniq[i];
        }
    }

    function _writeVR() internal {
        VRLayoutFixture(VR).writeVR(_ns("unicity.vr.registry.v1"));
    }

    function _writeLiability() internal {
        VRLayoutFixture(HOLDER).writeLiability();
    }

    function _check(string memory json, string memory name, address a, bytes32[] memory written)
        internal
        view
        returns (string memory dump)
    {
        bytes32[] memory slots =
            vm.parseJsonBytes32Array(json, string.concat(".scenarios.", name, ".slots"));
        bytes32[] memory words =
            vm.parseJsonBytes32Array(json, string.concat(".scenarios.", name, ".words"));
        assertEq(slots.length, words.length);
        for (uint256 i; i < slots.length; ++i) {
            assertEq(
                vm.load(a, slots[i]),
                words[i],
                string.concat(name, ": slot ", vm.toString(slots[i]))
            );
        }
        // every slot Solidity wrote is one the frozen layout names (zero words are written only where the scenario has them)
        uint256 nonzero;
        string memory s = "[";
        string memory w = "[";
        for (uint256 i; i < written.length; ++i) {
            bytes32 v = vm.load(a, written[i]);
            bool listed;
            for (uint256 j; j < slots.length; ++j) {
                if (slots[j] == written[i]) listed = true;
            }
            assertTrue(
                listed || v == bytes32(0),
                string.concat(name, ": unlisted slot ", vm.toString(written[i]))
            );
            if (v != bytes32(0)) nonzero++;
            string memory sep = i == 0 ? "" : ",";
            s = string.concat(s, sep, '"', vm.toString(written[i]), '"');
            w = string.concat(w, sep, '"', vm.toString(v), '"');
        }
        uint256 expectedNonzero;
        for (uint256 j; j < words.length; ++j) {
            if (words[j] != bytes32(0)) expectedNonzero++;
        }
        assertEq(nonzero, expectedNonzero, string.concat(name, ": written nonzero slot count"));
        dump = string.concat(
            '"', name, '":{"account":"', vm.toString(a), '","slots":', s, '],"words":', w, "]}"
        );
    }

    function test_namespaces() public pure {
        assertEq(
            _ns("unicity.vr.liability.v1"),
            0xb2905100cfe7c1af5dee2b1b6726fdfd755820e0f51ef675ed653be4f1102d00
        );
        assertEq(
            _ns("example.main"), 0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500
        );
    }

    function test_storageIsTheFrozenLayout() public {
        deployCodeTo("VRSchemaStorage.t.sol:VRLayoutFixture", VR);
        deployCodeTo("VRSchemaStorage.t.sol:VRLayoutFixture", HOLDER);
        string memory json = vm.readFile(string.concat(vm.projectRoot(), FLAT));
        string memory vr = _check(json, "vr", VR, _written(VR, _writeVR));
        string memory lia = _check(json, "liability", HOLDER, _written(HOLDER, _writeLiability));
        string memory out = string.concat(
            '{"format":"unicity.vr.schema/v1 storage-forge","scenarios":{', vr, ",", lia, "}}\n"
        );
        string memory path = string.concat(vm.projectRoot(), DUMP);
        if (vm.envOr("VR_WRITE_FIXTURES", false)) vm.writeFile(path, out);
        assertEq(
            vm.readFile(path),
            out,
            "storage-forge.json is stale; regenerate with VR_WRITE_FIXTURES=true"
        );
    }
}
