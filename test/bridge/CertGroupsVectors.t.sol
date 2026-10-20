// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {CertGroups} from "../../src/bridge/CertGroups.sol";
import {Anchor} from "../../src/bridge/BridgeTypes.sol";

contract CertGroupsVectorsHarness {
    /// the native batch's own item bound (32,768), which the verifier uses too (owner §36)
    function measure(Anchor[] memory a) external pure returns (CertGroups.Counts memory) {
        return CertGroups.measure(a, type(uint256).max, 32_768);
    }
}

/// @notice The Solidity scan and grouping against the shared corpus `b1-vectors/any-age-v1` (bft-core b1ref, independently constructed by
///         b1gen): for every CERT_BATCH_V2 vector with a stated grouping, `CertGroups` computes the same C, K, E, S, Q, A, P and the same
///         `G_batch` as the Go reference and the vector's charge; for every vector the native scan halts on, the scan refuses what it is
///         built to refuse and the rest is listed (the Solidity scan accepts a superset of the native one by design: the native call is
///         the authority, and a request it halts on fails there).
contract CertGroupsVectorsTest is Test {
    CertGroupsVectorsHarness internal h = new CertGroupsVectorsHarness();

    /// @dev The packed request as a table of anchors, or ok = false when the outer layout is not exactly `02 00 K | claims`.
    function _parse(bytes memory r) internal pure returns (bool ok, Anchor[] memory a) {
        if (r.length < 4 || r[0] != 0x02 || r[1] != 0x00) return (false, a);
        uint256 k = (uint256(uint8(r[2])) << 8) | uint8(r[3]);
        if (k == 0 || k > 16) return (false, a);
        a = new Anchor[](k);
        uint256 pos = 4;
        for (uint256 i = 0; i < k; ++i) {
            if (pos + 6 > r.length) return (false, a);
            a[i].partition = uint32(bytes4(_at(r, pos, 4)));
            uint256 sl = (uint256(uint8(r[pos + 4])) << 8) | uint8(r[pos + 5]);
            pos += 6;
            if (pos + sl + 100 > r.length) return (false, a);
            a[i].shard = _at(r, pos, sl);
            pos += sl;
            a[i].shardConfHash = bytes32(_at(r, pos, 32));
            a[i].expectedStateRoot = bytes32(_at(r, pos + 32, 32));
            a[i].expectedIRHash = bytes32(_at(r, pos + 64, 32));
            uint256 ul = uint32(bytes4(_at(r, pos + 96, 4)));
            pos += 100;
            if (pos + ul > r.length) return (false, a);
            a[i].uc = _at(r, pos, ul);
            pos += ul;
        }
        return (pos == r.length, a);
    }

    function _at(bytes memory b, uint256 off, uint256 len)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) {
            out[i] = b[off + i];
        }
    }

    function _key(string memory id, string memory field) internal pure returns (string memory) {
        return string.concat('.vectors["', id, '"].', field);
    }

    function test_everyGroupedVectorHasTheReferencesCountsAndCharge() public {
        string memory json = vm.readFile("test/bridge/b1-vectors.json");
        string[] memory ids = vm.parseJsonKeys(json, ".vectors");
        uint256 checked;
        uint256 strict;
        for (uint256 i = 0; i < ids.length; ++i) {
            if (!vm.keyExistsJson(json, _key(ids[i], "grouping"))) continue;
            (bool ok, Anchor[] memory a) = _parse(vm.parseJsonBytes(json, _key(ids[i], "request")));
            assertTrue(ok, string.concat(ids[i], ": the outer layout parses"));
            CertGroups.Counts memory n;
            try h.measure(a) returns (CertGroups.Counts memory got) {
                n = got;
            } catch {
                // The scan is stricter than the native batch in one place: a UC whose own shard differs from the claim's is a structural
                // refusal here and a semantic false there (the verifier reverts either way). It is allowed only for a false batch, and only
                // for the vector that builds exactly that.
                bool validBatch = keccak256(vm.parseJsonBytes(json, _key(ids[i], "output")))
                    == keccak256(abi.encode(uint256(2), true));
                assertFalse(validBatch, string.concat(ids[i], ": the scan refused a valid batch"));
                emit log_named_string("stricter than native (false there, refused here)", ids[i]);
                ++strict;
                continue;
            }
            assertEq(
                n.c, vm.parseJsonUint(json, _key(ids[i], "grouping.C")), string.concat(ids[i], " C")
            );
            assertEq(
                n.k, vm.parseJsonUint(json, _key(ids[i], "grouping.K")), string.concat(ids[i], " K")
            );
            assertEq(
                n.e, vm.parseJsonUint(json, _key(ids[i], "grouping.E")), string.concat(ids[i], " E")
            );
            assertEq(
                n.s, vm.parseJsonUint(json, _key(ids[i], "grouping.S")), string.concat(ids[i], " S")
            );
            assertEq(
                n.q, vm.parseJsonUint(json, _key(ids[i], "grouping.Q")), string.concat(ids[i], " Q")
            );
            assertEq(
                n.a, vm.parseJsonUint(json, _key(ids[i], "grouping.A")), string.concat(ids[i], " A")
            );
            assertEq(
                n.p, vm.parseJsonUint(json, _key(ids[i], "grouping.P")), string.concat(ids[i], " P")
            );
            assertEq(
                CertGroups.batchGas(n),
                vm.parseJsonUint(json, _key(ids[i], "gas")),
                string.concat(ids[i], " G_batch")
            );
            ++checked;
        }
        assertGe(checked + strict, 150, "the corpus has 157 grouped vectors");
        assertEq(
            strict,
            2,
            "cert.neg.shard-bit and topo.prefix-change.parent-claimed: a claim naming another shard than its UC"
        );
        emit log_named_uint("grouped vectors reproduced", checked);
    }

    /// The scan refuses what it is built to refuse. The native-only refusals (signature bytes, UTF-8, duplicate map keys and key order,
    /// summary and node-ID lengths, floats) are listed so a change to the set is visible.
    function test_theScanRefusesWhatItIsBuiltToRefuseAndTheNativeOnlyRestIsListed() public {
        string memory json = vm.readFile("test/bridge/b1-vectors.json");
        string[] memory ids = vm.parseJsonKeys(json, ".vectors");
        uint256 refused;
        uint256 accepted;
        string memory acceptedList = "";
        for (uint256 i = 0; i < ids.length; ++i) {
            if (!vm.keyExistsJson(json, _key(ids[i], "sentinel"))) continue;
            (bool ok, Anchor[] memory a) = _parse(vm.parseJsonBytes(json, _key(ids[i], "request")));
            if (!ok) continue; // refused at the packed layer: the bridge builds the table, so it is never sent
            try h.measure(a) returns (CertGroups.Counts memory) {
                ++accepted;
                acceptedList = string.concat(
                    acceptedList,
                    ids[i],
                    " (",
                    vm.parseJsonString(json, _key(ids[i], "sentinel")),
                    ") "
                );
            } catch {
                ++refused;
            }
        }
        emit log_named_uint("native halts the Solidity scan also refuses", refused);
        emit log_named_uint("native-only halts the Solidity scan accepts", accepted);
        emit log_string(acceptedList);
        assertGt(refused, 0);
    }
}
