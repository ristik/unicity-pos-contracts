// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: contract licensing is an explicit owner decision (bft-core #1), not a default.
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {B7Relation} from "../../src/b7/B7Relation.sol";

contract B7RelationHarness {
    function relationId() external pure returns (bytes32) {
        return B7Relation.relationId();
    }

    function commitment(
        bytes32 g,
        bytes32 p,
        uint64 e,
        bytes32[11] memory meta,
        bytes32[] memory members
    ) external pure returns (bytes32) {
        return B7Relation.epochCommitment(g, p, e, meta, members);
    }

    function decode(bytes calldata j) external pure returns (B7Relation.Journal memory) {
        return B7Relation.decodeJournal(j);
    }
}

/// @notice Replays bft-core's B7 relation vectors (`b7rel`, fixtures/b7-relation-vectors-v1.json): the limits and relation ID, C_e
///         over the stored entry words, and the canonical journal with each isolated refusal.
contract B7RelationVectorsTest is Test {
    string internal constant VECTORS = "/test/b7/fixtures/b7-relation-vectors-v1.json";
    B7RelationHarness internal h;
    string internal json;

    function setUp() public {
        h = new B7RelationHarness();
        json = vm.readFile(string.concat(vm.projectRoot(), VECTORS));
    }

    function test_domainsLimitsAndRelationIdAreGos() public view {
        assertEq(B7Relation.RELATION_DOMAIN, vm.parseJsonBytes32(json, ".relationDomain"));
        assertEq(B7Relation.COMMITMENT_DOMAIN, vm.parseJsonBytes32(json, ".commitmentDomain"));
        assertEq(B7Relation.JOURNAL_DOMAIN, vm.parseJsonBytes32(json, ".journalDomain"));
        assertEq(B7Relation.MAX_LEAVES, vm.parseJsonUint(json, ".limits.maxLeaves"));
        assertEq(B7Relation.MAX_TRANSFERS, vm.parseJsonUint(json, ".limits.maxTransfers"));
        assertEq(B7Relation.MAX_EPOCHS, vm.parseJsonUint(json, ".limits.maxEpochs"));
        assertEq(B7Relation.MAX_ANCHORS, vm.parseJsonUint(json, ".limits.maxAnchors"));
        assertEq(B7Relation.MAX_SEMANTIC_BYTES, vm.parseJsonUint(json, ".limits.maxSemanticBytes"));
        assertEq(B7Relation.MAX_WITNESS_BYTES, vm.parseJsonUint(json, ".limits.maxWitnessBytes"));
        assertEq(
            B7Relation.MAX_MEMBERS_PER_EPOCH, vm.parseJsonUint(json, ".limits.maxMembersPerEpoch")
        );
        assertEq(B7Relation.MAX_RSMT_SIBLINGS, vm.parseJsonUint(json, ".limits.maxRSMTSiblings"));
        assertEq(h.relationId(), vm.parseJsonBytes32(json, ".relationId"));
    }

    function _c(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".commitments[", vm.toString(i), "].", field);
    }

    function test_everyEpochCommitmentIsGos() public view {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(json, _c(i, "commitment")); ++i) {
            bytes32[] memory metaList = vm.parseJsonBytes32Array(json, _c(i, "metadata"));
            assertEq(metaList.length, 11);
            bytes32[11] memory meta;
            for (uint256 f; f < 11; ++f) {
                meta[f] = metaList[f];
            }
            uint256 m;
            while (vm.keyExistsJson(
                    json, string.concat(_c(i, "members"), "[", vm.toString(m), "]")
                )) {
                ++m;
            }
            bytes32[] memory members = new bytes32[](8 * m);
            for (uint256 j; j < m; ++j) {
                bytes32[] memory w = vm.parseJsonBytes32Array(
                    json, string.concat(_c(i, "members"), "[", vm.toString(j), "]")
                );
                assertEq(w.length, 8);
                for (uint256 f; f < 8; ++f) {
                    members[8 * j + f] = w[f];
                }
            }
            bytes32 got = h.commitment(
                vm.parseJsonBytes32(json, _c(i, "genesisCommitment")),
                vm.parseJsonBytes32(json, _c(i, "profileHash")),
                uint64(vm.parseJsonUint(json, _c(i, "epoch"))),
                meta,
                members
            );
            assertEq(
                got,
                vm.parseJsonBytes32(json, _c(i, "commitment")),
                vm.parseJsonString(json, _c(i, "name"))
            );
            ++n;
        }
        assertGe(n, 6);
    }

    function _j(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".journals[", vm.toString(i), "].", field);
    }

    function test_everyJournalIsDecodedOrRefusedAsGo() public {
        uint256 valid;
        uint256 refused;
        for (uint256 i; vm.keyExistsJson(json, _j(i, "journal")); ++i) {
            bytes memory b = vm.parseJsonBytes(json, _j(i, "journal"));
            string memory name = vm.parseJsonString(json, _j(i, "name"));
            if (vm.parseJsonBool(json, _j(i, "valid"))) {
                B7Relation.Journal memory j = h.decode(b);
                assertEq(keccak256(b), vm.parseJsonBytes32(json, _j(i, "digest")), name);
                assertEq(j.relationId, h.relationId(), name);
                assertEq(b.length, 32 * (16 + 4 * j.epochs.length), name);
                ++valid;
            } else {
                vm.expectRevert(B7Relation.JournalMalformed.selector);
                h.decode(b);
                ++refused;
            }
        }
        assertEq(valid, 4);
        assertGe(refused, 16);
    }

    /// The decoded fields are the encoded words: a re-encoding of the three-epoch journal reproduces its bytes.
    function test_decodedFieldsReencodeToTheSameBytes() public view {
        bytes memory b = vm.parseJsonBytes(json, _j(1, "journal"));
        B7Relation.Journal memory j = h.decode(b);
        bytes memory again = abi.encodePacked(
            abi.encode(
                B7Relation.JOURNAL_DOMAIN,
                j.relationId,
                j.chainId,
                j.genesisCommitment,
                j.profileHash,
                j.witnessCommitment,
                j.release.cfg,
                j.release.nonce,
                j.release.amount,
                j.release.tokenId,
                j.release.salt,
                j.release.firstPredicateHash,
                j.release.lockDigest,
                uint256(uint160(j.release.releaseTo)),
                j.release.nullifier,
                j.epochs.length
            )
        );
        for (uint256 i; i < j.epochs.length; ++i) {
            again = abi.encodePacked(
                again,
                abi.encode(
                    uint256(j.epochs[i].epoch),
                    j.epochs[i].commitment,
                    uint256(j.epochs[i].minRound),
                    uint256(j.epochs[i].maxRound)
                )
            );
        }
        assertEq(again, b);
    }
}
