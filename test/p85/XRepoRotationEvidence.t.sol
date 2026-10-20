// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {RecordKind, ReserveInput} from "../../src/p85/P85Types.sol";

/// @notice Root-signed evidence across a root-key rotation (the cross-repository suite; bft-core `xrepo/rotation_evidence_test.go`).
///
/// `fixtures/xrepo-go-rotation-evidence.json` is produced by bft-core: conflicting scheme 2 root votes built by the root's statement
/// derivation and signed by the root's signer with this suite's test scalars. Here custody runs the rotation of Evidence.t.sol:
/// identity 2 (rootPk(1)) stages the new root key 0x9501, the primary J is reserved with it and activated by an Ack, and the owner of
/// identity 2 changes afterwards. The Go-signed pairs are then submitted as they are:
/// - the OLD key in the OLD epoch is charged only to the genesis exposure (G's lot, not a deposit made after G);
/// - the NEW key in the NEW epoch is charged to J's exposure (both lots);
/// - the OLD key in the NEW epoch is refused (KeyMismatch): a key is attributed only where it was the identity's key.
contract XRepoRotationEvidenceTest is P85Flow {
    string internal constant GO_ROTATION = "/test/p85/fixtures/xrepo-go-rotation-evidence.json";
    string internal _json;

    function setUp() public override {
        super.setUp();
        _json = vm.readFile(string.concat(vm.projectRoot(), GO_ROTATION));
    }

    function _s(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".statements[", vm.toString(i), "].", field);
    }

    function _vote(uint256 i, string memory which)
        internal
        view
        returns (Evidence.SignedVote memory v)
    {
        v.parent = uint64(vm.parseJsonUint(_json, _s(i, string.concat(which, ".parent"))));
        v.exec = vm.parseJsonBytes32(_json, _s(i, string.concat(which, ".exec")));
        v.timestamp = uint64(vm.parseJsonUint(_json, _s(i, string.concat(which, ".timestamp"))));
        v.signature = vm.parseJsonBytes(_json, _s(i, string.concat(which, ".signature")));
    }

    function _header(uint256 i) internal view returns (Evidence.VoteHeader memory) {
        return Evidence.VoteHeader(
            NETWORK,
            1,
            vm.parseJsonBytes(_json, _s(i, "key")),
            uint64(vm.parseJsonUint(_json, _s(i, "votingEpoch"))),
            uint64(vm.parseJsonUint(_json, _s(i, "votingRound")))
        );
    }

    /// @dev Statement i: the contract reproduces Go's preimage and digest for both votes before anything is submitted.
    function _pair(uint256 i)
        internal
        view
        returns (
            Evidence.VoteHeader memory h,
            Evidence.SignedVote memory a,
            Evidence.SignedVote memory b
        )
    {
        h = _header(i);
        a = _vote(i, "a");
        b = _vote(i, "b");
        assertEq(evidence.votePreimage(h, a), vm.parseJsonBytes(_json, _s(i, "a.preimage")));
        assertEq(evidence.voteDigest(h, b), vm.parseJsonBytes32(_json, _s(i, "b.digest")));
    }

    function _settle(bytes32 caseID, uint256 lotID) internal returns (uint256) {
        uint256[] memory ids = new uint256[](1);
        ids[0] = lotID;
        return evidence.settleEvidence(caseID, ids);
    }

    function test_rootSignedEvidenceAcrossARotationActivatedByAnAck() public {
        assertEq(evidence.rootNetwork(), vm.parseJsonUint(_json, ".rootNetwork"));
        assertEq(evidence.rootGenesis(), vm.parseJsonBytes32(_json, ".rootGenesis"));
        bytes memory oldKey = vm.parseJsonBytes(_json, ".oldKey");
        bytes memory newKey = vm.parseJsonBytes(_json, ".newKey");
        assertEq(oldKey, compressed(rootPk(1)), "Go signed with identity 2's root key");
        assertEq(newKey, compressed(0x9501), "and with the new key it stages");

        // the rotation: identity 2 stages the new key with its possession proof; J is reserved with it and activated by an Ack
        bytes32 digest = keccak256(
            abi.encode(
                keccak256("unicity.p85.pop.proposeRootKey"),
                NETWORK,
                block.chainid,
                address(custody),
                gid(1),
                uint64(1),
                keccak256(newKey),
                uint64(0)
            )
        );
        vm.prank(vm.addr(ownerPk(1)));
        custody.proposeRootKey(gid(1), newKey, sign(0x9501, digest));
        uint256 later = bondFor(gid(1), 400 * UCT);
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        in_.members[1].rootKeyHash = keccak256(newKey);
        vm.prank(address(election));
        custody.reserveCandidate(in_);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();

        // the owner changes after the offences: attribution follows the identity's exposures, not its owner
        (,,,,, uint64 nonce,,,) = custody.positions(gid(1));
        address newOwner = makeAddr("new owner of identity 2");
        vm.prank(vm.addr(ownerPk(1)));
        custody.proposeRoles(gid(1), newOwner, vm.addr(wdPk(1)), nonce);
        vm.prank(newOwner);
        custody.acceptRoles(gid(1), nonce, newOwner, vm.addr(wdPk(1)));

        // the OLD key in the OLD epoch: only G's lot
        (Evidence.VoteHeader memory h, Evidence.SignedVote memory a, Evidence.SignedVote memory b) =
            _pair(0);
        vm.prank(reporter);
        bytes32 caseOld = evidence.submitEvidence(h, a, b, genesisExposure(1));
        assertEq(evidence.caseInfo(caseOld).lotCount, 1);
        uint256 old = lotOf(gid(1));
        _settle(caseOld, old);
        assertEq(lotv(later).penalized, 0, "a deposit made after G is not liable for G's offence");
        assertEq(lotv(old).penalized, 10 * UCT);

        // the NEW key in the NEW epoch: J's exposure, both lots
        (h, a, b) = _pair(1);
        vm.prank(reporter);
        bytes32 caseNew = evidence.submitEvidence(h, a, b, exposureID(ASG_J, gid(1)));
        assertEq(evidence.caseInfo(caseNew).lotCount, 2);

        // the OLD key in the NEW epoch cannot be attributed to J's exposure, nor to G's
        (h, a, b) = _pair(2);
        vm.prank(reporter);
        vm.expectRevert(Evidence.KeyMismatch.selector);
        evidence.submitEvidence(h, a, b, exposureID(ASG_J, gid(1)));
        vm.prank(reporter);
        vm.expectRevert(Evidence.EpochMismatch.selector);
        evidence.submitEvidence(h, a, b, genesisExposure(1));
    }
}
