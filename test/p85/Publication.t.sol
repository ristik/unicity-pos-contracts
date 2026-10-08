// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {
    ElectionParams,
    RecordKind,
    SessionClosedData,
    ReserveInput
} from "../../src/p85/P85Types.sol";

/// @notice PR3 slice 4: possession proofs, publication and the mandatory K commitment of a reserved result.
contract PublicationTest is P85Flow {
    address internal constant SYS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;
    bytes32 internal constant ORIGIN = keccak256("origin/1");
    bytes32 internal resultID;

    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 2,
            nTarget: 10,
            nMax: 32,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: 100_000,
            cadenceSeconds: 604_800
        });
    }

    function setUp() public override {
        super.setUp();
        clock(100_000, 604_800);
        vm.prank(SYS);
        election.elect(ORIGIN);
        resultID = election.openResult();
    }

    function _evm(uint256 i) internal returns (bytes memory) {
        return compressed(evmPk(i));
    }

    function _pop(uint256 i) internal returns (ElectionPolicy.PoPInput memory) {
        bytes memory key = _evm(i);
        bytes32 d = election.popDigest(resultID, gid(i), keccak256(key));
        return ElectionPolicy.PoPInput(gid(i), key, sign(evmPk(i), d));
    }

    function _all() internal returns (ElectionPolicy.PoPInput[] memory pops) {
        pops = new ElectionPolicy.PoPInput[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            pops[i] = _pop(i);
        }
    }

    function _publish() internal {
        election.submitAssignmentPoPs(resultID, _all());
        election.finalizeCandidate(resultID);
    }

    // --- K -------------------------------------------------------------------------------------

    function test_theRecoveryAuthorizationIsWrittenWithTheReservation() public view {
        ElectionPolicy.RecoveryAuthorization memory a = election.recoveryAuthorization(resultID);
        Asg memory inc = asg(GENESIS_ASSIGNMENT);
        assertEq(a.resultID, resultID);
        assertEq(a.incumbent, GENESIS_ASSIGNMENT);
        assertEq(a.incumbentExposureDigest, inc.exposureDigest);
        assertEq(a.incumbentKeyDigest, inc.keyDigest);
        assertEq(a.snapshotDigest, election.result(resultID).snapshotDigest);
        assertEq(a.policyDigest, keccak256(abi.encode(custody.policyTerms(GENESIS_ASSIGNMENT))));
        assertTrue(a.contractsDigest != bytes32(0) && a.kCommit != bytes32(0));
        assertEq(
            a.kCommit,
            keccak256(
                abi.encode(
                    keccak256("unicity.p85.recovery-authorization"),
                    NETWORK,
                    block.chainid,
                    resultID,
                    a.snapshotDigest,
                    a.incumbent,
                    a.incumbentExposureDigest,
                    a.incumbentKeyDigest,
                    a.policyDigest,
                    a.contractsDigest
                )
            )
        );
        assertFalse(election.publication(resultID).published);
    }

    function test_theContractsDigestNamesTheDeployment() public view {
        bytes32 want = keccak256(
            abi.encode(
                keccak256("unicity.p85.contracts"),
                block.chainid,
                address(custody),
                address(custody).codehash,
                address(election),
                address(election).codehash,
                address(evidence),
                address(evidence).codehash,
                address(election.selection()),
                address(election.selection()).codehash,
                address(election.policySource()),
                address(election.policySource()).codehash,
                address(roots)
            )
        );
        assertEq(election.recoveryAuthorization(resultID).contractsDigest, want);
    }

    // --- possession proofs -----------------------------------------------------------------

    function test_aValidProofIsStoredOnceAndRepeatsAreNoOps() public {
        ElectionPolicy.PoPInput[] memory one = new ElectionPolicy.PoPInput[](1);
        one[0] = _pop(0);
        vm.expectEmit(true, true, false, true, address(election));
        emit ElectionPolicy.PoPAccepted(resultID, gid(0), keccak256(one[0].signature));
        election.submitAssignmentPoPs(resultID, one);
        assertEq(election.popHash(resultID, gid(0)), keccak256(one[0].signature));
        assertEq(election.publication(resultID).popCount, 1);
        election.submitAssignmentPoPs(resultID, one); // exact repeat
        assertEq(election.publication(resultID).popCount, 1);
    }

    function test_aSecondValidProofForAStoredSlotIsRefused() public {
        ElectionPolicy.PoPInput[] memory one = new ElectionPolicy.PoPInput[](1);
        one[0] = _pop(0);
        election.submitAssignmentPoPs(resultID, one);
        // the same key signs the same digest again with another nonce: a distinct, valid, low-s signature
        bytes32 d = election.popDigest(resultID, gid(0), keccak256(one[0].evmKey));
        (uint8 v, bytes32 r, bytes32 s) = vm.signWithNonceUnsafe(evmPk(0), d, 12345);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        if (uint256(s) > n / 2) {
            s = bytes32(n - uint256(s));
            v = v == 27 ? 28 : 27;
        }
        one[0].signature = abi.encodePacked(r, s, v);
        assertTrue(keccak256(one[0].signature) != election.popHash(resultID, gid(0)));
        vm.expectRevert(abi.encodeWithSelector(ElectionPolicy.PoPConflict.selector, gid(0)));
        election.submitAssignmentPoPs(resultID, one);
        assertEq(election.publication(resultID).popCount, 1);
    }

    function test_aSignatureOverAnotherContextIsRefused() public {
        // the delegation digest of the same member, signed by the same key, is not a possession proof
        ElectionPolicy.PoPInput[] memory one = new ElectionPolicy.PoPInput[](1);
        one[0] = _pop(0);
        one[0].signature = sign(evmPk(0), keccak256("unicity.p85.admitDelegation"));
        vm.expectRevert(abi.encodeWithSelector(ElectionPolicy.BadPossession.selector, gid(0)));
        election.submitAssignmentPoPs(resultID, one);
    }

    function test_aSignatureByAnotherKeyIsRefused() public {
        ElectionPolicy.PoPInput[] memory one = new ElectionPolicy.PoPInput[](1);
        one[0] = _pop(0);
        one[0].signature =
            sign(evmPk(1), election.popDigest(resultID, gid(0), keccak256(one[0].evmKey)));
        vm.expectRevert(abi.encodeWithSelector(ElectionPolicy.BadPossession.selector, gid(0)));
        election.submitAssignmentPoPs(resultID, one);
    }

    function test_theKeyMustBeTheMembersFrozenEvmKey() public {
        ElectionPolicy.PoPInput[] memory one = new ElectionPolicy.PoPInput[](1);
        bytes memory other = compressed(evmPk(1));
        one[0] = ElectionPolicy.PoPInput(
            gid(0), other, sign(evmPk(1), election.popDigest(resultID, gid(0), keccak256(other)))
        );
        vm.expectRevert(abi.encodeWithSelector(ElectionPolicy.WrongEvmKey.selector, gid(0)));
        election.submitAssignmentPoPs(resultID, one);
    }

    function test_onlyFrozenMembersCanBeProved() public {
        ElectionPolicy.PoPInput[] memory one = new ElectionPolicy.PoPInput[](1);
        one[0] = _pop(0);
        one[0].id = 99;
        vm.expectRevert(abi.encodeWithSelector(ElectionPolicy.NotMember.selector, uint64(99)));
        election.submitAssignmentPoPs(resultID, one);
    }

    function test_batchesAreBounded() public {
        ElectionPolicy.PoPInput[] memory none = new ElectionPolicy.PoPInput[](0);
        vm.expectRevert(ElectionPolicy.BatchSize.selector);
        election.submitAssignmentPoPs(resultID, none);
        ElectionPolicy.PoPInput[] memory many = new ElectionPolicy.PoPInput[](33);
        vm.expectRevert(ElectionPolicy.BatchSize.selector);
        election.submitAssignmentPoPs(resultID, many);
    }

    function test_aProofForAnUnknownResultIsRefused() public {
        ElectionPolicy.PoPInput[] memory pops = _all();
        vm.expectRevert(ElectionPolicy.NotReserved.selector);
        election.submitAssignmentPoPs(keccak256("nope"), pops);
    }

    // --- publication ------------------------------------------------------------------------

    function test_publicationNeedsEveryProof() public {
        ElectionPolicy.PoPInput[] memory some = new ElectionPolicy.PoPInput[](N_GENESIS - 1);
        for (uint256 i; i < some.length; ++i) {
            some[i] = _pop(i);
        }
        election.submitAssignmentPoPs(resultID, some);
        vm.expectRevert(ElectionPolicy.MissingProofs.selector);
        election.finalizeCandidate(resultID);
    }

    function test_finalizeWritesTheFixedProofSlots() public {
        election.submitAssignmentPoPs(resultID, _all());
        vm.expectEmit(true, false, false, false, address(election));
        emit ElectionPolicy.CandidatePublished(resultID, bytes32(0));
        election.finalizeCandidate(resultID);
        ElectionPolicy.Publication memory p = election.publication(resultID);
        assertTrue(p.published);
        assertEq(p.popCount, N_GENESIS);
        ElectionPolicy.Result memory r = election.result(resultID);
        Asg memory a = asg(r.assignmentID);
        bytes32 fold = keccak256("unicity.p85.pop-set");
        for (uint256 i; i < N_GENESIS; ++i) {
            fold = keccak256(abi.encode(fold, gid(i), election.popHash(resultID, gid(i))));
        }
        assertEq(p.popSetDigest, fold);
        assertEq(
            p.primaryHash,
            keccak256(
                abi.encode(
                    keccak256("unicity.p85.primary-commitment"),
                    NETWORK,
                    block.chainid,
                    address(custody),
                    address(election),
                    resultID,
                    r.assignmentID,
                    r.predecessor,
                    r.attempt,
                    r.snapshotDigest,
                    a.exposureDigest,
                    a.keyDigest,
                    fold
                )
            )
        );
        assertEq(p.assignmentID, r.assignmentID);
        assertEq(p.snapshotDigest, r.snapshotDigest);
    }

    function test_publishedResultsAcceptNothingMore() public {
        _publish();
        vm.expectRevert(ElectionPolicy.AlreadyPublished.selector);
        election.finalizeCandidate(resultID);
        ElectionPolicy.PoPInput[] memory pops = _all();
        vm.expectRevert(ElectionPolicy.AlreadyPublished.selector);
        election.submitAssignmentPoPs(resultID, pops);
    }

    function test_aMemberWhoRetiredAfterTheSnapshotBlocksPublication() public {
        election.submitAssignmentPoPs(resultID, _all());
        requestRetirement(2);
        vm.expectRevert(abi.encodeWithSelector(ElectionPolicy.NotCovered.selector, gid(2)));
        election.finalizeCandidate(resultID);
        assertFalse(election.publication(resultID).published);
    }

    function test_aMemberWhoLostCoverageBlocksPublication() public {
        election.submitAssignmentPoPs(resultID, _all());
        // a penalty reduces the lot below weight * bondUnit: simulate by lowering remaining principal directly
        uint256 lot = lotOf(gid(1));
        bytes32 slot1 = bytes32(uint256(keccak256(abi.encode(lot, uint256(27)))) + 1); // lots mapping word 1: remaining | penalized
        bytes32 word = vm.load(address(custody), slot1);
        // remaining is the low 128 bits
        vm.store(
            address(custody),
            slot1,
            bytes32((uint256(word) >> 128 << 128) | (uint256(word) & type(uint128).max) - 1)
        );
        vm.expectRevert(abi.encodeWithSelector(ElectionPolicy.NotCovered.selector, gid(1)));
        election.finalizeCandidate(resultID);
    }

    function test_aClosedSessionCannotBePublished() public {
        election.submitAssignmentPoPs(resultID, _all());
        clock(100_010, 604_810);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(resultID)));
        applyAll();
        vm.expectRevert(ElectionPolicy.NotReserved.selector);
        election.finalizeCandidate(resultID);
    }
}
