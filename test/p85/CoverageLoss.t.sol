// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {IElectionPolicy} from "../../src/p85/IP85.sol";
import {ElectionParams, RecordKind} from "../../src/p85/P85Types.sol";

/// @notice A primary that was published must not pass Prepare after a member lost its coverage: the election marks the open result lost,
/// event-driven from Evidence (exclusion, settled penalties) and on demand through `reconcileCandidate`.
contract CoverageLossTest is P85Flow {
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);
    uint256 internal constant CUSTODY_LOTS = 27;
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
        election.elect(keccak256("origin"));
        resultID = election.openResult();
    }

    function _pops() internal returns (ElectionPolicy.PoPInput[] memory pops) {
        pops = new ElectionPolicy.PoPInput[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            bytes memory key = compressed(evmPk(i));
            pops[i] = ElectionPolicy.PoPInput(
                gid(i), key, sign(evmPk(i), election.popDigest(resultID, gid(i), keccak256(key)))
            );
        }
    }

    function _publish() internal {
        election.submitAssignmentPoPs(resultID, _pops());
        election.finalizeCandidate(resultID);
    }

    /// @dev Lowers the remaining principal of the member's lot by one base unit, as a settled penalty would.
    function _penalize(uint256 member) internal {
        bytes32 slot = bytes32(uint256(keccak256(abi.encode(lotOf(gid(member)), CUSTODY_LOTS))) + 1);
        vm.store(address(custody), slot, bytes32(uint256(vm.load(address(custody), slot)) - 1));
    }

    function _lost() internal view returns (bool) {
        return election.publication(resultID).lost;
    }

    // --- event-driven ---------------------------------------------------------------------------

    function test_coverageChangedIsEvidenceOnly() public {
        vm.expectRevert(ElectionPolicy.NotEvidence.selector);
        election.coverageChanged(gid(0));
        vm.prank(address(custody));
        vm.expectRevert(ElectionPolicy.NotEvidence.selector);
        election.coverageChanged(gid(0));
    }

    function test_aMemberWhoLostCoverageMarksThePublishedResultLost() public {
        _publish();
        _penalize(1);
        vm.expectEmit(true, true, false, false, address(election));
        emit ElectionPolicy.CoverageLostFor(resultID, gid(1));
        vm.prank(address(evidence));
        election.coverageChanged(gid(1));
        assertTrue(_lost());
        assertTrue(
            election.publication(resultID).published,
            "the publication stays; the loss is its own proven word"
        );
    }

    function test_aChangeThatKeepsTheMemberCoveredMarksNothing() public {
        _publish();
        vm.prank(address(evidence));
        election.coverageChanged(gid(1));
        assertFalse(_lost());
    }

    function test_aChangeToANonMemberOrWithoutAnOpenResultIsIgnored() public {
        _penalize(0);
        vm.prank(address(evidence));
        election.coverageChanged(99); // not a member: the penalized first member is not looked at
        assertFalse(_lost());
        // resolve the result, then the member's loss concerns no open result
        clock(100_050, 604_900);
        pushRecord(RecordKind.Ack, ackData(resultID, H_ROUND, 100, 101));
        applyAll();
        assertEq(election.openResult(), bytes32(0));
        vm.prank(address(evidence));
        election.coverageChanged(gid(0));
        assertFalse(_lost());
    }

    function test_theEvidenceModuleReportsExclusionAndSettlementToTheElection() public {
        _publish();
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, 1, compressed(rootPk(0)), 1, 99_950);
        Evidence.SignedVote memory a = Evidence.SignedVote(
            keccak256("A"), sign(rootPk(0), evidence.voteDigest(h, keccak256("A")))
        );
        Evidence.SignedVote memory b = Evidence.SignedVote(
            keccak256("B"), sign(rootPk(0), evidence.voteDigest(h, keccak256("B")))
        );
        vm.expectCall(address(election), abi.encodeCall(IElectionPolicy.coverageChanged, (gid(0))));
        vm.prank(reporter);
        bytes32 caseID = evidence.submitEvidence(h, a, b, genesisExposure(0));
        assertTrue(_lost(), "an excluded member is no longer covered");

        uint256[] memory lots = new uint256[](1);
        lots[0] = lotOf(gid(0));
        vm.expectCall(address(election), abi.encodeCall(IElectionPolicy.coverageChanged, (gid(0))));
        evidence.settleEvidence(caseID, lots);
    }

    // --- on demand ------------------------------------------------------------------------------

    function test_reconcileMarksTheResultWhenAnyMemberFellShort() public {
        _publish();
        assertFalse(election.reconcileCandidate(resultID));
        _penalize(3);
        assertTrue(election.reconcileCandidate(resultID));
        assertTrue(_lost());
        assertTrue(election.reconcileCandidate(resultID), "marking is permanent and idempotent");
    }

    function test_reconcileWorksBeforePublicationToo() public {
        _penalize(0);
        assertTrue(election.reconcileCandidate(resultID));
    }

    function test_reconcileNeedsAReservedResult() public {
        vm.expectRevert(ElectionPolicy.NotReserved.selector);
        election.reconcileCandidate(keccak256("none"));
    }

    // --- the effect -----------------------------------------------------------------------------

    function test_aLostResultCannotBeFinalizedOrCollectProofs() public {
        _penalize(2);
        election.reconcileCandidate(resultID);
        ElectionPolicy.PoPInput[] memory pops = _pops();
        vm.expectRevert(ElectionPolicy.CoverageLost.selector);
        election.submitAssignmentPoPs(resultID, pops);
        vm.expectRevert(ElectionPolicy.CoverageLost.selector);
        election.finalizeCandidate(resultID);
    }

    function test_theLostWordSharesTheLastProofSlotAtOffsetThirteen() public {
        _publish();
        _penalize(1);
        election.reconcileCandidate(resultID);
        bytes32 slot = bytes32(
            uint256(keccak256(abi.encode(resultID, uint256(16)))) + 10 // _publications at slot 16, last word is member 10
        );
        uint256 word = uint256(vm.load(address(election), slot));
        assertEq(uint8(word), 1, "published (offset 0)");
        assertEq(uint32(word >> 8), N_GENESIS, "popCount (offset 1)");
        assertEq(uint64(word >> 40), 1, "attempt (offset 5)");
        assertEq(uint8(word >> 104), 1, "lost (offset 13)");
    }
}
