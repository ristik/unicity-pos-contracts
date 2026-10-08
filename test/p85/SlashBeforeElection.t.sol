// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {ElectionParams} from "../../src/p85/P85Types.sol";

/// @notice Slice 7 acceptance, slash before election: an incumbent whose offence was admitted and settled through the real Evidence module
/// before the election is due is excluded from the primary, and the election answers with an ordered NoCandidate (here the strict
/// continuity bound) instead of electing around the offender or failing. Nothing is reserved, the incumbent authority continues, and the
/// offender stays in the exact K, so recovery of the incumbent slate is still possible.
contract SlashBeforeElectionTest is P85Flow {
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);
    bytes32 internal constant ORIGIN = keccak256("origin/slash");
    uint64 internal constant CAD_P = 100_000;
    uint64 internal constant CAD_T = 604_800;

    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 2,
            nTarget: 10,
            nMax: 32,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: CAD_P,
            cadenceSeconds: CAD_T
        });
    }

    function _offend(uint256 member) internal returns (bytes32 caseID) {
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, 1, compressed(rootPk(member)), 1, 50);
        Evidence.SignedVote memory a = Evidence.SignedVote(
            keccak256("A"), sign(rootPk(member), evidence.voteDigest(h, keccak256("A")))
        );
        Evidence.SignedVote memory b = Evidence.SignedVote(
            keccak256("B"), sign(rootPk(member), evidence.voteDigest(h, keccak256("B")))
        );
        vm.prank(reporter);
        caseID = evidence.submitEvidence(h, a, b, genesisExposure(member));
    }

    function _settle(bytes32 caseID, uint256 member) internal {
        uint256[] memory lots = new uint256[](1);
        lots[0] = lotOf(gid(member));
        evidence.settleEvidence(caseID, lots);
    }

    function _elect() internal returns (ElectionPolicy.Outcome) {
        vm.prank(SYS);
        return election.elect(ORIGIN);
    }

    function test_anIncumbentExcludedBeforeTheElectionIsNotElectedAround() public {
        bytes32 caseID = _offend(0);
        _settle(caseID, 0);
        assertTrue(evidence.excluded(gid(0)), "the real Evidence module excluded the offender");

        clock(CAD_P, CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));

        ElectionPolicy.Result memory r = election.result(_only());
        assertEq(uint8(r.state), uint8(ElectionPolicy.ResultState.NoCandidate));
        assertEq(uint8(r.reason), uint8(ElectionPolicy.Reason.MembershipChurn));
        assertEq(election.openResult(), bytes32(0), "no unresolved result");
        assertEq(custody.lastAckedAssignment(), GENESIS_ASSIGNMENT, "the authority continues");
        assertEq(
            expo(genesisExposure(0)).id, gid(0), "the offender's incumbent exposure is untouched"
        );
    }

    function test_theSameElectionWithoutTheOffenceIsReserved() public {
        // the control: only the offence differs, so the NoCandidate above is the exclusion and nothing else
        clock(CAD_P, CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
    }

    function test_anOffenceAdmittedButNotSettledStillExcludes() public {
        _offend(0);
        assertTrue(evidence.excluded(gid(0)), "exclusion is at admission, not at settlement");
        clock(CAD_P, CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));
    }

    function _only() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("unicity.p85.election-result"),
                NETWORK,
                block.chainid,
                address(election),
                custody.lastAckedAssignment(),
                uint64(1),
                ORIGIN
            )
        );
    }
}
