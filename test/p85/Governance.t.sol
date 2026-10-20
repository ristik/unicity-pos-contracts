// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {GovernanceParams} from "../../src/p85/GovernanceParams.sol";
import {PolicyBounds} from "../../src/p85/PolicyBounds.sol";
import {IGovernance, GovernanceSnapshot, IStakeCustody} from "../../src/p85/IP85.sol";
import {Policy, ElectionParams, RecordKind} from "../../src/p85/P85Types.sol";

/// @notice T8 step 1 (briefs/t8-p7-design.md section 2): GovernanceParams, the one-proposal state machine and its activation through the
/// real election entry point.
contract GovernanceTest is P85Flow {
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);
    bytes32 internal constant ORIGIN = keccak256("origin/1");
    uint64 internal constant CAD_P = 100_000;
    uint64 internal constant CAD_T = 604_800;

    GovernanceParams internal gov;

    function setUp() public override {
        super.setUp();
        gov = factory.POLICY();
    }

    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 2,
            nTarget: 10,
            nMax: 16,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: CAD_P,
            cadenceSeconds: CAD_T
        });
    }

    function _elect() internal returns (ElectionPolicy.Outcome) {
        vm.prank(SYS);
        return election.elect(ORIGIN);
    }

    function _proposal() internal pure returns (Policy memory p) {
        p = Policy({
            penaltyBps: 150,
            lifetimeCapBps: 400,
            bountyBps: 500,
            bountyCap: 2 ether,
            evidenceWindow: 800,
            suffixEvidenceWindow: 900,
            holdNormal: 1_500,
            holdSuffix: 1_600,
            holdRetirement: 1_700,
            timeFloor: 7_200
        });
    }

    function _queue(Policy memory p, uint128 rate) internal returns (uint64) {
        uint64 n = gov.nextNonce();
        bytes32 h = gov.currentPolicyHash();
        vm.prank(governanceAuthority);
        return gov.queue(p, rate, h, n);
    }

    /// @dev Queue at progress 0 / time 0 (the delays then end at 2,000 / 3,600), pass both delays and schedule.
    function _schedule(Policy memory p, uint128 rate) internal returns (uint64 n) {
        n = _queue(p, rate);
        clock(2_000, 3_600);
        gov.execute(n);
    }

    function _same(Policy memory a, Policy memory b) internal pure {
        assertEq(keccak256(abi.encode(a)), keccak256(abi.encode(b)));
    }

    // --- genesis ---------------------------------------------------------------------------------

    function test_genesisIsPolicyOne() public {
        assertEq(gov.currentPolicyID(), 1);
        GovernanceSnapshot memory s = gov.snapshotAt(1);
        _same(s.policy, _defaultPolicy());
        _same(gov.policy(), _defaultPolicy());
        _same(gov.policyAt(1), _defaultPolicy());
        assertEq(s.rewardRate, DEFAULT_REWARD_RATE);
        assertEq(gov.currentRewardRate(), DEFAULT_REWARD_RATE);
        assertEq(s.effectiveProgress, 0);
        assertEq(s.hash, gov.currentPolicyHash());
        assertEq(gov.AUTHORITY(), governanceAuthority);
        assertEq(gov.ELECTION(), address(election));
        assertEq(address(gov.ROOTS()), address(roots));
        assertEq(gov.nextNonce(), 1);
        assertEq(uint8(gov.pending().state), uint8(GovernanceParams.State.None));
        assertEq(address(election.policySource()), address(gov));
        vm.expectRevert(GovernanceParams.UnknownPolicy.selector);
        gov.policyAt(0);
        vm.expectRevert(GovernanceParams.UnknownPolicy.selector);
        gov.policyAt(2);
    }

    function test_theConstructorChecksItsInputs() public {
        Policy memory p = _defaultPolicy();
        uint128 overRate = gov.MAX_REWARD_RATE() + 1;
        vm.expectRevert(GovernanceParams.ZeroAddress.selector);
        new GovernanceParams(p, 0, address(0), address(election), address(roots));
        vm.expectRevert(GovernanceParams.ZeroAddress.selector);
        new GovernanceParams(p, 0, governanceAuthority, address(0), address(roots));
        vm.expectRevert(GovernanceParams.ZeroAddress.selector);
        new GovernanceParams(p, 0, governanceAuthority, address(election), address(0));
        vm.expectRevert(GovernanceParams.RewardRateOutOfBounds.selector);
        new GovernanceParams(p, overRate, governanceAuthority, address(election), address(roots));
        p.penaltyBps = 201;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("penaltyBps"))
        );
        new GovernanceParams(p, 0, governanceAuthority, address(election), address(roots));
    }

    // --- queue -----------------------------------------------------------------------------------

    function test_onlyTheAuthorityQueuesOrCancels() public {
        bytes32 h = gov.currentPolicyHash();
        Policy memory p = _proposal();
        vm.expectRevert(GovernanceParams.NotAuthority.selector);
        gov.queue(p, 1 ether, h, 1);
        uint64 n = _queue(p, 1 ether);
        vm.expectRevert(GovernanceParams.NotAuthority.selector);
        gov.cancel(n);
        vm.prank(governanceAuthority);
        gov.cancel(n);
    }

    function test_queueCapturesTheDelaysAndThePredecessor() public {
        clock(500, 1_000);
        bytes32 h = gov.currentPolicyHash();
        vm.expectEmit(true, false, false, false, address(gov));
        emit GovernanceParams.Queued(1, h, bytes32(0), 2_500, 4_600);
        uint64 n = _queue(_proposal(), 3 ether);
        assertEq(n, 1);
        GovernanceParams.Proposal memory pr = gov.pending();
        assertEq(uint8(pr.state), uint8(GovernanceParams.State.Queued));
        assertEq(pr.nonce, 1);
        assertEq(pr.predecessor, h);
        assertEq(pr.rewardRate, 3 ether);
        assertEq(pr.notBeforeProgress, 2_500, "progress + 2,000 rounds");
        assertEq(pr.notBeforeTime, 4_600, "UC time + 3,600 seconds");
        _same(pr.policy, _proposal());
        assertEq(gov.nextNonce(), 2);
        assertEq(gov.currentPolicyID(), 1, "queueing changes nothing in force");
    }

    function test_aStalePredecessorOrNonceIsRefused() public {
        Policy memory p = _proposal();
        bytes32 cur = gov.currentPolicyHash();
        vm.startPrank(governanceAuthority);
        vm.expectRevert(GovernanceParams.StalePredecessor.selector);
        gov.queue(p, 1 ether, keccak256("not the snapshot in force"), 1);
        vm.expectRevert(abi.encodeWithSelector(GovernanceParams.StaleNonce.selector, 1));
        gov.queue(p, 1 ether, cur, 2);
        vm.expectRevert(abi.encodeWithSelector(GovernanceParams.StaleNonce.selector, 1));
        gov.queue(p, 1 ether, cur, 0);
        vm.stopPrank();
    }

    function test_aSecondProposalIsRefusedWhileOneIsPendingOrScheduled() public {
        uint64 n = _queue(_proposal(), 1 ether);
        bytes32 cur = gov.currentPolicyHash();
        vm.prank(governanceAuthority);
        vm.expectRevert(GovernanceParams.ProposalPending.selector);
        gov.queue(_proposal(), 1 ether, cur, 2);
        clock(2_000, 3_600);
        gov.execute(n);
        vm.prank(governanceAuthority);
        vm.expectRevert(GovernanceParams.ProposalPending.selector);
        gov.queue(_proposal(), 1 ether, cur, 2);
    }

    function test_eachBoundIsEnforcedAtQueue() public {
        bytes32 h = gov.currentPolicyHash();
        uint128 maxRate = gov.MAX_REWARD_RATE();
        vm.startPrank(governanceAuthority);
        Policy memory p = _proposal();
        p.penaltyBps = 201;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("penaltyBps"))
        );
        gov.queue(p, 1 ether, h, 1);
        p = _proposal();
        p.holdNormal = p.evidenceWindow; // the coupled inequality: a hold exceeds its evidence window
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdNormal<=evidence")
            )
        );
        gov.queue(p, 1 ether, h, 1);
        p = _proposal();
        p.timeFloor = 3_599;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("timeFloor"))
        );
        gov.queue(p, 1 ether, h, 1);
        vm.expectRevert(GovernanceParams.RewardRateOutOfBounds.selector);
        gov.queue(_proposal(), maxRate + 1, h, 1);
        // the extremes are allowed, and a refused queue consumed no nonce
        gov.queue(_proposal(), maxRate, h, 1);
        vm.stopPrank();
        assertEq(gov.nextNonce(), 2);
    }

    function test_aZeroRewardRateIsAllowed() public {
        _schedule(_proposal(), 0);
        assertEq(gov.pending().rewardRate, 0);
    }

    // --- execute and cancel ----------------------------------------------------------------------

    function test_executeNeedsBothDelaysAndSchedulesOnly() public {
        uint64 n = _queue(_proposal(), 2 ether);
        uint256 snap = vm.snapshotState();
        vm.expectRevert(GovernanceParams.DelayNotElapsed.selector);
        gov.execute(n);
        clock(1_999, 900_000); // the time delay is long past, one round is missing
        vm.expectRevert(GovernanceParams.DelayNotElapsed.selector);
        gov.execute(n);
        vm.revertToState(snap);
        clock(900_000, 3_599); // rounds are long past, one second is missing
        vm.expectRevert(GovernanceParams.DelayNotElapsed.selector);
        gov.execute(n);
        vm.revertToState(snap);
        // equality of both passes, from anyone
        clock(2_000, 3_600);
        vm.expectEmit(true, false, false, false, address(gov));
        emit GovernanceParams.Executed(n);
        vm.prank(makeAddr("anyone"));
        gov.execute(n);
        assertEq(uint8(gov.pending().state), uint8(GovernanceParams.State.Scheduled));
        assertEq(gov.currentPolicyID(), 1, "execution schedules, it does not activate");
        _same(gov.policy(), _defaultPolicy());
        vm.expectRevert(GovernanceParams.WrongState.selector);
        gov.execute(n);
    }

    function test_executeNamesTheProposal() public {
        vm.expectRevert(GovernanceParams.NoProposal.selector);
        gov.execute(1);
        uint64 n = _queue(_proposal(), 1 ether);
        clock(2_000, 3_600);
        vm.expectRevert(GovernanceParams.NoProposal.selector);
        gov.execute(n + 1);
    }

    function test_cancelConsumesTheNonceAndFreesTheSlot() public {
        uint64 n = _queue(_proposal(), 1 ether);
        vm.expectEmit(true, false, false, false, address(gov));
        emit GovernanceParams.Cancelled(n);
        vm.prank(governanceAuthority);
        gov.cancel(n);
        assertEq(uint8(gov.pending().state), uint8(GovernanceParams.State.None));
        bytes32 cur = gov.currentPolicyHash();
        vm.startPrank(governanceAuthority);
        vm.expectRevert(abi.encodeWithSelector(GovernanceParams.StaleNonce.selector, 2));
        gov.queue(_proposal(), 1 ether, cur, n);
        gov.queue(_proposal(), 1 ether, cur, 2);
        vm.expectRevert(GovernanceParams.NoProposal.selector);
        gov.cancel(n);
        vm.stopPrank();
        vm.expectRevert(GovernanceParams.NoProposal.selector);
        gov.execute(n);
    }

    function test_aScheduledProposalCanBeCancelledBeforeActivation() public {
        uint64 n = _schedule(_proposal(), 1 ether);
        vm.prank(governanceAuthority);
        gov.cancel(n);
        clock(CAD_P, CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(gov.currentPolicyID(), 1, "a cancelled proposal never activates");
    }

    // --- activation only through the election ----------------------------------------------------

    function test_onlyTheElectionActivates() public {
        _schedule(_proposal(), 1 ether);
        vm.expectRevert(GovernanceParams.NotElection.selector);
        gov.activateDue(CAD_P, CAD_T);
        vm.prank(governanceAuthority);
        vm.expectRevert(GovernanceParams.NotElection.selector);
        gov.activateDue(CAD_P, CAD_T);
        assertEq(gov.currentPolicyID(), 1);
    }

    function test_theElectionActivatesAtItsDueBoundaryBeforeCapturingThePolicy() public {
        uint64 n = _schedule(_proposal(), 3 ether);
        bytes32 before = gov.currentPolicyHash();
        clock(CAD_P, CAD_T);
        vm.expectEmit(true, true, false, false, address(gov));
        emit GovernanceParams.Activated(2, n, bytes32(0), CAD_P);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));

        assertEq(gov.currentPolicyID(), 2);
        _same(gov.policy(), _proposal());
        _same(gov.policyAt(2), _proposal());
        assertEq(gov.currentRewardRate(), 3 ether);
        GovernanceSnapshot memory s = gov.snapshotAt(2);
        assertEq(s.effectiveProgress, CAD_P);
        assertEq(s.effectiveTime, CAD_T);
        assertTrue(s.hash != before);
        assertEq(uint8(gov.pending().state), uint8(GovernanceParams.State.None));
        // the history is immutable
        _same(gov.policyAt(1), _defaultPolicy());
        assertEq(gov.rewardRateAt(1), DEFAULT_REWARD_RATE);
        assertEq(gov.snapshotAt(1).hash, before);
        // the election captured the NEW id, and the new assignment holds its terms
        bytes32 resultID = election.openResult();
        assertEq(election.result(resultID).policyID, 2);
        Asg memory a = asg(election.result(resultID).assignmentID);
        assertEq(a.policyID, 2);
        // an obligation that captured policy 1 keeps it
        assertEq(asg(GENESIS_ASSIGNMENT).policyID, 1);
        _same(custody.policyTerms(GENESIS_ASSIGNMENT), _defaultPolicy());
        _same(custody.policyTerms(election.result(resultID).assignmentID), _proposal());
    }

    function test_nothingActivatesBeforeTheElectionIsDue() public {
        _schedule(_proposal(), 1 ether);
        uint256 snap = vm.snapshotState();
        clock(CAD_P - 1, CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NotDue));
        vm.revertToState(snap);
        clock(CAD_P, CAD_T - 1);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NotDue));
        assertEq(gov.currentPolicyID(), 1);
        assertEq(uint8(gov.pending().state), uint8(GovernanceParams.State.Scheduled));
        clock(CAD_P, CAD_T);
        _elect();
        assertEq(gov.currentPolicyID(), 2);
    }

    function test_aQueuedButUnexecutedProposalIsNotActivated() public {
        _queue(_proposal(), 1 ether);
        clock(CAD_P, CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        assertEq(gov.currentPolicyID(), 1);
        assertEq(uint8(gov.pending().state), uint8(GovernanceParams.State.Queued));
    }

    function test_nothingActivatesWhileAnElectionIsUnresolved() public {
        clock(CAD_P, CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        uint64 n = _queue(_proposal(), 1 ether);
        clock(CAD_P + 2_000, CAD_T + 3_600);
        gov.execute(n);
        clock(3 * CAD_P, 3 * CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Disabled));
        assertEq(gov.currentPolicyID(), 1, "an unresolved result blocks the boundary");
        assertEq(uint8(gov.pending().state), uint8(GovernanceParams.State.Scheduled));
    }

    function test_nothingActivatesWhileTheRecordPrefixIsIncomplete() public {
        _schedule(_proposal(), 1 ether);
        clock(CAD_P, CAD_T);
        roots.push(RecordKind.SessionClosed, hex"");
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Disabled));
        assertEq(gov.currentPolicyID(), 1);
    }

    function test_aFailedSelectionStillActivatesAndNeverMixesPolicyIDs() public {
        // one eligible identity left, below the floor of two: the election records Cardinality
        requestRetirement(0);
        requestRetirement(1);
        requestRetirement(2);
        _schedule(_proposal(), 1 ether);
        clock(CAD_P, CAD_T);
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.NoCandidateRecorded));
        assertEq(gov.currentPolicyID(), 2, "the due boundary activated under the old threshold");
        assertEq(election.openResult(), bytes32(0));
        // the next attempt (the cadence runs from the attempt) captures only the new id
        assertEq(election.attemptCursor(), 1);
    }

    function test_aRefusedActivationLeavesTheElectionAndThePolicyUnchanged() public {
        _schedule(_proposal(), 1 ether);
        clock(CAD_P, CAD_T);
        vm.mockCallRevert(
            address(gov), abi.encodeCall(IGovernance.activateDue, (CAD_P, CAD_T)), "refused"
        );
        assertEq(uint8(_elect()), uint8(ElectionPolicy.Outcome.Reserved));
        vm.clearMockedCalls();
        assertEq(gov.currentPolicyID(), 1);
        assertEq(election.result(election.openResult()).policyID, 1);
        assertEq(uint8(gov.pending().state), uint8(GovernanceParams.State.Scheduled));
    }

    function test_theNextProposalChainsOnTheActivatedSnapshot() public {
        _schedule(_proposal(), 1 ether);
        clock(CAD_P, CAD_T);
        _elect();
        bytes32 h2 = gov.currentPolicyHash();
        // the old hash is stale now
        bytes32 h1 = gov.snapshotAt(1).hash;
        vm.prank(governanceAuthority);
        vm.expectRevert(GovernanceParams.StalePredecessor.selector);
        gov.queue(_defaultPolicy(), 1 ether, h1, 2);
        vm.prank(governanceAuthority);
        gov.queue(_defaultPolicy(), 2 ether, h2, 2);
        assertEq(gov.pending().predecessor, h2);
        // returning to the old terms is a NEW snapshot, never a reuse of id 1
        clock(CAD_P + 2_000, CAD_T + 3_600);
        gov.execute(2);
        assertEq(gov.currentPolicyID(), 2);
    }

    /// @dev The gas the hook pays for governance: an election with nothing scheduled (one extra call that returns false) and the same
    /// election that activates a scheduled snapshot. Logged for the gas profile; the bound is generous and guards a gross regression.
    function test_governanceGasOverheadOfTheElectionHook() public {
        uint256 snap = vm.snapshotState();
        clock(CAD_P, CAD_T);
        vm.prank(SYS);
        uint256 g0 = gasleft();
        election.elect(ORIGIN);
        uint256 plain = g0 - gasleft();
        vm.revertToState(snap);
        _schedule(_proposal(), 1 ether);
        clock(CAD_P, CAD_T);
        vm.prank(SYS);
        g0 = gasleft();
        election.elect(ORIGIN);
        uint256 activating = g0 - gasleft();
        emit log_named_uint("elect, nothing scheduled", plain);
        emit log_named_uint("elect, activating a snapshot", activating);
        assertLt(activating, plain + 200_000);
    }

    // --- the surface -----------------------------------------------------------------------------

    /// @dev Governance has no setter for the knobs this deployment keeps immutable: the only state-changing functions are the four of the
    /// proposal state machine. The ABI is read from the compiled artifact.
    function test_theOnlyStateChangingFunctionsAreTheProposalStateMachine() public view {
        string memory json = vm.readFile("out/GovernanceParams.sol/GovernanceParams.json");
        bytes32 got;
        uint256 count;
        for (uint256 i; vm.keyExistsJson(json, string.concat(".abi[", vm.toString(i), "]")); ++i) {
            string memory entry = string.concat(".abi[", vm.toString(i), "]");
            if (
                keccak256(bytes(vm.parseJsonString(json, string.concat(entry, ".type"))))
                    != keccak256("function")
            ) continue;
            bytes32 mut = keccak256(
                bytes(vm.parseJsonString(json, string.concat(entry, ".stateMutability")))
            );
            if (mut == keccak256("view") || mut == keccak256("pure")) continue;
            got ^= keccak256(bytes(vm.parseJsonString(json, string.concat(entry, ".name"))));
            ++count;
        }
        assertEq(count, 4);
        assertEq(
            got,
            keccak256("queue") ^ keccak256("execute") ^ keccak256("cancel")
                ^ keccak256("activateDue")
        );
    }

    // --- a sequence of snapshots never rewrites the past ------------------------------------------

    function testFuzz_snapshotsAreImmutableAndChained(uint256 seed) public {
        uint256 rounds = 1 + (seed % 4);
        bytes32[] memory hashes = new bytes32[](rounds + 1);
        Policy[] memory pols = new Policy[](rounds + 1);
        uint128[] memory rates = new uint128[](rounds + 1);
        hashes[0] = gov.currentPolicyHash();
        pols[0] = _defaultPolicy();
        rates[0] = DEFAULT_REWARD_RATE;
        uint64 p = 0;
        uint64 t = 0;
        for (uint256 i = 1; i <= rounds; ++i) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            Policy memory q = _proposal();
            q.penaltyBps = uint16(seed % 201);
            q.bountyBps = uint16((seed >> 16) % 2_001);
            q.timeFloor = uint64(3_600 + ((seed >> 32) % 600_000));
            uint128 rate = uint128((seed >> 64) % (uint256(gov.MAX_REWARD_RATE()) + 1));
            uint64 n = _queue(q, rate);
            p += 2_000;
            t += 3_600;
            clock(p, t);
            gov.execute(n);
            // the election is due under the cadence that runs from the last attempt
            p += CAD_P;
            t += CAD_T;
            clock(p, t);
            _elect();
            // the open result must resolve for the next boundary: close it as an unelected attempt
            bytes32 open = election.openResult();
            if (open != bytes32(0)) {
                vm.prank(address(custody));
                election.resultResolved(open, 3, p, t);
            }
            assertEq(gov.currentPolicyID(), i + 1);
            hashes[i] = gov.currentPolicyHash();
            pols[i] = q;
            rates[i] = rate;
            for (uint256 j = 0; j <= i; ++j) {
                GovernanceSnapshot memory s = gov.snapshotAt(uint32(j + 1));
                assertEq(s.hash, hashes[j]);
                assertEq(s.rewardRate, rates[j]);
                _same(s.policy, pols[j]);
            }
        }
    }
}
