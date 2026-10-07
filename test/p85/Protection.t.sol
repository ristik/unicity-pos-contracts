// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {MockRootRecords} from "./MockRootRecords.sol";
import {UncheckedPolicy} from "./UncheckedPolicy.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {
    Policy,
    Limits,
    RecordKind,
    ReserveInput,
    RecoveryAckData,
    SessionClosedData,
    RetirementData,
    Delegation,
    DelegationRequest
} from "../../src/p85/P85Types.sol";

/// @notice Captured protection maxima across several obligations of one lot, suffix-capable windows,
/// and the exposure commitments the root binds.
contract ProtectionTest is P85Flow {
    function _limits() internal pure returns (Limits memory) {
        return Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32});
    }

    /// A later closure under a laxer captured policy and an earlier anchor must not shorten any of
    /// the lot's maxima: hold, evidence window, UC floor and the retirement liability anchor.
    function test_laterClosureUnderALaxerPolicyNeverShortensCapturedMaxima() public {
        Policy memory lax = _defaultPolicy();
        lax.holdNormal = 401;
        lax.holdSuffix = 401;
        lax.evidenceWindow = 200;
        lax.suffixEvidenceWindow = 200;
        lax.timeFloor = 1;
        UncheckedPolicy source = new UncheckedPolicy(_defaultPolicy());
        _deployManual(address(source), _limits());
        source.addSnapshot(lax); // J and J2 capture the lax snapshot

        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(20, 100);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 10, 101)); // J: offset 10, first round 101
        clock(30, 1_000);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "g"));
        applyAll(); // G anchor = max(p(1,100) = 99, 30) = 99

        reserve(RES_J2, ASG_J2, allMembers(), 2);
        clock(35, 1_100);
        pushRecord(RecordKind.Ack, ackData(RES_J2, 102, 200, 201)); // J ends at round 102: p = 11
        clock(50, 1_200);
        pushRecord(RecordKind.Closure, closureData(ASG_J, 102, "j"));
        applyAll(); // J anchor = max(11, 50) = 50, under the lax policy

        LotV memory l = lotv(1);
        assertEq(l.holdUntil, 99 + 2_000, "strict G hold survives J's shorter hold");
        assertEq(l.evidenceUntil, 99 + 1_000);
        assertEq(l.timeUntil, 1_000 + 3_600, "strict G floor survives J's 1 s floor");
        assertEq(custody.maxLiabilityAnchor(gid(0), 1), 99, "the larger liability anchor stays");
    }

    /// Hold and evidence windows after a closure use the larger of the ordinary and suffix values.
    function test_suffixPolicyWindowsApplyAfterClosure() public {
        Policy memory p = _defaultPolicy();
        p.holdNormal = 2_000;
        p.holdSuffix = 3_000;
        p.evidenceWindow = 1_000;
        p.suffixEvidenceWindow = 1_500;
        _deploy(p);
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        assertEq(lotv(1).holdUntil, 150 + 3_000, "suffix hold is larger");
        assertEq(lotv(1).evidenceUntil, 150 + 1_500, "suffix window is larger");

        // and the other way round: the ordinary values are larger
        p.holdNormal = 3_000;
        p.holdSuffix = 2_000;
        p.evidenceWindow = 1_500;
        p.suffixEvidenceWindow = 1_000;
        roots = new MockRootRecords();
        _deploy(p);
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        assertEq(lotv(1).holdUntil, 150 + 3_000, "ordinary hold is larger");
        assertEq(lotv(1).evidenceUntil, 150 + 1_500, "ordinary window is larger");
    }

    /// The UC-time gate honours a closure floor that exceeds the retirement floor.
    function test_closureFloorsBindWhenTheyExceedTheRetirementFloor() public {
        Policy memory p1 = _defaultPolicy();
        p1.timeFloor = 1; // lots and G capture a 1 s floor
        p1.holdRetirement = 401;
        Policy memory p2 = _defaultPolicy();
        p2.timeFloor = 5_000; // J captures a 5,000 s floor
        p2.holdNormal = 5_000; // and 5,000-round holds
        p2.holdSuffix = 5_000;
        UncheckedPolicy source = new UncheckedPolicy(p1);
        _deployManual(address(source), _limits());
        source.addSnapshot(p2);

        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        clock(150, 1_200);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "g"));
        applyAll();

        requestRetirement(1); // identity 2 retires and is dropped by J2
        reserve(RES_J2, ASG_J2, allExcept(1), 2);
        clock(160, 1_300);
        pushRecord(RecordKind.Ack, ackData(RES_J2, 130, 300, 131));
        clock(170, 1_400);
        pushRecord(RecordKind.Closure, closureData(ASG_J, 130, "j"));
        applyAll();
        retireRecordAt(gid(1), 180, 1_500);

        // retirement floor = 1,500 + 1; J's closure floor = 1,400 + 5,000 = 6,400 binds.
        // round gate: max(p_ret + 401, anchor 170 + 5,000) = 5,170 binds over 180 + 401.
        uint256 lot = lotOf(gid(1));
        clock(5_170, 6_399);
        vm.expectRevert(StakeCustody.RoundGateNotMet.selector);
        matureOne(lot);
        clock(5_171, 6_399);
        vm.expectRevert(StakeCustody.TimeGateNotMet.selector);
        matureOne(lot);
        clock(5_171, 6_400);
        matureOne(lot);
        assertEq(creditOf(vm.addr(wdPk(1))), GENESIS_BOND);
    }

    // --- exposure commitments ----------------------------------------------------------------------

    function _foldExposure(bytes32 previous, bytes32 exposureID_) internal view returns (bytes32) {
        Expo memory e = expo(exposureID_);
        bytes32 lotsHash = keccak256(abi.encode(custody.exposureLots(exposureID_)));
        return
            keccak256(abi.encode(previous, exposureID_, e.id, e.weight, e.operatorPayee, lotsHash));
    }

    function _foldKeys(bytes32 previous, bytes32 exposureID_) internal view returns (bytes32) {
        Expo memory e = expo(exposureID_);
        return keccak256(abi.encode(previous, e.id, e.rootKeyHash, e.evmKeyHash));
    }

    function _fold(bytes32 assignmentID)
        internal
        view
        returns (bytes32 expoDigest, bytes32 keyDigest)
    {
        bytes32[] memory ids = custody.assignmentExposures(assignmentID);
        expoDigest = keccak256("unicity.p85.exposure-digest");
        keyDigest = keccak256("unicity.p85.key-history-digest");
        for (uint256 i = 0; i < ids.length; ++i) {
            expoDigest = _foldExposure(expoDigest, ids[i]);
            keyDigest = _foldKeys(keyDigest, ids[i]);
        }
    }

    function test_exposureDigestsMatchAnIndependentRecomputation() public {
        (bytes32 d, bytes32 k) = _fold(GENESIS_ASSIGNMENT);
        assertEq(asg(GENESIS_ASSIGNMENT).exposureDigest, d, "genesis exposures");
        assertEq(asg(GENESIS_ASSIGNMENT).keyDigest, k, "genesis keys");
        bytes32 returned = reserve(RES_J, ASG_J, allExcept(0), 1);
        (d, k) = _fold(ASG_J);
        assertEq(asg(ASG_J).exposureDigest, d, "reserved exposures");
        assertEq(returned, d, "reserveCandidate returns the digest");
        assertEq(asg(ASG_J).keyDigest, k, "reserved keys");
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll();
        (d, k) = _fold(ASG_K);
        assertEq(asg(ASG_K).exposureDigest, d, "derived K exposures");
        assertEq(asg(ASG_K).keyDigest, k, "derived K keys");
    }

    function _digestOf(ReserveInput memory in_)
        internal
        returns (bytes32 exposure_, bytes32 keys_)
    {
        vm.prank(address(election));
        custody.reserveCandidate(in_);
        return (asg(in_.assignmentID).exposureDigest, asg(in_.assignmentID).keyDigest);
    }

    /// The commitment the root checks changes with the payee, weight, lot set and either key.
    function test_exposureDigestChangesWithPayeeWeightLotsAndKeys() public {
        uint256 clean = vm.snapshotState();
        (bytes32 baseExposure, bytes32 baseKeys) =
            _digestOf(_reserveInput(RES_J, ASG_J, allMembers(), 1));

        vm.revertToState(clean);
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        in_.members[0].operatorPayee = address(0xBEEF); // candidate payee tampering
        (bytes32 e1, bytes32 k1) = _digestOf(in_);
        assertTrue(e1 != baseExposure, "payee");
        assertEq(k1, baseKeys, "a payee change is not a key change");

        vm.revertToState(clean);
        in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        in_.members[0].weight = 9;
        (e1, k1) = _digestOf(in_);
        assertTrue(e1 != baseExposure, "weight");

        vm.revertToState(clean);
        bondFor(gid(0), 50 * UCT); // dust: same weight, one more lot
        in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        assertEq(in_.members[0].weight, 10);
        (e1, k1) = _digestOf(in_);
        assertTrue(e1 != baseExposure, "lots");

        vm.revertToState(clean);
        DelegationRequest memory r;
        r.id = gid(0);
        r.generation = 1;
        r.binding = Delegation(
            keccak256(abi.encode("root", uint256(0))),
            compressed(rootPk(0)),
            keccak256(abi.encode("evm", uint256(0))),
            compressed(0x9701),
            vm.addr(payeePk(0))
        );
        r.expiry = 1_000;
        bytes32 digest = election.delegationDigest(r);
        election.admitDelegation(r, sign(ownerPk(0), digest), sign(0x9701, digest));
        in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1); // carries the newly bound EVM key
        (e1, k1) = _digestOf(in_);
        assertTrue(k1 != baseKeys, "evm key");
        assertEq(e1, baseExposure, "an EVM key change is a key commitment, not an exposure one");

        vm.revertToState(clean);
        in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        in_.members[0].rootKeyHash = keccak256("a staged key would sit here");
        vm.prank(address(election));
        vm.expectRevert(StakeCustody.WrongKey.selector); // only the current or staged key is allowed
        custody.reserveCandidate(in_);
    }

    /// The retirement reference digest is a hash chain over every exposure ever created for the
    /// generation, in creation order; recompute it independently, including an aborted attempt.
    function test_exposureChainMatchesAnIndependentRecomputation() public {
        bytes32 chain = 0;
        chain = keccak256(
            abi.encode(keccak256("unicity.p85.exposure-chain"), chain, genesisExposure(0))
        );
        assertEq(custody.exposureChain(gid(0), 1), chain, "genesis");
        reserve(RES_J, ASG_J, allMembers(), 1);
        chain = keccak256(
            abi.encode(keccak256("unicity.p85.exposure-chain"), chain, exposureID(ASG_J, gid(0)))
        );
        assertEq(custody.exposureChain(gid(0), 1), chain, "reserved");
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        applyAll();
        assertEq(custody.exposureChain(gid(0), 1), chain, "an aborted exposure stays in the chain");
        assertEq(custody.exposureChain(gid(1), 1) != chain, true, "chains are per identity");
        // a retirement record bound to the independently computed chain is accepted
        requestRetirement(0);
        reserve(RES_J2, ASG_J2, allExcept(0), 2);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J2, H_ROUND, 100, 101));
        clock(150, 1_200);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "g"));
        applyAll();
        clock(160, 1_300);
        pushRecord(RecordKind.Retirement, abi.encode(RetirementData(gid(0), 1, chain)));
        applyAll();
        (bool imported,,) = custody.retirements(gid(0), 1);
        assertTrue(imported);
    }

    /// K keeps the incumbent's captured policy snapshot even when a newer snapshot is in force.
    function test_recoveredSlateKeepsTheIncumbentsCapturedPolicySnapshot() public {
        UncheckedPolicy source = new UncheckedPolicy(_defaultPolicy());
        _deployManual(address(source), _limits());
        source.addSnapshot(_defaultPolicy()); // snapshot 2 is now current
        reserve(RES_J, ASG_J, allExcept(0), 1);
        assertEq(asg(ASG_J).policyID, 2, "the candidate captures the current snapshot");
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll();
        assertEq(asg(GENESIS_ASSIGNMENT).policyID, 1);
        assertEq(asg(ASG_K).policyID, 1, "K carries the incumbent's snapshot, not the current one");
    }
}
