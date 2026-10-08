// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Base} from "./P85Base.sol";
import {PosFactory} from "../../src/p85/PosFactory.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {SelectionEngine} from "../../src/p85/SelectionEngine.sol";
import {EligibilityReader} from "../../src/p85/EligibilityReader.sol";
import {FixedPolicy} from "../../src/p85/FixedPolicy.sol";
import {PolicyBounds} from "../../src/p85/PolicyBounds.sol";
import {
    Policy,
    Limits,
    Manifest,
    CustodyConfig,
    GenesisAssignment,
    GenesisIdentity,
    Delegation
} from "../../src/p85/P85Types.sol";

/// @dev Deployments go through an external call so that vm.expectRevert applies to a real call
/// frame (a bare `new` that does not revert would leave the expectation silently unchecked).
contract Deployer {
    uint8 internal nonce = 1; // a contract's CREATE nonce starts at one

    /// @dev Deploys fresh modules constructed with the factory's address, then the factory itself.
    function factory(PosFactory.Config calldata c) external payable returns (address) {
        PosFactory.Config memory m = c;
        address f = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(this), nonce + 5)
                    )
                )
            )
        );
        m.custody = address(new StakeCustody(f));
        m.election = address(new ElectionPolicy(f));
        m.evidence = address(new Evidence(f));
        m.selection = address(new SelectionEngine());
        m.reader = address(new EligibilityReader(m.custody, m.evidence));
        nonce += 6; // three modules, the engine, the reader, the factory
        return address(new PosFactory{value: msg.value}(m));
    }

    function policy(Policy calldata p) external returns (address) {
        nonce += 1;
        return address(new FixedPolicy(p));
    }
}

contract GenesisTest is P85Base {
    Deployer internal deployer = new Deployer();

    function test_genesisStateIsComplete() public {
        assertTrue(custody.initialized());
        assertEq(custody.nextStakingID(), N_GENESIS);
        assertEq(custody.manifestHash(), factory.MANIFEST_HASH());
        assertEq(election.manifestHash(), factory.MANIFEST_HASH());
        assertEq(evidence.manifestHash(), factory.MANIFEST_HASH());
        assertEq(custody.lastAckedAssignment(), GENESIS_ASSIGNMENT);
        for (uint256 i; i < N_GENESIS; ++i) {
            uint64 id = gid(i);
            (address owner, address wd, bytes32 rootHash,, uint64 gen,, uint32 open,,) =
                custody.positions(id);
            assertEq(owner, vm.addr(ownerPk(i)));
            assertEq(wd, vm.addr(wdPk(i)));
            assertEq(rootHash, keccak256(compressed(rootPk(i))));
            assertEq(gen, 1);
            assertEq(open, 1);
            (bytes32 asg,,,,, uint64 weight, address payee,,) =
                custody.exposures(genesisExposure(i));
            assertEq(asg, GENESIS_ASSIGNMENT);
            assertEq(weight, 10);
            assertEq(payee, vm.addr(payeePk(i)));
            assertTrue(election.isIndexed(id));
            (uint64 lotOwner,, uint128 initial, uint128 remaining,, uint8 cat,, uint32 refs,,,,,) =
                custody.lots(i + 1);
            assertEq(lotOwner, id);
            assertEq(initial, GENESIS_BOND);
            assertEq(remaining, GENESIS_BOND);
            assertEq(cat, 2, "genesis lot is encumbered by the genesis exposure");
            assertEq(refs, 1);
        }
        assertEq(election.liveCount(), N_GENESIS);
        assertEq(custody.totalEncumbered(), N_GENESIS * GENESIS_BOND);
        assertEq(address(custody).balance, N_GENESIS * GENESIS_BOND);
        assertConserved();
    }

    function test_genesisEvmKeysAreTombstonedAsEvmRole() public {
        for (uint256 i; i < N_GENESIS; ++i) {
            (uint64 id, uint8 role) = custody.keyOwner(keccak256(compressed(evmPk(i))));
            assertEq(id, gid(i));
            assertEq(role, 2);
            (id, role) = custody.keyOwner(keccak256(compressed(rootPk(i))));
            assertEq(id, gid(i));
            assertEq(role, 1);
        }
    }

    // --- initializer gates, each isolated ----------------------------------------------------------

    function test_custodyInitializeOnlyByFactory() public {
        CustodyConfig memory c;
        vm.expectRevert(StakeCustody.NotFactory.selector);
        custody.initialize(bytes32(0), c);
    }

    function test_custodyInitializeCannotRunTwice() public {
        CustodyConfig memory c;
        vm.prank(address(factory));
        vm.expectRevert(StakeCustody.AlreadyInitialized.selector);
        custody.initialize(bytes32(0), c);
    }

    function test_seedGenesisOnlyByFactory() public {
        vm.expectRevert(StakeCustody.NotFactory.selector);
        custody.seedGenesis(address(1), address(2), "", "", address(3));
    }

    function test_seedGenesisAfterSealReverts() public {
        vm.prank(address(factory));
        vm.expectRevert(StakeCustody.NotInitialized.selector);
        custody.seedGenesis(address(1), address(2), "", "", address(3));
    }

    function test_sealGenesisOnlyByFactoryAndOnce() public {
        vm.expectRevert(StakeCustody.NotFactory.selector);
        custody.sealGenesis();
        vm.prank(address(factory));
        vm.expectRevert(StakeCustody.NotInitialized.selector);
        custody.sealGenesis();
    }

    function test_electionAndEvidenceInitializeOnlyOnceByFactory() public {
        Manifest memory m;
        m.election = address(election);
        m.evidence = address(evidence);
        vm.expectRevert(ElectionPolicy.NotFactory.selector);
        election.initialize(bytes32(0), m);
        vm.expectRevert(Evidence.NotFactory.selector);
        evidence.initialize(bytes32(0), m);
        vm.startPrank(address(factory));
        vm.expectRevert(ElectionPolicy.AlreadyInitialized.selector);
        election.initialize(bytes32(0), m);
        vm.expectRevert(Evidence.AlreadyInitialized.selector);
        evidence.initialize(bytes32(0), m);
        vm.stopPrank();
    }

    function test_electionInitializeRejectsForeignManifest() public {
        ElectionPolicy fresh = new ElectionPolicy(address(this));
        Manifest memory m; // m.election is not this contract
        vm.expectRevert(ElectionPolicy.ManifestMismatch.selector);
        fresh.initialize(bytes32(0), m);
    }

    function test_electionRefusesAReaderWiredToOtherModules() public {
        ElectionPolicy fresh = new ElectionPolicy(address(this));
        Manifest memory m;
        m.election = address(fresh);
        m.custody = address(custody);
        m.evidence = address(evidence);
        m.roots = address(roots);
        m.selection = address(new SelectionEngine());
        m.electionParams = _electionParams();
        m.limits = Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32});
        m.reader = address(new EligibilityReader(address(evidence), address(custody))); // swapped
        vm.expectRevert(ElectionPolicy.InvalidParams.selector);
        fresh.initialize(bytes32(0), m);
        m.reader = address(new EligibilityReader(address(custody), address(roots))); // swapped evidence
        vm.expectRevert(ElectionPolicy.InvalidParams.selector);
        fresh.initialize(bytes32(0), m);
        m.reader = address(new EligibilityReader(address(roots), address(evidence))); // swapped custody only
        vm.expectRevert(ElectionPolicy.InvalidParams.selector);
        fresh.initialize(bytes32(0), m);
        m.reader = address(0xdead); // no code
        vm.expectRevert(ElectionPolicy.InvalidParams.selector);
        fresh.initialize(bytes32(0), m);
    }

    function test_evidenceInitializeRejectsForeignManifest() public {
        Evidence fresh = new Evidence(address(this));
        Manifest memory m;
        vm.expectRevert(Evidence.ManifestMismatch.selector);
        fresh.initialize(bytes32(0), m);
    }

    function test_uninitializedModulesRejectEverything() public {
        StakeCustody raw = new StakeCustody(address(this));
        vm.deal(address(this), 1);
        vm.expectRevert(StakeCustody.NotInitialized.selector);
        raw.bond{value: 1}(1);
        vm.expectRevert(StakeCustody.NotInitialized.selector);
        raw.register("", "", address(1));
        ElectionPolicy rawElection = new ElectionPolicy(address(this));
        vm.expectRevert(ElectionPolicy.NotInitialized.selector);
        rawElection.syncLiveIndex(1);
        Evidence rawEvidence = new Evidence(address(this));
        uint256[] memory none = new uint256[](0);
        vm.expectRevert(Evidence.NotInitialized.selector);
        rawEvidence.settleEvidence(bytes32(0), none);
    }

    function test_factoryRejectsValueThatDiffersFromBonds() public {
        GenesisIdentity[] memory ids = new GenesisIdentity[](1);
        ids[0] = GenesisIdentity({
            owner: address(0xA1),
            withdrawal: address(0xA2),
            rootKey: compressed(rootPk(0)),
            evmKey: compressed(evmPk(0)),
            rootNodeID: bytes32(uint256(1)),
            evmNodeID: bytes32(uint256(2)),
            operatorPayee: address(0xA3),
            bond: 1_000 * UCT
        });
        PosFactory.Config memory c = _config(ids);
        vm.deal(address(this), 2_000 * UCT);
        vm.expectRevert(PosFactory.GenesisValueMismatch.selector);
        deployer.factory{value: 1_001 * UCT}(c);
    }

    function test_factoryRejectsGenesisBondBelowOneUnit() public {
        GenesisIdentity[] memory ids = new GenesisIdentity[](1);
        ids[0] = GenesisIdentity({
            owner: address(0xA1),
            withdrawal: address(0xA2),
            rootKey: compressed(rootPk(0)),
            evmKey: compressed(evmPk(0)),
            rootNodeID: bytes32(uint256(1)),
            evmNodeID: bytes32(uint256(2)),
            operatorPayee: address(0xA3),
            bond: 99 * UCT
        });
        PosFactory.Config memory c = _config(ids);
        vm.deal(address(this), 99 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 99 * UCT}(c);
    }

    function test_factoryRejectsRootKeyReusedAsEvmKey() public {
        GenesisIdentity[] memory ids = new GenesisIdentity[](1);
        ids[0] = GenesisIdentity({
            owner: address(0xA1),
            withdrawal: address(0xA2),
            rootKey: compressed(rootPk(0)),
            evmKey: compressed(rootPk(0)),
            rootNodeID: bytes32(uint256(1)),
            evmNodeID: bytes32(uint256(2)),
            operatorPayee: address(0xA3),
            bond: 100 * UCT
        });
        PosFactory.Config memory c = _config(ids);
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.KeyAlreadyUsed.selector);
        deployer.factory{value: 100 * UCT}(c);
    }

    function test_factoryRejectsMalformedGenesisKeys() public {
        GenesisIdentity[] memory ids = new GenesisIdentity[](1);
        ids[0] = GenesisIdentity({
            owner: address(0xA1),
            withdrawal: address(0xA2),
            rootKey: hex"0102",
            evmKey: compressed(evmPk(0)),
            rootNodeID: bytes32(uint256(1)),
            evmNodeID: bytes32(uint256(2)),
            operatorPayee: address(0xA3),
            bond: 100 * UCT
        });
        PosFactory.Config memory c = _config(ids);
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidRootKey.selector);
        deployer.factory{value: 100 * UCT}(c);
    }

    function _oneIdentity() internal returns (GenesisIdentity[] memory ids) {
        ids = new GenesisIdentity[](1);
        ids[0] = GenesisIdentity({
            owner: address(0xA1),
            withdrawal: address(0xA2),
            rootKey: compressed(rootPk(0)),
            evmKey: compressed(evmPk(0)),
            rootNodeID: bytes32(uint256(1)),
            evmNodeID: bytes32(uint256(2)),
            operatorPayee: address(0xA3),
            bond: 100 * UCT
        });
    }

    function test_factoryRejectsEachInvalidCustodyParameter() public {
        PosFactory.Config memory c = _config(_oneIdentity());
        c.treasury = address(0);
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
        c = _config(_oneIdentity());
        c.bondUnit = 0;
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
        c = _config(_oneIdentity());
        c.limits.vMax = 0;
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
        c = _config(_oneIdentity());
        c.limits.lMax = 0;
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
        c = _config(_oneIdentity());
        c.limits.rMax = 2; // active + candidate + K needs at least three
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
        c = _config(_oneIdentity());
        c.limits.maxBatch = 0;
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
        c = _config(_oneIdentity());
        c.genesis.assignmentID = bytes32(0);
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
        // the unmodified configuration is accepted
        c = _config(_oneIdentity());
        vm.deal(address(this), 100 * UCT);
        deployer.factory{value: 100 * UCT}(c);
    }

    function test_review_factoryRejectsBatchAboveImmutableCeiling() public {
        PosFactory.Config memory c = _config(_oneIdentity());
        c.limits.maxBatch = 33;
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
    }

    function test_review_factoryRejectsVAboveImmutableCeiling() public {
        PosFactory.Config memory c = _config(_oneIdentity());
        c.limits.vMax = 129;
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
    }

    function test_review_factoryRejectsLAboveImmutableCeiling() public {
        PosFactory.Config memory c = _config(_oneIdentity());
        c.limits.lMax = 9;
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
    }

    function test_review_factoryRejectsRAboveImmutableCeiling() public {
        PosFactory.Config memory c = _config(_oneIdentity());
        c.limits.rMax = 5;
        vm.deal(address(this), 100 * UCT);
        vm.expectRevert(StakeCustody.InvalidGenesis.selector);
        deployer.factory{value: 100 * UCT}(c);
    }

    function test_review_factoryAcceptsCeilingsAndSmallerBoundedGenesis() public {
        PosFactory.Config memory c = _config(_oneIdentity());
        vm.deal(address(this), 200 * UCT);
        deployer.factory{value: 100 * UCT}(c); // exact upper ceilings
        c.limits = Limits({vMax: 1, lMax: 1, rMax: 3, maxBatch: 1});
        deployer.factory{value: 100 * UCT}(c);
    }

    function _config(GenesisIdentity[] memory ids)
        internal
        view
        returns (PosFactory.Config memory)
    {
        return PosFactory.Config({
            custody: address(0), // the Deployer helper installs fresh modules
            election: address(0),
            evidence: address(0),
            selection: address(0),
            reader: address(0),
            network: NETWORK,
            roots: address(roots),
            treasury: treasury,
            bondUnit: uint128(100 * UCT),
            minBond: uint128(100 * UCT),
            limits: Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32}),
            genesis: GenesisAssignment({
                assignmentID: GENESIS_ASSIGNMENT,
                lineage: LINEAGE,
                rootEpoch: 1,
                evmEpoch: 1,
                firstRound: 1
            }),
            policy: _defaultPolicy(),
            electionParams: _electionParams(),
            identities: ids
        });
    }

    // --- policy bounds -----------------------------------------------------------------------------

    function test_policyBoundsRejectEachOutOfRangeField() public {
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 201;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("penaltyBps"))
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.lifetimeCapBps = 1_001;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("lifetimeCapBps")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.bountyBps = 2_001;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("bountyBps"))
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.bountyCap = 10 ether + 1;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("bountyCap"))
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.evidenceWindow = 199;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("evidenceWindow")
            )
        );
        deployer.policy(p);
        // both ends of every range
        p = _defaultPolicy();
        p.evidenceWindow = 10_001;
        p.holdNormal = 20_000;
        p.holdSuffix = 20_000;
        p.holdRetirement = 20_000;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("evidenceWindow")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.suffixEvidenceWindow = 199;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("suffixEvidenceWindow")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.suffixEvidenceWindow = 10_001;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("suffixEvidenceWindow")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdNormal = 399;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdNormal"))
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdNormal = 20_001;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdNormal"))
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdSuffix = 399;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdSuffix"))
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdSuffix = 20_001;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdSuffix"))
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdRetirement = 399;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdRetirement")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdRetirement = 20_001;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdRetirement")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.timeFloor = 604_801;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("timeFloor"))
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdNormal = 1_000; // not strictly greater than the 1,000 evidence window
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdNormal<=evidence")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdSuffix = 1_000;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdSuffix<=evidence")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.holdRetirement = 1_000;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBounds.PolicyOutOfBounds.selector, bytes32("holdRetirement<=evidence")
            )
        );
        deployer.policy(p);
        p = _defaultPolicy();
        p.timeFloor = 3_599;
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBounds.PolicyOutOfBounds.selector, bytes32("timeFloor"))
        );
        deployer.policy(p);
    }

    function test_policyBoundsAcceptTheBoundaries() public {
        Policy memory p = _defaultPolicy();
        p.penaltyBps = 200;
        p.lifetimeCapBps = 1_000;
        p.bountyBps = 2_000;
        p.bountyCap = 10 ether;
        p.evidenceWindow = 200;
        p.suffixEvidenceWindow = 10_000;
        p.holdNormal = 400;
        p.holdSuffix = 10_001;
        p.holdRetirement = 10_001;
        p.timeFloor = 604_800;
        FixedPolicy f = FixedPolicy(deployer.policy(p));
        assertEq(f.currentPolicyID(), 1);
        assertEq(f.policyAt(1).timeFloor, 604_800);
        vm.expectRevert(FixedPolicy.UnknownPolicy.selector);
        f.policyAt(2);
    }
}
