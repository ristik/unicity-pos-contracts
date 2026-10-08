// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test, Vm} from "forge-std/Test.sol";
import {PosFactory} from "../../src/p85/PosFactory.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {SelectionEngine} from "../../src/p85/SelectionEngine.sol";
import {EligibilityReader} from "../../src/p85/EligibilityReader.sol";
import {FixedPolicy} from "../../src/p85/FixedPolicy.sol";
import {
    Policy,
    Limits,
    Manifest,
    CustodyConfig,
    GenesisAssignment,
    GenesisIdentity,
    ReserveInput,
    ReserveMember,
    RecordKind,
    AckData,
    RecoveryAckData,
    ClosureData,
    RetirementData,
    SessionClosedData,
    DelegationRequest,
    Delegation,
    ElectionParams
} from "../../src/p85/P85Types.sol";
import {MockRootRecords} from "./MockRootRecords.sol";

/// @notice Shared fixture: a fresh genesis with four identities deployed through PosFactory, a
/// local root-record fixture ("to be replaced by PR1 fixtures"), key helpers and record builders.
abstract contract P85Base is Test {
    uint256 internal constant UCT = 1 ether;
    uint256 internal constant GENESIS_BOND = 1_000 * UCT; // weight 10 at the 100 UCT bond unit
    bytes32 internal constant NETWORK = keccak256("p85-test-network");
    bytes32 internal constant LINEAGE = keccak256("p85-test-lineage");
    bytes32 internal constant GENESIS_ASSIGNMENT = keccak256("assignment/genesis");

    PosFactory internal factory;
    StakeCustody internal custody;
    ElectionPolicy internal election;
    Evidence internal evidence;
    MockRootRecords internal roots;
    address internal treasury = makeAddr("treasury");
    address internal reporter = makeAddr("reporter");

    uint256 internal constant N_GENESIS = 4;

    function setUp() public virtual {
        roots = new MockRootRecords();
        _deploy(_defaultPolicy());
    }

    function _defaultPolicy() internal pure returns (Policy memory) {
        return Policy({
            penaltyBps: 100,
            lifetimeCapBps: 500,
            bountyBps: 1_000,
            bountyCap: 1 ether,
            evidenceWindow: 1_000,
            suffixEvidenceWindow: 1_000,
            holdNormal: 2_000,
            holdSuffix: 2_000,
            holdRetirement: 2_000,
            timeFloor: 3_600
        });
    }

    /// @dev DEV-DEFAULT election profile (design v5 section 6).
    /// @dev The epochs of the genesis assignment.
    uint64 internal genesisRootEpoch = 1;
    uint64 internal genesisEvmEpoch = 1;

    /// @dev B_min of manual deployments (the factory's deployments use the unit).
    uint128 internal manualMinBond = uint128(100 * UCT);

    function _electionParams() internal view virtual returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: 10,
            nMax: 32,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: 100_000,
            cadenceSeconds: 604_800
        });
    }

    function _deploy(Policy memory policy) internal {
        GenesisIdentity[] memory ids = new GenesisIdentity[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            ids[i] = GenesisIdentity({
                owner: vm.addr(ownerPk(i)),
                withdrawal: vm.addr(wdPk(i)),
                rootKey: compressed(rootPk(i)),
                evmKey: compressed(evmPk(i)),
                rootNodeID: keccak256(abi.encode("root", i)),
                evmNodeID: keccak256(abi.encode("evm", i)),
                operatorPayee: vm.addr(payeePk(i)),
                bond: GENESIS_BOND
            });
        }
        // the modules are constructed with the address the factory will have: five creations (three modules, the engine, the reader)
        // precede it
        address f = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 5);
        address cu = address(new StakeCustody(f));
        address el = address(new ElectionPolicy(f));
        address ev = address(new Evidence(f));
        PosFactory.Config memory c = PosFactory.Config({
            custody: cu,
            election: el,
            evidence: ev,
            selection: address(new SelectionEngine()),
            reader: address(new EligibilityReader(cu, ev)),
            network: NETWORK,
            roots: address(roots),
            treasury: treasury,
            bondUnit: uint128(100 * UCT),
            minBond: uint128(100 * UCT),
            limits: Limits({vMax: 128, lMax: 8, rMax: 4, maxBatch: 32}),
            genesis: GenesisAssignment({
                assignmentID: GENESIS_ASSIGNMENT,
                lineage: LINEAGE,
                rootEpoch: genesisRootEpoch,
                evmEpoch: genesisEvmEpoch,
                firstRound: 1
            }),
            policy: policy,
            electionParams: _electionParams(),
            identities: ids
        });
        vm.deal(address(this), N_GENESIS * GENESIS_BOND);
        factory = new PosFactory{value: N_GENESIS * GENESIS_BOND}(c);
        custody = factory.CUSTODY();
        election = factory.ELECTION();
        evidence = factory.EVIDENCE();
    }

    function _genesisIdentities() internal returns (GenesisIdentity[] memory ids) {
        ids = new GenesisIdentity[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            ids[i] = GenesisIdentity({
                owner: vm.addr(ownerPk(i)),
                withdrawal: vm.addr(wdPk(i)),
                rootKey: compressed(rootPk(i)),
                evmKey: compressed(evmPk(i)),
                rootNodeID: keccak256(abi.encode("root", i)),
                evmNodeID: keccak256(abi.encode("evm", i)),
                operatorPayee: vm.addr(payeePk(i)),
                bond: GENESIS_BOND
            });
        }
    }

    /// @dev Wire the modules by hand (this test contract acts as the factory), to run with a custom
    /// policy source or resource limits that the factory's FixedPolicy bounds would not allow.
    function _deployManual(address policySource, Limits memory limits) internal {
        custody = new StakeCustody(address(this));
        election = new ElectionPolicy(address(this));
        evidence = new Evidence(address(this));
        GenesisIdentity[] memory ids = _genesisIdentities();
        GenesisAssignment memory g = GenesisAssignment({
            assignmentID: GENESIS_ASSIGNMENT,
            lineage: LINEAGE,
            rootEpoch: genesisRootEpoch,
            evmEpoch: genesisEvmEpoch,
            firstRound: 1
        });
        Manifest memory m = Manifest({
            network: NETWORK,
            chainId: block.chainid,
            custody: address(custody),
            election: address(election),
            evidence: address(evidence),
            selection: address(new SelectionEngine()),
            reader: address(new EligibilityReader(address(custody), address(evidence))),
            policySource: policySource,
            roots: address(roots),
            treasury: treasury,
            bondUnit: uint128(100 * UCT),
            minBond: manualMinBond,
            limits: limits,
            genesis: g,
            electionParams: _electionParams(),
            identities: ids
        });
        bytes32 h = keccak256(abi.encode(m));
        custody.initialize(
            h,
            CustodyConfig({
                network: NETWORK,
                election: address(election),
                evidence: address(evidence),
                policySource: policySource,
                roots: address(roots),
                treasury: treasury,
                bondUnit: uint128(100 * UCT),
                minBond: manualMinBond,
                limits: limits,
                genesis: g
            })
        );
        vm.deal(address(this), N_GENESIS * GENESIS_BOND);
        for (uint256 i; i < N_GENESIS; ++i) {
            custody.seedGenesis{value: ids[i].bond}(
                ids[i].owner, ids[i].withdrawal, ids[i].rootKey, ids[i].evmKey, ids[i].operatorPayee
            );
        }
        custody.sealGenesis();
        election.initialize(h, m);
        evidence.initialize(h, m);
    }

    // --- keys ---------------------------------------------------------------------------------

    function ownerPk(uint256 i) internal pure returns (uint256) {
        return 0x1000 + i;
    }

    function wdPk(uint256 i) internal pure returns (uint256) {
        return 0x1100 + i;
    }

    function payeePk(uint256 i) internal pure returns (uint256) {
        return 0x1200 + i;
    }

    function rootPk(uint256 i) internal pure returns (uint256) {
        return 0x2000 + i;
    }

    function evmPk(uint256 i) internal pure returns (uint256) {
        return 0x3000 + i;
    }

    function compressed(uint256 pk) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(pk);
        return abi.encodePacked(uint8(2 + (w.publicKeyY & 1)), bytes32(w.publicKeyX));
    }

    function sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev StakingID of genesis identity i (assigned in manifest order from 1).
    function gid(uint256 i) internal pure returns (uint64) {
        return uint64(i + 1);
    }

    // --- registration helpers -----------------------------------------------------------------

    function registerDigest(address owner, address withdrawal, bytes memory key, uint64 nonce)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                keccak256("unicity.p85.pop.register"),
                NETWORK,
                block.chainid,
                address(custody),
                owner,
                withdrawal,
                keccak256(key),
                nonce
            )
        );
    }

    function register(uint256 ownerKey, uint256 rootKey, address withdrawal)
        internal
        returns (uint64 id)
    {
        address owner = vm.addr(ownerKey);
        bytes memory key = compressed(rootKey);
        bytes memory pop =
            sign(rootKey, registerDigest(owner, withdrawal, key, custody.registerNonce(owner)));
        vm.prank(owner);
        id = custody.register(key, pop, withdrawal);
    }

    function bondFor(uint64 id, uint256 amount) internal returns (uint256 lotID) {
        (address owner,,,,,,,,) = custody.positions(id);
        vm.deal(owner, owner.balance + amount);
        vm.prank(owner);
        lotID = custody.bond{value: amount}(id);
    }

    // --- exposures and records ----------------------------------------------------------------

    function exposureID(bytes32 assignmentID, uint64 id) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("unicity.p85.exposure"),
                NETWORK,
                block.chainid,
                address(custody),
                assignmentID,
                id
            )
        );
    }

    function lotsOf(uint64 id) internal view returns (uint256[] memory) {
        (,,,, uint64 gen,,,,) = custody.positions(id);
        return custody.generationLots(id, gen);
    }

    function genesisExposure(uint256 i) internal view returns (bytes32) {
        return exposureID(GENESIS_ASSIGNMENT, gid(i));
    }

    /// @dev Reserve a primary candidate over genesis identities `members` (indexes), reusing each
    /// identity's current keys, as the fixed ElectionPolicy would.
    function reserve(
        bytes32 resultID,
        bytes32 assignmentID,
        uint256[] memory members,
        uint64 attempt
    ) internal returns (bytes32 digest) {
        ReserveInput memory in_ = _reserveInput(resultID, assignmentID, members, attempt);
        vm.prank(address(election));
        digest = custody.reserveCandidate(in_);
    }

    function _reserveInput(
        bytes32 resultID,
        bytes32 assignmentID,
        uint256[] memory members,
        uint64 attempt
    ) internal view returns (ReserveInput memory in_) {
        in_.resultID = resultID;
        in_.assignmentID = assignmentID;
        in_.lineage = LINEAGE;
        in_.attempt = attempt;
        in_.rootEpoch = 2;
        in_.evmEpoch = 2;
        in_.incumbentAssignmentID = custody.lastAckedAssignment();
        in_.members = new ReserveMember[](members.length);
        for (uint256 k; k < members.length; ++k) {
            uint64 id = gid(members[k]);
            (,, bytes32 rootHash,,,,,,) = custody.positions(id);
            (bytes memory evm,) = _evmKeyOf(id);
            in_.members[k] = ReserveMember({
                id: id,
                weight: uint64(coverage(id) / (100 * UCT)),
                rootKeyHash: rootHash,
                evmKeyHash: keccak256(evm),
                operatorPayee: _payeeOf(id),
                lotIDs: lotsOf(id)
            });
        }
    }

    function coverage(uint64 id) internal view returns (uint256 backing) {
        uint256[] memory ids = lotsOf(id);
        for (uint256 i; i < ids.length; ++i) {
            (,,, uint128 remaining,,,,,,,,,) = custody.lots(ids[i]);
            backing += remaining;
        }
    }

    function _evmKeyOf(uint64 id) internal view returns (bytes memory key, bytes32 nodeID) {
        (Delegation memory d,,) = election.delegation(id, 1);
        return (d.evmKey, d.evmNodeID);
    }

    function _payeeOf(uint64 id) internal view returns (address) {
        (,,,, uint64 gen,,,,) = custody.positions(id);
        (Delegation memory d,,) = election.delegation(id, gen);
        return d.operatorPayee;
    }

    function pushRecord(RecordKind kind, bytes memory data) internal returns (uint64) {
        return roots.push(kind, data);
    }

    function applyAll() internal {
        uint64 count = roots.recordCount();
        uint64 done = custody.recordCursor();
        while (done < count) {
            uint64 step = count - done > 32 ? 32 : count - done;
            custody.applyRootRecords(uint32(step));
            done += step;
        }
    }

    function clock(uint64 p, uint64 t) internal {
        roots.setClock(p, t);
    }

    struct Asg {
        uint8 state;
        bytes32 lineage;
        uint64 rootEpoch;
        uint64 evmEpoch;
        uint64 offset;
        uint64 firstRound;
        bool offsetSet;
        bool hKnown;
        uint64 hRound;
        bool closed;
        uint64 pClose;
        uint64 tClose;
        bytes32 closureKey;
        bytes32 exposureDigest;
        bytes32 keyDigest;
        uint32 policyID;
    }

    struct LotV {
        uint64 id;
        uint64 generation;
        uint128 initial;
        uint128 remaining;
        uint128 penalized;
        uint8 category;
        uint16 capBps;
        uint32 refCount;
        uint64 holdRetirement;
        uint64 timeFloor;
        uint64 holdUntil;
        uint64 evidenceUntil;
        uint64 timeUntil;
    }

    struct Expo {
        bytes32 assignmentID;
        uint64 id;
        uint64 generation;
        bytes32 rootKeyHash;
        bytes32 evmKeyHash;
        uint64 weight;
        address operatorPayee;
        bool released;
        uint32 locks;
    }

    function asg(bytes32 assignmentID) internal view returns (Asg memory a) {
        (
            a.state,
            a.lineage,
            a.rootEpoch,
            a.evmEpoch,
            a.offset,
            a.firstRound,
            a.offsetSet,
            a.hKnown,
            a.hRound,
            a.closed,
            a.pClose,
            a.tClose,
            a.closureKey,
            a.exposureDigest,
            a.keyDigest,
            a.policyID
        ) = custody.assignments(assignmentID);
    }

    function lotv(uint256 lotID) internal view returns (LotV memory l) {
        (
            l.id,
            l.generation,
            l.initial,
            l.remaining,
            l.penalized,
            l.category,
            l.capBps,
            l.refCount,
            l.holdRetirement,
            l.timeFloor,
            l.holdUntil,
            l.evidenceUntil,
            l.timeUntil
        ) = custody.lots(lotID);
    }

    function expo(bytes32 exposureID_) internal view returns (Expo memory e) {
        (
            e.assignmentID,
            e.id,
            e.generation,
            e.rootKeyHash,
            e.evmKeyHash,
            e.weight,
            e.operatorPayee,
            e.released,
            e.locks
        ) = custody.exposures(exposureID_);
    }

    function closureData(bytes32 assignmentID, uint64 hRound, bytes32 tag)
        internal
        view
        returns (bytes memory)
    {
        Asg memory a = asg(assignmentID);
        return abi.encode(
            ClosureData({
                assignmentID: assignmentID,
                hRound: hRound,
                hRecordID: keccak256(abi.encode("H", tag)),
                terminalRoot: keccak256(abi.encode("R_H", tag)),
                exposureDigest: a.exposureDigest,
                keyHistoryDigest: a.keyDigest
            })
        );
    }

    /// @dev Account-level conservation: balance = F + E + D + C + U with U >= 0.
    function assertConserved() internal view {
        uint256 accounted = custody.totalFree() + custody.totalEncumbered()
            + custody.totalDraining() + custody.totalCredits();
        assertGe(address(custody).balance, accounted, "balance below accounted principal+credits");
    }
}
