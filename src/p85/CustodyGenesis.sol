// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the immutable V/L/R/batch ceilings validated by custody at genesis.
// Fixed deployment modules are trusted; guard failures must revert the entire bounded operation.
// forge-lint: disable-start(require-revert-in-loop, calls-loop, reentrancy-no-eth)

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {
    Policy,
    Limits,
    CustodyConfig,
    ReserveInput,
    ReserveMember,
    RootRecord,
    RecordKind,
    SessionClosedData,
    AckData,
    RecoveryAckData,
    ClosureData,
    RetirementData,
    Position,
    Exposure,
    Assignment,
    SeatBinding,
    AssignmentSeat
} from "./P85Types.sol";
import {IRootRecords, IPolicySource, IEvidence, IElectionPolicy, CaseView} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";
import {Quantize} from "./Quantize.sol";
import {VRC} from "../vr/VRConstants.sol";

import {CustodyStorage} from "./CustodyStorage.sol";

/// @title CustodyGenesis
/// @notice The genesis-only functions of StakeCustody (`initialize`, `seedGenesis`, `sealGenesis`), run by DELEGATECALL from the custody's
/// stubs, in the custody's storage and with the factory's msg.sender and msg.value. Never called directly: its own storage is never read.
// forge-lint: disable-next-line(locked-ether)
contract CustodyGenesis is CustodyStorage {
    constructor(address factory_) CustodyStorage(factory_) {}

    /// @notice Factory-only genesis step 1: wire the fixed modules and parameters. The factory then
    /// calls `seedGenesis` once per manifest identity and `sealGenesis`, all in its constructor.
    function initialize(bytes32 manifestHash_, CustodyConfig calldata c) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (genesisStarted) revert AlreadyInitialized();
        if (
            c.treasury == address(0) || c.bondUnit == 0 || c.limits.vMax == 0 || c.limits.lMax == 0
                || c.limits.rMax < 3 || c.limits.maxBatch == 0
                || c.genesis.assignmentID == bytes32(0)
        ) revert InvalidGenesis();
        // Immutable development resource ceilings; alternative test genesis remains bounded.
        if (c.limits.vMax > 128) revert InvalidGenesis();
        if (c.limits.lMax > 8) revert InvalidGenesis();
        if (c.limits.rMax > 4) revert InvalidGenesis();
        if (c.limits.maxBatch > 32) revert InvalidGenesis();
        genesisStarted = true;
        manifestHash = manifestHash_;
        network = c.network;
        // forge-lint: disable-start(missing-events-access-control)
        election = c.election;
        evidence = c.evidence;
        policySource = c.policySource;
        roots = c.roots;
        treasury = c.treasury;
        bondUnit = c.bondUnit;
        minBond = c.minBond;
        limits = c.limits;
        deploymentDomain = c.deployment == address(0) ? address(this) : c.deployment;
        // forge-lint: disable-end(missing-events-access-control)
        genesisAssignmentID = c.genesis.assignmentID;
        Assignment storage a = assignments[c.genesis.assignmentID];
        a.state = ASSIGN_ACTIVE;
        a.lineage = c.genesis.lineage;
        a.rootEpoch = c.genesis.rootEpoch;
        a.evmEpoch = c.genesis.evmEpoch;
        a.firstRound = c.genesis.firstRound;
        a.offsetSet = true;
        a.policyID = IPolicySource(policySource).currentPolicyID();
    }

    /// @notice Factory-only genesis step 2: one manifest identity with its bond (msg.value) and an
    /// Active exposure in the genesis assignment. Manifest authentication replaces fresh possession.
    function seedGenesis(
        address owner,
        address withdrawal,
        bytes calldata rootKey,
        bytes calldata evmKey,
        address operatorPayee,
        bytes32 rootNode,
        bytes32 evmNode
    ) external payable {
        if (msg.sender != FACTORY) revert NotFactory();
        if (!genesisStarted || initialized) revert NotInitialized();
        uint256 weight = msg.value / bondUnit;
        if (
            owner == address(0) || withdrawal == address(0) || operatorPayee == address(0)
                || weight == 0 || weight > WEIGHT_CAP_B || nextStakingID >= limits.vMax
        ) revert InvalidGenesis();
        uint64 id = ++nextStakingID;
        bytes32 rootHash = _claimKey(rootKey, id, ROLE_ROOT);
        bytes32 evmHash = _claimKey(evmKey, id, ROLE_EVM);
        positions[id] = Position(owner, withdrawal, rootHash, bytes32(0), 1, 0, 0, 0, false);
        uint256 lotID = _newLot(id, msg.value);
        if (_compact()) {
            uint64 handle = _recordBinding(
                SeatBinding(id, 1, rootNode, rootHash, evmNode, evmHash, operatorPayee)
            );
            // forge-lint: disable-next-line(unsafe-typecast)
            _seats[genesisAssignmentID].push(_packSeat(id, handle, uint64(weight), uint64(weight)));
            _referenceSeat(id, 1, lotID, _exposureID(genesisAssignmentID, id));
        } else {
            uint256[] memory seeded = new uint256[](1);
            seeded[0] = lotID;
            bytes32 eid = _createExposure(
                genesisAssignmentID,
                id,
                1,
                // weight <= B is checked in seedGenesis, and the factory caps their total at B
                // forge-lint: disable-next-line(unsafe-typecast)
                uint64(weight),
                // forge-lint: disable-next-line(unsafe-typecast)
                uint64(weight), // at genesis q = x
                rootHash,
                evmHash,
                operatorPayee,
                seeded
            );
            assignments[genesisAssignmentID].exposureIDs.push(eid);
            // a VR generation: the genesis seat's member digest is VR's (the VR-domain exposure formula over GENESIS_RESULT)
            if (deploymentDomain != address(this)) {
                exposureMemberDigest[eid] = keccak256(
                    abi.encode(
                        EXPOSURE_DOMAIN,
                        network,
                        block.chainid,
                        deploymentDomain,
                        VRC.GENESIS_RESULT,
                        id
                    )
                );
            }
        }
    }

    /// @notice Factory-only genesis step 3: commit the exposure digests and seal initialization.
    function sealGenesis() external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (!genesisStarted || initialized || nextStakingID == 0) revert NotInitialized();
        Assignment storage a = assignments[genesisAssignmentID];
        if (_compact()) {
            _foldCompact(genesisAssignmentID, false);
        } else {
            a.exposureDigest = _digestExposures(a.exposureIDs);
            a.keyDigest = _digestKeys(a.exposureIDs);
        }
        lastAckedAssignment = genesisAssignmentID;
        initialized = true;
        emit Initialized(manifestHash);
    }

    /// @notice Save the exact delegation version for subsequent reservations and evidence.
    function internSeatBinding(SeatBinding calldata binding) external {
        if (!initialized) revert NotInitialized();
        if (msg.sender != election) revert NotElection();
        if (_compact()) _recordBinding(binding);
    }

    /// @notice Reserve a primary candidate's exact lots and lock the incumbent exposures (the
    /// recovery slate K) for the session. Primary coverage and eligibility only; K is never
    /// filtered, never re-collateralized and never recreated.
    function reserveCandidate(ReserveInput calldata in_) external returns (bytes32 exposureDigest) {
        if (!initialized) revert NotInitialized();
        if (msg.sender != election) revert NotElection();
        if (_sessions[in_.resultID].state != 0) revert SessionExists();
        if (in_.assignmentID == bytes32(0) || assignments[in_.assignmentID].state != 0) {
            revert AssignmentExists();
        }
        if (in_.incumbentAssignmentID != lastAckedAssignment) revert IncumbentMismatch();
        Assignment storage incumbent = assignments[in_.incumbentAssignmentID];
        if (incumbent.lineage != in_.lineage) revert LineageMismatch();
        if (in_.members.length == 0 || in_.members.length > limits.vMax) {
            revert InvalidMemberCount();
        }

        Assignment storage a = assignments[in_.assignmentID];
        a.state = ASSIGN_RESERVED;
        a.lineage = in_.lineage;
        a.rootEpoch = in_.rootEpoch;
        a.evmEpoch = in_.evmEpoch;
        a.policyID = IPolicySource(policySource).currentPolicyID();

        if (_compact()) {
            if (in_.members.length > 16) revert InvalidMemberCount();
            _reserveCompact(in_);
        } else {
            uint64 previous = 0;
            for (uint256 i = 0; i < in_.members.length; ++i) {
                ReserveMember calldata m = in_.members[i];
                if (m.id <= previous) revert MembersUnsorted();
                previous = m.id;
                _checkPrimaryMember(m);
                a.exposureIDs
                    .push(
                        _createExposure(
                            in_.assignmentID,
                            m.id,
                            positions[m.id].generation,
                            m.weight,
                            m.rawWeight,
                            m.rootKeyHash,
                            m.evmKeyHash,
                            m.operatorPayee,
                            m.lotIDs
                        )
                    );
            }
            a.exposureDigest = _digestExposures(a.exposureIDs);
            a.keyDigest = _digestKeys(a.exposureIDs);
        }
        exposureDigest = a.exposureDigest;

        _sessions[in_.resultID] = Session({
            state: SESSION_OPEN,
            assignmentID: in_.assignmentID,
            lineage: in_.lineage,
            attempt: in_.attempt,
            incumbentAssignmentID: in_.incumbentAssignmentID
        });
        // Lock the incumbent slate (K) for the session and keep one reference slot per incumbent lot
        // free for deriving K at recovery, so recovery can never be blocked by reference capacity.
        if (_compact()) {
            bytes32 source = _source(in_.incumbentAssignmentID);
            uint256[] storage seats = _seats[source];
            _slateState[in_.incumbentAssignmentID].locks++;
            for (uint256 i; i < seats.length; ++i) {
                (,, uint256 lotID) = _seatLot(seats[i]);
                if (lots[lotID].refCount >= limits.rMax) revert ReferenceCapacity();
            }
        } else {
            bytes32[] storage ids = incumbent.exposureIDs;
            for (uint256 i = 0; i < ids.length; ++i) {
                Exposure storage inc = exposures[ids[i]];
                inc.sessionLocks++;
                for (uint256 j = 0; j < inc.lotIDs.length; ++j) {
                    if (lots[inc.lotIDs[j]].refCount >= limits.rMax) revert ReferenceCapacity();
                }
            }
        }
        emit CandidateReserved(in_.resultID, in_.resultID, exposureDigest);
    }

    function _reserveCompact(ReserveInput calldata in_) private {
        uint64 previous;
        uint256[] storage seats = _seats[in_.assignmentID];
        for (uint256 i; i < in_.members.length; ++i) {
            ReserveMember calldata m = in_.members[i];
            if (m.id <= previous) revert MembersUnsorted();
            previous = m.id;
            _checkPrimaryMember(m);
            uint64 handle = _latestBinding[m.id][positions[m.id].generation];
            SeatBinding storage b = _bindings[handle];
            if (
                handle == 0 || m.rootKeyHash != b.rootKeyHash || m.evmKeyHash != b.evmKeyHash
                    || m.operatorPayee != b.payee
            ) revert WrongKey();
            seats.push(_packSeat(m.id, handle, m.weight, m.rawWeight));
        }
        _foldCompact(in_.assignmentID, true);
    }

    function _checkPrimaryMember(ReserveMember calldata m) private view {
        Position storage p = positions[m.id];
        if (p.owner == address(0)) revert UnknownIdentity();
        if (p.retirementRequested) revert PrimaryRetiring();
        if (IEvidence(evidence).excluded(m.id)) revert IdentityExcluded();
        if (m.weight == 0) revert ZeroWeight();
        if (
            m.rootKeyHash != p.rootKeyHash
                && (p.stagedRootKeyHash == bytes32(0) || m.rootKeyHash != p.stagedRootKeyHash)
        ) revert WrongKey();
        KeyRecord storage ek = _keys[m.evmKeyHash];
        if (ek.id != m.id || ek.role != ROLE_EVM) revert WrongKey();
        if (m.operatorPayee == address(0)) revert ZeroAddress();
        if (m.lotIDs.length != p.openLots) revert LotSetMismatch();
        uint256 backing = 0;
        uint256 previousLot = 0;
        for (uint256 j = 0; j < m.lotIDs.length; ++j) {
            uint256 lotID = m.lotIDs[j];
            if (lotID <= previousLot) revert LotSetMismatch();
            previousLot = lotID;
            Lot storage l = lots[lotID];
            if (l.id != m.id || l.generation != p.generation || l.category == CAT_RELEASED) {
                revert LotNotEligible();
            }
            if (l.refCount >= limits.rMax) revert ReferenceCapacity();
            backing += l.remaining;
        }
        // the lots must cover the RAW weight x the committed q was derived from (q <= x), not q itself
        if (backing < uint256(m.rawWeight) * bondUnit) revert InsufficientCoverage();
    }
}
