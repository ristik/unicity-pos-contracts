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
    Assignment
} from "./P85Types.sol";
import {IRootRecords, IPolicySource, IEvidence, IElectionPolicy, CaseView} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";
import {Quantize} from "./Quantize.sol";

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
        address operatorPayee
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
        uint256[] memory seeded = new uint256[](1);
        seeded[0] = _newLot(id, msg.value);
        assignments[genesisAssignmentID].exposureIDs
            .push(
                _createExposure(
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
                )
            );
    }

    /// @notice Factory-only genesis step 3: commit the exposure digests and seal initialization.
    function sealGenesis() external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (!genesisStarted || initialized || nextStakingID == 0) revert NotInitialized();
        Assignment storage a = assignments[genesisAssignmentID];
        a.exposureDigest = _digestExposures(a.exposureIDs);
        a.keyDigest = _digestKeys(a.exposureIDs);
        lastAckedAssignment = genesisAssignmentID;
        initialized = true;
        emit Initialized(manifestHash);
    }
}
