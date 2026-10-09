// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Genesis identity seeding is bounded by custody's immutable V ceiling and calls fixed modules.
// forge-lint: disable-start(calls-loop)

import {
    Policy,
    Limits,
    Manifest,
    CustodyConfig,
    GenesisAssignment,
    GenesisIdentity,
    ElectionParams
} from "./P85Types.sol";
import {StakeCustody} from "./StakeCustody.sol";
import {ElectionPolicy} from "./ElectionPolicy.sol";
import {Evidence} from "./Evidence.sol";
import {FixedPolicy} from "./FixedPolicy.sol";
import {Quantize} from "./Quantize.sol";

/// @title PosFactory
/// @notice Initializes the pre-deployed P85 modules atomically in its constructor, then has no entry point: every module's initializer is
/// callable only by this factory and only once. The modules are deployed first, each constructed with this factory's address (the
/// deployer's next-but-modules CREATE address), because their creation code together would exceed the initcode limit of one factory.
/// Module addresses are recorded in the manifest, whose hash every module stores and the factory
/// pins as `MANIFEST_HASH`; genesis tooling compares that hash with the manifest it intends.
// forge-lint: disable-next-line(locked-ether)
contract PosFactory {
    struct Config {
        address custody; // the deployed, uninitialized modules this factory initializes; each was constructed with this factory's address
        address election;
        address evidence;
        address selection;
        address reader;
        bytes32 network;
        address roots;
        address treasury;
        uint128 bondUnit;
        uint128 minBond;
        Limits limits;
        GenesisAssignment genesis;
        ElectionParams electionParams;
        Policy policy;
        GenesisIdentity[] identities;
    }

    error GenesisValueMismatch();
    /// @dev The genesis committee's total weight (the sum of bond / bondUnit) exceeds the profile cap B.
    error GenesisWeightAboveCap();

    bytes32 public immutable MANIFEST_HASH;
    StakeCustody public immutable CUSTODY;
    ElectionPolicy public immutable ELECTION;
    Evidence public immutable EVIDENCE;
    FixedPolicy public immutable POLICY;

    event Deployed(
        bytes32 manifestHash, address custody, address election, address evidence, address policy
    );

    constructor(Config memory c) payable {
        POLICY = new FixedPolicy(c.policy);
        CUSTODY = StakeCustody(c.custody);
        ELECTION = ElectionPolicy(c.election);
        EVIDENCE = Evidence(c.evidence);
        Manifest memory m = Manifest({
            network: c.network,
            chainId: block.chainid,
            custody: address(CUSTODY),
            election: address(ELECTION),
            evidence: address(EVIDENCE),
            selection: c.selection,
            reader: c.reader,
            policySource: address(POLICY),
            roots: c.roots,
            treasury: c.treasury,
            bondUnit: c.bondUnit,
            minBond: c.minBond,
            limits: c.limits,
            genesis: c.genesis,
            electionParams: c.electionParams,
            identities: c.identities
        });
        bytes32 h = keccak256(abi.encode(m));
        MANIFEST_HASH = h;
        CUSTODY.initialize(
            h,
            CustodyConfig({
                network: c.network,
                election: address(ELECTION),
                evidence: address(EVIDENCE),
                policySource: address(POLICY),
                roots: c.roots,
                treasury: c.treasury,
                bondUnit: c.bondUnit,
                minBond: c.minBond,
                limits: c.limits,
                genesis: c.genesis
            })
        );
        uint256 total = 0;
        uint256 weight = 0;
        for (uint256 i = 0; i < c.identities.length; ++i) {
            GenesisIdentity memory g = c.identities[i];
            total += g.bond;
            weight += g.bond / c.bondUnit;
            CUSTODY.seedGenesis{value: g.bond}(
                g.owner, g.withdrawal, g.rootKey, g.evmKey, g.operatorPayee
            );
        }
        if (total != msg.value) revert GenesisValueMismatch();
        if (weight > Quantize.WEIGHT_CAP_B) revert GenesisWeightAboveCap();
        CUSTODY.sealGenesis();
        ELECTION.initialize(h, m);
        EVIDENCE.initialize(h, m);
        emit Deployed(h, address(CUSTODY), address(ELECTION), address(EVIDENCE), address(POLICY));
    }
}

// forge-lint: disable-end(calls-loop)
