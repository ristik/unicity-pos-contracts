// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {
    Policy,
    Limits,
    Manifest,
    CustodyConfig,
    GenesisAssignment,
    GenesisIdentity
} from "./P85Types.sol";
import {StakeCustody} from "./StakeCustody.sol";
import {ElectionPolicy} from "./ElectionPolicy.sol";
import {Evidence} from "./Evidence.sol";
import {FixedPolicy} from "./FixedPolicy.sol";

/// @title PosFactory
/// @notice Deploys the P85 modules and initializes all of them atomically in its constructor, then
/// has no entry point: every module's initializer is callable only by this factory and only once.
/// Module addresses are recorded in the manifest, whose hash every module stores and the factory
/// pins as `MANIFEST_HASH`; genesis tooling compares that hash with the manifest it intends.
// forge-lint: disable-next-line(locked-ether)
contract PosFactory {
    struct Config {
        bytes32 network;
        address roots;
        address treasury;
        uint128 bondUnit;
        uint128 minBond;
        Limits limits;
        GenesisAssignment genesis;
        Policy policy;
        GenesisIdentity[] identities;
    }

    error GenesisValueMismatch();

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
        CUSTODY = new StakeCustody();
        ELECTION = new ElectionPolicy();
        EVIDENCE = new Evidence();
        Manifest memory m = Manifest({
            network: c.network,
            chainId: block.chainid,
            custody: address(CUSTODY),
            election: address(ELECTION),
            evidence: address(EVIDENCE),
            policySource: address(POLICY),
            roots: c.roots,
            treasury: c.treasury,
            bondUnit: c.bondUnit,
            minBond: c.minBond,
            limits: c.limits,
            genesis: c.genesis,
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
        for (uint256 i = 0; i < c.identities.length; ++i) {
            GenesisIdentity memory g = c.identities[i];
            total += g.bond;
            CUSTODY.seedGenesis{value: g.bond}(
                g.owner, g.withdrawal, g.rootKey, g.evmKey, g.operatorPayee
            );
        }
        if (total != msg.value) revert GenesisValueMismatch();
        CUSTODY.sealGenesis();
        ELECTION.initialize(h, m);
        EVIDENCE.initialize(h, m);
        emit Deployed(h, address(CUSTODY), address(ELECTION), address(EVIDENCE), address(POLICY));
    }
}
