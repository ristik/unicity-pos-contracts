// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Script} from "forge-std/Script.sol";
import {MockRootRecords} from "../test/p85/MockRootRecords.sol";
import {PosFactory} from "../src/p85/PosFactory.sol";
import {StakeCustody} from "../src/p85/StakeCustody.sol";
import {ElectionPolicy} from "../src/p85/ElectionPolicy.sol";
import {Evidence} from "../src/p85/Evidence.sol";
import {SelectionEngine} from "../src/p85/SelectionEngine.sol";
import {EligibilityReader} from "../src/p85/EligibilityReader.sol";
import {
    Policy,
    Limits,
    GenesisAssignment,
    GenesisIdentity,
    ElectionParams
} from "../src/p85/P85Types.sol";

/// @notice Produces the proof-of-stake genesis state of the EVM shard: the P85 modules deployed and initialized by the factory in one
/// constructor, with the genesis identities bonded. `script/p85-genesis.sh` runs it and folds the state dump into a genesis alloc.
///
/// Inputs (environment): P85_GENESIS_JSON (the genesis plan bft-core's `ubft pos-relayer genesis --out-contracts` writes), P85_NETWORK_WORD,
/// P85_CHAIN_ID, P85_ROOTS (the registry that serves the root records), P85_TREASURY, P85_V_MAX, P85_L_MAX, P85_N_MAX (the caps the election
/// price was measured at), P85_CADENCE_ROUNDS, P85_CADENCE_SECONDS, P85_OUT (a directory under ./script/genesis-out); optional P85_DIST_NUM / P85_DIST_DEN: the election's weight-distance bound D <= num/den. THIS genesis script is the devnet/testnet
/// profile, whose small committees (4 -> 5 is D = 2/5, one replacement in four D = 1/2) need 1/2 (default 1/2, range-checked 0 < num <= den); the contracts have no built-in
/// bound, so a PRODUCTION genesis must set P85_DIST_NUM/P85_DIST_DEN explicitly (1/4 is the production policy) and never rely on the default (briefs/p85-churn-bound-note.md). The roots' installed EVM configuration must commit the same bound
/// (`continuity_max_distance`).
contract P85Genesis is Script {
    /// @dev The testnet profile's bound when P85_DIST_NUM / P85_DIST_DEN are unset. The contracts have NO built-in bound (ElectionParams carries
    /// it, and the election takes whatever genesis commits), so a production genesis must name its bound explicitly (1/4 is the production
    /// policy) and must not rely on this default.
    uint256 public constant TESTNET_DIST_NUM = 1;
    uint256 public constant TESTNET_DIST_DEN = 2;

    /// @dev The election's weight-distance bound D <= num/den: 0 < num <= den (a bound above 1 admits everything, zero admits no change).  A zero denominator is refused by num <= den with num != 0.
    function _distanceBound() internal view returns (uint64, uint64) {
        return _checkedBound(
            vm.envOr("P85_DIST_NUM", TESTNET_DIST_NUM), vm.envOr("P85_DIST_DEN", TESTNET_DIST_DEN)
        );
    }

    function _checkedBound(uint256 num, uint256 den) internal pure returns (uint64, uint64) {
        require(
            num != 0 && num <= den && den <= type(uint64).max,
            "P85: distance bound must satisfy 0 < num <= den"
        );
        return (uint64(num), uint64(den));
    }

    function run() external {
        vm.chainId(vm.envUint("P85_CHAIN_ID"));
        string memory json = vm.envString("P85_GENESIS_JSON");
        string memory out = vm.envString("P85_OUT");

        GenesisIdentity[] memory ids = _identities(json);
        uint256 total;
        for (uint256 i; i < ids.length; ++i) {
            total += ids[i].bond;
        }
        uint32 nMax = uint32(vm.envUint("P85_N_MAX"));
        (uint64 distNum, uint64 distDen) = _distanceBound();
        PosFactory.Config memory c = PosFactory.Config({
            custody: address(0),
            election: address(0),
            evidence: address(0),
            selection: address(0),
            reader: address(0),
            network: vm.envBytes32("P85_NETWORK_WORD"),
            roots: vm.envAddress("P85_ROOTS"),
            treasury: vm.envAddress("P85_TREASURY"),
            bondUnit: uint128(vm.parseJsonUint(json, ".bondUnit")),
            minBond: uint128(vm.parseJsonUint(json, ".bondUnit")),
            limits: Limits({
                vMax: uint32(vm.envUint("P85_V_MAX")),
                lMax: uint32(vm.envUint("P85_L_MAX")),
                rMax: 4,
                maxBatch: 32
            }),
            genesis: GenesisAssignment({
                assignmentID: vm.parseJsonBytes32(json, ".assignmentId"),
                lineage: keccak256("p85/lane/lineage"),
                rootEpoch: 1,
                evmEpoch: 1,
                firstRound: 1
            }),
            electionParams: ElectionParams({
                nMin: 4,
                nTarget: nMax,
                nMax: nMax,
                maxM: 4,
                distNum: distNum,
                distDen: distDen,
                cadenceRounds: uint64(vm.envUint("P85_CADENCE_ROUNDS")),
                cadenceSeconds: uint64(vm.envUint("P85_CADENCE_SECONDS"))
            }),
            policy: Policy({
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
            }),
            identities: ids
        });
        // The election reads the record source's clock when it is initialized, so a record source with code must exist at the address the
        // manifest names. Here it is a stand-in that is not part of the genesis alloc (the lane's registry is allocated by the B1 genesis).
        address roots = vm.envAddress("P85_ROOTS");
        vm.etch(roots, address(new MockRootRecords()).code);
        // The creations run as a fixed deployer account (a script contract may not rely on its own address): the first five are the three
        // modules, the engine and the reader, the sixth is the factory, so the modules can be constructed with its future address.
        address deployer = address(uint160(uint256(keccak256("p85-genesis-deployer"))));
        vm.deal(deployer, total);
        vm.startPrank(deployer);
        address f = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 5);
        c.custody = address(new StakeCustody(f));
        c.election = address(new ElectionPolicy(f));
        c.evidence = address(new Evidence(f));
        c.selection = address(new SelectionEngine());
        c.reader = address(new EligibilityReader(c.custody, c.evidence));
        PosFactory factory = new PosFactory{value: total}(c);
        vm.stopPrank();
        require(address(factory) == f, "factory address");

        string memory d = "deployment";
        vm.serializeAddress(d, "factory", address(factory));
        vm.serializeAddress(d, "custody", address(factory.CUSTODY()));
        vm.serializeAddress(d, "election", address(factory.ELECTION()));
        vm.serializeAddress(d, "evidence", address(factory.EVIDENCE()));
        vm.serializeAddress(d, "selection", address(factory.ELECTION().selection()));
        vm.serializeAddress(d, "reader", address(factory.ELECTION().reader()));
        vm.serializeAddress(d, "policy", address(factory.POLICY()));
        vm.serializeBytes32(d, "manifestHash", factory.MANIFEST_HASH());
        vm.serializeBytes32(d, "networkWord", c.network);
        vm.serializeBytes32(d, "custodyCodeHash", address(factory.CUSTODY()).codehash);
        vm.serializeBytes32(d, "electionCodeHash", address(factory.ELECTION()).codehash);
        vm.serializeUint(d, "chainId", block.chainid);
        vm.serializeUint(d, "vMax", c.limits.vMax);
        vm.serializeUint(d, "lMax", c.limits.lMax);
        string memory dep = vm.serializeUint(d, "nMax", nMax);
        vm.writeJson(dep, string.concat(out, "/deployment.json"));
        vm.dumpState(string.concat(out, "/state.json"));
    }

    /// @dev Fields in the alphabetical order `vm.parseJson` encodes an object in.
    struct PlanIdentity {
        uint256 bond;
        bytes evmKey;
        bytes32 evmNodeId;
        address owner;
        address payee;
        bytes rootKey;
        bytes32 rootNodeId;
        address withdrawal;
    }

    function _identities(string memory json) private pure returns (GenesisIdentity[] memory ids) {
        PlanIdentity[] memory plan = abi.decode(vm.parseJson(json, ".identities"), (PlanIdentity[]));
        ids = new GenesisIdentity[](plan.length);
        for (uint256 i; i < plan.length; ++i) {
            ids[i] = GenesisIdentity({
                owner: plan[i].owner,
                withdrawal: plan[i].withdrawal,
                rootKey: plan[i].rootKey,
                evmKey: plan[i].evmKey,
                rootNodeID: plan[i].rootNodeId,
                evmNodeID: plan[i].evmNodeId,
                operatorPayee: plan[i].payee,
                bond: plan[i].bond
            });
        }
    }
}
