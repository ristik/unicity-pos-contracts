// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRGenesis} from "./VRGenesis.s.sol";
import {ValidatorRegistry} from "../src/vr/ValidatorRegistry.sol";
import {PosElectionAdapter, IPosCustody} from "../src/vr/pos/PosElectionAdapter.sol";
import {VRC} from "../src/vr/VRConstants.sol";
import {VRCodec} from "../src/vr/VRCodec.sol";
import {IVR} from "../src/vr/VRTypes.sol";
import {MockRootRecords} from "../test/p85/MockRootRecords.sol";
import {P85ReportProfile} from "./P85ReportProfile.sol";
import {PosFactory} from "../src/p85/PosFactory.sol";
import {StakeCustody} from "../src/p85/StakeCustody.sol";
import {CustodyGenesis} from "../src/p85/CustodyGenesis.sol";
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

/// @notice The PoS-prototype VR generation's contracts genesis (VT-04, design 3.8): the ValidatorRegistry core and its three facets, the
/// FoundationMultisig, the P85 stack (custody, election, evidence, selection engine, reader, governed policy, reward pool, constructed by
/// PosFactory with the genesis identities bonded) and the PosElectionAdapter at 0xff..07 as VR's active module. The same VR plan as
/// `VRGenesis` (format `unicity.vr.genesis-input.v1`) plus a `pos` object. VR registers the genesis identities in plan order, so VR ids
/// equal custody StakingIDs (1..n); the P85 stack is constructed with `hookCaller` = the adapter and the VR address as the deployment
/// domain of its exposure digests; the multisig is `GovernanceParams.AUTHORITY`. There is no composer: the PoA module's account is the
/// adapter's. `script/vr-pos-genesis.sh` runs it and folds the state into an alloc.
///
/// `pos` object: `bondUnit` (decimal base units of one weight unit; each identity bonds rawWeight x bondUnit), `treasury`, `rootNetwork`,
/// `rootGenesis` (the root consensus identity the Evidence module verifies votes under), `assignmentId` (the genesis assignment id of the
/// FULL shard configuration, which the roots close), `rewardFunding`, `rewardRate` (decimal base units), `cadenceRounds`, `cadenceSeconds`.
contract VRPosGenesis is VRGenesis {
    uint32 internal constant MAX_COMMITTEE = 16;
    uint32 internal constant MAX_POOL = 20;
    address internal constant ADAPTER = address(uint160((uint256(0xff) << 152) | 0x07));

    function run() external override {
        runWith(vm.envString("VR_GENESIS_JSON"), vm.envString("VR_OUT"));
    }

    /// @dev The genesis of one plan into one output directory, without the process environment (the tests run in parallel).
    function runWith(string memory json, string memory out) public {
        require(
            keccak256(bytes(vm.parseJsonString(json, ".format"))) == keccak256(bytes(FORMAT)),
            "VR genesis: unknown input format"
        );
        vm.chainId(vm.parseJsonUint(json, ".chainId"));
        for (uint256 a = 3; a <= 9; ++a) {
            address taken = address(uint160((uint256(0xff) << 152) | a));
            require(taken.code.length == 0, "VR genesis: a genesis address is taken");
        }
        ValidatorRegistry.Genesis memory g = _genesis(json);
        require(g.rMax <= 4, "VR PoS genesis: custody's reference ceiling");
        // The measured deployment limit of the prototype (test/vr/pos/PosLimit.t.sol; astra's ruling and the coordinator's
        // decision): the PoS-capable VR build's caps (CAP_ELECT 7.0 M, CAP_OUTPUT 1.5 M, CAP_RECORD 2.5 M) carry the P85 election, outputOf and
        // The bounded compact profile is selected with a live index above the legacy ceiling.
        require(
            g.nMax <= 5 || g.vMax > 8, "VR PoS genesis: large committee requires compact custody"
        );
        require(
            g.nMax <= MAX_COMMITTEE && g.nTarget <= g.nMax,
            "VR PoS genesis: nMax and nTarget above the measured limit"
        );
        require(
            _members(g).length <= MAX_COMMITTEE,
            "VR PoS genesis: the genesis committee is above the measured limit"
        );
        require(
            g.vMax <= MAX_POOL && g.lMax == 1,
            "VR PoS genesis: vMax and lMax above the measured limit"
        );
        address multisig = MULTISIG;

        // 1. the facets
        _deployTo("VRGovernanceFacetPos.sol:VRGovernanceFacetPos", GOV_FACET);
        _deployTo("VRRepairFacetPos.sol:VRRepairFacetPos", REPAIR_FACET);
        _deployTo("VRRecordsFacetPos.sol:VRRecordsFacetPos", RECORDS_FACET);

        // 2. the governor
        address[5] memory signers;
        for (uint256 i; i < 5; ++i) {
            signers[i] =
                vm.parseJsonAddress(json, string.concat(".governorSigners[", vm.toString(i), "]"));
        }
        _deployTo("FoundationMultisig.sol:FoundationMultisig", abi.encode(signers), multisig);
        g.governor = multisig;

        // 3. the P85 stack: record source stand-in at the SealRegistry's address (the election reads its clock when initialized; the
        // alloc keeps the real registry), then the modules and the factory
        (address custody, address election) = _stack(json, g, multisig);

        // 4. the adapter, then VR constructed at its address (every digest it writes uses the VR domain)
        _deployTo(
            "PosElectionAdapter.sol:PosElectionAdapter",
            abi.encode(VR_ADDR, ElectionPolicy(election), IPosCustody(custody)),
            ADAPTER
        );
        g.module = ADAPTER;
        g.moduleCodeHash = ADAPTER.codehash;
        g.governanceFacet = GOV_FACET;
        g.repairFacet = REPAIR_FACET;
        g.recordsFacet = RECORDS_FACET;
        _deployTo("ValidatorRegistryPos.sol:ValidatorRegistryPos", abi.encode(g), VR_ADDR);
        _checkPos(g, custody);

        string memory d = "deployment";
        vm.serializeString(d, "format", "unicity.vr.deployment.v1");
        vm.serializeUint(d, "chainId", block.chainid);
        vm.serializeBytes32(d, "networkWord", g.network);
        vm.serializeAddress(d, "registry", VR_ADDR);
        vm.serializeBytes32(d, "registryCodeHash", VR_ADDR.codehash);
        vm.serializeAddress(d, "governanceFacet", GOV_FACET);
        vm.serializeBytes32(d, "governanceFacetCodeHash", GOV_FACET.codehash);
        vm.serializeAddress(d, "repairFacet", REPAIR_FACET);
        vm.serializeBytes32(d, "repairFacetCodeHash", REPAIR_FACET.codehash);
        vm.serializeAddress(d, "recordsFacet", RECORDS_FACET);
        vm.serializeBytes32(d, "recordsFacetCodeHash", RECORDS_FACET.codehash);
        vm.serializeAddress(d, "module", ADAPTER);
        vm.serializeBytes32(d, "moduleCodeHash", ADAPTER.codehash);
        vm.serializeBytes32(d, "moduleTag", PosElectionAdapter(ADAPTER).TAG());
        vm.serializeAddress(d, "governor", multisig);
        vm.serializeBytes32(d, "governorCodeHash", multisig.codehash);
        vm.serializeBytes32(d, "committeeDigest", VRCodec.membersDigest(IVR(VR_ADDR).committee()));
        vm.serializeBytes32(d, "lastAcked", IVR(VR_ADDR).lastAcked());
        vm.serializeUint(d, "identityCount", g.identities.length);
        vm.serializeUint(d, "members", _members(g).length);
        _posDeployment(d, custody, election, out);
        vm.dumpState(string.concat(out, "/state.json"));
    }

    function _posDeployment(string memory d, address custody, address election, string memory out)
        internal
    {
        ElectionPolicy e = ElectionPolicy(election);
        vm.serializeAddress(d, "custody", custody);
        vm.serializeBytes32(d, "custodyCodeHash", custody.codehash);
        vm.serializeAddress(d, "election", election);
        vm.serializeBytes32(d, "electionCodeHash", election.codehash);
        address publicationImpl = e.PUBLICATION_IMPL();
        vm.serializeAddress(d, "electionPublication", publicationImpl);
        vm.serializeBytes32(d, "electionPublicationCodeHash", publicationImpl.codehash);
        vm.serializeAddress(d, "evidence", address(PosFactoryRef(factory).EVIDENCE()));
        vm.serializeAddress(d, "selection", address(e.selection()));
        vm.serializeAddress(d, "reader", address(e.reader()));
        vm.serializeAddress(d, "policy", address(PosFactoryRef(factory).POLICY()));
        vm.serializeBytes32(d, "policyCodeHash", address(PosFactoryRef(factory).POLICY()).codehash);
        vm.serializeAddress(d, "rewardPool", address(PosFactoryRef(factory).REWARDS()));
        vm.serializeBytes32(
            d, "rewardPoolCodeHash", address(PosFactoryRef(factory).REWARDS()).codehash
        );
        vm.serializeAddress(d, "genesisImpl", genesisImpl);
        vm.serializeBytes32(d, "genesisImplCodeHash", genesisImpl.codehash);
        vm.serializeAddress(d, "factory", factory);
        vm.serializeBytes32(d, "manifestHash", PosFactoryRef(factory).MANIFEST_HASH());
        vm.serializeBytes32(d, "posAssignmentId", genesisAssignment);
        string memory dep = vm.serializeBool(d, "pos", true);
        vm.writeJson(dep, string.concat(out, "/deployment.json"));
    }

    // state of the stack construction, read by the deployment report
    address internal factory;
    address internal genesisImpl;
    bytes32 internal genesisAssignment;

    function _stack(string memory json, ValidatorRegistry.Genesis memory g, address multisig)
        internal
        returns (address custody, address election)
    {
        vm.etch(VRC.SEAL_REGISTRY, address(new MockRootRecords()).code);
        PosFactory.Config memory c = _config(json, g, multisig);
        uint256 total;
        for (uint256 i; i < c.identities.length; ++i) {
            total += c.identities[i].bond;
        }
        address deployer = address(uint160(uint256(keccak256("p85-genesis-deployer"))));
        vm.deal(deployer, total + c.rewardFunding);
        vm.startPrank(deployer);
        address f = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 5);
        address implDeployer = address(uint160(uint256(keccak256("p85-genesis-impl-deployer"))));
        vm.stopPrank();
        vm.prank(implDeployer);
        genesisImpl = address(new CustodyGenesis(f));
        vm.startPrank(deployer);
        c.custody = address(new StakeCustody(f, genesisImpl));
        c.election = address(new ElectionPolicy(f));
        c.evidence = address(new Evidence(f));
        c.selection = address(new SelectionEngine());
        c.reader = address(new EligibilityReader(c.custody, c.evidence));
        PosFactory pf = new PosFactory{value: total + c.rewardFunding}(c);
        vm.stopPrank();
        require(address(pf) == f, "factory address");
        factory = f;
        genesisAssignment = c.genesis.assignmentID;
        return (c.custody, c.election);
    }

    function _config(string memory json, ValidatorRegistry.Genesis memory g, address multisig)
        internal
        view
        returns (PosFactory.Config memory c)
    {
        // #1297/#1298: the retirement report profile named by P85_PROFILE (default testnet; P85ReportProfile).
        uint64 timeFloor;
        (timeFloor, c.reportWindow, c.settlementMargin) =
            P85ReportProfile.named(vm.envOr("P85_PROFILE", string("testnet")));
        c.network = g.network;
        c.rootNetwork = uint64(vm.parseJsonUint(json, ".pos.rootNetwork"));
        c.rootGenesis = vm.parseJsonBytes32(json, ".pos.rootGenesis");
        c.roots = VRC.SEAL_REGISTRY;
        c.treasury = vm.parseJsonAddress(json, ".pos.treasury");
        uint128 unit = uint128(vm.parseJsonUint(json, ".pos.bondUnit"));
        c.bondUnit = unit;
        c.minBond = unit;
        c.limits = Limits({vMax: g.vMax, lMax: g.lMax, rMax: g.rMax, maxBatch: g.maxBatch});
        c.genesis = GenesisAssignment({
            assignmentID: vm.parseJsonBytes32(json, ".pos.assignmentId"),
            lineage: keccak256("p85/lane/lineage"),
            rootEpoch: 1,
            evmEpoch: 1,
            firstRound: 1
        });
        c.electionParams = ElectionParams({
            nMin: g.nMin,
            nTarget: g.nTarget,
            nMax: g.nMax,
            maxM: g.maxM,
            distNum: g.distNum,
            distDen: g.distDen,
            cadenceRounds: uint64(vm.parseJsonUint(json, ".pos.cadenceRounds")),
            cadenceSeconds: uint64(vm.parseJsonUint(json, ".pos.cadenceSeconds"))
        });
        c.policy = Policy({
            penaltyBps: 100,
            lifetimeCapBps: 500,
            bountyBps: 1_000,
            bountyCap: 1 ether,
            evidenceWindow: 1_000,
            suffixEvidenceWindow: 1_000,
            holdNormal: 2_000,
            holdSuffix: 2_000,
            holdRetirement: 2_000,
            timeFloor: timeFloor
        });
        c.rewardRate = uint128(vm.parseJsonUint(json, ".pos.rewardRate"));
        c.governanceAuthority = multisig;
        c.rewardFunding = vm.parseJsonUint(json, ".pos.rewardFunding");
        c.hookCaller = ADAPTER;
        c.deployment = VR_ADDR;
        c.identities = new GenesisIdentity[](g.identities.length);
        for (uint256 i; i < g.identities.length; ++i) {
            ValidatorRegistry.GenesisIdentity memory gi = g.identities[i];
            c.identities[i] = GenesisIdentity({
                owner: gi.owner,
                withdrawal: gi.owner,
                rootKey: gi.binding.rootKey,
                evmKey: gi.binding.evmKey,
                rootNodeID: keccak256(bytes(gi.binding.rootNodeID)),
                evmNodeID: keccak256(bytes(gi.binding.evmNodeID)),
                operatorPayee: gi.binding.payee,
                bond: uint256(gi.rawWeight) * unit
            });
        }
    }

    /// @dev What the PoS generation pins after construction: VR's module and holder 0 are the adapter and custody, VR ids are custody ids,
    /// custody's genesis member digests are VR's seat digests, and the election answers to the adapter alone.
    function _checkPos(ValidatorRegistry.Genesis memory g, address custody) internal view {
        IVR vr = IVR(VR_ADDR);
        require(vr.activeModule().module == ADAPTER, "VR PoS genesis: active module");
        require(
            vr.holderCount() == 1 && vr.holderAt(0).holder == custody, "VR PoS genesis: holder 0"
        );
        require(vr.lastAcked() == VRC.GENESIS_RESULT, "VR PoS genesis: lastAcked");
        require(vr.openOutput() == bytes32(0), "VR PoS genesis: an open output");
        require(vr.committee().length == _members(g).length, "VR PoS genesis: committee size");
        require(
            StakeCustody(payable(custody)).nextStakingID() == g.identities.length,
            "VR PoS genesis: ids"
        );
        require(
            ElectionPolicy(PosElectionAdapter(ADAPTER).ELECTION()).hookCaller() == ADAPTER,
            "VR PoS genesis: hook caller"
        );
    }
}

interface PosFactoryRef {
    function EVIDENCE() external view returns (Evidence);
    function POLICY() external view returns (address);
    function REWARDS() external view returns (address);
    function MANIFEST_HASH() external view returns (bytes32);
}
