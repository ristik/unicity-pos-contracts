// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Script} from "forge-std/Script.sol";
import {ValidatorRegistry} from "../src/vr/ValidatorRegistry.sol";
import {FoundationMultisig} from "../src/vr/FoundationMultisig.sol";
import {PoaElection} from "../src/vr/poa/PoaElection.sol";
import {PoaComposerEngine} from "../src/vr/poa/PoaComposer.sol";
import {VRC} from "../src/vr/VRConstants.sol";
import {VRCodec} from "../src/vr/VRCodec.sol";
import {Registration, FeeSet, IVR} from "../src/vr/VRTypes.sol";

/// @notice The VR generation's contracts genesis (VT-14, bft-core#1158; design section 2.1 "Genesis consistency"): the ValidatorRegistry
/// core and its three facets, the PoA module and its composer engine, and the FoundationMultisig, constructed at their genesis
/// addresses in a simulated chain and dumped as state. `script/vr-genesis.sh` runs it and folds the dump into a genesis alloc.
///
/// The addresses are the owner-question default (briefs/owner-questions.md "VT-02 ureth hook test"): VR 0xff..03, VRGovernanceFacet
/// 0xff..04, VRRepairFacet 0xff..05, VRRecordsFacet 0xff..06, PoaElection 0xff..07, PoaComposerEngine 0xff..08, and the multisig
/// 0xff..09 (VT-14 default). VR's runtime carries the facets' addresses and code hashes as immutables, the facets carry their own
/// address and PoaElection carries VR's and the engine's, so these code hashes are defined only for these addresses.
///
/// Order (owner-questions "Two contracts"): the composer engine first, and its runtime is checked to be exactly the compiled
/// PoaComposerEngine and no proxy (no DELEGATECALL, CALLCODE, SELFDESTRUCT, CALL, CREATE or SSTORE in its code, and no storage),
/// because PoaElection's code hash commits to the engine's address only; then the facets, the module, the multisig and VR.
///
/// Input: VR_GENESIS_JSON, the plan `ubft vr-genesis plan` writes (format "unicity.vr.genesis-input.v1"), and VR_OUT, a directory
/// under ./script/genesis-out.
contract VRGenesis is Script {
    address internal constant VR_ADDR = address(uint160((uint256(0xff) << 152) | 0x03));
    address internal constant GOV_FACET = address(uint160((uint256(0xff) << 152) | 0x04));
    address internal constant REPAIR_FACET = address(uint160((uint256(0xff) << 152) | 0x05));
    address internal constant RECORDS_FACET = address(uint160((uint256(0xff) << 152) | 0x06));
    address internal constant POA = address(uint160((uint256(0xff) << 152) | 0x07));
    address internal constant COMPOSER = address(uint160((uint256(0xff) << 152) | 0x08));
    address internal constant MULTISIG = address(uint160((uint256(0xff) << 152) | 0x09));

    string internal constant FORMAT = "unicity.vr.genesis-input.v1";

    function run() external virtual {
        string memory json = vm.envString("VR_GENESIS_JSON");
        string memory out = vm.envString("VR_OUT");
        require(
            keccak256(bytes(vm.parseJsonString(json, ".format"))) == keccak256(bytes(FORMAT)),
            "VR genesis: unknown input format"
        );
        vm.chainId(vm.parseJsonUint(json, ".chainId"));
        for (uint256 a = 3; a <= 9; ++a) {
            address taken = address(uint160((uint256(0xff) << 152) | a));
            require(taken.code.length == 0, "VR genesis: a genesis address is taken");
        }

        // 1. the composer engine, verified before anything pins its address
        _deployTo("PoaComposer.sol:PoaComposerEngine", COMPOSER);
        bytes memory built = vm.getDeployedCode("PoaComposer.sol:PoaComposerEngine");
        require(keccak256(COMPOSER.code) == keccak256(built), "VR genesis: composer runtime");
        _requireNoProxy(COMPOSER.code);

        // 2. the facets (their only immutable is their own address)
        _deployTo("VRGovernanceFacet.sol:VRGovernanceFacet", GOV_FACET);
        _deployTo("VRRepairFacet.sol:VRRepairFacet", REPAIR_FACET);
        _deployTo("VRRecordsFacet.sol:VRRecordsFacet", RECORDS_FACET);

        // 3. the PoA module, with the genesis committee's ids
        ValidatorRegistry.Genesis memory g = _genesis(json);
        _deployTo(
            "PoaElection.sol:PoaElection",
            abi.encode(VR_ADDR, PoaComposerEngine(COMPOSER), _members(g)),
            POA
        );
        g.module = POA;
        g.moduleCodeHash = POA.codehash;

        // 4. the governor
        address[5] memory signers;
        for (uint256 i; i < 5; ++i) {
            signers[i] =
                vm.parseJsonAddress(json, string.concat(".governorSigners[", vm.toString(i), "]"));
        }
        _deployTo("FoundationMultisig.sol:FoundationMultisig", abi.encode(signers), MULTISIG);
        g.governor = MULTISIG;

        // 5. VR, constructed at its address so every digest it writes uses the VR domain
        g.governanceFacet = GOV_FACET;
        g.repairFacet = REPAIR_FACET;
        g.recordsFacet = RECORDS_FACET;
        _deployTo("ValidatorRegistry.sol:ValidatorRegistry", abi.encode(g), VR_ADDR);
        _check(g);

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
        vm.serializeAddress(d, "module", POA);
        vm.serializeBytes32(d, "moduleCodeHash", POA.codehash);
        vm.serializeBytes32(d, "moduleTag", PoaElection(POA).TAG());
        vm.serializeAddress(d, "composer", COMPOSER);
        vm.serializeBytes32(d, "composerCodeHash", COMPOSER.codehash);
        vm.serializeAddress(d, "governor", MULTISIG);
        vm.serializeBytes32(d, "governorCodeHash", MULTISIG.codehash);
        vm.serializeBytes32(d, "committeeDigest", _committeeDigest());
        vm.serializeBytes32(d, "lastAcked", IVR(VR_ADDR).lastAcked());
        vm.serializeUint(d, "identityCount", g.identities.length);
        string memory dep = vm.serializeUint(d, "members", _members(g).length);
        vm.writeJson(dep, string.concat(out, "/deployment.json"));
        vm.dumpState(string.concat(out, "/state.json"));
    }

    /// @dev Runs the artifact's constructor AT `where` (so `address(this)` and every immutable naming it are the genesis address) and
    /// leaves the runtime it returns there: forge-std's deployCodeTo, which a Script does not inherit.
    function _deployTo(string memory what, address where) internal {
        _deployTo(what, "", where);
    }

    function _deployTo(string memory what, bytes memory args, address where) internal {
        vm.etch(where, abi.encodePacked(vm.getCode(what), args));
        (bool ok, bytes memory runtime) = where.call("");
        require(ok, string.concat("VR genesis: constructing ", what));
        vm.etch(where, runtime);
    }

    function _genesis(string memory json)
        internal
        pure
        returns (ValidatorRegistry.Genesis memory g)
    {
        g.network = vm.parseJsonBytes32(json, ".network");
        g.nMin = uint32(vm.parseJsonUint(json, ".limits.nMin"));
        g.nTarget = uint32(vm.parseJsonUint(json, ".limits.nTarget"));
        g.nMax = uint32(vm.parseJsonUint(json, ".limits.nMax"));
        g.vMax = uint32(vm.parseJsonUint(json, ".limits.vMax"));
        g.lMax = uint32(vm.parseJsonUint(json, ".limits.lMax"));
        g.rMax = uint32(vm.parseJsonUint(json, ".limits.rMax"));
        g.maxBatch = uint32(vm.parseJsonUint(json, ".limits.maxBatch"));
        g.knownRootEpoch = uint64(vm.parseJsonUint(json, ".knownRootEpoch"));
        g.epochStartProgress = uint64(vm.parseJsonUint(json, ".epochStartProgress"));
        g.fees = FeeSet(
            uint64(vm.parseJsonUint(json, ".fees.baseFeeFloor")),
            uint64(vm.parseJsonUint(json, ".fees.changeDenominator")),
            vm.parseJsonAddress(json, ".fees.feeCollector")
        );
        g.maxGas = uint64(vm.parseJsonUint(json, ".maxGas"));
        g.systemGas = uint64(vm.parseJsonUint(json, ".systemGas"));
        g.maxM = uint64(vm.parseJsonUint(json, ".continuity.maxM"));
        g.distNum = uint64(vm.parseJsonUint(json, ".continuity.distNum"));
        g.distDen = uint64(vm.parseJsonUint(json, ".continuity.distDen"));
        uint256 n = vm.parseJsonUint(json, ".identityCount");
        g.identities = new ValidatorRegistry.GenesisIdentity[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".identities[", vm.toString(i), "]");
            require(
                vm.parseJsonUint(json, string.concat(p, ".id")) == i + 1,
                "VR genesis: ids are 1..n in order"
            );
            g.identities[i].owner = vm.parseJsonAddress(json, string.concat(p, ".owner"));
            g.identities[i].binding = Registration({
                rootNodeID: vm.parseJsonString(json, string.concat(p, ".rootNodeID")),
                rootKey: vm.parseJsonBytes(json, string.concat(p, ".rootKey")),
                evmNodeID: vm.parseJsonString(json, string.concat(p, ".evmNodeID")),
                evmKey: vm.parseJsonBytes(json, string.concat(p, ".evmKey")),
                payee: vm.parseJsonAddress(json, string.concat(p, ".payee")),
                nonce: 0
            });
            g.identities[i].rawWeight =
                uint64(vm.parseJsonUint(json, string.concat(p, ".rawWeight")));
        }
    }

    /// @dev The genesis committee's ids, ascending (the identities with a nonzero raw weight).
    function _members(ValidatorRegistry.Genesis memory g)
        internal
        pure
        returns (uint64[] memory ids)
    {
        uint256 k;
        for (uint256 i; i < g.identities.length; ++i) {
            if (g.identities[i].rawWeight != 0) ++k;
        }
        ids = new uint64[](k);
        k = 0;
        for (uint256 i; i < g.identities.length; ++i) {
            if (g.identities[i].rawWeight != 0) ids[k++] = uint64(i + 1);
        }
    }

    function _committeeDigest() internal view returns (bytes32) {
        return VRCodec.membersDigest(IVR(VR_ADDR).committee());
    }

    /// @dev What the generation pins must hold after construction: the module, the governor, the committee and the hook limits.
    function _check(ValidatorRegistry.Genesis memory g) internal view {
        IVR vr = IVR(VR_ADDR);
        require(vr.activeModule().module == POA, "VR genesis: active module");
        require(vr.lastAcked() == VRC.GENESIS_RESULT, "VR genesis: lastAcked");
        require(vr.openOutput() == bytes32(0), "VR genesis: an open output");
        require(vr.recordCursor() == 0, "VR genesis: record cursor");
        (,,, uint32 maxBatch) = vr.limits();
        require(maxBatch == g.maxBatch, "VR genesis: maxBatch");
        require(vr.committee().length == _members(g).length, "VR genesis: committee size");
        require(PoaElection(POA).VR() == VR_ADDR, "VR genesis: PoA's VR");
        require(address(PoaElection(POA).COMPOSER()) == COMPOSER, "VR genesis: PoA's composer");
    }

    /// @dev A stateless engine that cannot forward or change anything: no opcode that calls, creates, delegates, self-destructs or
    /// writes storage (PUSH data skipped), and no storage at its address.
    function _requireNoProxy(bytes memory code) internal view {
        _requireInert(code);
        require(
            vm.load(
                COMPOSER,
                bytes32(uint256(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc))
            ) == bytes32(0),
            "VR genesis: an EIP-1967 implementation slot"
        );
    }

    function _requireInert(bytes memory code) internal pure {
        for (uint256 i; i < code.length; ++i) {
            uint8 op = uint8(code[i]);
            if (op >= 0x60 && op <= 0x7f) {
                i += op - 0x5f;
                continue;
            }
            require(
                op != 0xf0 && op != 0xf1 && op != 0xf2 && op != 0xf4 && op != 0xf5 && op != 0xff
                    && op != 0x55,
                "VR genesis: the composer engine can call, create, delegate, self-destruct or write"
            );
        }
    }
}
