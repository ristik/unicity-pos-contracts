// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "../../p85/P85Flow.sol";
import {MockRootRecords} from "../../p85/MockRootRecords.sol";
import {ValidatorRegistry} from "../../../src/vr/ValidatorRegistry.sol";
import {VRGovernanceFacet} from "../../../src/vr/VRGovernanceFacet.sol";
import {VRRepairFacet} from "../../../src/vr/VRRepairFacet.sol";
import {VRRecordsFacet} from "../../../src/vr/VRRecordsFacet.sol";
import {PosElectionAdapter} from "../../../src/vr/pos/PosElectionAdapter.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {Registration, Member, FeeSet, IVR} from "../../../src/vr/VRTypes.sol";
import {ElectionPolicy} from "../../../src/p85/ElectionPolicy.sol";
import {
    Delegation,
    DelegationRequest,
    ElectionParams,
    Policy,
    RecordKind,
    BoundaryData,
    OutputRejectedData,
    RecoveryAckData,
    HolderRetirementData,
    SessionClosedData
} from "../../../src/p85/P85Types.sol";

/// @notice A VR generation on the PoS prototype (design 3.8): VR at 0xff..03 with its facets, a mock SealRegistry at 0xff..02 that is both
/// VR's and P85's record source, the real P85 stack constructed by PosFactory with `hookCaller` = the adapter (0xff..07) and the VR
/// address as the exposure-digest domain, the multisig as GovernanceParams.AUTHORITY and VR's governor, and the four genesis identities
/// registered in VR in manifest order (VR ids = custody StakingIDs).
abstract contract PosBase is P85Flow {
    address internal constant VR_ADDR = 0xFF00000000000000000000000000000000000003;
    address internal constant ADAPTER = 0xfF00000000000000000000000000000000000007;
    address internal constant MULTISIG = 0xff00000000000000000000000000000000000009;
    address internal constant SYS = 0xff00000000000000000000000000000000000001;

    IVR internal vr;
    PosElectionAdapter internal adapter;
    bytes32 internal constant ORIGIN = keccak256("pos/origin");
    uint64 internal progress = 0;
    uint64 internal ucTime = 0;

    // the election is due once the cadence has passed
    function _electionParams() internal view virtual override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: 10,
            nMax: 16,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: 200,
            cadenceSeconds: 100
        });
    }

    function _recordSource() internal pure override returns (address) {
        return VRC.SEAL_REGISTRY;
    }

    function _hookCaller() internal pure override returns (address) {
        return ADAPTER;
    }

    function _digestDomain() internal pure override returns (address) {
        return VR_ADDR;
    }

    function setUp() public virtual override {
        vm.etch(VRC.SEAL_REGISTRY, address(new MockRootRecords()).code);
        roots = MockRootRecords(VRC.SEAL_REGISTRY);
        governanceAuthority = MULTISIG;
        _deploy(_defaultPolicy());
        deployCodeTo(
            "PosElectionAdapter.sol:PosElectionAdapter",
            abi.encode(VR_ADDR, address(election), address(custody)),
            ADAPTER
        );
        adapter = PosElectionAdapter(ADAPTER);
        address[5] memory signers =
            [address(0xA1), address(0xA2), address(0xA3), address(0xA4), address(0xA5)];
        deployCodeTo("FoundationMultisig.sol:FoundationMultisig", abi.encode(signers), MULTISIG);
        ValidatorRegistry.Genesis memory g = _vrGenesis();
        g.governanceFacet = address(new VRGovernanceFacet());
        g.repairFacet = address(new VRRepairFacet());
        g.recordsFacet = address(new VRRecordsFacet());
        deployCodeTo("ValidatorRegistry.sol:ValidatorRegistry", abi.encode(g), VR_ADDR);
        vr = IVR(VR_ADDR);
    }

    function _vrGenesis() internal returns (ValidatorRegistry.Genesis memory g) {
        g.network = NETWORK;
        g.governor = MULTISIG;
        g.module = ADAPTER;
        g.moduleCodeHash = ADAPTER.codehash;
        ElectionParams memory p = _electionParams();
        g.nMin = p.nMin;
        g.nTarget = p.nTarget;
        g.nMax = p.nMax;
        g.vMax = _manifestLimits().vMax;
        g.lMax = _manifestLimits().lMax;
        g.rMax = _manifestLimits().rMax;
        g.maxBatch = _manifestLimits().maxBatch;
        g.knownRootEpoch = 1;
        g.epochStartProgress = 0;
        g.fees = FeeSet(1_000_000, 8, address(0xC011EC7));
        g.maxGas = 30_000_000;
        g.systemGas = 2_000_000;
        g.maxM = p.maxM;
        g.distNum = p.distNum;
        g.distDen = p.distDen;
        g.identities = new ValidatorRegistry.GenesisIdentity[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            g.identities[i].owner = vm.addr(ownerPk(i));
            g.identities[i].binding = Registration({
                rootNodeID: string.concat("root-", string(abi.encodePacked(bytes1(uint8(97 + i))))),
                rootKey: _rootKey(i),
                evmNodeID: string.concat("evm-", string(abi.encodePacked(bytes1(uint8(97 + i))))),
                evmKey: compressed(evmPk(i)),
                payee: vm.addr(payeePk(i)),
                nonce: 0
            });
            g.identities[i].rawWeight = uint64(GENESIS_BOND / (100 * UCT));
        }
    }

    /// @dev Custody's exposure id on a VR generation: the deployment domain is VR.
    function _eid(bytes32 assignmentID, uint64 id) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("unicity.p85.exposure"), NETWORK, block.chainid, VR_ADDR, assignmentID, id
            )
        );
    }

    /// @dev Every account of the generation cold again (the system call of a fresh transaction meets them so; a measurement inside the
    /// transaction that built the state is warm and a lower bound).
    function _coolAll() internal {
        address[10] memory a = [
            VR_ADDR,
            ADAPTER,
            address(custody),
            address(election),
            address(evidence),
            address(election.selection()),
            address(election.reader()),
            address(election.policySource()),
            address(factory.REWARDS()),
            VRC.SEAL_REGISTRY
        ];
        for (uint256 i; i < a.length; ++i) {
            vm.cool(a[i]);
        }
        vm.cool(address(uint160((uint256(0xff) << 152) | 4)));
        vm.cool(address(uint160((uint256(0xff) << 152) | 5)));
        vm.cool(address(uint160((uint256(0xff) << 152) | 6)));
    }

    // ---- clock and hooks ----

    function _advance(uint64 dp, uint64 dt) internal {
        progress += dp;
        ucTime += dt;
        roots.setClock(progress, ucTime);
        vm.roll(block.number + 1);
    }

    function _vrElect(bytes32 origin) internal returns (uint8 outcome) {
        vm.prank(SYS);
        outcome = vr.elect(origin);
    }

    function _vrApply(uint32 n) internal {
        vm.prank(SYS);
        vr.applyRootRecords(n);
    }

    function _vrApplyAll() internal {
        uint64 c = roots.recordCount();
        uint64 cur = vr.recordCursor();
        while (cur < c) {
            uint64 n = c - cur > 32 ? 32 : c - cur;
            _vrApply(uint32(n));
            cur = vr.recordCursor();
        }
        assertEq(vr.health(), VRC.HEALTHY, "no module fault while applying records");
    }

    // ---- P85 election flow through VR ----

    function _pops(bytes32 rid, uint256[] memory idx)
        internal
        returns (ElectionPolicy.PoPInput[] memory pops)
    {
        pops = new ElectionPolicy.PoPInput[](idx.length);
        for (uint256 k; k < idx.length; ++k) {
            uint256 i = idx[k];
            bytes memory key = compressed(evmPk(i));
            pops[k] = ElectionPolicy.PoPInput(
                gid(i), key, sign(evmPk(i), election.popDigest(rid, gid(i), keccak256(key)))
            );
        }
    }

    function _allIdx() internal pure returns (uint256[] memory idx) {
        idx = new uint256[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            idx[i] = i;
        }
    }

    /// @dev The cadence passes, the hook elects: the P85 election reserves a result and VR holds it Reserved (not yet Ready).
    function _electFromStake() internal returns (bytes32 rid) {
        _advance(300, 200);
        uint256 g0 = gasleft();
        uint8 o = _vrElect(ORIGIN);
        emit log_named_uint(
            string.concat("elect gas, committee ", vm.toString(vr.committee().length)),
            g0 - gasleft()
        );
        if (o != VRC.ELECT_RESERVED) {
            emit log_named_uint("elect outcome", o);
            emit log_named_uint("vr health", vr.health());
            emit log_named_uint(
                "p85 reason", uint8(election.result(election.lastAttemptResult()).reason)
            );
            emit log_named_uint("committee", vr.committee().length);
        }
        assertEq(o, VRC.ELECT_RESERVED, "an election from stake");
        rid = vr.openOutput();
        assertEq(rid, election.openResult(), "VR holds P85's own result id");
    }

    /// @dev Proofs of possession and `finalizeCandidate`, then anyone publishes in VR.
    function _publishResult(bytes32 rid) internal returns (uint8 status) {
        election.submitAssignmentPoPs(rid, _pops(rid, _allIdx()));
        election.finalizeCandidate(rid);
        status = vr.publish(rid);
    }

    function _ackRecord(bytes32 rid) internal {
        pushRecord(RecordKind.Ack, ackData(rid, 150, 160, 161));
    }

    function _boundaryRecord(bytes32 rid, bool recovered) internal {
        uint64 e = vr.config().knownRootEpoch + 1;
        pushRecord(
            RecordKind.Boundary,
            abi.encode(BoundaryData(rid, e, recovered ? e + 1 : e, e, 5_000, recovered, 0))
        );
    }

    function _rejectedRecord(bytes32 rid, uint8 reason) internal {
        pushRecord(RecordKind.OutputRejected, abi.encode(OutputRejectedData(rid, reason, 0, 0)));
    }

    function _closedRecord(bytes32 rid) internal {
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(rid)));
    }

    // ---- a PoS joiner: VR register, custody register, bond, admitDelegation ----

    uint256 internal joinerCount;

    struct Joiner {
        uint64 id;
        uint256 ownerPk;
        uint256 rootPk;
        uint256 evmPk;
        address payee;
    }

    function _joinPos(uint256 bond) internal returns (Joiner memory j) {
        return _joinPosX(bond, false);
    }

    /// @dev `misalign`: the P85 delegation names another operator payee than the VR registration (the identity is not VR-aligned).
    function _joinPosX(uint256 bond, bool misalign) internal returns (Joiner memory j) {
        uint256 n = ++joinerCount;
        j.ownerPk = 0x7000 + n;
        j.rootPk = 0x7100 + n;
        j.evmPk = 0x7200 + n;
        j.payee = vm.addr(0x7300 + n);
        address owner = vm.addr(j.ownerPk);
        string memory tag = vm.toString(n);
        Registration memory r = Registration({
            rootNodeID: string.concat("root-j", tag),
            rootKey: compressed(j.rootPk),
            evmNodeID: string.concat("evm-j", tag),
            evmKey: compressed(j.evmPk),
            payee: j.payee,
            nonce: vr.registrationNonce(owner)
        });
        bytes32 d = keccak256(
            abi.encode(
                VRC.REGISTER_DOMAIN,
                NETWORK,
                block.chainid,
                VR_ADDR,
                owner,
                uint256(0),
                keccak256(bytes(r.rootNodeID)),
                keccak256(r.rootKey),
                keccak256(bytes(r.evmNodeID)),
                keccak256(r.evmKey),
                r.payee,
                uint256(r.nonce)
            )
        );
        vm.prank(owner);
        j.id = vr.register(r, sign(j.rootPk, d), sign(j.evmPk, d));
        uint64 cid = register(j.ownerPk, j.rootPk, owner);
        assertEq(cid, j.id, "VR id = custody StakingID");
        bondFor(j.id, bond);
        DelegationRequest memory dr;
        dr.id = j.id;
        dr.generation = 1;
        dr.binding = Delegation({
            rootNodeID: keccak256(bytes(r.rootNodeID)),
            rootKey: r.rootKey,
            evmNodeID: keccak256(bytes(r.evmNodeID)),
            evmKey: r.evmKey,
            operatorPayee: misalign ? vm.addr(0x7f00 + n) : j.payee
        });
        dr.expiry = type(uint64).max;
        bytes32 dd = election.delegationDigest(dr);
        election.admitDelegation(dr, sign(j.ownerPk, dd), sign(j.evmPk, dd));
    }

    /// @dev Keys of identity `id`, genesis or joiner, for its proofs of possession.
    mapping(uint64 => uint256) internal evmPkOf;

    // ---- holder facts (design 3.9.2): read from custody's storage at the frozen slots ----

    function _factsWord0(uint64 id, uint64 gen) internal view returns (uint256) {
        return uint256(vm.load(address(custody), _factsSlot(id, gen)));
    }

    function _factsWord1(uint64 id, uint64 gen) internal view returns (bytes32) {
        return vm.load(address(custody), bytes32(uint256(_factsSlot(id, gen)) + 1));
    }

    function _factsSlot(uint64 id, uint64 gen) internal pure returns (bytes32) {
        uint256 b = uint256(VRC.LIABILITY_NAMESPACE);
        bytes32 q = keccak256(abi.encode(uint256(id), b + 1));
        return keccak256(abi.encode(uint256(gen), q));
    }

    function _cursorFact() internal view returns (uint64) {
        return uint64(uint256(vm.load(address(custody), VRC.LIABILITY_NAMESPACE)));
    }

    /// @dev The generic facts equal custody's own state for (id, gen): live exposures, lot references, anchor, exposure chain, requested,
    /// no reserved bits.
    function _assertFacts(uint64 id, uint64 gen) internal view {
        uint256 w = _factsWord0(id, gen);
        assertEq(w >> 136, 0, "reserved bits are zero");
        assertEq(uint8(w), _requestedOf(id, gen) ? 1 : 0, "requested");
        assertEq(uint32(w >> 8), custody.liveExposures(id, gen), "liveExposures");
        assertEq(uint32(w >> 40), _lotRefs(id, gen), "lotReferences");
        assertEq(uint64(w >> 72), custody.maxLiabilityAnchor(id, gen), "maxLiabilityAnchor");
        assertEq(_factsWord1(id, gen), custody.exposureChain(id, gen), "refDigest");
    }

    function _refCount(uint256 lotID) internal view returns (uint32 rc) {
        (,,,,,,, rc,,,,,) = custody.lots(lotID);
    }

    function _lotRefs(uint64 id, uint64 gen) internal view returns (uint256 refs) {
        uint256[] memory ls = custody.generationLots(id, gen);
        for (uint256 i; i < ls.length; ++i) {
            refs += _refCount(ls[i]);
        }
    }

    mapping(uint64 => mapping(uint64 => bool)) internal requestedSeen;

    function _requestedOf(uint64 id, uint64 gen) internal view returns (bool) {
        return requestedSeen[id][gen];
    }

    function _state(bytes32 rid) internal view returns (uint8) {
        return vr.output(rid).state;
    }

    // ---- election helpers over any committee ----

    uint64 internal lastH;

    function _ackNext(bytes32 rid) internal {
        _advance(10, 10);
        lastH = 150 + progress;
        pushRecord(RecordKind.Ack, ackData(rid, lastH, 160 + progress, 161 + progress));
        _boundaryRecord(rid, false);
        _vrApplyAll();
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
    }

    function _elect2() internal returns (bytes32 rid) {
        rid = _electFromStake();
        assertEq(_publishResult2(rid), VRC.PUB_PUBLISHED);
    }

    function _publishResult2(bytes32 rid) internal returns (uint8) {
        ElectionPolicy.Frozen[] memory f = election.frozenMembers(rid);
        ElectionPolicy.PoPInput[] memory pops = new ElectionPolicy.PoPInput[](f.length);
        for (uint256 k; k < f.length; ++k) {
            uint256 pk = f[k].id <= N_GENESIS ? evmPk(f[k].id - 1) : evmPkOf[f[k].id];
            bytes memory key = compressed(pk);
            pops[k] = ElectionPolicy.PoPInput(
                f[k].id, key, sign(pk, election.popDigest(rid, f[k].id, keccak256(key)))
            );
        }
        election.submitAssignmentPoPs(rid, pops);
        election.finalizeCandidate(rid);
        return vr.publish(rid);
    }
}
