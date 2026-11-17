// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test, Vm} from "forge-std/Test.sol";
import {ValidatorRegistry} from "../../src/vr/ValidatorRegistry.sol";
import {VRGovernanceFacet} from "../../src/vr/VRGovernanceFacet.sol";
import {VRRepairFacet} from "../../src/vr/VRRepairFacet.sol";
import {VRRecordsFacet} from "../../src/vr/VRRecordsFacet.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {VRCodec} from "../../src/vr/VRCodec.sol";
import {Registration, Member, FeeSet, ChangeView, OutputView, IVR} from "../../src/vr/VRTypes.sol";
import {MockSeal, MockModule} from "./VRMocks.sol";

/// @notice Shared fixture: a VR generation at 0xff..03 with a mock SealRegistry at 0xff..02, a configurable module and `n` genesis
/// members with real secp256k1 keys (so registrations and binding proposals carry real proofs of possession).
abstract contract VRBase is Test {
    address internal constant VR_ADDR = 0xFF00000000000000000000000000000000000003;
    bytes32 internal constant NETWORK = keccak256("unicity.vr.test-network");
    bytes32 internal constant POA_TAG = keccak256("unicity.vr.poa.v1");
    address internal constant COLLECTOR = address(0xC011EC7);

    IVR internal vr;
    address internal govFacet;
    address internal repairFacet;
    address internal recordsFacet;
    MockSeal internal seal;
    MockModule internal module;
    address internal governor;

    uint256 internal keySeed = 0x1000;
    uint64 internal progress = 1_000;
    uint64 internal ucTime = 1_700_000_000;

    struct Keys {
        uint256 rootPk;
        uint256 evmPk;
        bytes rootKey;
        bytes evmKey;
    }

    mapping(uint64 => Keys) internal keysOf;

    // ---- keys ----

    function _compressed(uint256 pk) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(pk);
        return abi.encodePacked(
            w.publicKeyY % 2 == 0 ? bytes1(0x02) : bytes1(0x03), bytes32(w.publicKeyX)
        );
    }

    function _freshKeys() internal returns (Keys memory k) {
        k.rootPk = ++keySeed;
        k.evmPk = ++keySeed;
        k.rootKey = _compressed(k.rootPk);
        k.evmKey = _compressed(k.evmPk);
    }

    function _reg(Keys memory k, string memory tag, address payee, uint64 nonce)
        internal
        pure
        returns (Registration memory r)
    {
        r.rootNodeID = string.concat("root-", tag);
        r.rootKey = k.rootKey;
        r.evmNodeID = string.concat("evm-", tag);
        r.evmKey = k.evmKey;
        r.payee = payee;
        r.nonce = nonce;
    }

    function _regDigest(bytes32 domain, address sender, uint64 id, Registration memory r)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                domain,
                NETWORK,
                block.chainid,
                VR_ADDR,
                sender,
                uint256(id),
                keccak256(bytes(r.rootNodeID)),
                keccak256(r.rootKey),
                keccak256(bytes(r.evmNodeID)),
                keccak256(r.evmKey),
                r.payee,
                uint256(r.nonce)
            )
        );
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ---- genesis ----

    function _genesis(uint256 n, uint32 nMin, uint32 nTarget, uint32 nMax)
        internal
        returns (ValidatorRegistry.Genesis memory g)
    {
        g.network = NETWORK;
        g.governor = governor;
        g.module = address(module);
        g.moduleCodeHash = address(module).codehash;
        g.nMin = nMin;
        g.nTarget = nTarget;
        g.nMax = nMax;
        g.vMax = 16;
        g.lMax = 8;
        g.rMax = 8;
        g.maxBatch = 32;
        g.knownRootEpoch = 4;
        g.epochStartProgress = 0;
        g.fees = FeeSet(1_000_000, 8, COLLECTOR);
        g.maxGas = 30_000_000;
        g.systemGas = 2_000_000;
        g.maxM = 4;
        g.distNum = 1;
        g.distDen = 2;
        g.identities = new ValidatorRegistry.GenesisIdentity[](n);
        for (uint256 i = 0; i < n; ++i) {
            Keys memory k = _freshKeys();
            keysOf[uint64(i + 1)] = k;
            g.identities[i].owner = address(uint160(0xA000 + i + 1));
            g.identities[i].binding =
                _reg(k, vm.toString(i + 1), address(uint160(0xB000 + i + 1)), 0);
            g.identities[i].rawWeight = 1;
        }
    }

    /// @dev The genesis plan's alloc: the constructor runs at the pinned address, so every digest it writes uses the VR domain.
    function _deploy(ValidatorRegistry.Genesis memory g) internal {
        if (govFacet == address(0)) govFacet = address(new VRGovernanceFacet());
        if (repairFacet == address(0)) repairFacet = address(new VRRepairFacet());
        g.governanceFacet = govFacet;
        g.repairFacet = repairFacet;
        if (recordsFacet == address(0)) recordsFacet = address(new VRRecordsFacet());
        g.recordsFacet = recordsFacet;
        deployCodeTo("ValidatorRegistry.sol:ValidatorRegistry", abi.encode(g), VR_ADDR);
        vr = IVR(VR_ADDR);
        module.setVR(VR_ADDR);
    }

    function _setUpVR(uint256 n, uint32 nMin, uint32 nTarget, uint32 nMax) internal {
        MockSeal s = new MockSeal();
        vm.etch(VRC.SEAL_REGISTRY, address(s).code);
        seal = MockSeal(VRC.SEAL_REGISTRY);
        seal.setClock(progress, ucTime);
        if (address(module) == address(0)) module = new MockModule(POA_TAG);
        if (governor == address(0)) governor = address(this);
        _deploy(_genesis(n, nMin, nTarget, nMax));
    }

    // ---- clock and hooks ----

    function _advance(uint64 dp, uint64 dt) internal {
        progress += dp;
        ucTime += dt;
        seal.setClock(progress, ucTime);
        vm.roll(block.number + 1);
    }

    function _elect() internal returns (uint8 outcome) {
        vm.prank(VRC.SYSTEM_CALLER);
        outcome = vr.elect(keccak256(abi.encode("origin", block.number, progress)));
    }

    function _electWith(bytes32 origin) internal returns (uint8 outcome) {
        vm.prank(VRC.SYSTEM_CALLER);
        outcome = vr.elect(origin);
    }

    function _apply(uint32 n) internal {
        vm.prank(VRC.SYSTEM_CALLER);
        vr.applyRootRecords(n);
    }

    function _applyAll() internal {
        uint64 c = seal.recordCount();
        uint64 cur = vr.recordCursor();
        while (cur < c) {
            uint64 n = c - cur > 32 ? 32 : c - cur;
            _apply(uint32(n));
            cur = vr.recordCursor();
        }
    }

    // ---- records ----

    function _recClosed(bytes32 rid) internal {
        seal.push(VRC.REC_SESSION_CLOSED, abi.encode(rid));
    }

    function _recAck(bytes32 rid) internal {
        seal.push(VRC.REC_ACK, abi.encode(rid, uint256(10), uint256(20), uint256(30)));
    }

    function _recRecoveryAck(bytes32 rid) internal {
        bytes memory d =
            abi.encode(rid, keccak256("k-assignment"), uint256(1), uint256(2), uint256(3));
        d = bytes.concat(d, abi.encode(uint256(4), uint256(5), uint256(6), uint256(7)));
        seal.push(VRC.REC_RECOVERY_ACK, d);
    }

    function _recBoundary(bytes32 rid, uint64 changesEpoch, bool recovered, uint16 bitmap)
        internal
    {
        uint64 installed = changesEpoch + (recovered ? 1 : 0);
        seal.push(
            VRC.REC_BOUNDARY,
            abi.encode(
                rid,
                uint256(changesEpoch),
                uint256(installed),
                uint256(installed),
                uint256(5_000),
                recovered,
                uint256(bitmap)
            )
        );
    }

    function _recRejected(bytes32 rid, uint8 reason) internal {
        seal.push(VRC.REC_OUTPUT_REJECTED, abi.encode(rid, uint256(reason), uint256(0), uint256(0)));
    }

    function _nextEpoch() internal view returns (uint64) {
        return vr.config().knownRootEpoch + 1;
    }

    /// @dev Ack + Boundary for `rid` with the given bitmap, applied.
    function _acknowledge(bytes32 rid, uint16 bitmap) internal {
        _recAck(rid);
        _recBoundary(rid, _nextEpoch(), false, bitmap);
        _applyAll();
    }

    // ---- governance ----

    function _queue(uint8 kind, bytes memory payload) internal returns (uint64 id) {
        vm.prank(governor);
        id = vr.queue(kind, payload);
    }

    function _passDelays() internal {
        _advance(VRC.DELAY_ROUNDS, VRC.DELAY_SECONDS);
    }

    function _queueScheduled(uint8 kind, bytes memory payload) internal returns (uint64 id) {
        id = _queue(kind, payload);
        _passDelays();
        vr.execute(id);
    }

    function _limitsPayload(uint32 a, uint32 b, uint32 c) internal pure returns (bytes memory) {
        return abi.encode(a, b, c);
    }

    // ---- outputs ----

    /// @dev The module reserves `rid` at the next election; `ready` publishes in the same call.
    function _moduleReserve(bytes32 rid, bool ready) internal returns (uint8 outcome) {
        module.setElect(VRC.ELECT_RESERVED, ready, rid);
        outcome = _elect();
        module.setElect(VRC.ELECT_NOT_DUE, false, 0);
    }

    function _state(bytes32 rid) internal view returns (uint8) {
        return vr.output(rid).state;
    }

    function _changeState(uint64 id) internal view returns (uint8) {
        return vr.change(id).state;
    }

    function _members() internal view returns (Member[] memory) {
        return vr.committee();
    }

    /// @dev The committee without `id`, re-quantized (unit raw weights stay unit weights).
    function _without(Member[] memory ms, uint64 id) internal pure returns (Member[] memory out) {
        out = new Member[](ms.length - 1);
        uint256 k = 0;
        for (uint256 i = 0; i < ms.length; ++i) {
            if (ms[i].id != id) out[k++] = ms[i];
        }
    }

    function _rid(string memory name) internal pure returns (bytes32) {
        return keccak256(bytes(name));
    }
}
