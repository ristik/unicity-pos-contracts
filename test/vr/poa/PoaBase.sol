// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "../VRBase.sol";
import {MockSeal, MockModule} from "../VRMocks.sol";
import {ValidatorRegistry} from "../../../src/vr/ValidatorRegistry.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {Registration, Member, OutputView, IdentityView} from "../../../src/vr/VRTypes.sol";
import {PoaElection} from "../../../src/vr/poa/PoaElection.sol";
import {PoaComposerEngine} from "../../../src/vr/poa/PoaComposer.sol";

/// @notice A VR generation whose active module is the real PoaElection: VR at 0xff..03 with its facets, a mock SealRegistry at
/// 0xff..02, `n` genesis members with unit raw weights and real keys, and helpers to register, apply, admit, elect and acknowledge.
abstract contract PoaBase is VRBase {
    // PoA states (design 3.7.1)
    uint8 internal constant NONE = 0;
    uint8 internal constant APPLIED = 1;
    uint8 internal constant ADMITTED = 2;
    uint8 internal constant JOINING = 3;
    uint8 internal constant ACTIVE = 4;
    uint8 internal constant EXIT_REQUESTED = 5;
    uint8 internal constant REMOVING = 6;
    uint8 internal constant LEAVING = 7;
    uint8 internal constant EXITED = 8;
    uint8 internal constant PARKED = 9;

    uint64 internal constant A_ADMIT = 1;
    uint64 internal constant A_REMOVE = 2;
    uint64 internal constant A_CONFIRM_EXIT = 3;

    PoaElection internal poa;
    PoaComposerEngine internal engine;
    uint256 internal regCount;
    // the genesis continuity budget (VRBase's default: maxM 4, distance 1/2)
    uint64 internal contMaxM = 4;
    uint64 internal contDistNum = 1;
    uint64 internal contDistDen = 2;

    function _setUpPoa(uint256 n, uint32 nMin, uint32 nTarget, uint32 nMax) internal {
        _setUpPoaWeights(_unit(n), nMin, nTarget, nMax);
    }

    function _unit(uint256 n) internal pure returns (uint64[] memory w) {
        w = new uint64[](n);
        for (uint256 i = 0; i < n; ++i) {
            w[i] = 1;
        }
    }

    /// @dev Genesis with the given raw weights for ids 1..n (all members).
    function _setUpPoaWeights(uint64[] memory raw, uint32 nMin, uint32 nTarget, uint32 nMax)
        internal
    {
        MockSeal s = new MockSeal();
        vm.etch(VRC.SEAL_REGISTRY, address(s).code);
        seal = MockSeal(VRC.SEAL_REGISTRY);
        seal.setClock(progress, ucTime);
        module = new MockModule(keccak256("unicity.vr.mock-module")); // a second module for the switch tests
        governor = address(this);
        uint256 n = raw.length;
        uint64[] memory ids = new uint64[](n);
        for (uint256 i = 0; i < n; ++i) {
            ids[i] = uint64(i + 1);
        }
        if (address(engine) == address(0)) engine = new PoaComposerEngine();
        poa = new PoaElection(VR_ADDR, engine, ids);
        ValidatorRegistry.Genesis memory g = _genesis(n, nMin, nTarget, nMax);
        for (uint256 i = 0; i < n; ++i) {
            g.identities[i].rawWeight = raw[i];
        }
        g.module = address(poa);
        g.moduleCodeHash = address(poa).codehash;
        g.maxM = contMaxM;
        g.distNum = contDistNum;
        g.distDen = contDistDen;
        _deploy(g);
    }

    // ---- identities ----

    function _ownerOf(uint64 id) internal view returns (address) {
        return vr.ownerOf(id);
    }

    /// @dev Registers a fresh identity (not a member) with real proofs of possession.
    function _registerNew() internal returns (uint64 id) {
        Keys memory k = _freshKeys();
        address who = address(uint160(0xD000 + ++regCount));
        Registration memory r = _reg(
            k,
            string.concat("joiner-", vm.toString(regCount)),
            address(uint160(0xE000 + regCount)),
            0
        );
        bytes32 d = _regDigest(VRC.REGISTER_DOMAIN, who, 0, r);
        vm.prank(who);
        id = vr.register(r, _sig(k.rootPk, d), _sig(k.evmPk, d));
        keysOf[id] = k;
    }

    /// @dev Stages a new binding for `id` (fresh keys).
    function _stageBinding(uint64 id) internal returns (bytes32 ref) {
        Keys memory k = _freshKeys();
        IdentityView memory v = vr.identity(id);
        Registration memory r = _reg(
            k,
            string.concat("rot-", vm.toString(id), "-", vm.toString(keySeed)),
            v.current.payee,
            v.bindingNonce
        );
        bytes32 d = _regDigest(VRC.BINDING_DOMAIN, v.owner, id, r);
        vm.prank(v.owner);
        vr.proposeBinding(id, r, _sig(k.rootPk, d), _sig(k.evmPk, d));
        ref = vr.identity(id).stagedRef;
    }

    function _submit(uint64 id) internal {
        vm.prank(_ownerOf(id));
        poa.submitApplication(id);
    }

    function _action(uint64 a, uint64 id) internal returns (uint64 changeId) {
        changeId = _queueScheduled(VRC.K_MODULE_ACTION, abi.encode(address(poa), abi.encode(a, id)));
    }

    /// @dev Register, apply and admit a new joiner.
    function _admitNew() internal returns (uint64 id) {
        id = _registerNew();
        _submit(id);
        uint64 c = _action(A_ADMIT, id);
        assertEq(_changeState(c), VRC.CH_ACTIVE, "admit executed");
        assertEq(_st(id), ADMITTED);
    }

    function _st(uint64 id) internal view returns (uint8 s) {
        (s,) = poa.status(id);
    }

    // ---- elections ----

    /// @dev Elects at the next block past the epoch gap; returns the outcome and the reserved result id (zero unless Reserved).
    function _electPoa() internal returns (uint8 outcome, bytes32 rid) {
        _advance(VRC.MIN_EPOCH_GAP, 1);
        outcome = _elect();
        rid = vr.openOutput();
    }

    function _ids(Member[] memory ms) internal pure returns (uint64[] memory ids) {
        ids = new uint64[](ms.length);
        for (uint256 i = 0; i < ms.length; ++i) {
            ids[i] = ms[i].id;
        }
    }

    function _committeeIds() internal view returns (uint64[] memory) {
        return _ids(vr.committee());
    }

    function _outputIds(bytes32 rid) internal view returns (uint64[] memory) {
        return _ids(vr.output(rid).members);
    }

    function _eqIds(uint64[] memory a, uint64[] memory b) internal pure returns (bool) {
        if (a.length != b.length) return false;
        for (uint256 i = 0; i < a.length; ++i) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    function _seq(uint64 from, uint64 to) internal pure returns (uint64[] memory ids) {
        ids = new uint64[](to - from + 1);
        for (uint64 i = from; i <= to; ++i) {
            ids[i - from] = i;
        }
    }

    function _with(uint64[] memory xs, uint64 x) internal pure returns (uint64[] memory out) {
        out = new uint64[](xs.length + 1);
        uint256 k = 0;
        bool placed = false;
        for (uint256 i = 0; i < xs.length; ++i) {
            if (!placed && x < xs[i]) {
                out[k++] = x;
                placed = true;
            }
            out[k++] = xs[i];
        }
        if (!placed) out[k] = x;
    }

    function _minus(uint64[] memory xs, uint64 x) internal pure returns (uint64[] memory out) {
        out = new uint64[](xs.length - 1);
        uint256 k = 0;
        for (uint256 i = 0; i < xs.length; ++i) {
            if (xs[i] != x) out[k++] = xs[i];
        }
    }
}
