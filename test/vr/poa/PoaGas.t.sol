// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PoaBase} from "./PoaBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {PoaElection} from "../../../src/vr/poa/PoaElection.sol";

/// @notice The PoA module's worst-case step costs, measured through VR (design 3.3.4: the pin is the compound measurement x 5/4). The
/// module's `gasBounds` must cover each measurement with that margin and stay below VR's immutable caps. Run with -vv for the figures.
///
/// - elect, search-bound: 16 members, all with a staged binding, 4 ForceRemoves, 2 joiners, a continuity budget nothing passes
///   (maxM 1, D <= 1/100): a pool of 6 and all 64 trials evaluated, NoCandidate;
/// - elect, output-bound: 16 members all staged, an output of 16 with two replacements, packed and served;
/// - onRecords: one Boundary (committee read and a 16-member sync) and a 32-record batch of foreign records;
/// - attach: 16 members and a full joiner queue;
/// - onGovernance: Admit into an almost full queue.
contract PoaGasTest is PoaBase {
    function _ctx(uint32 dueWork, uint16 fr) internal view returns (bytes memory) {
        VRCodec.Context memory c;
        c.origin = keccak256("gas");
        c.progress = progress;
        c.ucTime = ucTime;
        c.knownRootEpoch = vr.config().knownRootEpoch;
        c.lastAcked = vr.lastAcked();
        c.nMin = vr.config().nMin;
        c.nTarget = vr.config().nTarget;
        c.nMax = vr.config().nMax;
        c.dueWork = dueWork;
        c.forceRemoved = fr;
        return VRCodec.encodeContext(c);
    }

    function _bound(uint256 i) internal view returns (uint64 b) {
        (uint64 e, uint64 o, uint64 r, uint64 rs, uint64 a, uint64 d, uint64 g, uint64 ad) =
            poa.gasBounds();
        uint64[8] memory all = [e, o, r, rs, a, d, g, ad];
        b = all[i];
    }

    /// @dev Registers and admits `k` joiners with one delay (so the work deadline does not lapse), optionally removing 4 and 9 too.
    function _admitBatch(uint256 k, bool removeTwo) internal returns (uint64[] memory ids) {
        ids = new uint64[](k);
        for (uint256 i = 0; i < k; ++i) {
            ids[i] = _registerNew();
            _submit(ids[i]);
            _queue(VRC.K_MODULE_ACTION, abi.encode(address(poa), abi.encode(A_ADMIT, ids[i])));
        }
        if (removeTwo) {
            _queue(VRC.K_MODULE_ACTION, abi.encode(address(poa), abi.encode(A_REMOVE, uint64(4))));
            _queue(VRC.K_MODULE_ACTION, abi.encode(address(poa), abi.encode(A_REMOVE, uint64(9))));
        }
        _passDelays();
        uint64[] memory p = vr.pendingChanges();
        for (uint256 i = 0; i < p.length; ++i) {
            vr.execute(p[i]);
        }
        for (uint256 i = 0; i < k; ++i) {
            assertEq(_st(ids[i]), ADMITTED);
        }
    }

    function _cool() internal {
        vm.cool(VR_ADDR);
        vm.cool(address(poa));
        vm.cool(VRC.SEAL_REGISTRY);
        vm.cool(govFacet);
    }

    function _check(string memory what, uint256 used, uint256 boundIndex) internal {
        emit log_named_uint(what, used);
        assertLe(
            used * 5 / 4, _bound(boundIndex), string.concat(what, ": bound below measured x 5/4")
        );
    }

    function test_gasElectSearchBound() public {
        contMaxM = 1;
        contDistNum = 1;
        contDistDen = 100;
        _setUpPoa(16, 1, 16, 16);
        for (uint64 id = 1; id <= 16; ++id) {
            _stageBinding(id);
        }
        _admitNew();
        _admitNew();
        uint64[4] memory fr = [uint64(3), 6, 9, 12];
        for (uint256 i = 0; i < 4; ++i) {
            _queue(VRC.K_FORCE_REMOVE, abi.encode(fr[i]));
        }
        _passDelays();
        uint64[] memory p = vr.pendingChanges();
        for (uint256 i = 0; i < p.length; ++i) {
            vr.execute(p[i]);
        }
        _advance(VRC.MIN_EPOCH_GAP, 1);
        bytes memory ctx = _ctx(0, uint16((1 << 2) | (1 << 5) | (1 << 8) | (1 << 11)));
        _cool();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        bytes memory ret = poa.elect(ctx);
        uint256 used = g - gasleft();
        (, uint8 outcome,,) = VRCodec.decodeElect(abi.encode(ret));
        assertEq(outcome, VRC.ELECT_NO_CANDIDATE, "every trial fails");
        _check("module elect, 64 trials, NoCandidate", used, 0);
        // the same through VR's hook (VR's gate, watchdogs, context and the contained step)
        g = gasleft();
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE);
        emit log_named_uint("VR.elect, module path, NoCandidate", g - gasleft());
        assertEq(vr.health(), VRC.HEALTHY);
    }

    /// @dev The search and the output together: a generous budget (maxM 8, D <= 1) where the last trial (all six changes: 2
    /// removals, 2 replacements, 2 joiners) ranks first, so the search evaluates trial after trial and then composes 16 members.
    function test_gasElectSearchThenOutput() public {
        contMaxM = 8;
        contDistNum = 1;
        contDistDen = 1;
        _setUpPoa(16, 1, 16, 16);
        for (uint64 id = 1; id <= 16; ++id) {
            _stageBinding(id);
        }
        uint64[] memory js = _admitBatch(2, true);
        _advance(VRC.MIN_EPOCH_GAP, 1);
        bytes memory ctx = _ctx(0, 0);
        _cool();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        bytes memory ret = poa.elect(ctx);
        uint256 used = g - gasleft();
        (, uint8 outcome,,) = VRCodec.decodeElect(abi.encode(ret));
        assertEq(outcome, VRC.ELECT_RESERVED);
        assertEq(_st(4), LEAVING);
        assertEq(_st(9), LEAVING);
        assertEq(_st(js[0]), JOINING);
        assertEq(_st(js[1]), JOINING);
        _check("module elect, search then a 16-member output", used, 0);
    }

    function test_gasElectOutputBound() public {
        _setUpPoa(16, 1, 16, 16);
        for (uint64 id = 1; id <= 16; ++id) {
            _stageBinding(id);
        }
        _advance(VRC.MIN_EPOCH_GAP, 1);
        bytes memory ctx = _ctx(0, 0);
        _cool();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        bytes memory ret = poa.elect(ctx);
        uint256 used = g - gasleft();
        (, uint8 outcome,, bytes32 rid) = VRCodec.decodeElect(abi.encode(ret));
        assertEq(outcome, VRC.ELECT_RESERVED);
        _check("module elect, 16-member output", used, 0);
        assertTrue(rid != 0);
        // through VR: the module's output validated, bound and published (the direct call advanced only the module's counter)
        _cool();
        g = gasleft();
        assertEq(_elect(), VRC.ELECT_RESERVED);
        emit log_named_uint("VR.elect, module path, 16-member output published", g - gasleft());
        assertEq(vr.output(vr.openOutput()).members.length, 16);
    }

    function test_gasRecords() public {
        // a 2-for-2 swap at 16 (3 * 2 < 16, M = 4, D = 1/4) with a full queue whose other 28 entries are Removing non-members: the
        // Boundary moves 4 member states and exits 28 queue entries
        _setUpPoa(16, 1, 16, 16);
        uint64[] memory js = _admitBatch(30, false);
        for (uint256 i = 2; i < 30; ++i) {
            _queue(VRC.K_MODULE_ACTION, abi.encode(address(poa), abi.encode(A_REMOVE, js[i])));
        }
        _queue(VRC.K_MODULE_ACTION, abi.encode(address(poa), abi.encode(A_REMOVE, uint64(4))));
        _queue(VRC.K_MODULE_ACTION, abi.encode(address(poa), abi.encode(A_REMOVE, uint64(9))));
        _passDelays();
        uint64[] memory pend = vr.pendingChanges();
        for (uint256 i = 0; i < pend.length; ++i) {
            vr.execute(pend[i]);
        }
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(vr.output(rid).members.length, 16);
        _recAck(rid);
        _recBoundary(rid, _nextEpoch(), false, 0);
        uint64 from = seal.recordCount() - 2;
        // VR applies the batch while the module's onRecords is stubbed; then the module reads the same two records, measured cold
        vm.mockCall(address(poa), abi.encodeWithSelector(PoaElection.onRecords.selector), "");
        _applyAll();
        vm.clearMockedCalls();
        _cool();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        poa.onRecords(from, 2);
        uint256 used = g - gasleft();
        emit log_named_uint(
            "module onRecords, Ack + Boundary (16 members, 2 in, 2 out, 28 queue exits)", used
        );
        assertLe(used * 5 / 4, uint256(_bound(2)) * 2, "the two-record cap");
        assertLe(used * 5 / 4, uint256(_bound(2)), "the Boundary alone fits one record's bound");
        assertEq(_st(4), EXITED);
        assertEq(_st(9), EXITED);
        assertEq(_st(js[0]), ACTIVE);
        assertEq(_st(js[29]), EXITED);
        assertEq(poa.queue().length, 0);
        // 32 foreign records (Closures) in one batch
        from = seal.recordCount();
        for (uint256 i = 0; i < 32; ++i) {
            seal.push(
                VRC.REC_CLOSURE,
                abi.encode(
                    keccak256(abi.encode(i)),
                    uint256(1),
                    keccak256("h"),
                    keccak256("t"),
                    keccak256("e"),
                    keccak256("k")
                )
            );
        }
        vm.mockCall(address(poa), abi.encodeWithSelector(PoaElection.onRecords.selector), "");
        _applyAll();
        vm.clearMockedCalls();
        _cool();
        vm.prank(VR_ADDR);
        g = gasleft();
        poa.onRecords(from, 32);
        used = g - gasleft();
        emit log_named_uint("module onRecords, 32 foreign records", used);
        assertLe(used * 5 / 4, uint256(_bound(2)) * 32, "per-record bound");
    }

    function test_gasAttachAndGovernance() public {
        _setUpPoa(16, 1, 16, 16);
        _admitBatch(31, false);
        uint64 id = _registerNew();
        _submit(id);
        _cool();
        vm.prank(VR_ADDR);
        uint256 g = gasleft();
        poa.onGovernance(abi.encode(A_ADMIT, id));
        _check("module onGovernance, Admit into a queue of 31", g - gasleft(), 6);
        // attach: a fresh module instance over the 16-member committee
        PoaElection fresh = new PoaElection(VR_ADDR, engine, new uint64[](0));
        VRCodec.AttachContext memory a;
        a.lastAcked = vr.lastAcked();
        a.knownRootEpoch = 4;
        a.progress = progress;
        a.ucTime = ucTime;
        a.identityCount = 48;
        a.namespace = VR_ADDR;
        a.previousModule = address(poa);
        a.previousTag = POA_TAG;
        a.holderIndex = VRC.NO_HOLDER;
        a.committee = vr.committee();
        a.initData = "";
        bytes memory ctx = VRCodec.encodeAttachContext(a);
        _cool();
        vm.cool(address(fresh));
        vm.prank(VR_ADDR);
        g = gasleft();
        fresh.attach(ctx);
        _check("module attach, 16 members", g - gasleft(), 4);
        // and the same old module re-attached with its full queue (Joining entries returned)
        _cool();
        vm.prank(VR_ADDR);
        g = gasleft();
        poa.attach(ctx);
        _check("module attach, 16 members and a queue of 32", g - gasleft(), 4);
    }
}
