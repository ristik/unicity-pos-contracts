// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PoaBase} from "./poa/PoaBase.sol";
import {MockSeal, MockModule} from "./VRMocks.sol";
import {ValidatorRegistry} from "../../src/vr/ValidatorRegistry.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {VRRecord} from "../../src/vr/VRTypes.sol";
import {PoaElection} from "../../src/vr/poa/PoaElection.sol";
import {PoaComposerEngine} from "../../src/vr/poa/PoaComposer.sol";

/// @notice Generates the VR states the ureth hook test runs (design section 11, VT-02: "a ureth hook test running VR bytecode"; the
/// completion gate before the VR code hash is pinned). Every scenario deploys the real VR core and its three facets, the real PoA
/// module and composer, and the test modules at fixed genesis addresses on chain id 1337, sets the scenario up, then plays one EVM
/// block's hooks exactly as ureth calls them: `applyRootRecords(min(H, available))` and `elect(origin)` from SYSTEM_CALLER, with the
/// block's records, progress and UC time. The pre and post states are raw `vm.dumpState` output; `tools/vr_hook_state.py` folds them
/// into `test/vr/fixtures/vr-hook.json`, which ureth (`crates/unicity/execution/tests/vr_hook.rs`) loads into its genesis, runs through
/// its real block path against the real SealRegistry, and compares slot for slot.
///
///     VR_WRITE_HOOK_STATE=test/vr/fixtures/vr-hook-raw forge test --match-contract VRHookStateTest
///     python3 tools/vr_hook_state.py test/vr/fixtures/vr-hook-raw test/vr/fixtures/vr-hook.json
///
/// The SealRegistry here is the record-source stand-in (MockSeal); in ureth it is the real registry, whose `recordAt`, `recordCount`,
/// `progress` and `ucTime` must hand VR the same records and clock. Nothing is pushed to it before the block, so its log is the
/// block's import and VR's cursor starts at zero, as in a genesis whose first records the block imports.
contract VRHookStateTest is PoaBase {
    // ---- genesis addresses (VT-14 default; owner-questions.md "VT-02 ureth hook") ----
    address internal constant GOV_FACET_ADDR = address(uint160((uint256(0xff) << 152) | 0x04));
    address internal constant REPAIR_FACET_ADDR = address(uint160((uint256(0xff) << 152) | 0x05));
    address internal constant RECORDS_FACET_ADDR = address(uint160((uint256(0xff) << 152) | 0x06));
    address internal constant POA_ADDR = address(uint160((uint256(0xff) << 152) | 0x07));
    address internal constant COMPOSER_ADDR = address(uint160((uint256(0xff) << 152) | 0x08));
    // ---- test-only accounts ----
    address internal constant POA_NEXT_ADDR = address(uint160(0xc0de7));
    address internal constant MOCK_ADDR = address(uint160(0xc0de1));
    address internal constant MOCK_NEXT_ADDR = address(uint160(0xc0de2));
    address internal constant HOLDER_ADDR = address(uint160(0xc0de3));
    address internal constant HOLDER_NEXT_ADDR = address(uint160(0xc0de4));
    address internal constant GOVERNOR_NEXT_ADDR = address(uint160(0xc0de5));

    uint64 internal constant CHAIN_ID = 1337;
    /// @dev The identity of the root origin the ureth test block carries (`RootInputV2::origin_identity` of `input(1, 1, genesis)`);
    /// the Rust test asserts it.
    bytes32 internal constant ORIGIN =
        0xb1a70288ef0aefa92b9d12c38fcef6957ca94ddb29eee251d2afa7da67ac5b04;
    /// @dev The ureth block's number (its first block over the genesis).
    uint256 internal constant BLOCK_NUMBER = 1;

    // MockModule behaviours and steps (VRMocks.sol)
    uint8 internal constant M_REVERT = 1;
    uint8 internal constant M_BURN = 2;
    uint8 internal constant M_MALFORMED = 3;
    uint8 internal constant M_HUGE = 4;
    uint8 internal constant M_REENTER = 5;
    uint8 internal constant M_REENTER_BUBBLE = 6;
    uint8 internal constant M_GRIEF = 7;
    uint8 internal constant M_WRITE_THEN_REVERT = 8;
    uint8 internal constant M_RETURN_WORD = 10;
    uint8 internal constant S_ELECT = 1;
    uint8 internal constant S_OUTPUT = 2;
    uint8 internal constant S_RECORDS = 3;
    uint8 internal constant S_RESOLVED = 4;
    uint8 internal constant S_ATTACH = 5;

    string internal _name;
    uint32 internal _h;

    // =============================================================================================
    // the harness
    // =============================================================================================

    function _dir() internal view returns (string memory) {
        return vm.envOr("VR_WRITE_HOOK_STATE", string(""));
    }

    /// @dev The fixed-address deployment every scenario shares: the facets, the composer and the test module. Their runtimes are
    /// identical across scenarios (the facets' and the module's immutables are their own and VR's addresses).
    function _begin(string memory name) internal {
        _name = name;
        vm.chainId(CHAIN_ID);
        deployCodeTo("VRGovernanceFacet.sol:VRGovernanceFacet", GOV_FACET_ADDR);
        deployCodeTo("VRRepairFacet.sol:VRRepairFacet", REPAIR_FACET_ADDR);
        deployCodeTo("VRRecordsFacet.sol:VRRecordsFacet", RECORDS_FACET_ADDR);
        govFacet = GOV_FACET_ADDR;
        repairFacet = REPAIR_FACET_ADDR;
        recordsFacet = RECORDS_FACET_ADDR;
        deployCodeTo("PoaComposer.sol:PoaComposerEngine", COMPOSER_ADDR);
        engine = PoaComposerEngine(COMPOSER_ADDR);
        deployCodeTo(
            "VRMocks.sol:MockModule", abi.encode(keccak256("unicity.vr.mock-module")), MOCK_ADDR
        );
        module = MockModule(MOCK_ADDR);
        governor = address(this);
    }

    /// @dev A PoA generation (PoaBase's, at the genesis addresses): ids 1..n with unit raw weights, the real PoaElection at POA_ADDR.
    function _poaGenesis(uint256 n, uint32 nMin, uint32 nTarget, uint32 nMax) internal {
        MockSeal s = new MockSeal();
        vm.etch(VRC.SEAL_REGISTRY, address(s).code);
        seal = MockSeal(VRC.SEAL_REGISTRY);
        seal.setClock(progress, ucTime);
        deployCodeTo(
            "PoaElection.sol:PoaElection",
            abi.encode(VR_ADDR, COMPOSER_ADDR, _seq(1, uint64(n))),
            POA_ADDR
        );
        poa = PoaElection(POA_ADDR);
        ValidatorRegistry.Genesis memory g = _genesis(n, nMin, nTarget, nMax);
        g.module = POA_ADDR;
        g.moduleCodeHash = POA_ADDR.codehash;
        g.maxM = contMaxM;
        g.distNum = contDistNum;
        g.distDen = contDistDen;
        _deploy(g);
    }

    /// @dev A generation whose active module is the configurable MockModule at MOCK_ADDR.
    function _mockGenesis(uint256 n, uint32 nMin, uint32 nTarget, uint32 nMax) internal {
        _setUpVR(n, nMin, nTarget, nMax);
    }

    function _mockAt(address where, bytes32 tag) internal returns (MockModule m) {
        deployCodeTo("VRMocks.sol:MockModule", abi.encode(tag), where);
        m = MockModule(where);
        m.setVR(VR_ADDR);
    }

    /// @dev Opens the block: its clock (one progress unit and one second after the setup) and the ureth block number. Records pushed
    /// after this are the block's import.
    function _openBlock() internal {
        assertEq(seal.recordCount(), 0, "the block's import is the registry's whole log");
        assertEq(vr.recordCursor(), 0);
        _advance(1, 1);
        vm.roll(BLOCK_NUMBER);
    }

    function _touch() internal view returns (uint256 t) {
        address[11] memory all = [
            VR_ADDR,
            GOV_FACET_ADDR,
            REPAIR_FACET_ADDR,
            RECORDS_FACET_ADDR,
            POA_ADDR,
            COMPOSER_ADDR,
            POA_NEXT_ADDR,
            MOCK_ADDR,
            MOCK_NEXT_ADDR,
            HOLDER_ADDR,
            HOLDER_NEXT_ADDR
        ];
        for (uint256 i = 0; i < all.length; ++i) {
            t += all[i].balance + all[i].code.length;
        }
        t += GOVERNOR_NEXT_ADDR.code.length;
    }

    /// @dev The block's hooks as ureth runs them (hook.rs `run_hooks`): the cursor gate, exactly one `applyRootRecords(min(H,
    /// available))` when records are available, then `elect(origin)`. Dumps the state before and after and writes the scenario's meta.
    function _runBlock(uint32 h) internal returns (uint8 outcome) {
        string memory dir = _dir();
        _h = h;
        assertGt(_touch(), 0);
        if (bytes(dir).length != 0) {
            vm.dumpState(string.concat(dir, "/", _name, ".pre.json"));
        }
        uint64 count = seal.recordCount();
        uint64 cursor = vr.recordCursor();
        uint64 n = count - cursor;
        if (n > h) n = h;
        if (n != 0) {
            vm.prank(VRC.SYSTEM_CALLER);
            vr.applyRootRecords(uint32(n));
            assertEq(
                vr.recordCursor(), cursor + n, "the cursor advances by exactly the applied amount"
            );
        }
        vm.prank(VRC.SYSTEM_CALLER);
        outcome = vr.elect(ORIGIN);
        assertLe(outcome, 3);
        assertGt(_touch(), 0);
        if (bytes(dir).length != 0) {
            vm.dumpState(string.concat(dir, "/", _name, ".post.json"));
            _meta(dir, outcome, n);
        }
    }

    function _meta(string memory dir, uint8 outcome, uint64 applied) internal {
        string memory m = "meta";
        vm.serializeString(m, "scenario", _name);
        vm.serializeUint(m, "chainId", block.chainid);
        vm.serializeBytes32(m, "origin", ORIGIN);
        vm.serializeUint(m, "blockNumber", block.number);
        vm.serializeUint(m, "h", _h);
        vm.serializeUint(m, "progress", seal.progress());
        vm.serializeUint(m, "ucTime", seal.ucTime());
        vm.serializeUint(m, "applied", applied);
        vm.serializeUint(m, "outcome", outcome);
        vm.serializeUint(m, "health", vr.health());
        vm.serializeUint(m, "cursor", vr.recordCursor());
        vm.serializeBytes32(m, "openOutput", vr.openOutput());
        vm.serializeBytes32(m, "lastAcked", vr.lastAcked());
        vm.serializeAddress(m, "activeModule", vr.activeModule().module);
        vm.serializeUint(m, "recordCount", seal.recordCount());
        string memory body = vm.serializeString(m, "records", _records());
        vm.writeJson(body, string.concat(dir, "/", _name, ".meta.json"));
    }

    function _records() internal returns (string memory out) {
        uint64 n = seal.recordCount();
        string memory arr = string.concat("records-", _name);
        out = "{}";
        for (uint64 i = 0; i < n; ++i) {
            VRRecord memory r = seal.recordAt(i);
            string memory k = string.concat("r", vm.toString(i));
            vm.serializeUint(k, "index", r.index);
            vm.serializeBytes32(k, "recordId", r.recordID);
            vm.serializeBytes32(k, "predecessor", r.predecessor);
            vm.serializeUint(k, "kind", r.kind);
            vm.serializeUint(k, "progress", r.progress);
            vm.serializeUint(k, "ucTime", r.ucTime);
            string memory last = vm.serializeBytes(k, "data", r.data);
            out = vm.serializeString(arr, k, last);
        }
    }

    // ---- records (VRBase's helpers, plus the holder and foreign kinds) ----

    function _recHolderRetirement(uint8 holder, uint64 id, uint64 gen) internal {
        seal.push(
            VRC.REC_HOLDER_RETIREMENT,
            abi.encode(uint256(holder), uint256(id), uint256(gen), keccak256(abi.encode(id, gen)))
        );
    }

    function _recClosure(bytes32 assignment) internal {
        seal.push(
            VRC.REC_CLOSURE,
            abi.encode(
                assignment,
                uint256(1),
                keccak256("h-record"),
                keccak256("terminal"),
                keccak256("exposure"),
                keccak256("key-history")
            )
        );
    }

    // ---- shared setups ----

    /// @dev A MockModule generation of five whose output R is reserved and published (ready in the same call), with a fee change
    /// bound to it; the block imports Ack(R) and Boundary(R).
    function _mockWithPublishedOutput() internal returns (bytes32 rid) {
        _mockGenesis(5, 1, 5, 16);
        _queueScheduled(VRC.K_FEE_PARAMS, abi.encode(uint64(2_000_000), uint64(8), address(0xFEE)));
        rid = _rid("R");
        assertEq(_moduleReserve(rid, true), VRC.ELECT_RESERVED);
        assertEq(_state(rid), VRC.OUT_PUBLISHED);
    }

    function _ackBoundary(bytes32 rid) internal {
        _recAck(rid);
        _recBoundary(rid, _nextEpoch(), false, 0);
    }

    // =============================================================================================
    // the committed fixture is the one these sources generate
    // =============================================================================================

    /// @dev The runtimes in `test/vr/fixtures/vr-hook.json` are the ones this tree builds at the genesis addresses: a change to VR, a
    /// facet, PoA or the composer fails here until the fixture is regenerated (and ureth's copy with it).
    function test_fixtureMatchesTheBuiltRuntimes() public {
        _begin("fixture-check");
        _poaGenesis(5, 1, 6, 16);
        string memory f = vm.readFile("test/vr/fixtures/vr-hook.json");
        string[6] memory roles =
            ["vr", "governanceFacet", "repairFacet", "recordsFacet", "poa", "composer"];
        address[6] memory where = [
            VR_ADDR, GOV_FACET_ADDR, REPAIR_FACET_ADDR, RECORDS_FACET_ADDR, POA_ADDR, COMPOSER_ADDR
        ];
        for (uint256 i = 0; i < roles.length; ++i) {
            string memory key = string.concat(".accounts.", roles[i]);
            assertEq(vm.parseJsonAddress(f, string.concat(key, ".address")), where[i], roles[i]);
            assertEq(
                vm.parseJsonBytes32(f, string.concat(key, ".codeHash")), where[i].codehash, roles[i]
            );
            emit log_named_bytes32(roles[i], where[i].codehash);
        }
    }

    // =============================================================================================
    // real PoA module
    // =============================================================================================

    /// @dev PoA, five members and an admitted joiner: the hook's election reserves and publishes the six-member output.
    function test_poaElect() public {
        _begin("poa-elect");
        _poaGenesis(5, 1, 6, 16);
        uint64 j = _admitNew();
        _advance(VRC.MIN_EPOCH_GAP, 1);
        _openBlock();
        assertEq(_runBlock(32), VRC.ELECT_RESERVED);
        assertEq(_st(j), JOINING);
        assertEq(vr.output(vr.openOutput()).members.length, 6);
    }

    /// @dev PoA, 16 members all with a staged binding: the 16-member output (the output-bound elect of PoaGas.t.sol).
    function test_poaElect16() public {
        _begin("poa-elect-16");
        _poaGenesis(16, 1, 16, 16);
        for (uint64 id = 1; id <= 16; ++id) {
            _stageBinding(id);
        }
        _advance(VRC.MIN_EPOCH_GAP, 1);
        _openBlock();
        assertEq(_runBlock(32), VRC.ELECT_RESERVED);
        assertEq(vr.output(vr.openOutput()).members.length, 16);
    }

    /// @dev PoA's search-bound elect (PoaGas.t.sol): 16 staged members, two joiners, four ForceRemoves and a continuity budget nothing
    /// passes, so all 64 trials run and the answer is NoCandidate (not a fault).
    function test_poaElectSearch() public {
        _begin("poa-elect-search");
        contMaxM = 1;
        contDistNum = 1;
        contDistDen = 100;
        _poaGenesis(16, 1, 16, 16);
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
        _openBlock();
        assertEq(_runBlock(32), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    /// @dev The pointer switch through the hook: PoA -> a fresh PoA instance, with a Removing member leaving and a fee change bound
    /// to the switching output. The block's Ack and Boundary install the output, activate the fee change, deliver both records to the
    /// old module, detach it and attach the new one; the new module's election in the same block is not due.
    function test_poaSwitch() public {
        _begin("poa-switch");
        _poaGenesis(5, 1, 6, 16);
        deployCodeTo(
            "PoaElection.sol:PoaElection",
            abi.encode(VR_ADDR, COMPOSER_ADDR, new uint64[](0)),
            POA_NEXT_ADDR
        );
        assertEq(POA_NEXT_ADDR.codehash, POA_ADDR.codehash, "one runtime, two instances");
        uint64 sw = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(POA_NEXT_ADDR, POA_NEXT_ADDR.codehash, bytes(""))
        );
        uint64 fee = _queueScheduled(
            VRC.K_FEE_PARAMS, abi.encode(uint64(2_000_000), uint64(8), address(0xFEE))
        );
        _action(A_REMOVE, 2);
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(_changeState(sw), VRC.CH_BOUND);
        assertEq(_changeState(fee), VRC.CH_BOUND);
        _openBlock();
        _ackBoundary(rid);
        _runBlock(32);
        assertEq(vr.activeModule().module, POA_NEXT_ADDR);
        assertEq(_changeState(sw), VRC.CH_ACTIVE);
        assertEq(_changeState(fee), VRC.CH_ACTIVE);
        assertEq(_st(2), EXITED, "the old module saw its Boundary before the detach");
        assertTrue(_eqIds(PoaElection(POA_NEXT_ADDR).members(), _minus(_seq(1, 5), 2)));
        assertEq(vr.health(), VRC.HEALTHY);
    }

    /// @dev Kind 7 with the real PoA: the expiry rejection of a six-member output whose ready bitmap lacks the joiner, then its
    /// closure. The output is Rejected then Closed, its bound work released, and the joiner parked.
    function test_poaRejected() public {
        _begin("poa-rejected");
        _poaGenesis(5, 1, 6, 16);
        uint64 j = _admitNew();
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        _openBlock();
        seal.push(
            VRC.REC_OUTPUT_REJECTED,
            abi.encode(rid, uint256(VRC.REJ_EXPIRED), uint256(0), uint256(0x1f))
        );
        _recClosed(rid);
        _runBlock(32);
        assertEq(_state(rid), VRC.OUT_CLOSED);
        assertEq(_st(j), PARKED);
    }

    // =============================================================================================
    // record kinds 6 to 8 with a liability holder
    // =============================================================================================

    /// @dev A holder generation (the module is LIABILITY_HOLDER, holder 0 from genesis): one batch with Ack, Boundary, two
    /// HolderRetirements and a foreign Closure. Every record applies, the retirements are marked and the cursor advances by five.
    function test_holderBatch() public {
        _begin("holder-batch");
        deployCodeTo("VRMocks.sol:MockHolder", HOLDER_ADDR);
        module.setCaps(VRC.CAP_LIABILITY_HOLDER);
        module.setHolder(HOLDER_ADDR);
        bytes32 rid = _mockWithPublishedOutput();
        assertEq(vr.holderCount(), 1);
        _openBlock();
        _ackBoundary(rid);
        _recHolderRetirement(0, 2, 1);
        _recClosure(keccak256("a foreign assignment"));
        _recHolderRetirement(0, 3, 1);
        _runBlock(32);
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
        assertTrue(vr.retired(0, 2, 1));
        assertTrue(vr.retired(0, 3, 1));
        assertEq(vr.health(), VRC.HEALTHY);
    }

    /// @dev The worst Boundary (VRGas.t.sol): 16 members installed, 15 changes activated, the pointer switched with adoption, detach
    /// and attach, a holder entry allocated, and every callback burning to its cap.
    function test_boundaryWorst() public {
        _begin("boundary-worst");
        _mockGenesis(16, 1, 16, 16);
        MockModule next = _mockAt(MOCK_NEXT_ADDR, keccak256("unicity.vr.gas-next"));
        deployCodeTo("VRMocks.sol:MockHolder", HOLDER_NEXT_ADDR);
        next.setCaps(VRC.CAP_ADOPTION_CHECK | VRC.CAP_LIABILITY_HOLDER);
        next.setHolder(HOLDER_NEXT_ADDR);
        _bindSixteen(address(next));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        assertEq(vr.output(r).changes.length, 16);
        module.setGriefLeave(20_000);
        module.setMode(S_RECORDS, M_GRIEF);
        module.setMode(S_RESOLVED, M_GRIEF);
        module.setMode(6, M_GRIEF); // detach
        next.setMode(S_ATTACH, M_GRIEF);
        next.setMode(8, M_GRIEF); // adoptionReady
        next.setGriefLeave(60_000);
        _openBlock();
        _ackBoundary(r);
        _runBlock(32);
        assertEq(vr.activeModule().module, MOCK_NEXT_ADDR, "switched");
        assertEq(vr.committee().length, 16);
        assertEq(vr.holderCount(), 1);
        assertEq(vr.health(), VRC.HEALTHY, "every callback answered at its cap");
    }

    function _bindSixteen(address nextModule) internal {
        uint64[] memory ids = new uint64[](16);
        uint256 k = 0;
        for (uint256 i = 0; i < 8; ++i) {
            ids[k++] = _queue(
                VRC.K_UPDATE_PARTITION,
                abi.encode(
                    uint32(7 + i),
                    abi.encodePacked(uint8(0x80), uint8(i)),
                    keccak256(abi.encode(i)),
                    new bytes(256)
                )
            );
        }
        ids[k++] =
            _queue(VRC.K_SET_MODULE, abi.encode(nextModule, nextModule.codehash, bytes("init")));
        deployCodeTo("VRMocks.sol:MockHolder", GOVERNOR_NEXT_ADDR);
        ids[k++] =
            _queue(VRC.K_SET_GOVERNOR, abi.encode(GOVERNOR_NEXT_ADDR, GOVERNOR_NEXT_ADDR.codehash));
        ids[k++] = _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 16, 16));
        ids[k++] =
            _queue(VRC.K_FEE_PARAMS, abi.encode(uint64(2_000_000), uint64(8), address(0xFEE)));
        uint64 e = vr.config().knownRootEpoch;
        for (uint256 i = 0; i < 4; ++i) {
            ids[k++] = _queue(
                VRC.K_SCHEDULE_ACTIVATION,
                abi.encode(
                    keccak256(abi.encode("unicity.rule/gas", i)),
                    keccak256("rel"),
                    e + 3,
                    uint64(ucTime + 3600),
                    "gas"
                )
            );
        }
        _passDelays();
        for (uint256 i = 0; i < 16; ++i) {
            vr.execute(ids[i]);
        }
    }

    // =============================================================================================
    // native repair
    // =============================================================================================

    /// @dev The worst native elect (VRGas.t.sol): 16 members, four ForceRemove candidates through the full trial search and a limits
    /// change, the module Faulted by a reverting elect in an earlier block.
    function test_nativeWorst() public {
        _begin("native-worst");
        _mockGenesis(16, 1, 16, 16);
        for (uint64 i = 0; i < 4; ++i) {
            _queue(VRC.K_FORCE_REMOVE, abi.encode(uint64(3 + 4 * i)));
        }
        _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 13, 16));
        _passDelays();
        for (uint64 i = 1; i <= 5; ++i) {
            vr.execute(i);
        }
        module.setMode(S_ELECT, M_REVERT);
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
        _advance(VRC.MIN_EPOCH_GAP, 1);
        _openBlock();
        assertEq(_runBlock(32), VRC.ELECT_RESERVED);
        assertEq(vr.output(vr.openOutput()).members.length, 13);
        assertTrue(vr.output(vr.openOutput()).native);
    }

    // =============================================================================================
    // containment at the hook: a misbehaving module never invalidates the block
    // =============================================================================================

    /// @dev The module's elect misbehaves while it would reserve a ready output.
    function _electVariant(string memory name, uint8 mode) internal returns (uint8 outcome) {
        _begin(name);
        _mockGenesis(5, 1, 5, 16);
        module.setElect(VRC.ELECT_RESERVED, true, _rid("R"));
        module.setMode(S_ELECT, mode);
        _openBlock();
        outcome = _runBlock(32);
    }

    function test_electRevert() public {
        assertEq(_electVariant("elect-revert", M_REVERT), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_electOutOfGas() public {
        assertEq(_electVariant("elect-oog", M_BURN), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_electMalformed() public {
        assertEq(_electVariant("elect-malformed", M_MALFORMED), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_electHugeReturn() public {
        assertEq(_electVariant("elect-huge", M_HUGE), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_electWriteThenRevert() public {
        assertEq(_electVariant("elect-write-revert", M_WRITE_THEN_REVERT), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
        assertEq(module.sideEffect(), 0, "the module's write rolled back with its frame");
        assertEq(vr.openOutput(), bytes32(0));
    }

    /// @dev The module re-enters every VR mutator (each refused), then answers: the reservation stands and nothing faults.
    function test_electReenter() public {
        assertEq(_electVariant("elect-reenter", M_REENTER), VRC.ELECT_RESERVED);
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(module.reentryRefusals(), module.reentryAttempts());
        assertEq(module.reentryAttempts(), 12);
    }

    /// @dev The module re-enters `publish` and lets the revert bubble: a fault.
    function test_electReenterBubble() public {
        assertEq(_electVariant("elect-reenter-bubble", M_REENTER_BUBBLE), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
    }

    /// @dev The module burns its elect cap down to 20,000 and then answers: VR's own work still fits.
    function test_electGrief() public {
        assertEq(_electVariant("elect-grief", M_GRIEF), VRC.ELECT_RESERVED);
        assertEq(vr.health(), VRC.HEALTHY);
    }

    /// @dev The module reserves ready, then its outputOf misbehaves (or serves an output VR rejects): the reservation rolls back and the
    /// module is Faulted.
    function _outputVariant(string memory name, uint8 mode, bool wrongPredecessor) internal {
        _begin(name);
        _mockGenesis(5, 1, 5, 16);
        module.setElect(VRC.ELECT_RESERVED, true, _rid("R"));
        module.setMode(S_OUTPUT, mode);
        if (wrongPredecessor) module.setOverrides(0, keccak256("not the predecessor"));
        _openBlock();
        assertEq(_runBlock(32), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
        assertEq(vr.openOutput(), bytes32(0));
        assertEq(_state(_rid("R")), VRC.OUT_NONE);
    }

    function test_outputMalformed() public {
        _outputVariant("output-malformed", M_MALFORMED, false);
    }

    function test_outputHuge() public {
        _outputVariant("output-huge", M_HUGE, false);
    }

    function test_outputInvalid() public {
        _outputVariant("output-invalid", 0, true);
    }

    /// @dev The block's Ack and Boundary of the module's published output, with one callback misbehaving: the records still apply,
    /// the cursor advances by two and the module is Faulted (or, for detach, which never faults, nothing).
    function _recordsVariant(string memory name, uint8 step, uint8 mode) internal {
        _begin(name);
        bytes32 rid = _mockWithPublishedOutput();
        module.setMode(step, mode);
        _openBlock();
        _ackBoundary(rid);
        _runBlock(32);
        assertEq(vr.recordCursor(), 2);
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_recordsRevert() public {
        _recordsVariant("records-revert", S_RECORDS, M_REVERT);
    }

    function test_recordsOutOfGas() public {
        _recordsVariant("records-oog", S_RECORDS, M_BURN);
    }

    function test_recordsHugeReturn() public {
        _recordsVariant("records-huge", S_RECORDS, M_HUGE);
    }

    function test_recordsReturnWord() public {
        _recordsVariant("records-word", S_RECORDS, M_RETURN_WORD);
    }

    function test_recordsReenterBubble() public {
        _recordsVariant("records-reenter", S_RECORDS, M_REENTER_BUBBLE);
    }

    function test_resolvedRevert() public {
        _recordsVariant("resolved-revert", S_RESOLVED, M_REVERT);
    }

    function test_resolvedOutOfGas() public {
        _recordsVariant("resolved-oog", S_RESOLVED, M_BURN);
    }

    /// @dev A switch whose new module's attach reverts: the pointer moves, the attach fails, the module is Faulted and no holder entry
    /// is consumed; the block stays valid.
    function test_attachRevert() public {
        _begin("attach-revert");
        _mockGenesis(5, 1, 5, 16);
        MockModule next = _mockAt(MOCK_NEXT_ADDR, keccak256("unicity.vr.next"));
        next.setMode(S_ATTACH, M_REVERT);
        uint64 sw = _queueScheduled(
            VRC.K_SET_MODULE, abi.encode(MOCK_NEXT_ADDR, MOCK_NEXT_ADDR.codehash, bytes(""))
        );
        bytes32 rid = _rid("R");
        assertEq(_moduleReserve(rid, true), VRC.ELECT_RESERVED);
        assertEq(_changeState(sw), VRC.CH_BOUND);
        _openBlock();
        _ackBoundary(rid);
        _runBlock(32);
        assertEq(vr.activeModule().module, MOCK_NEXT_ADDR);
        assertEq(vr.health(), VRC.FAULTED);
        assertEq(vr.holderCount(), 0);
    }
}
