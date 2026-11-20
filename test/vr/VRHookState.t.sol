// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PoaBase} from "./poa/PoaBase.sol";
import {MockSeal, MockModule} from "./VRMocks.sol";
import {ValidatorRegistry} from "../../src/vr/ValidatorRegistry.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {VRRecord, IVR} from "../../src/vr/VRTypes.sol";
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
///     rm -rf test/vr/fixtures/vr-hook-raw && mkdir -p test/vr/fixtures/vr-hook-raw
///     VR_WRITE_HOOK_STATE=test/vr/fixtures/vr-hook-raw forge test --match-contract VRHookStateTest
///     python3 tools/vr_hook_state.py test/vr/fixtures/vr-hook-raw test/vr/fixtures/vr-hook.json
///
/// The SealRegistry here is the record-source stand-in (MockSeal); in ureth it is the real registry, whose `recordAt`, `recordCount`,
/// `progress` and `ucTime` must hand VR the same records and clock. ureth's block imports the whole log; records a scenario pushed and
/// applied before the block (an Ack delivered a block before its Boundary) are imported too and VR's cursor already covers them.
///
/// A scenario may also carry public transactions that follow the hooks in the same block (`_publicTx`); forge runs them as calls and
/// ureth as signed transactions, and the state after the hooks alone is dumped as well.
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
    address internal constant DRIVER_ADDR = address(uint160(0xc0de6));

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

    uint8 internal constant M_OVERSIZE = 11;
    uint8 internal constant S_DETACH = 6;
    uint8 internal constant S_ADOPT = 8;

    /// @dev VR's immutable per-call caps (src/vr/VRShared.sol): a module at these bounds is the most VR accepts.
    uint64 internal constant CAP_ELECT = 4_000_000;
    uint64 internal constant CAP_OUTPUT = 1_000_000;
    uint64 internal constant CAP_RECORD = 1_500_000;
    uint64 internal constant CAP_RESOLVED = 500_000;
    uint64 internal constant CAP_ATTACH = 3_000_000;
    uint64 internal constant CAP_DETACH = 500_000;
    uint64 internal constant CAP_GOV = 1_000_000;
    uint64 internal constant CAP_ADOPT = 1_000_000;

    struct PublicTx {
        address to;
        bytes data;
        uint64 gasLimit; // the ureth transaction's limit; forge forwards it less the intrinsic cost
        bool success;
    }

    string internal _name;
    uint32 internal _h;
    PublicTx[] internal _txs;

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
        assertLe(seal.recordCount(), 32, "ureth imports the registry's whole log in one block");
        assertEq(vr.recordCursor(), seal.recordCount(), "VR is caught up when the block opens");
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
        t += GOVERNOR_NEXT_ADDR.code.length + DRIVER_ADDR.code.length;
    }

    /// @dev A public transaction after the block's hooks: `gasLimit` is the ureth transaction's limit, forge forwards it less the
    /// intrinsic cost (21,000 plus calldata), so both execute it with the same gas.
    function _queueTx(address to, bytes memory data, uint64 gasLimit) internal {
        _txs.push(PublicTx(to, data, gasLimit, false));
    }

    function _intrinsic(bytes memory data) internal pure returns (uint256 g) {
        g = 21_000;
        for (uint256 i = 0; i < data.length; ++i) {
            g += data[i] == 0 ? 4 : 16;
        }
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
        if (_txs.length != 0) {
            if (bytes(dir).length != 0) {
                vm.dumpState(string.concat(dir, "/", _name, ".hooks.json"));
            }
            for (uint256 i = 0; i < _txs.length; ++i) {
                PublicTx storage t = _txs[i];
                (bool ok,) = t.to.call{gas: t.gasLimit - _intrinsic(t.data)}(t.data);
                t.success = ok;
            }
        }
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
        vm.serializeString(m, "txs", _txsJson());
        string memory body = vm.serializeString(m, "records", _records());
        vm.writeJson(body, string.concat(dir, "/", _name, ".meta.json"));
    }

    function _txsJson() internal returns (string memory out) {
        string memory arr = string.concat("txs-", _name);
        out = "{}";
        for (uint256 i = 0; i < _txs.length; ++i) {
            string memory k = string.concat("t", vm.toString(i));
            vm.serializeAddress(k, "to", _txs[i].to);
            vm.serializeBytes(k, "data", _txs[i].data);
            vm.serializeUint(k, "gasLimit", _txs[i].gasLimit);
            string memory last = vm.serializeBool(k, "success", _txs[i].success);
            out = vm.serializeString(arr, k, last);
        }
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
                keccak256(abi.encode("h-record", assignment)), // the registry keys a Closure by (epoch, hRecordID, hRound)
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
        // the committed fixture is the PoA build's (the PoS-capable build has its own runtime hashes and its own fixture)
        if (keccak256(bytes(vm.envOr("VR_BUILD", string("")))) == keccak256("pos")) return;
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
        if (keccak256(bytes(vm.envOr("VR_BUILD", string("")))) == keccak256("pos")) return; // the PoA fixture; the PoS build has its own
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

    /// @dev The module re-enters every VR mutator with a well-formed call, then answers: register, proposeBinding and the other
    /// locked mutators are refused with Locked, the hooks with NotSystemCaller and the step entry points with NotSelf; the lock-exempt
    /// `invalidate` (of an unknown result) succeeds and changes nothing. The reservation stands and nothing faults.
    function test_electReenter() public {
        assertEq(_electVariant("elect-reenter", M_REENTER), VRC.ELECT_RESERVED);
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(module.reentryAttempts(), 14);
        assertEq(module.reentryRefusals(), 13);
        bytes4 locked = bytes4(keccak256("Locked()"));
        assertEq(module.reentryErrors(11), locked, "register");
        assertEq(module.reentryErrors(12), locked, "proposeBinding");
        assertEq(module.reentryErrors(13), bytes4(0), "invalidate is lock-exempt");
        assertEq(module.reentryErrors(0), locked, "publish");
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

    /// @dev A successful 16-member Ready answer one byte above the 5,408-byte cap (VR refuses it before copying): a fault.
    function test_outputOversize() public {
        _begin("output-oversize");
        _mockGenesis(16, 1, 16, 16);
        module.setElect(VRC.ELECT_RESERVED, true, _rid("R"));
        module.setMode(S_OUTPUT, M_OVERSIZE);
        _openBlock();
        assertEq(_runBlock(32), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
        assertEq(vr.openOutput(), bytes32(0));
        assertEq(_state(_rid("R")), VRC.OUT_NONE);
        // the same module without the extra byte returns exactly the cap and is accepted
        (bool ok, bytes memory ret) =
            address(module).staticcall(abi.encodeCall(MockModule.outputOf, (_rid("R"))));
        assertTrue(ok);
        assertEq(ret.length, 5409);
    }

    /// @dev The module builds a 1 MiB return and runs out of gas expanding memory in its own frame (MemoryOOG): a failed call, not
    /// oversized return data; output-oversize covers the size check itself.
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
        if (keccak256(bytes(vm.envOr("VR_BUILD", string("")))) == keccak256("pos")) return; // the PoA fixture; the PoS build has its own
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

    // =============================================================================================
    // the maximum compound paths: modules at VR's maximum accepted caps (design 3.3.4)
    // =============================================================================================

    function _maxBounds(MockModule m) internal {
        m.setBounds(
            [
                CAP_ELECT,
                CAP_OUTPUT,
                CAP_RECORD,
                CAP_RESOLVED,
                CAP_ATTACH,
                CAP_DETACH,
                CAP_GOV,
                CAP_ADOPT
            ]
        );
    }

    /// @dev A mock generation whose module advertises VR's maximum caps (read at genesis), with its output R reserved and published.
    function _maxModuleWithPublishedOutput(uint256 n) internal returns (bytes32 rid) {
        _maxBounds(module);
        _mockGenesis(n, 1, uint32(n), 16);
        rid = _rid("R");
        assertEq(_moduleReserve(rid, true), VRC.ELECT_RESERVED);
        assertEq(_state(rid), VRC.OUT_PUBLISHED);
    }

    /// @dev Ack(R), Boundary(R) and 30 foreign Closures: a full H = 32 batch, delivered to the module in one onRecords of 32.
    function _batch32(bytes32 rid) internal {
        _ackBoundary(rid);
        for (uint256 i = 0; i < 30; ++i) {
            _recClosure(keccak256(abi.encode("a foreign assignment", i)));
        }
        assertEq(seal.recordCount(), 32);
    }

    /// @dev H = 32 at the maximum record cap (1,500,000 per record, 48,000,000 for the batch) with a healthy delivery that burns its
    /// whole cap before answering, and an onResolved that burns its 500,000 cap: every record applies, both callbacks ran with the
    /// right content, and the module stays Healthy.
    function test_batch32Max() public {
        _begin("batch32-max");
        bytes32 rid = _maxModuleWithPublishedOutput(5);
        module.clearLog();
        module.setGriefLeave(20_000);
        module.setMode(S_RECORDS, M_GRIEF);
        module.setMode(S_RESOLVED, M_GRIEF);
        _openBlock();
        _batch32(rid);
        _runBlock(32);
        assertEq(vr.recordCursor(), 32);
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(module.logLength(), 3);
        assertEq(module.log(0), "onResolved:1");
        assertEq(module.log(1), "onRecords:0:32");
        assertEq(module.log(2), "elect");
    }

    /// @dev The same batch with an onRecords that exhausts its 48,000,000 cap: the 32 records still apply (cursor + 32, R
    /// Acknowledged), the module's onRecords frame rolls back (no log entry) and the module is Faulted.
    function test_batch32Exhausted() public {
        _begin("batch32-exhausted");
        bytes32 rid = _maxModuleWithPublishedOutput(5);
        module.clearLog();
        module.setMode(S_RECORDS, M_BURN);
        _openBlock();
        _batch32(rid);
        _runBlock(32);
        assertEq(vr.recordCursor(), 32);
        assertEq(_state(rid), VRC.OUT_ACKNOWLEDGED);
        assertEq(vr.lastAcked(), rid);
        assertEq(vr.health(), VRC.FAULTED);
        assertEq(module.logLength(), 1, "only onResolved ran to completion");
        assertEq(module.log(0), "onResolved:1");
    }

    /// @dev Sixteen bound changes with the largest legal payloads: Σ exactly MAX_BOUND_PAYLOAD (64 KiB), the SetModule at
    /// MAX_CHANGE_PAYLOAD (16 KiB, its initData 16,256 bytes), 8 root-side UpdatePartitions sharing the rest.
    function _bindSixteenMax(address nextModule) internal returns (bytes memory initData) {
        uint64[] memory ids = new uint64[](16);
        uint256 k = 0;
        uint256 total = 0;
        initData = new bytes(VRC.MAX_CHANGE_PAYLOAD - 128);
        for (uint256 i = 0; i < initData.length; ++i) {
            initData[i] = bytes1(uint8(i * 7 + 1));
        }
        bytes memory p = abi.encode(nextModule, nextModule.codehash, initData);
        assertEq(p.length, VRC.MAX_CHANGE_PAYLOAD);
        ids[k++] = _queue(VRC.K_SET_MODULE, p);
        total += p.length;
        deployCodeTo("VRMocks.sol:MockHolder", GOVERNOR_NEXT_ADDR);
        p = abi.encode(GOVERNOR_NEXT_ADDR, GOVERNOR_NEXT_ADDR.codehash);
        ids[k++] = _queue(VRC.K_SET_GOVERNOR, p);
        total += p.length;
        p = _limitsPayload(1, 16, 16);
        ids[k++] = _queue(VRC.K_COMMITTEE_LIMITS, p);
        total += p.length;
        p = abi.encode(uint64(2_000_000), uint64(8), address(0xFEE));
        ids[k++] = _queue(VRC.K_FEE_PARAMS, p);
        total += p.length;
        uint64 e = vr.config().knownRootEpoch;
        for (uint256 i = 0; i < 4; ++i) {
            p = abi.encode(
                keccak256(abi.encode("unicity.rule/gas", i)),
                keccak256("rel"),
                e + 3,
                uint64(ucTime + 3600),
                "gas"
            );
            ids[k++] = _queue(VRC.K_SCHEDULE_ACTIVATION, p);
            total += p.length;
        }
        // 8 UpdatePartitions (224 bytes plus their last field each) fill the remaining bytes exactly
        uint256 rest = VRC.MAX_BOUND_PAYLOAD - total;
        uint256 each = ((rest / 8 - 224) / 32) * 32;
        for (uint256 i = 0; i < 8; ++i) {
            uint256 len = i == 0 ? rest - 7 * (224 + each) - 224 : each;
            p = abi.encode(
                uint32(7 + i),
                abi.encodePacked(uint8(0x80), uint8(i)),
                keccak256(abi.encode(i)),
                new bytes(len)
            );
            assertLe(p.length, VRC.MAX_CHANGE_PAYLOAD);
            ids[k++] = _queue(VRC.K_UPDATE_PARTITION, p);
            total += p.length;
        }
        assertEq(total, VRC.MAX_BOUND_PAYLOAD, "the bound payloads sum to exactly 64 KiB");
        _passDelays();
        for (uint256 i = 0; i < 16; ++i) {
            vr.execute(ids[i]);
        }
    }

    /// @dev The next module of the switch at VR's maximum caps, with adoption and a liability holder.
    function _maxNext() internal returns (MockModule next) {
        next = _mockAt(MOCK_NEXT_ADDR, keccak256("unicity.vr.max-next"));
        deployCodeTo("VRMocks.sol:MockHolder", HOLDER_NEXT_ADDR);
        next.setCaps(VRC.CAP_ADOPTION_CHECK | VRC.CAP_LIABILITY_HOLDER);
        next.setHolder(HOLDER_NEXT_ADDR);
        _maxBounds(next);
    }

    /// @dev The compound module-path election at VR's maximum caps: 16 members, 16 bound changes with the largest legal payloads (8
    /// root-side), the module's elect burning its 4,000,000 cap and its outputOf its 1,000,000 cap before serving the 16-member Ready
    /// output, which VR validates, binds and publishes. Healthy.
    function test_electMax() public {
        _begin("elect-max");
        _maxBounds(module);
        _mockGenesis(16, 1, 16, 16);
        MockModule next = _maxNext();
        _bindSixteenMax(address(next));
        module.setMembers(vr.committee());
        module.setMode(S_ELECT, M_GRIEF);
        module.setMode(S_OUTPUT, M_GRIEF);
        module.setGriefLeave(700_000);
        module.setElect(VRC.ELECT_RESERVED, true, _rid("R"));
        _openBlock();
        assertEq(_runBlock(32), VRC.ELECT_RESERVED);
        assertEq(vr.health(), VRC.HEALTHY);
        assertEq(vr.openOutput(), _rid("R"));
        assertEq(vr.output(_rid("R")).members.length, 16);
        assertEq(vr.output(_rid("R")).changes.length, 16);
        assertEq(_state(_rid("R")), VRC.OUT_PUBLISHED);
    }

    /// @dev The 16-member pointer-switch Boundary at VR's maximum caps, delivered on its own: the Ack applied in an earlier block,
    /// this block imports the Boundary alone. It installs 16 members, activates 15 changes with the largest legal payloads, and
    /// switches with every callback burning its maximum cap: onResolved (500,000), adoption (1,000,000), the old module's onRecords
    /// (1,500,000), detach (500,000) and attach (3,000,000, with the 16,256-byte initData in its context). Healthy, holder allocated.
    function test_switchMax() public {
        _begin("switch-max");
        _maxBounds(module);
        _mockGenesis(16, 1, 16, 16);
        MockModule next = _maxNext();
        bytes memory initData = _bindSixteenMax(address(next));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        assertEq(vr.output(r).changes.length, 16);
        _recAck(r);
        _apply(1);
        assertEq(vr.pendingPair(), r, "the Ack staged the pair a block earlier");
        module.clearLog();
        module.setGriefLeave(20_000);
        module.setMode(S_RECORDS, M_GRIEF);
        module.setMode(S_RESOLVED, M_GRIEF);
        module.setMode(S_DETACH, M_GRIEF);
        next.setMode(S_ATTACH, M_GRIEF);
        next.setMode(S_ADOPT, M_GRIEF);
        next.setGriefLeave(60_000);
        _openBlock();
        _recBoundary(r, _nextEpoch(), false, 0);
        _runBlock(32);
        assertEq(vr.recordCursor(), 2);
        assertEq(vr.activeModule().module, MOCK_NEXT_ADDR, "switched");
        assertEq(vr.health(), VRC.HEALTHY, "every callback answered at its maximum cap");
        assertEq(vr.committee().length, 16);
        assertEq(vr.holderCount(), 1);
        assertEq(module.log(0), "onResolved:1");
        assertEq(
            module.log(1), "onRecords:1:1", "the old module got the Boundary before the detach"
        );
        assertEq(module.log(2), "detach");
        assertEq(next.log(0), "attach");
        assertEq(next.attachMembers(), 16);
        assertEq(next.attachInitHash(), keccak256(initData), "attach saw the whole initData");
        assertEq(next.attachPrevious(), MOCK_ADDR);
    }

    /// @dev The combined fixtures of the VR batch rule (astra, urethhook r2; VT-14 acceptance: bft-core b1state CheckVRHookGas). One
    /// H = 32 records call carries the 16-member, 64 KiB switching output's Ack, 30 ordinary records and its Boundary, the switch at
    /// the start, the middle or the end of the batch, with both modules' record callbacks and every switch callback burning their
    /// maximum caps. The batch rule's reservation, R_32 + B, must cover each of them: the single-live-output invariant allows one
    /// switch per call, and its two onRecords segments sum to at most H records.
    function test_mixedFirst() public {
        _begin("mixed-first");
        _mixed(0);
    }

    function test_mixedMiddle() public {
        _begin("mixed-middle");
        _mixed(15);
    }

    function test_mixedLast() public {
        _begin("mixed-last");
        _mixed(30);
    }

    function _mixed(uint256 beforeBoundary) internal {
        _maxBounds(module);
        _mockGenesis(16, 1, 16, 16);
        MockModule next = _maxNext();
        _bindSixteenMax(address(next));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        module.clearLog();
        module.setGriefLeave(20_000);
        module.setMode(S_RECORDS, M_GRIEF);
        module.setMode(S_RESOLVED, M_GRIEF);
        module.setMode(S_DETACH, M_GRIEF);
        next.setMode(S_ATTACH, M_GRIEF);
        next.setMode(S_ADOPT, M_GRIEF);
        next.setMode(S_RECORDS, M_GRIEF);
        next.setGriefLeave(60_000);
        _openBlock();
        _recAck(r);
        for (uint256 i; i < beforeBoundary; ++i) {
            _recClosure(keccak256(abi.encode("mixed ordinary", i)));
        }
        _recBoundary(r, _nextEpoch(), false, 0);
        for (uint256 i = beforeBoundary; i < 30; ++i) {
            _recClosure(keccak256(abi.encode("mixed ordinary", i)));
        }
        _runBlock(32);
        assertEq(vr.recordCursor(), 32);
        assertEq(_state(r), VRC.OUT_ACKNOWLEDGED);
        assertEq(vr.activeModule().module, MOCK_NEXT_ADDR, "switched");
        assertEq(vr.health(), VRC.HEALTHY, "every callback answered at its maximum cap");
        assertEq(vr.committee().length, 16);
        assertEq(vr.holderCount(), 1);
        string memory through = string.concat("onRecords:0:", vm.toString(beforeBoundary + 2));
        assertEq(module.log(0), "onResolved:1");
        assertEq(module.log(1), through, "the old module's segment runs through the Boundary");
        assertEq(module.log(2), "detach");
        assertEq(next.log(0), "attach");
        if (beforeBoundary < 30) {
            assertEq(
                next.log(1),
                string.concat(
                    "onRecords:",
                    vm.toString(beforeBoundary + 2),
                    ":",
                    vm.toString(30 - beforeBoundary)
                ),
                "the new module gets the rest"
            );
        }
    }

    // =============================================================================================
    // fault attribution through public transactions after the hooks
    // =============================================================================================

    /// @dev An asynchronous output: the hook's election reserves R without publishing it (the module is Pending). Public transactions
    /// in the same block: one that calls publish 100 times (each Pending, the lock taken and cleared 100 times in one transaction);
    /// a publish with too little gas for its contained step (BudgetShort revert); the module turning Ready; and one transaction that
    /// first makes a short publish (refused inside the transaction) and then a funded one, which publishes. Health stays Healthy
    /// throughout: no early, short or refused publish is a fault.
    function test_publishTrace() public {
        _begin("publish-trace");
        _mockGenesis(5, 1, 5, 16);
        deployCodeTo("VRHookState.t.sol:PublishDriver", DRIVER_ADDR);
        bytes32 rid = _rid("R");
        module.setElect(VRC.ELECT_RESERVED, false, rid);
        module.setOutputStatus(VRC.STATUS_PENDING);
        _queueTx(DRIVER_ADDR, abi.encodeCall(PublishDriver.early, (rid, 100)), 20_000_000);
        _queueTx(VR_ADDR, abi.encodeCall(vr.publish, (rid)), 250_000);
        _queueTx(MOCK_ADDR, abi.encodeCall(MockModule.setOutputStatus, (VRC.STATUS_READY)), 100_000);
        _queueTx(DRIVER_ADDR, abi.encodeCall(PublishDriver.shortThenPublish, (rid)), 10_000_000);
        _openBlock();
        assertEq(_runBlock(32), VRC.ELECT_RESERVED);
        assertTrue(_txs[0].success, "100 early publishes");
        assertFalse(_txs[1].success, "the low-gas publish reverts BudgetShort");
        assertTrue(_txs[2].success);
        assertTrue(_txs[3].success, "short then funded, in one transaction");
        PublishDriver d = PublishDriver(DRIVER_ADDR);
        assertEq(d.pendingSeen(), 100);
        assertTrue(d.shortRefused());
        assertTrue(d.published());
        assertEq(_state(rid), VRC.OUT_PUBLISHED);
        assertEq(vr.health(), VRC.HEALTHY);
    }
}

/// @notice The public caller of the publish trace (test only, at 0xc0de6): it records what VR answered.
contract PublishDriver {
    address internal constant VR = address(uint160((uint256(0xff) << 152) | 0x03));
    uint256 public pendingSeen;
    bool public shortRefused;
    bool public published;

    function early(bytes32 rid, uint256 n) external {
        for (uint256 i = 0; i < n; ++i) {
            require(IVR(VR).publish(rid) == VRC.PUB_PENDING, "not pending");
            ++pendingSeen;
        }
    }

    function shortThenPublish(bytes32 rid) external {
        try IVR(VR).publish{gas: 300_000}(rid) returns (uint8) {
            revert("a short publish went through");
        } catch (bytes memory err) {
            require(bytes4(err) == bytes4(keccak256("BudgetShort(uint8)")), "not BudgetShort");
            shortRefused = true;
        }
        require(IVR(VR).publish(rid) == VRC.PUB_PUBLISHED, "not published");
        published = true;
    }
}
