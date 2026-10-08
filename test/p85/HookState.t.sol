// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {MockRootRecords} from "./MockRootRecords.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {RecordKind, RecoveryAckData, RootRecord} from "../../src/p85/P85Types.sol";

/// @notice Generates the custody states the ureth records hook is tested against: the real `StakeCustody` runtime and its storage
/// before and after it applies real root records, on the execution chain id the profile pins (1337) and with `roots` pointing at the
/// registry's fixed address (0xff00..02), so the same bytes run in the registry's world.
///
/// Both dumps are raw `vm.dumpState` output; `tools/hook_state.py` filters them to the modules and writes
/// `test/p85/fixtures/hook-<scenario>.json`. The post state is what custody computed with `block.chainid == 1337`: ureth must reproduce
/// it slot for slot, which a hook that runs under revm's default chain id (1) cannot (exposure identifiers hash the chain id).
///
///     P85_WRITE_HOOK_STATE=/tmp/hook forge test --match-contract "HookState.*"
abstract contract HookStateBase is P85Flow {
    address internal constant REGISTRY = address(0xff00000000000000000000000000000000000002);
    uint256 internal constant ROOTS_SLOT = 8;
    uint256 internal constant LIMITS_SLOT = 11;
    uint64 internal constant CHAIN_ID = 1337;

    /// @dev Nothing is deployed in `setUp`: `vm.dumpState` holds only the accounts and slots the current transaction touched, so the
    /// whole deployment, the scenario's setup and the dumps all happen inside the one test transaction (`_deployAll`).
    function setUp() public virtual override {}

    function _deployAll() internal {
        vm.chainId(CHAIN_ID);
        roots = new MockRootRecords();
        _deploy(_defaultPolicy());
    }

    function _out() internal view returns (string memory dir) {
        dir = vm.envOr("P85_WRITE_HOOK_STATE", string(""));
    }

    function _dump(string memory dir, string memory name) internal {
        // vm.dumpState holds the accounts the current transaction has touched: touch every module
        uint256 touched =
            address(custody).balance + address(election).balance + address(evidence).balance;
        touched += address(custody).code.length + address(election).code.length
        + address(evidence).code.length;
        assertGt(touched, 0);
        address mock = address(roots);
        vm.store(address(custody), bytes32(ROOTS_SLOT), bytes32(uint256(uint160(REGISTRY))));
        vm.dumpState(string.concat(dir, "/", name, ".json"));
        vm.store(address(custody), bytes32(ROOTS_SLOT), bytes32(uint256(uint160(mock))));
    }

    function _records(uint256 n) internal returns (string memory out) {
        string memory arr = "records";
        string memory last;
        for (uint256 i; i < n; ++i) {
            RootRecord memory r = roots.recordAt(uint64(i));
            string memory k = string.concat("r", vm.toString(i));
            vm.serializeUint(k, "index", r.index);
            vm.serializeBytes32(k, "recordId", r.recordID);
            vm.serializeBytes32(k, "predecessor", r.predecessor);
            vm.serializeUint(k, "kind", uint8(r.kind));
            vm.serializeUint(k, "progress", r.progress);
            vm.serializeUint(k, "ucTime", r.ucTime);
            last = vm.serializeBytes(k, "data", r.data);
            out = vm.serializeString(arr, k, last);
        }
    }

    function _meta(string memory dir, string memory name, uint256 n) internal {
        string memory m = "meta";
        vm.serializeUint(m, "chainId", CHAIN_ID);
        vm.serializeAddress(m, "custody", address(custody));
        vm.serializeAddress(m, "election", address(election));
        vm.serializeAddress(m, "evidence", address(evidence));
        vm.serializeAddress(m, "registry", REGISTRY);
        vm.serializeBytes32(m, "rolesNote", bytes32(0));
        vm.serializeUint(m, "recordCount", n);
        string memory recs = _records(n);
        string memory body = vm.serializeString(m, "records", recs);
        vm.writeJson(body, string.concat(dir, "/", name, ".meta.json"));
    }
}

/// @dev Scenario `ack`: J is reserved over members 1..3 (in `setUp`, so the pre-state dump is committed state) and acknowledged.
contract HookStateAckTest is HookStateBase {
    function test_writeAck() public {
        string memory dir = _out();
        if (bytes(dir).length == 0) return;
        _deployAll();
        reserve(RES_J, ASG_J, allExcept(0), 1);
        _dump(dir, "ack.pre");
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        assertEq(custody.recordCursor(), 1);
        _dump(dir, "ack.post");
        _meta(dir, "ack", 1);
    }
}

/// @dev Scenario `recovery`: identity 0 asks to retire, J is reserved without it, and the RecoveryAck derives the exposures of K.
contract HookStateRecoveryTest is HookStateBase {
    function test_writeRecovery() public {
        string memory dir = _out();
        if (bytes(dir).length == 0) return;
        _deployAll();
        requestRetirement(0);
        reserve(RES_J, ASG_J, allExcept(0), 1);
        _dump(dir, "recovery.pre");
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll();
        assertEq(custody.lastAckedAssignment(), ASG_K);
        _dump(dir, "recovery.post");
        _meta(dir, "recovery", 1);
    }
}

contract HookStateLayoutTest is HookStateBase {
    function setUp() public override {
        _deployAll();
    }

    /// @dev The slot layout the Rust side edits: `roots` and the packed limits (maxBatch is the high 32 bits of the struct's slot).
    function test_layoutMatchesTheDocumentedSlots() public view {
        assertEq(
            address(uint160(uint256(vm.load(address(custody), bytes32(ROOTS_SLOT))))),
            address(roots)
        );
        uint256 w = uint256(vm.load(address(custody), bytes32(LIMITS_SLOT)));
        (uint32 vMax, uint32 lMax, uint32 rMax, uint32 maxBatch) = custody.limits();
        assertEq(uint32(w), vMax);
        assertEq(uint32(w >> 32), lMax);
        assertEq(uint32(w >> 64), rMax);
        assertEq(uint32(w >> 96), maxBatch);
        assertEq(maxBatch, 32);
        assertEq(block.chainid, CHAIN_ID);
    }
}
