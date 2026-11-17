// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {console2} from "forge-std/console2.sol";
import {VRBase} from "./VRBase.sol";
import {MockModule, MockHolder} from "./VRMocks.sol";
import {VRC} from "../../src/vr/VRConstants.sol";

/// @notice Measured compound budgets (design section 3.3.4): the worst `elect` on the module path (16 members, 16 bound changes of
/// which 8 root-side, with the 16-member validation, quantization and continuity) and on the native path (16 members, four ForceRemove
/// candidates through the full trial search), the worst Boundary (16 members installed, 15 changes activated, the pointer switched with
/// adoption, detach, attach and a holder entry), and an `onRecords` batch of 32 records. The module here is a cheap mock, so each
/// figure is VR's own share plus the mock's; the profile pin adds the real module's caps (cap_elect + cap_output on the module path,
/// cap_adopt + cap_detach + cap_attach + cap_resolved + the records share on the Boundary) and takes x 5/4. `forge test -vv` prints them.
contract VRGasTest is VRBase {
    function setUp() public {
        _setUpVR(16, 1, 16, 16);
    }

    function _bindSixteen(address nextModule) internal returns (uint64[] memory ids) {
        ids = new uint64[](16);
        uint256 k = 0;
        // 8 root-side: UpdatePartition on 8 shards (448-byte payloads)
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
        MockHolder g = new MockHolder();
        ids[k++] = _queue(VRC.K_SET_GOVERNOR, abi.encode(address(g), address(g).codehash));
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

    function _nextModule() internal returns (MockModule next) {
        next = new MockModule(keccak256("unicity.vr.gas-next"));
        next.setVR(VR_ADDR);
        MockHolder h = new MockHolder();
        next.setCaps(VRC.CAP_ADOPTION_CHECK | VRC.CAP_LIABILITY_HOLDER);
        next.setHolder(address(h));
    }

    function test_gasWorstModuleElectAndBoundary() public {
        MockModule next = _nextModule();
        _bindSixteen(address(next));
        bytes32 r = _rid("R");
        module.setElect(VRC.ELECT_RESERVED, true, r);
        uint256 g0 = gasleft();
        vm.prank(VRC.SYSTEM_CALLER);
        uint8 outcome = vr.elect(keccak256("origin"));
        uint256 electGas = g0 - gasleft();
        assertEq(outcome, VRC.ELECT_RESERVED);
        assertEq(vr.output(r).members.length, 16);
        assertEq(vr.output(r).changes.length, 16);
        console2.log("elect, module path, 16 members, 16 bound changes:", electGas);

        _recAck(r);
        _recBoundary(r, _nextEpoch(), false, 0);
        _apply(1);
        g0 = gasleft();
        _apply(1);
        uint256 boundaryGas = g0 - gasleft();
        assertEq(vr.activeModule().module, address(next), "switched");
        assertEq(vr.committee().length, 16);
        assertEq(vr.holderCount(), 1);
        console2.log(
            "Boundary: install 16, activate 15, switch with adoption/detach/attach:", boundaryGas
        );
    }

    function test_gasWorstNativeElect() public {
        // four ForceRemove candidates plus other work, the module Faulted
        for (uint64 i = 0; i < 4; ++i) {
            _queue(VRC.K_FORCE_REMOVE, abi.encode(uint64(3 + 4 * i)));
        }
        _queue(VRC.K_COMMITTEE_LIMITS, _limitsPayload(1, 13, 16));
        _passDelays();
        for (uint64 i = 1; i <= 5; ++i) {
            vr.execute(i);
        }
        module.setMode(1, 1);
        assertEq(_elect(), VRC.ELECT_NO_CANDIDATE);
        assertEq(vr.health(), VRC.FAULTED);
        _advance(VRC.MIN_EPOCH_GAP, 1);
        uint256 g0 = gasleft();
        vm.prank(VRC.SYSTEM_CALLER);
        uint8 outcome = vr.elect(keccak256("origin"));
        uint256 nativeGas = g0 - gasleft();
        assertEq(outcome, VRC.ELECT_RESERVED);
        assertEq(
            vr.output(vr.openOutput()).members.length,
            13,
            "three removals: four fail the turnover bound"
        );
        console2.log("elect, native path, 16 members, 4 ForceRemove candidates:", nativeGas);
    }

    function test_gasRecordsBatchOf32() public {
        for (uint64 k = 0; k < 32; ++k) {
            seal.push(
                VRC.REC_CLOSURE,
                abi.encode(
                    keccak256(abi.encode("a", k)),
                    uint256(1),
                    bytes32(uint256(2)),
                    bytes32(uint256(3)),
                    bytes32(uint256(4)),
                    bytes32(uint256(5))
                )
            );
        }
        uint256 g0 = gasleft();
        _apply(32);
        uint256 batch = g0 - gasleft();
        assertEq(vr.recordCursor(), 32);
        console2.log("applyRootRecords(32), Closure records, one onRecords call:", batch);
        console2.log("per record:", batch / 32);
    }

    /// @dev The compound budget holds when the module uses every unit of its caps: elect and outputOf burn to their caps before
    /// answering (a 16-member Ready output with 16 bound changes), and VR's own work still completes inside the step budget.
    function test_gasModulePathWithTheModuleAtItsCaps() public {
        MockModule next = _nextModule();
        _bindSixteen(address(next));
        bytes32 r = _rid("R");
        module.setMembers(vr.committee());
        module.setMode(1, 7); // elect: GRIEF
        module.setMode(2, 7); // outputOf: GRIEF
        module.setGriefLeave(700_000);
        module.setElect(VRC.ELECT_RESERVED, true, r);
        uint256 g0 = gasleft();
        vm.prank(VRC.SYSTEM_CALLER);
        uint8 outcome = vr.elect(keccak256("origin"));
        uint256 used = g0 - gasleft();
        assertEq(outcome, VRC.ELECT_RESERVED, "VR's share fits the step budget");
        assertEq(vr.health(), VRC.HEALTHY);
        console2.log("elect, module path, module at its caps (3,000,000 + 800,000):", used);
    }

    /// @dev The worst Boundary with every callback at its cap: onResolved, adoptionReady, detach, attach and the two onRecords segments.
    function test_gasBoundaryWithCallbacksAtTheirCaps() public {
        MockModule next = _nextModule();
        _bindSixteen(address(next));
        bytes32 r = _rid("R");
        assertEq(_moduleReserve(r, true), VRC.ELECT_RESERVED);
        _recAck(r);
        _recBoundary(r, _nextEpoch(), false, 0);
        _apply(1);
        module.setGriefLeave(20_000);
        next.setGriefLeave(20_000);
        module.setMode(3, 7); // onRecords
        module.setMode(4, 7); // onResolved
        module.setMode(6, 7); // detach
        next.setMode(5, 7); // attach
        next.setMode(8, 7); // adoptionReady (view)
        next.setGriefLeave(60_000);
        uint256 g0 = gasleft();
        _apply(1);
        uint256 used = g0 - gasleft();
        assertEq(vr.activeModule().module, address(next), "switched");
        assertEq(vr.health(), VRC.HEALTHY, "every callback answered at its cap");
        console2.log("Boundary with every callback at its cap:", used);
    }
}
