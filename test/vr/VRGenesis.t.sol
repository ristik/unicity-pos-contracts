// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {VRGenesis} from "../../script/VRGenesis.s.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {IVR, Member} from "../../src/vr/VRTypes.sol";
import {PoaElection} from "../../src/vr/poa/PoaElection.sol";
import {FoundationMultisig} from "../../src/vr/FoundationMultisig.sol";

contract VRGenesisHarness is VRGenesis {
    function inert(bytes memory code) external pure {
        _requireInert(code);
    }
}

/// @notice The VR generation's contracts genesis (script/VRGenesis.s.sol, VT-14): built from the sample plan, every account sits at its
/// genesis address with exactly the runtime the VR hook fixture (test/vr/fixtures/vr-hook.json, the code ureth's hook test and the
/// VR batch measurement ran) carries, so the measurement is of the deployed code.
contract VRGenesisTest is Test {
    string internal constant OUT = "script/genesis-out/vr-genesis-test";

    function _run() internal returns (VRGenesisHarness s) {
        vm.setEnv("VR_GENESIS_JSON", vm.readFile("test/vr/fixtures/vr-genesis-input.json"));
        vm.setEnv("VR_OUT", OUT);
        vm.createDir(OUT, true);
        s = new VRGenesisHarness();
        s.run();
    }

    function _at(uint256 low) internal pure returns (address) {
        return address(uint160((uint256(0xff) << 152) | low));
    }

    function test_theGenesisCodeIsTheHookFixtureCode() public {
        _run();
        string memory f = vm.readFile("test/vr/fixtures/vr-hook.json");
        string[6] memory roles =
            ["vr", "governanceFacet", "repairFacet", "recordsFacet", "poa", "composer"];
        uint256[6] memory low = [uint256(3), 4, 5, 6, 7, 8];
        for (uint256 i; i < roles.length; ++i) {
            string memory key = string.concat(".accounts.", roles[i]);
            assertEq(vm.parseJsonAddress(f, string.concat(key, ".address")), _at(low[i]), roles[i]);
            assertEq(
                vm.parseJsonBytes32(f, string.concat(key, ".codeHash")),
                _at(low[i]).codehash,
                roles[i]
            );
        }
        string memory d = vm.readFile(string.concat(OUT, "/deployment.json"));
        assertEq(vm.parseJsonBytes32(d, ".registryCodeHash"), _at(3).codehash);
        assertEq(vm.parseJsonBytes32(d, ".moduleCodeHash"), _at(7).codehash);
        assertEq(vm.parseJsonBytes32(d, ".composerCodeHash"), _at(8).codehash);
        assertEq(vm.parseJsonAddress(d, ".governor"), _at(9));
    }

    function test_theGenesisStateIsThePlan() public {
        _run();
        IVR vr = IVR(_at(3));
        Member[] memory k = vr.committee();
        assertEq(k.length, 4);
        for (uint256 i; i < k.length; ++i) {
            assertEq(k[i].id, i + 1);
            assertEq(k[i].generation, 1);
            assertEq(k[i].rawWeight, 1);
            (uint8 st,) = PoaElection(_at(7)).status(uint64(i + 1));
            assertEq(st, 4, "Active in PoA");
        }
        assertEq(vr.lastAcked(), VRC.GENESIS_RESULT);
        assertEq(vr.activeModule().module, _at(7));
        assertEq(vr.config().governor, _at(9));
        assertTrue(FoundationMultisig(_at(9)).isSigner(address(0xc001)));
        assertEq(block.chainid, 3);
    }

    function test_aComposerThatCanCallOrWriteIsRefused() public {
        VRGenesisHarness s = new VRGenesisHarness();
        s.inert(hex"6055600052"); // PUSH1 0x55 is data, not SSTORE
        for (uint256 i; i < 7; ++i) {
            bytes1 op = [bytes1(0xf0), 0xf1, 0xf2, 0xf4, 0xf5, 0xff, 0x55][i];
            vm.expectRevert(
                bytes(
                    "VR genesis: the composer engine can call, create, delegate, self-destruct or write"
                )
            );
            s.inert(abi.encodePacked(hex"6001", op));
        }
    }
}
