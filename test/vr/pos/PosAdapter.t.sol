// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PosBase} from "./PosBase.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {Member, HolderView, ModuleView} from "../../../src/vr/VRTypes.sol";

contract PosAdapterTest is PosBase {
    function test_genesisIsAPoSGeneration() public view {
        ModuleView memory m = vr.activeModule();
        assertEq(m.module, ADAPTER);
        assertEq(vr.holderCount(), 1);
        HolderView memory h = vr.holderAt(0);
        assertEq(h.holder, address(custody));
        assertEq(h.holderCodeHash, address(custody).codehash);
        assertEq(vr.committee().length, N_GENESIS);
        assertEq(vr.ownerOf(1), vm.addr(ownerPk(0)));
    }
}
