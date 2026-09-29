// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Script} from "forge-std/Script.sol";
import {FeeCollector} from "../src/FeeCollector.sol";
import {WUCT} from "../src/WUCT.sol";

/// @notice Deploys canonical test instances in Foundry's local script VM and saves their actual
/// metadata-free runtime bytecode, including FeeCollector's constructor immutables.
contract T2T3Artifacts is Script {
    address payable internal constant TEST_TREASURY =
        payable(0x000000000000000000000000000000000000bEEF);
    uint16 internal constant TEST_TREASURY_SHARE_BPS = 6000;

    function run() external {
        WUCT wrapped = new WUCT();
        FeeCollector collector = new FeeCollector(TEST_TREASURY, TEST_TREASURY_SHARE_BPS);

        string memory json = vm.serializeString("t2t3", "profile", "t2t3/test-v1");
        json = vm.serializeBytes("t2t3", "wuctRuntimeBytecode", address(wrapped).code);
        json = vm.serializeBytes32("t2t3", "wuctCodeHash", keccak256(address(wrapped).code));
        json = vm.serializeAddress("t2t3", "feeCollectorTestTreasury", TEST_TREASURY);
        json = vm.serializeUint("t2t3", "feeCollectorTreasuryShareBps", TEST_TREASURY_SHARE_BPS);
        json = vm.serializeBytes("t2t3", "feeCollectorRuntimeBytecode", address(collector).code);
        json =
            vm.serializeBytes32("t2t3", "feeCollectorCodeHash", keccak256(address(collector).code));
        vm.writeJson(json, string.concat(vm.projectRoot(), "/out/t2t3-runtimes.json"));
    }
}
