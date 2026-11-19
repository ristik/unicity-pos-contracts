// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {VRPosGenesis} from "../../../script/VRPosGenesis.s.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {IVR, Member} from "../../../src/vr/VRTypes.sol";
import {StakeCustody} from "../../../src/p85/StakeCustody.sol";
import {ElectionPolicy} from "../../../src/p85/ElectionPolicy.sol";
import {GovernanceParams} from "../../../src/p85/GovernanceParams.sol";

/// @notice The PoS-prototype generation's contracts genesis (script/VRPosGenesis.s.sol): VR ids are custody StakingIDs, VR's committee seats
/// carry the digests custody's genesis exposures carry, the adapter is VR's module and custody is holder 0, the multisig is the policy
/// authority, and the election answers to the adapter alone.
contract PosGenesisTest is Test {
    string internal constant OUT = "script/genesis-out/vr-pos-genesis-test";

    function _at(uint256 low) internal pure returns (address) {
        return address(uint160((uint256(0xff) << 152) | low));
    }

    function _input() internal view returns (string memory) {
        string memory plan = vm.readFile("test/vr/fixtures/vr-genesis-input.json");
        plan = vm.replace(plan, "\"rMax\": 8", "\"rMax\": 4");
        plan = vm.replace(plan, "\"maxGas\": 200000000", "\"maxGas\": 200000000");
        string memory pos = string.concat(
            ',"pos":{"bondUnit":"1000000000000000000","treasury":"0x00000000000000000000000000000000000000ee",',
            '"rootNetwork":3,"rootGenesis":"0x1111111111111111111111111111111111111111111111111111111111111111",',
            '"assignmentId":"0x2222222222222222222222222222222222222222222222222222222222222222",',
            '"rewardFunding":"1000000000000000000000","rewardRate":"1000000000000000000","cadenceRounds":400,"cadenceSeconds":300}}'
        );
        bytes memory b = bytes(plan);
        uint256 end = b.length;
        while (b[end - 1] != "}") {
            --end;
        }
        bytes memory head = new bytes(end - 1);
        for (uint256 i; i < end - 1; ++i) {
            head[i] = b[i];
        }
        return string.concat(string(head), pos);
    }

    function test_thePoSGenerationsGenesisIsConsistent() public {
        vm.setEnv("VR_GENESIS_JSON", _input());
        vm.setEnv("VR_OUT", OUT);
        vm.createDir(OUT, true);
        VRPosGenesis s = new VRPosGenesis();
        s.run();
        IVR vr = IVR(_at(3));
        assertEq(vr.activeModule().module, _at(7));
        assertEq(vr.holderCount(), 1);
        string memory d = vm.readFile(string.concat(OUT, "/deployment.json"));
        address custodyAddr = vm.parseJsonAddress(d, ".custody");
        assertEq(vr.holderAt(0).holder, custodyAddr);
        StakeCustody custody = StakeCustody(payable(custodyAddr));
        assertEq(custody.nextStakingID(), 4);
        Member[] memory c = vr.committee();
        assertEq(c.length, 4);
        for (uint64 id = 1; id <= 4; ++id) {
            assertTrue(vr.ownerOf(id) != address(0));
            assertEq(c[id - 1].id, id, "VR ids are custody ids");
        }
        ElectionPolicy election = ElectionPolicy(vm.parseJsonAddress(d, ".election"));
        assertEq(election.hookCaller(), _at(7));
        GovernanceParams policy = GovernanceParams(vm.parseJsonAddress(d, ".policy"));
        assertEq(policy.AUTHORITY(), _at(9));
        assertEq(vr.config().governor, _at(9));
        assertEq(custody.recordCursor(), 0);
    }
}
