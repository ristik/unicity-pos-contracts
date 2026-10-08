// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {RecordKind, RecoveryAckData} from "../../src/p85/P85Types.sol";

/// @notice Custody's own digests over an assignment's exposures, written as the fixture bft-core derives them from the frozen identity
/// records (evmassign.AssignmentExposureDigest, KeyHistoryDigestFromHashes, ExposureChainStep). Custody is normative for these words
/// (briefs/p85-pr1c-control-records.md section 7), so the fixture is generated from its state and bft-core must reproduce it. The test
/// fails when the committed fixture differs from what custody produces now; run with P85_WRITE_FIXTURES=1 to regenerate.
contract CustodyDigestsTest is P85Flow {
    string internal constant FIXTURE = "/test/p85/fixtures/custody-digests.json";

    function _u(uint256 v) internal pure returns (string memory) {
        return vm.toString(v);
    }

    function _lots(uint256[] memory lots) internal pure returns (string memory out) {
        out = "[";
        for (uint256 i; i < lots.length; ++i) {
            out = string.concat(out, i == 0 ? "" : ",", _u(lots[i]));
        }
        out = string.concat(out, "]");
    }

    function _members(bytes32 assignmentID, uint256[] memory idx)
        internal
        view
        returns (string memory out)
    {
        out = "[";
        for (uint256 i; i < idx.length; ++i) {
            bytes32 eid = exposureID(assignmentID, gid(idx[i]));
            Expo memory e = expo(eid);
            assertEq(e.assignmentID, assignmentID, "the exposure belongs to the assignment");
            out = string.concat(
                out,
                i == 0 ? "" : ",",
                '{"id":',
                _u(e.id),
                ',"generation":',
                _u(e.generation),
                ',"weight":',
                _u(e.weight),
                ',"operatorPayee":"',
                vm.toString(e.operatorPayee),
                '","rootKeyHash":"',
                vm.toString(e.rootKeyHash),
                '","evmKeyHash":"',
                vm.toString(e.evmKeyHash),
                '","lotIds":',
                _lots(custody.exposureLots(eid)),
                ',"exposureId":"',
                vm.toString(eid),
                '"}'
            );
        }
        out = string.concat(out, "]");
    }

    function _assignment(bytes32 assignmentID, uint256[] memory idx)
        internal
        view
        returns (string memory)
    {
        Asg memory a = asg(assignmentID);
        return string.concat(
            '{"assignmentId":"',
            vm.toString(assignmentID),
            '","exposureDigest":"',
            vm.toString(a.exposureDigest),
            '","keyDigest":"',
            vm.toString(a.keyDigest),
            '","members":',
            _members(assignmentID, idx),
            "}"
        );
    }

    function _chains(uint256 count) internal view returns (string memory out) {
        out = "[";
        for (uint256 i; i < count; ++i) {
            out = string.concat(
                out,
                i == 0 ? "" : ",",
                '{"id":',
                _u(gid(i)),
                ',"generation":1,"chain":"',
                vm.toString(custody.exposureChain(gid(i), 1)),
                '"}'
            );
        }
        out = string.concat(out, "]");
    }

    function _idx(uint256 from, uint256 to) internal pure returns (uint256[] memory out) {
        out = new uint256[](to - from);
        for (uint256 i; i < out.length; ++i) {
            out[i] = from + i;
        }
    }

    function _deployment() internal view returns (string memory) {
        return string.concat(
            '{"networkWord":"',
            vm.toString(NETWORK),
            '","chainId":',
            _u(block.chainid),
            ',"custody":"',
            vm.toString(address(custody)),
            '"}'
        );
    }

    function _scenarios() internal returns (string memory) {
        string memory genesisOnly = string.concat(
            '{"name":"genesis","assignments":[',
            _assignment(GENESIS_ASSIGNMENT, _idx(0, N_GENESIS)),
            '],"chains":',
            _chains(N_GENESIS),
            "}"
        );

        uint256 snap = vm.snapshotState();
        handoffExcluding(0);
        string memory primary = string.concat(
            '{"name":"primary","assignments":[',
            _assignment(GENESIS_ASSIGNMENT, _idx(0, N_GENESIS)),
            ",",
            _assignment(ASG_J, _idx(1, N_GENESIS)),
            '],"chains":',
            _chains(N_GENESIS),
            "}"
        );
        vm.revertToState(snap);

        reserve(RES_J, ASG_J, allExcept(0), 1);
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        applyAll();
        string memory recovery = string.concat(
            '{"name":"recovery","assignments":[',
            _assignment(GENESIS_ASSIGNMENT, _idx(0, N_GENESIS)),
            ",",
            _assignment(ASG_J, _idx(1, N_GENESIS)),
            ",",
            _assignment(ASG_K, _idx(0, N_GENESIS)),
            '],"chains":',
            _chains(N_GENESIS),
            "}"
        );
        return string.concat("[", genesisOnly, ",", primary, ",", recovery, "]");
    }

    function test_custodyDigestsAreTheSharedFixture() public {
        string memory json = string.concat(
            '{"format":"UNICITY_P85_CUSTODY_DIGESTS/v1","deployment":',
            _deployment(),
            ',"scenarios":',
            _scenarios(),
            "}\n"
        );
        string memory path = string.concat(vm.projectRoot(), FIXTURE);
        if (vm.envOr("P85_WRITE_FIXTURES", false)) vm.writeFile(path, json);
        assertEq(
            vm.readFile(path),
            json,
            "the committed custody digest fixture is stale; regenerate with P85_WRITE_FIXTURES=1"
        );
    }
}
