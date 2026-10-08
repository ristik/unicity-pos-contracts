// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {ElectionParams} from "../../src/p85/P85Types.sol";

/// @notice The proof slots of a reserved and of a published result, and every word the root recomputes from a candidate's identity
/// records and possession proofs (bft-core evmassign.VerifyPrimary): the fixture bft-core must reproduce. Generated here, never
/// written by hand; the test fails when the committed fixture differs from what the contracts produce now. Regenerate with
/// P85_WRITE_FIXTURES=true.
contract PublicationFixtureTest is P85Flow {
    string internal constant FIXTURE = "/test/p85/fixtures/publication.json";
    address internal constant SYS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;
    bytes32 internal constant ORIGIN = keccak256("origin/1");

    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 2,
            nTarget: 10,
            nMax: 32,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: 100_000,
            cadenceSeconds: 604_800
        });
    }

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

    /// @dev The identity records of an assignment, ascending, as the root's Identity carries them.
    function _identities(bytes32 assignmentID) internal returns (string memory out) {
        bytes32[] memory ids = custody.assignmentExposures(assignmentID);
        out = "[";
        for (uint256 i; i < ids.length; ++i) {
            Expo memory e = expo(ids[i]);
            (bytes memory evm,) = _evmKeyOf(e.id);
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
                '","rootKey":"',
                vm.toString(compressed(rootPk(e.id - 1))),
                '","evmKey":"',
                vm.toString(evm),
                '","lotIds":',
                _lots(custody.exposureLots(ids[i])),
                "}"
            );
        }
        out = string.concat(out, "]");
    }

    function _slots(bytes32 resultID) internal returns (string memory) {
        vm.record();
        election.publication(resultID);
        (bytes32[] memory reads,) = vm.accesses(address(election));
        string memory slots = "[";
        string memory words = "[";
        for (uint256 i; i < reads.length; ++i) {
            bool seen;
            for (uint256 j; j < i; ++j) {
                if (reads[j] == reads[i]) seen = true;
            }
            if (seen) continue;
            string memory sep = bytes(slots).length == 1 ? "" : ",";
            slots = string.concat(slots, sep, '"', vm.toString(reads[i]), '"');
            words = string.concat(
                words, sep, '"', vm.toString(vm.load(address(election), reads[i])), '"'
            );
        }
        return string.concat('"slots":', slots, '],"words":', words, "]");
    }

    /// @dev One getter call on `target`, recorded: the slots it read and their words.
    function _read(string memory name, address target, bytes memory callData)
        internal
        returns (string memory)
    {
        vm.record();
        (bool ok,) = target.staticcall(callData);
        require(ok, "getter failed");
        (bytes32[] memory reads,) = vm.accesses(target);
        string memory slots = "[";
        string memory words = "[";
        uint256 n;
        for (uint256 i; i < reads.length; ++i) {
            bool seen;
            for (uint256 j; j < i; ++j) {
                if (reads[j] == reads[i]) seen = true;
            }
            if (seen) continue;
            string memory sep = n++ == 0 ? "" : ",";
            slots = string.concat(slots, sep, '"', vm.toString(reads[i]), '"');
            words = string.concat(words, sep, '"', vm.toString(vm.load(target, reads[i])), '"');
        }
        return string.concat('{"name":"', name, '","slots":', slots, '],"words":', words, "]}");
    }

    /// @dev The reads the root performs at P besides the publication itself: Election's pins and custody's session, assignment and
    /// last-acknowledged words.
    function _otherReads(bytes32 resultID, bytes32 assignmentID) internal returns (string memory) {
        return string.concat(
            '"electionReads":[',
            _read("network", address(election), abi.encodeCall(election.network, ())),
            ",",
            _read("custody", address(election), abi.encodeCall(election.custody, ())),
            '],"custodyReads":[',
            _read("network", address(custody), abi.encodeCall(custody.network, ())),
            ",",
            _read("session", address(custody), abi.encodeCall(custody.session, (resultID))),
            ",",
            _read(
                "assignments", address(custody), abi.encodeCall(custody.assignments, (assignmentID))
            ),
            ",",
            _read(
                "lastAckedAssignment",
                address(custody),
                abi.encodeCall(custody.lastAckedAssignment, ())
            ),
            "]"
        );
    }

    function _pops(bytes32 resultID) internal returns (string memory out) {
        ElectionPolicy.Frozen[] memory f = election.frozenMembers(resultID);
        out = "[";
        for (uint256 i; i < f.length; ++i) {
            bytes memory key = compressed(evmPk(f[i].id - 1));
            bytes32 d = election.popDigest(resultID, f[i].id, keccak256(key));
            out = string.concat(
                out,
                i == 0 ? "" : ",",
                '{"id":',
                _u(f[i].id),
                ',"evmKey":"',
                vm.toString(key),
                '","digest":"',
                vm.toString(d),
                '","signature":"',
                vm.toString(_sig(evmPk(f[i].id - 1), d)),
                '"}'
            );
        }
        out = string.concat(out, "]");
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function test_publicationIsTheSharedFixture() public {
        clock(100_000, 604_800);
        vm.prank(SYS);
        election.elect(ORIGIN);
        bytes32 resultID = election.openResult();
        ElectionPolicy.Result memory r = election.result(resultID);

        string memory reserved = _slots(resultID);
        string memory pops = _pops(resultID);
        ElectionPolicy.PoPInput[] memory inputs =
            new ElectionPolicy.PoPInput[](election.frozenMembers(resultID).length);
        for (uint256 i; i < inputs.length; ++i) {
            bytes memory key = compressed(evmPk(i));
            inputs[i] = ElectionPolicy.PoPInput(
                gid(i), key, _sig(evmPk(i), election.popDigest(resultID, gid(i), keccak256(key)))
            );
        }
        election.submitAssignmentPoPs(resultID, inputs);
        election.finalizeCandidate(resultID);
        ElectionPolicy.Publication memory p = election.publication(resultID);
        Asg memory a = asg(r.assignmentID);

        string memory head = string.concat(
            '{"format":"UNICITY_P85_PUBLICATION/v1","deployment":{"networkWord":"',
            vm.toString(NETWORK),
            '","chainId":',
            _u(block.chainid),
            ',"custody":"',
            vm.toString(address(custody)),
            '","election":"',
            vm.toString(address(election)),
            '"},"resultId":"',
            vm.toString(resultID),
            '","assignmentId":"',
            vm.toString(r.assignmentID),
            '","incumbentAssignmentId":"',
            vm.toString(r.predecessor),
            '","attempt":',
            _u(r.attempt),
            ',"snapshotDigest":"',
            vm.toString(r.snapshotDigest),
            '"'
        );
        string memory body = string.concat(
            ',"identities":',
            _identities(r.assignmentID),
            ',"incumbentIdentities":',
            _identities(r.predecessor),
            ',"pops":',
            pops,
            ',"expected":{"exposureDigest":"',
            vm.toString(a.exposureDigest),
            '","keyDigest":"',
            vm.toString(a.keyDigest),
            '","popSetDigest":"',
            vm.toString(p.popSetDigest),
            '","primaryHash":"',
            vm.toString(p.primaryHash),
            '","kCommit":"',
            vm.toString(p.kCommit),
            '","policyDigest":"',
            vm.toString(p.policyDigest),
            '","contractsDigest":"',
            vm.toString(p.contractsDigest),
            '","incumbentExposureDigest":"',
            vm.toString(p.incumbentExposureDigest),
            '","incumbentKeyDigest":"',
            vm.toString(p.incumbentKeyDigest),
            '"},"reserved":{',
            reserved,
            '},"published":{',
            _slots(resultID),
            "},",
            _otherReads(resultID, r.assignmentID),
            "}\n"
        );
        string memory json = string.concat(head, body);
        string memory path = string.concat(vm.projectRoot(), FIXTURE);
        if (vm.envOr("P85_WRITE_FIXTURES", false)) vm.writeFile(path, json);
        assertEq(
            vm.readFile(path),
            json,
            "the committed publication fixture is stale; regenerate with P85_WRITE_FIXTURES=true"
        );
    }
}
