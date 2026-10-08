// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {RecordKind} from "../../src/p85/P85Types.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";

/// @notice The custody storage the root authenticates with Ethereum storage proofs (briefs/p85-pr1c-control-records.md sections 3 and 4):
/// for each scenario, the exact storage slots the public getters read, recorded by the EVM itself (`vm.accesses`), with their words, and
/// the facts those words encode. bft-core derives every slot from the declared layout and must land on the recorded one; the
/// fixture is generated here, never written by hand. The test fails when the committed fixture differs from what custody produces now;
/// run with P85_WRITE_FIXTURES=1 to regenerate.
contract StateSlotsTest is P85Flow {
    string internal constant FIXTURE = "/test/p85/fixtures/state-slots.json";

    function _u(uint256 v) internal pure returns (string memory) {
        return vm.toString(v);
    }

    function _unique(bytes32[] memory in_) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](in_.length);
        uint256 n;
        for (uint256 i; i < in_.length; ++i) {
            bool seen;
            for (uint256 j; j < n; ++j) {
                if (out[j] == in_[i]) seen = true;
            }
            if (!seen) out[n++] = in_[i];
        }
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    /// @dev One getter call, recorded: the slots it read and their words.
    function _read(string memory name, string memory args, bytes memory callData)
        internal
        returns (string memory)
    {
        vm.record();
        (bool ok,) = address(custody).staticcall(callData);
        require(ok, "getter failed");
        (bytes32[] memory reads,) = vm.accesses(address(custody));
        reads = _unique(reads);
        string memory slots = "[";
        string memory words = "[";
        for (uint256 i; i < reads.length; ++i) {
            string memory sep = i == 0 ? "" : ",";
            slots = string.concat(slots, sep, '"', vm.toString(reads[i]), '"');
            words = string.concat(
                words, sep, '"', vm.toString(vm.load(address(custody), reads[i])), '"'
            );
        }
        return string.concat(
            '{"name":"', name, '","args":', args, ',"slots":', slots, '],"words":', words, "]}"
        );
    }

    function _generationReads(uint64 id, uint64 gen) internal returns (string memory out) {
        out = string.concat(
            _read(
                "positions",
                string.concat("[", _u(id), "]"),
                abi.encodeCall(custody.positions, (id))
            ),
            ",",
            _read(
                "retirements",
                string.concat("[", _u(id), ",", _u(gen), "]"),
                abi.encodeCall(custody.retirements, (id, gen))
            ),
            ",",
            _read(
                "liveExposures",
                string.concat("[", _u(id), ",", _u(gen), "]"),
                abi.encodeCall(custody.liveExposures, (id, gen))
            ),
            ",",
            _read(
                "exposureChain",
                string.concat("[", _u(id), ",", _u(gen), "]"),
                abi.encodeCall(custody.exposureChain, (id, gen))
            )
        );
        out = string.concat(
            out,
            ",",
            _read(
                "maxLiabilityAnchor",
                string.concat("[", _u(id), ",", _u(gen), "]"),
                abi.encodeCall(custody.maxLiabilityAnchor, (id, gen))
            ),
            ",",
            _read(
                "generationLots",
                string.concat("[", _u(id), ",", _u(gen), "]"),
                abi.encodeCall(custody.generationLots, (id, gen))
            )
        );
        uint256[] memory lots = custody.generationLots(id, gen);
        for (uint256 i; i < lots.length; ++i) {
            out = string.concat(
                out,
                ",",
                _read(
                    "lots",
                    string.concat("[", _u(lots[i]), "]"),
                    abi.encodeCall(custody.lots, (lots[i]))
                )
            );
        }
    }

    function _scalarReads() internal returns (string memory) {
        return string.concat(
            _read("network", "[]", abi.encodeCall(custody.network, ())),
            ",",
            _read("roots", "[]", abi.encodeCall(custody.roots, ())),
            ",",
            _read("limits", "[]", abi.encodeCall(custody.limits, ())),
            ",",
            _read("recordCursor", "[]", abi.encodeCall(custody.recordCursor, ())),
            ",",
            _read("lastAckedAssignment", "[]", abi.encodeCall(custody.lastAckedAssignment, ()))
        );
    }

    function _lotRefs(uint64 id, uint64 gen) internal view returns (string memory out) {
        uint256[] memory lots = custody.generationLots(id, gen);
        out = "[";
        for (uint256 i; i < lots.length; ++i) {
            out = string.concat(out, i == 0 ? "" : ",", _u(lotv(lots[i]).refCount));
        }
        out = string.concat(out, "]");
    }

    /// @dev A retirement scenario: the reads and the facts custody's own getters report for (id, generation).
    function _retirement(string memory name, uint64 id) internal returns (string memory) {
        (,,,, uint64 gen,,,, bool requested) = custody.positions(id);
        (bool imported,,) = custody.retirements(id, gen);
        return string.concat(
            '{"name":"',
            name,
            '","kind":"retirement","id":',
            _u(id),
            ',"generation":',
            _u(gen),
            ',"reads":[',
            _scalarReads(),
            ",",
            _generationReads(id, gen),
            '],"facts":{"requested":',
            requested ? "true" : "false",
            ',"imported":',
            imported ? "true" : "false",
            ',"liveExposures":',
            _u(custody.liveExposures(id, gen)),
            ',"refDigest":"',
            vm.toString(custody.exposureChain(id, gen)),
            '","maxLiabilityAnchor":',
            _u(custody.maxLiabilityAnchor(id, gen)),
            ',"lotRefs":',
            _lotRefs(id, gen),
            ',"recordCursor":',
            _u(custody.recordCursor()),
            ',"rootsCount":',
            _u(roots.recordCount()),
            "}}"
        );
    }

    function _reject(string memory name, bytes32 resultID) internal returns (string memory) {
        StakeCustody.Session memory s = custody.session(resultID);
        (uint8 asgState,,,,,,,,,,,,,,,) = custody.assignments(s.assignmentID);
        return string.concat(
            '{"name":"',
            name,
            '","kind":"reject","resultId":"',
            vm.toString(resultID),
            '","reads":[',
            _scalarReads(),
            ",",
            _read(
                "session",
                string.concat('["', vm.toString(resultID), '"]'),
                abi.encodeCall(custody.session, (resultID))
            ),
            ",",
            _read(
                "assignments",
                string.concat('["', vm.toString(s.assignmentID), '"]'),
                abi.encodeCall(custody.assignments, (s.assignmentID))
            ),
            '],"facts":{"sessionState":',
            _u(s.state),
            ',"attempt":',
            _u(s.attempt),
            ',"assignmentState":',
            _u(asgState),
            ',"incumbent":"',
            vm.toString(s.incumbentAssignmentID),
            '","lastAcked":"',
            vm.toString(custody.lastAckedAssignment()),
            '"}}'
        );
    }

    function _scenarios() internal returns (string memory out) {
        uint256 snap = vm.snapshotState();
        // nothing requested: a genesis identity with its genesis exposure live
        string memory plain = _retirement("not-requested", gid(0));
        // requested, but the genesis exposure is still live
        requestRetirement(0);
        string memory live = _retirement("requested-live", gid(0));
        vm.revertToState(snap);

        // requested, dropped by J, genesis closed: every reference released, the retirement record not yet imported
        requestRetirement(0);
        handoffExcluding(0);
        closeGenesisAt(150, 1_200);
        string memory ready = _retirement("retirable", gid(0));
        // the identity that stayed has live references in J
        string memory stayed = _retirement("stayed-in-j", gid(1));
        retireRecordAt(gid(0), 160, 1_210);
        string memory imported = _retirement("imported", gid(0));
        vm.revertToState(snap);

        // an open session: reserved, not acknowledged
        reserve(RES_J, ASG_J, allExcept(0), 1);
        string memory open_ = _reject("session-open", RES_J);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        string memory acked = _reject("session-acknowledged", RES_J);
        vm.revertToState(snap);

        reserve(RES_J, ASG_J, allExcept(0), 1);
        pushRecord(RecordKind.SessionClosed, abi.encode(RES_J));
        applyAll();
        string memory closed = _reject("session-closed", RES_J);

        out = string.concat(
            "[", plain, ",", live, ",", ready, ",", stayed, ",", imported, ",", open_
        );
        out = string.concat(out, ",", acked, ",", closed, "]");
    }

    function test_custodyStorageSlotsAreTheSharedFixture() public {
        string memory json = string.concat(
            '{"format":"UNICITY_P85_STATE_SLOTS/v1","custody":"',
            vm.toString(address(custody)),
            '","networkWord":"',
            vm.toString(NETWORK),
            '","scenarios":',
            _scenarios(),
            "}\n"
        );
        string memory path = string.concat(vm.projectRoot(), FIXTURE);
        if (vm.envOr("P85_WRITE_FIXTURES", false)) vm.writeFile(path, json);
        assertEq(
            vm.readFile(path),
            json,
            "the committed state-slots fixture is stale; regenerate with P85_WRITE_FIXTURES=1"
        );
    }
}
