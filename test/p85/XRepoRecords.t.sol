// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {CustodyStorage} from "../../src/p85/CustodyStorage.sol";
import {ElectionParams, RootRecord, RecordKind, ClosureData} from "../../src/p85/P85Types.sol";

/// @notice The cross-repository consistency suite, contracts half (bft-core: package `xrepo`).
///
/// `fixtures/xrepo-go-records.json` is produced by bft-core from this repository's own publication fixture: the root records its
/// projection emits for one published election result, with the assignment ids the root names (the genesis assignment, the primary
/// derived from the result, the recovery assignment it announces in the RecoveryAck) and the exposure and key-history digests it
/// derives from the frozen identity records. Three histories: the primary is never acknowledged and the incumbent slate returns
/// (Closure of G, Closure of the Reserved J, RecoveryAck, Closure of K); the primary is acknowledged and later closed; the root
/// closes the session before any handoff.
///
/// This test rebuilds the publication fixture's state with the real modules and applies those records VERBATIM, one at a time: no
/// word is replaced and no identifier re-linked. Custody must accept every record, and after each one its state must be what the
/// file says the root holds. What custody then reports is written to `fixtures/xrepo-custody-view.json`, which bft-core compares
/// with its own model; the test fails when the committed view differs from what custody produces now (regenerate with
/// P85_WRITE_FIXTURES=true).
contract XRepoRecordsTest is P85Flow {
    string internal constant GO_RECORDS = "/test/p85/fixtures/xrepo-go-records.json";
    string internal constant PUBLICATION = "/test/p85/fixtures/publication.json";
    string internal constant VIEW = "/test/p85/fixtures/xrepo-custody-view.json";
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);
    bytes32 internal constant ORIGIN = keccak256("origin/1");
    /// @dev StakeCustody.pendingAssignment has no getter (the contract is at its size limit); its slot (declared in CustodyStorage) from
    /// `forge inspect StakeCustody storageLayout`. The recovery history checks it is zero, then J, then zero again, so a layout change
    /// that moves it fails the test instead of passing silently.
    uint256 internal constant PENDING_ASSIGNMENT_SLOT = 38;

    /// @dev The election parameters of PublicationFixture.t.sol: the result must be that fixture's.
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

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// @dev The steps of PublicationFixture.t.sol up to the published result.
    function _publish() internal returns (bytes32 resultID) {
        clock(100_000, 604_800);
        vm.prank(SYS);
        election.elect(ORIGIN);
        resultID = election.openResult();
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
    }

    function _rec(uint256 b, uint256 i, string memory field) internal pure returns (string memory) {
        return
            string.concat(".branches[", vm.toString(b), "].records[", vm.toString(i), "].", field);
    }

    function _step(uint256 b, uint256 s, string memory field)
        internal
        pure
        returns (string memory)
    {
        return string.concat(".branches[", vm.toString(b), "].steps[", vm.toString(s), "].", field);
    }

    function _load(string memory json, uint256 b, uint256 i)
        internal
        pure
        returns (RootRecord memory r)
    {
        r.index = uint64(vm.parseJsonUint(json, _rec(b, i, "index")));
        r.recordID = vm.parseJsonBytes32(json, _rec(b, i, "recordId"));
        r.predecessor = vm.parseJsonBytes32(json, _rec(b, i, "predecessor"));
        r.kind = RecordKind(uint8(vm.parseJsonUint(json, _rec(b, i, "kind"))));
        r.progress = uint64(vm.parseJsonUint(json, _rec(b, i, "progress")));
        r.ucTime = uint64(vm.parseJsonUint(json, _rec(b, i, "ucTime")));
        r.data = vm.parseJsonBytes(json, _rec(b, i, "data"));
    }

    function _u(uint256 v) internal pure returns (string memory) {
        return vm.toString(v);
    }

    function _stateName(uint8 s) internal pure returns (string memory) {
        if (s == 1) return "reserved";
        if (s == 2) return "active";
        if (s == 3) return "aborted";
        return "none";
    }

    function _sessionName(uint8 s) internal pure returns (string memory) {
        if (s == 1) return "open";
        if (s == 2) return "acked";
        if (s == 3) return "closed";
        if (s == 4) return "recovered";
        return "none";
    }

    function _pending() internal view returns (bytes32) {
        return vm.load(address(custody), bytes32(PENDING_ASSIGNMENT_SLOT));
    }

    /// @dev One assignment as custody holds it, in the words of bft-core's assignmentJSON.
    function _assignment(string memory role, bytes32 id) internal view returns (string memory) {
        Asg memory a = asg(id);
        bool pending = _pending() == id;
        return string.concat(
            string.concat(
                '{"role":"',
                role,
                '","assignmentId":"',
                vm.toString(id),
                '","exposureDigest":"',
                vm.toString(a.exposureDigest),
                '","keyDigest":"',
                vm.toString(a.keyDigest),
                '","state":"',
                _stateName(a.state),
                '","closed":',
                a.closed ? "true" : "false",
                ',"pending":',
                pending ? "true" : "false"
            ),
            ',"hRound":',
            _u(a.hRound),
            ',"pClose":',
            _u(a.pClose),
            ',"tClose":',
            _u(a.tClose),
            ',"offset":',
            _u(a.offset),
            ',"firstRound":',
            _u(a.firstRound),
            ',"rootEpoch":',
            _u(a.rootEpoch),
            "}"
        );
    }

    struct Ids {
        bytes32 result;
        bytes32 genesis;
        bytes32 primary;
        bytes32 recovery;
    }

    /// @dev Custody's state after `applied` records of a history.
    function _view(Ids memory ids, uint256 applied) internal view returns (string memory out) {
        CustodyStorage.Session memory s = custody.session(ids.result);
        out = string.concat(
            '{"afterRecords":',
            _u(applied),
            ',"lastAckedAssignment":"',
            vm.toString(custody.lastAckedAssignment()),
            '","pendingAssignment":"',
            vm.toString(_pending()),
            '","sessionState":"',
            _sessionName(s.state),
            '","assignments":[',
            _assignment("genesis", ids.genesis),
            ",",
            _assignment("primary", ids.primary)
        );
        if (asg(ids.recovery).state != 0) {
            out = string.concat(out, ",", _assignment("recovery", ids.recovery));
        }
        out = string.concat(out, "]}");
    }

    /// @dev Custody's state must be the step the file expects after `applied` records (the root's own statement of what it holds).
    function _checkStep(string memory json, uint256 b, uint256 s, Ids memory ids) internal view {
        assertEq(
            custody.lastAckedAssignment(),
            vm.parseJsonBytes32(json, _step(b, s, "lastAckedAssignment")),
            "last acknowledged assignment"
        );
        assertEq(
            _pending(),
            vm.parseJsonBytes32(json, _step(b, s, "pendingAssignment")),
            "pending assignment"
        );
        assertEq(
            _sessionName(custody.session(ids.result).state),
            vm.parseJsonString(json, _step(b, s, "sessionState")),
            "session state"
        );
        for (uint256 k; vm.keyExistsJson(json, _asgPath(b, s, k, "role")); ++k) {
            bytes32 id = vm.parseJsonBytes32(json, _asgPath(b, s, k, "assignmentId"));
            Asg memory a = asg(id);
            string memory role = vm.parseJsonString(json, _asgPath(b, s, k, "role"));
            assertEq(
                a.exposureDigest,
                vm.parseJsonBytes32(json, _asgPath(b, s, k, "exposureDigest")),
                string.concat(role, ": exposure digest")
            );
            assertEq(
                a.keyDigest,
                vm.parseJsonBytes32(json, _asgPath(b, s, k, "keyDigest")),
                string.concat(role, ": key digest")
            );
            assertEq(
                _stateName(a.state),
                vm.parseJsonString(json, _asgPath(b, s, k, "state")),
                string.concat(role, ": state")
            );
            assertEq(
                a.closed,
                vm.parseJsonBool(json, _asgPath(b, s, k, "closed")),
                string.concat(role, ": closed")
            );
            assertEq(
                _pending() == id,
                vm.parseJsonBool(json, _asgPath(b, s, k, "pending")),
                string.concat(role, ": pending")
            );
            assertEq(a.hRound, _n(json, b, s, k, "hRound"), string.concat(role, ": H round"));
            assertEq(a.pClose, _n(json, b, s, k, "pClose"), string.concat(role, ": p_close"));
            assertEq(a.tClose, _n(json, b, s, k, "tClose"), string.concat(role, ": t_close"));
            assertEq(a.offset, _n(json, b, s, k, "offset"), string.concat(role, ": offset"));
            assertEq(
                a.firstRound, _n(json, b, s, k, "firstRound"), string.concat(role, ": first round")
            );
            assertEq(
                a.rootEpoch, _n(json, b, s, k, "rootEpoch"), string.concat(role, ": root epoch")
            );
        }
    }

    function _asgPath(uint256 b, uint256 s, uint256 k, string memory field)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            ".branches[",
            vm.toString(b),
            "].steps[",
            vm.toString(s),
            "].assignments[",
            vm.toString(k),
            "].",
            field
        );
    }

    function _n(string memory json, uint256 b, uint256 s, uint256 k, string memory field)
        internal
        pure
        returns (uint256)
    {
        return vm.parseJsonUint(json, _asgPath(b, s, k, field));
    }

    /// @dev Applies history `b` verbatim, one record per import, and returns custody's view after each record.
    function _history(string memory json, uint256 b, Ids memory ids)
        internal
        returns (string memory out)
    {
        string memory name = vm.parseJsonString(json, string.concat(".branches[", _u(b), "].name"));
        out = string.concat('{"name":"', name, '","steps":[');
        bytes32 previous;
        uint256 s;
        for (uint256 i; vm.keyExistsJson(json, _rec(b, i, "index")); ++i) {
            RootRecord memory r = _load(json, b, i);
            assertEq(r.index, i, "indexed from zero");
            assertEq(
                r.recordID,
                keccak256(abi.encode(r.index, r.predecessor, r.kind, r.progress, r.ucTime, r.data)),
                "the record id is the keccak of the record's content"
            );
            assertEq(r.predecessor, previous, "linked to its predecessor");
            previous = r.recordID;
            roots.pushRaw(r);
            roots.setClock(r.progress, r.ucTime);
            custody.applyRootRecords(1); // verbatim: a record custody does not accept reverts here
            assertEq(custody.lastRecordID(), r.recordID, "custody's cursor is at the record");
            if (
                vm.keyExistsJson(json, _step(b, s, "afterRecords"))
                    && vm.parseJsonUint(json, _step(b, s, "afterRecords")) == i + 1
            ) {
                _checkStep(json, b, s, ids);
                out = string.concat(out, s == 0 ? "" : ",", _view(ids, i + 1));
                ++s;
            }
        }
        assertFalse(
            vm.keyExistsJson(json, _step(b, s, "afterRecords")), "every expected step was reached"
        );
        out = string.concat(out, "]}");
        assertConserved();
    }

    function test_custodyAcceptsTheRootsRecordsVerbatim() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), GO_RECORDS));
        string memory pub = vm.readFile(string.concat(vm.projectRoot(), PUBLICATION));
        Ids memory ids;
        ids.result = _publish();
        ElectionPolicy.Result memory r = election.result(ids.result);
        ids.genesis = r.predecessor;
        ids.primary = r.assignmentID;
        ids.recovery = vm.parseJsonBytes32(json, ".recoveryAssignmentId");

        // the state is the publication fixture's, and the file was produced for it
        assertEq(
            ids.result, vm.parseJsonBytes32(pub, ".resultId"), "the publication fixture's result"
        );
        assertEq(
            ids.result, vm.parseJsonBytes32(json, ".resultId"), "the records are for this result"
        );
        // the ids the root names are the keys custody holds the assignments under
        assertEq(
            vm.parseJsonBytes32(json, ".genesisAssignmentId"), ids.genesis, "genesis assignment id"
        );
        assertEq(
            ids.genesis, custody.lastAckedAssignment(), "the genesis assignment is the incumbent"
        );
        assertEq(
            vm.parseJsonBytes32(json, ".primaryAssignmentId"), ids.primary, "primary assignment id"
        );
        assertEq(_pending(), bytes32(0), "nothing is pending before the records");

        string memory out = '{"format":"UNICITY_XREPO_CUSTODY_VIEW/v1","branches":[';
        for (uint256 b; vm.keyExistsJson(json, string.concat(".branches[", _u(b), "].name")); ++b) {
            uint256 snap = vm.snapshotState();
            out = string.concat(out, b == 0 ? "" : ",", _history(json, b, ids));
            vm.revertToState(snap);
        }
        out = string.concat(out, "]}\n");

        string memory path = string.concat(vm.projectRoot(), VIEW);
        if (vm.envOr("P85_WRITE_FIXTURES", false)) vm.writeFile(path, out);
        assertEq(
            vm.readFile(path),
            out,
            "the committed custody view is stale; regenerate with P85_WRITE_FIXTURES=true and copy it to bft-core xrepo/testdata"
        );
    }

    /// @dev Record `i` of history `b` with its ClosureData changed by `how`, linked after what custody has applied.
    function _changedClosure(string memory json, uint256 b, uint256 i, uint8 how, bytes32 word)
        internal
        view
        returns (RootRecord memory r)
    {
        r = _load(json, b, i);
        ClosureData memory c = abi.decode(r.data, (ClosureData));
        if (how == 0) c.assignmentID = word;
        if (how == 1) c.exposureDigest = word;
        r.data = abi.encode(c);
        r.predecessor = custody.lastRecordID();
        r.recordID =
            keccak256(abi.encode(r.index, r.predecessor, r.kind, r.progress, r.ucTime, r.data));
    }

    function _applyVerbatim(string memory json, uint256 b, uint256 i) internal {
        RootRecord memory r = _load(json, b, i);
        roots.pushRaw(r);
        roots.setClock(r.progress, r.ucTime);
        custody.applyRootRecords(1);
    }

    function _refused(RootRecord memory r, bytes4 err) internal {
        roots.pushRaw(r);
        vm.expectRevert(err);
        custody.applyRootRecords(1);
    }

    /// @notice The three Go/Solidity disagreements that stopped the P85 lane on 2026-10-11, each as the one changed word in the root's
    /// records. Custody refuses each, which is what halted the shard then; the test above is what shows the unchanged records are
    /// accepted. (History 0 is the recovery: Closure of G, Closure of J, RecoveryAck, Closure of K.)
    function test_theDisagreementsThatStoppedTheLaneAreRefused() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), GO_RECORDS));
        bytes32 result = _publish();
        ElectionPolicy.Result memory r = election.result(result);
        bytes32 gExposure = asg(r.predecessor).exposureDigest;

        // runs 25 and 26: the first closure names a genesis assignment custody was never deployed with (the id of the base shard
        // configuration instead of the full one)
        uint256 snap = vm.snapshotState();
        _refused(
            _changedClosure(
                json, 0, 0, 0, keccak256("the genesis assignment id of another configuration")
            ),
            CustodyStorage.AssignmentNotActive.selector
        );
        vm.revertToState(snap);

        // run 27: the closure of the primary J names it by its assignment hash; custody keys a primary by its election result
        snap = vm.snapshotState();
        _applyVerbatim(json, 0, 0);
        _refused(
            _changedClosure(json, 0, 1, 0, keccak256("the assignment hash of J")),
            CustodyStorage.AssignmentNotActive.selector
        );
        vm.revertToState(snap);

        // a digest derived under another assignment's id: J's closure with the genesis assignment's exposure digest
        snap = vm.snapshotState();
        _applyVerbatim(json, 0, 0);
        _refused(
            _changedClosure(json, 0, 1, 1, gExposure), CustodyStorage.ClosureDigestMismatch.selector
        );
        vm.revertToState(snap);

        // the recovery assignment K holds the incumbent slate under K's own id: the slate's digest under the genesis id is not K's
        snap = vm.snapshotState();
        _applyVerbatim(json, 0, 0);
        _applyVerbatim(json, 0, 1);
        _applyVerbatim(json, 0, 2);
        _refused(
            _changedClosure(json, 0, 3, 1, gExposure), CustodyStorage.ClosureDigestMismatch.selector
        );
        vm.revertToState(snap);
    }
}
