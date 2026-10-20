// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {RegistryDriver} from "./RegistryDriver.sol";
import {SealRegistry} from "../../src/SealRegistry.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {CustodyStorage} from "../../src/p85/CustodyStorage.sol";
import {ElectionParams, RootRecord, RecordKind, RetirementData} from "../../src/p85/P85Types.sol";

/// @notice The cross-repository retirement and evidence case, contracts half (bft-core: `xrepo/retirement_test.go`).
///
/// `fixtures/xrepo-go-retirement.json` is produced by bft-core from this repository's publication fixture: the records the root's
/// projection emits for the acknowledged history (Closure of G, Ack of J, Closure of J) followed by the Retirements of identities 1
/// and 2, whose reference digests are the evmassign model of custody's exposure-chain storage word (a root reads it from custody's storage proof); and two
/// conflicting scheme 2 root votes of identity 1's root key in J's epoch, built by the root's statement derivation and signed by the
/// root's signer.
///
/// This test rebuilds the publication fixture's state with the real modules, reading root records from the real SealRegistry. Each
/// record is imported by the system call of one registry round and applied by custody VERBATIM: no word is replaced. Identity 1's
/// generation retires and is then charged for the Go-signed equivocation through its historical exposure in J, so its lot is held;
/// identity 2's lot is clean. Past the gates the clean lot matures and its credit is claimed while the held lot cannot mature; once
/// the case is settled the held lot matures with the penalty deducted and is claimed too.
contract XRepoRetirementTest is P85Flow {
    string internal constant GO_RETIREMENT = "/test/p85/fixtures/xrepo-go-retirement.json";
    string internal constant PUBLICATION = "/test/p85/fixtures/publication.json";
    bytes32 internal constant ORIGIN = keccak256("origin/1");

    RegistryDriver internal driver;
    address internal sys;
    string internal _json;

    function setUp() public override {
        // placed, not created: the test's nonce (and so the module addresses the result id commits to) stays the publication fixture's
        driver = RegistryDriver(address(uint160(uint256(keccak256("p85-test-registry-driver")))));
        vm.etch(address(driver), type(RegistryDriver).runtimeCode);
        uint64 nonce = vm.getNonce(address(this));
        driver.install(); // the registry with its genesis
        vm.setNonceUnsafe(address(this), nonce); // the install's creation must not move the module addresses either
        sys = driver.systemCaller();
        super.setUp(); // custody, election and evidence read their root records from it
        _json = vm.readFile(string.concat(vm.projectRoot(), GO_RETIREMENT));
    }

    function _recordSource() internal view override returns (address) {
        return driver.registry();
    }

    /// @dev The election parameters of PublicationFixture.t.sol: the result must be that fixture's.
    function _electionParams() internal pure override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 2,
            nTarget: 10,
            nMax: 16,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: 100_000,
            cadenceSeconds: 604_800
        });
    }

    // --- the registry ------------------------------------------------------------------------------------

    /// @dev One registry round importing these records (or none) at anchors (p, t).
    function _block(uint64 p, uint64 t, SealRegistry.ImportedRecord[] memory es) internal {
        driver.round(p, t, es);
    }

    function _rec(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".records[", vm.toString(i), "].", field);
    }

    function _load(uint256 i) internal view returns (SealRegistry.ImportedRecord memory e) {
        RootRecord memory r;
        r.index = uint64(vm.parseJsonUint(_json, _rec(i, "index")));
        r.recordID = vm.parseJsonBytes32(_json, _rec(i, "recordId"));
        r.predecessor = vm.parseJsonBytes32(_json, _rec(i, "predecessor"));
        r.kind = RecordKind(uint8(vm.parseJsonUint(_json, _rec(i, "kind"))));
        r.progress = uint64(vm.parseJsonUint(_json, _rec(i, "progress")));
        r.ucTime = uint64(vm.parseJsonUint(_json, _rec(i, "ucTime")));
        r.data = vm.parseJsonBytes(_json, _rec(i, "data"));
        e = SealRegistry.ImportedRecord(r, uint64(vm.parseJsonUint(_json, _rec(i, "closedEpoch"))));
    }

    /// @dev Record i of the file, imported in its own registry round at its own anchors and applied by custody as it is.
    function _importAndApply(uint256 i) internal {
        SealRegistry.ImportedRecord[] memory es = new SealRegistry.ImportedRecord[](1);
        es[0] = _load(i);
        _block(es[0].record.progress, es[0].record.ucTime, es);
        custody.applyRootRecords(1); // verbatim: a record custody does not accept reverts here
        assertEq(custody.lastRecordID(), es[0].record.recordID, "custody's cursor is at the record");
    }

    function _none() internal pure returns (SealRegistry.ImportedRecord[] memory) {
        return new SealRegistry.ImportedRecord[](0);
    }

    // --- the publication fixture ---------------------------------------------------------------------------

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// @dev The steps of PublicationFixture.t.sol up to the published result, with the clock taken from the registry.
    function _publish() internal returns (bytes32 resultID) {
        _block(100_000, 604_800, _none());
        vm.prank(sys);
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

    // --- the evidence ----------------------------------------------------------------------------------------

    function _ev(string memory field) internal pure returns (string memory) {
        return string.concat(".evidence.", field);
    }

    function _vote(string memory which) internal view returns (Evidence.SignedVote memory v) {
        v.parent = uint64(vm.parseJsonUint(_json, _ev(string.concat(which, ".parent"))));
        v.exec = vm.parseJsonBytes32(_json, _ev(string.concat(which, ".exec")));
        v.timestamp = uint64(vm.parseJsonUint(_json, _ev(string.concat(which, ".timestamp"))));
        v.signature = vm.parseJsonBytes(_json, _ev(string.concat(which, ".signature")));
    }

    function _header() internal view returns (Evidence.VoteHeader memory h) {
        h = Evidence.VoteHeader(
            NETWORK,
            1,
            vm.parseJsonBytes(_json, _ev("key")),
            uint64(vm.parseJsonUint(_json, _ev("votingEpoch"))),
            uint64(vm.parseJsonUint(_json, _ev("votingRound")))
        );
    }

    // --- the test --------------------------------------------------------------------------------------------

    function test_aGoRetirementMaturesAndClaimsAndAGoSignedOffenceHoldsTheRetiredLot() public {
        bytes32 result = _publish();
        ElectionPolicy.Result memory res = election.result(result);
        assertEq(result, vm.parseJsonBytes32(_json, ".resultId"), "the records are for this result");
        assertEq(
            result,
            vm.parseJsonBytes32(
                vm.readFile(string.concat(vm.projectRoot(), PUBLICATION)), ".resultId"
            ),
            "the publication fixture's result"
        );
        assertEq(vm.parseJsonBytes32(_json, ".genesisAssignmentId"), res.predecessor);
        assertEq(vm.parseJsonBytes32(_json, ".primaryAssignmentId"), res.assignmentID);
        // the Go signer signed for this deployment's root network and genesis
        assertEq(evidence.rootNetwork(), vm.parseJsonUint(_json, _ev("rootNetwork")));
        assertEq(evidence.rootGenesis(), vm.parseJsonBytes32(_json, _ev("rootGenesis")));

        // the acknowledged history: Closure of G, Ack of J, Closure of J; every exposure of identities 1 and 2 is then released
        for (uint256 i; i < 3; ++i) {
            _importAndApply(i);
        }
        uint256[2] memory lot;
        for (uint256 k; k < 2; ++k) {
            string memory r = string.concat(".retirements[", vm.toString(k), "]");
            uint64 id = uint64(vm.parseJsonUint(_json, string.concat(r, ".id")));
            uint64 gen = uint64(vm.parseJsonUint(_json, string.concat(r, ".generation")));
            lot[k] = vm.parseJsonUint(_json, string.concat(r, ".lot"));
            assertEq(custody.liveExposures(id, gen), 0, "no live exposure is left");
            assertEq(
                custody.exposureChain(id, gen),
                vm.parseJsonBytes32(_json, string.concat(r, ".refDigest")),
                "the root's reference digest is custody's exposure chain"
            );
            assertEq(
                custody.maxLiabilityAnchor(id, gen),
                vm.parseJsonUint(_json, string.concat(r, ".maxLiabilityAnchor")),
                "and its liability anchor the one the root waited for"
            );
            bytes32[] memory exps =
                vm.parseJsonBytes32Array(_json, string.concat(r, ".exposureIds"));
            assertEq(exps[0], exposureID(res.predecessor, id), "G's exposure");
            assertEq(exps[1], exposureID(res.assignmentID, id), "J's exposure");
            vm.prank(vm.addr(ownerPk(id - 1)));
            custody.requestRetirement(id);
        }

        // a Retirement whose reference digest is one word off is refused by custody (the registry stores any well-formed record)
        {
            uint256 snap = vm.snapshotState();
            SealRegistry.ImportedRecord[] memory es = new SealRegistry.ImportedRecord[](1);
            es[0] = _load(3);
            RetirementData memory d = abi.decode(es[0].record.data, (RetirementData));
            d.refDigest = keccak256("another digest");
            es[0].record.data = abi.encode(d);
            RootRecord memory r = es[0].record;
            es[0].record.recordID =
                keccak256(abi.encode(r.index, r.predecessor, r.kind, r.progress, r.ucTime, r.data));
            _block(r.progress, r.ucTime, es);
            vm.expectRevert(CustodyStorage.RefDigestMismatch.selector);
            custody.applyRootRecords(1);
            vm.revertToState(snap);
        }

        // the Retirements, verbatim
        _importAndApply(3);
        _importAndApply(4);
        for (uint256 k; k < 2; ++k) {
            (bool imported, uint64 pRet,) = custody.retirements(uint64(k + 1), 1);
            assertTrue(imported, "the generation is retired");
            assertEq(pRet, _load(3 + k).record.progress, "at the record's progress");
        }

        // identity 1's retired root key equivocated in J's epoch: the Go pair is what the contract verifies, and it is charged to
        // the historical exposure in J, holding identity 1's lot only
        Evidence.VoteHeader memory h = _header();
        Evidence.SignedVote memory a = _vote("a");
        Evidence.SignedVote memory b = _vote("b");
        assertEq(evidence.votePreimage(h, a), vm.parseJsonBytes(_json, _ev("a.preimage")));
        assertEq(evidence.voteDigest(h, b), vm.parseJsonBytes32(_json, _ev("b.digest")));
        bytes32 exposure = vm.parseJsonBytes32(_json, _ev("exposureId"));
        assertEq(exposure, exposureID(res.assignmentID, 1), "J's exposure of identity 1");
        vm.prank(reporter);
        bytes32 caseID = evidence.submitEvidence(h, a, b, exposure);
        assertEq(evidence.pendingHolds(lot[0]), 1, "the retired identity's lot is held");
        assertEq(evidence.pendingHolds(lot[1]), 0, "the other lot is clean");

        // past every gate (hold, evidence window, retirement and UC-time floors)
        _block(110_000, 700_000, _none());

        uint256[] memory one = new uint256[](1);
        one[0] = lot[0];
        vm.expectRevert(CustodyStorage.EvidenceHoldPending.selector);
        custody.mature(one);

        // the clean lot matures to its withdrawal address and is claimed
        uint256 clean = lotv(lot[1]).remaining;
        one[0] = lot[1];
        custody.mature(one);
        address wd2 = vm.addr(wdPk(1));
        assertEq(custody.credit(wd2), clean);
        uint256 before = wd2.balance;
        vm.prank(wd2);
        custody.claim(clean, wd2);
        assertEq(wd2.balance - before, clean, "the clean lot's principal is withdrawn");

        // settling the case debits the held lot and lifts the hold; it then matures with the penalty deducted
        uint256 initial = lotv(lot[0]).remaining;
        uint256[] memory ids = new uint256[](1);
        ids[0] = lot[0];
        uint256 debit = evidence.settleEvidence(caseID, ids);
        assertGt(debit, 0, "the offence is charged");
        assertEq(evidence.pendingHolds(lot[0]), 0);
        one[0] = lot[0];
        custody.mature(one);
        address wd1 = vm.addr(wdPk(0));
        assertEq(custody.credit(wd1), initial - debit, "the held lot matures less its penalty");
        before = wd1.balance;
        vm.prank(wd1);
        custody.claim(initial - debit, wd1);
        assertEq(wd1.balance - before, initial - debit);
        assertConserved();
    }
}
