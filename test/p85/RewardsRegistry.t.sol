// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {RegistryDriver} from "./RegistryDriver.sol";
import {SealRegistry} from "../../src/SealRegistry.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {RewardPool} from "../../src/p85/RewardPool.sol";
import {ElectionParams, RootRecord, RecordKind, AckData} from "../../src/p85/P85Types.sol";

/// @notice T8 step 3: the funded reward pool over the REAL SealRegistry and bft-core's own root records (the acknowledged history of
/// `fixtures/xrepo-go-retirement.json`: Closure of G, Ack of J, Closure of J, then the Retirements). Each record is imported by the
/// system call of one registry round, applied by custody verbatim, then read by the pool from the registry; the credits are
/// compared with an independent model over the same boundaries. The pool reads the registry's progress and records exactly as
/// the live deployment does.
contract RewardsRegistryTest is P85Flow {
    string internal constant GO_RETIREMENT = "/test/p85/fixtures/xrepo-go-retirement.json";
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

    mapping(address => uint256) internal expected;
    address[] internal touched;

    function _credit(address who, uint256 amount) internal {
        if (expected[who] == 0) touched.push(who);
        expected[who] += amount;
    }

    /// @dev The model: members of `assignment` split `budget` by committed weight, rounded down, to their frozen payees.
    function _split(bytes32 assignment, uint256 budget) internal {
        bytes32[] memory ids = custody.assignmentExposures(assignment);
        uint256 total;
        uint64[] memory w = new uint64[](ids.length);
        address[] memory p = new address[](ids.length);
        for (uint256 i; i < ids.length; ++i) {
            (,,, w[i],,,, p[i],,) = custody.exposures(ids[i]);
            total += w[i];
        }
        for (uint256 i; i < ids.length; ++i) {
            _credit(p[i], budget * w[i] / total);
        }
    }

    function test_theGoAcknowledgedHistoryIsRewardedOverTheRealRegistry() public {
        bytes32 result = _publish();
        ElectionPolicy.Result memory res = election.result(result);
        RewardPool pool = factory.REWARDS();
        assertEq(address(pool.ROOTS()), driver.registry(), "the pool reads the real registry");

        // Closure of G, Ack of J, Closure of J: imported, applied by custody, then read by the pool
        for (uint256 i; i < 3; ++i) {
            _importAndApply(i);
        }
        AckData memory ack = abi.decode(_load(1).record.data, (AckData));
        while (pool.recordCursor() < 3) {
            pool.advanceRecords(2);
        }
        assertEq(pool.segmentCount(), 2);
        assertEq(pool.segmentAt(0).assignmentID, res.predecessor);
        assertEq(pool.segmentAt(0).end, ack.offset, "G ends where the root's Ack says");
        assertEq(pool.segmentAt(1).assignmentID, res.assignmentID);
        assertEq(pool.segmentAt(1).start, ack.offset);

        // the registry moves on; the pool closes everything up to its progress
        uint64 finalP = 103_500;
        _block(finalP, 605_000, _none());
        uint256 closed;
        while (true) {
            try pool.closeInterval() {
                ++closed;
            } catch {
                break;
            }
        }
        assertGt(closed, 100);

        // the model, from the boundaries alone
        uint64 a = pool.START();
        while (true) {
            uint64 end = (a / 1_000 + 1) * 1_000;
            bool second = a >= ack.offset;
            if (!second && ack.offset < end) end = ack.offset;
            if (end > finalP) break;
            _split(second ? res.assignmentID : res.predecessor, 1 ether * uint256(end - a) / 1_000);
            a = end;
        }
        assertEq(pool.nextStart(), a);
        uint256 sum;
        for (uint256 i; i < touched.length; ++i) {
            assertEq(pool.credits(touched[i]), expected[touched[i]], "credit of payee");
            sum += expected[touched[i]];
        }
        assertEq(pool.totalCredits(), sum);
        assertEq(address(pool).balance, pool.accounted() + pool.surplus());
    }
}
