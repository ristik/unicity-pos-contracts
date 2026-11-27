// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {SealRegistryBase} from "../SealRegistryBase.sol";
import {SealRegistry} from "../../src/SealRegistry.sol";
import {B1Entry, B1Update} from "../../src/B1Layout.sol";

/// @notice Drives the real SealRegistry at A_SR for a P85 test: installs its genesis, then runs one registry round per call (open,
/// the mandatory import of the given records at the given anchors, finalize) as the system caller. A separate contract because the
/// registry test base and the P85 test base declare the same names.
contract RegistryDriver is SealRegistryBase {
    OpenArgs internal _round;

    /// @dev The registry with its genesis, at the genesis UC time 0 of the P85 fixtures (the publication fixture's election thresholds
    /// count from the record source's UC time at initialization; the registry base's own fixture starts at 1,000).
    function install() external {
        maxEpochsFixture = MAX_EPOCHS; // the driver is etched, so its initializers never ran
        setUp();
        setWord("records.ucTime", bytes32(0));
    }

    function registry() external pure returns (address) {
        return A_SR;
    }

    function systemCaller() external pure returns (address) {
        return A_SYS;
    }

    function round(uint64 p, uint64 t, SealRegistry.ImportedRecord[] calldata es) external {
        _round = _round.n == 0 ? firstPayload() : _next(_round);
        (bool ok, bytes memory ret) = callAs(A_SYS, openCalldata(_round));
        require(ok, string(ret));
        SealRegistry reg = SealRegistry(A_SR);
        uint64 target = reg.recordCount() + uint64(es.length);
        bytes32 tip = es.length == 0
            ? bytes32(uintWord("records.targetTip"))
            : es[es.length - 1].record.recordID;
        (ok, ret) = callAs(
            A_SYS, abi.encodeCall(SealRegistry.importRootRecords, (_round.n, p, t, target, tip, es))
        );
        require(ok, "import refused");
        (ok, ret) = callAs(
            A_SYS, finalizeCalldata(_round.n, keccak256(abi.encode("p85-registry-round", _round.n)))
        );
        require(ok, "finalize refused");
    }

    /// @dev One acknowledgement round that installs the given consecutive successor root epochs (the last one open, the first starting
    /// where the former tip closes) as an ordinary EVM assignment change, with an empty record import at the current anchors. Later
    /// rounds continue in the new assignment. P85 post-term evidence (#1297) and custody's term anchors read the installed epochs.
    function advance(B1Entry[] calldata news) external {
        _advance(news);
    }

    /// @dev `advance` with `delta` generated successor entries (three placeholder members each) starting after the last root round.
    function advanceEpochs(uint64 delta) external {
        uint64 tip = uint64(b1Word("b1.importedTipEpoch"));
        B1Update memory u =
            advanceUpdate(tip, uint64(uintWord("clock.rootRound")) + delta, delta, 3);
        _advance(u.newEntries);
    }

    function _advance(B1Entry[] memory news) internal {
        OpenArgs memory a = _round.n == 0 ? firstPayload() : _next(_round);
        uint64 delta = uint64(news.length);
        uint64 oldRoot = uint64(uintWord("assignment.rootEpoch"));
        uint64 oldShard = uint64(uintWord("assignment.epoch"));
        bytes32 oldHash = word("assignment.activeConfHash");
        bytes32 newHash = keccak256(abi.encode("conf", oldRoot, delta));
        uint64 lastStart = news[news.length - 1].start;
        if (a.rootRound < lastStart) a.rootRound = lastStart;
        a.rootEpoch = oldRoot + delta;
        a.certEpoch = oldShard;
        a.authEpoch = oldShard + delta;
        a.hasBlockHash = true;
        a.blockHash = keccak256("parent block");
        a.transitionCount = 1;
        a.bodyID = keccak256("ack body");
        a.genesisID = keccak256("ack genesis");
        a.frozenID = keccak256("ack frozen");
        a.commitID = keccak256("ack commit");
        a.frozenParent = keccak256("ack frozen parent");
        a.successorTR = keccak256("ack successor TR");
        a.activeConfHash = newHash;
        a.assignment = assignmentProjection(
            oldRoot,
            oldShard,
            oldHash,
            oldRoot + delta,
            oldShard + delta,
            newHash,
            delta > 1 ? delta : 0,
            delta > 1 ? keccak256("verified span") : bytes32(0)
        );
        a.update = B1Update({
            priorTipEpoch: oldRoot, hasOldTipEnd: true, oldTipEnd: news[0].start, newEntries: news
        });
        (bool ok, bytes memory ret) = callAs(A_SYS, openCalldata(a));
        require(ok, string(ret));
        SealRegistry reg = SealRegistry(A_SR);
        SealRegistry.ImportedRecord[] memory none = new SealRegistry.ImportedRecord[](0);
        (ok, ret) = callAs(
            A_SYS,
            abi.encodeCall(
                SealRegistry.importRootRecords,
                (
                    a.n,
                    reg.progress(),
                    reg.ucTime(),
                    reg.recordCount(),
                    bytes32(uintWord("records.targetTip")),
                    none
                )
            )
        );
        require(ok, "import refused");
        (ok, ret) =
            callAs(A_SYS, finalizeCalldata(a.n, keccak256(abi.encode("p85-registry-round", a.n))));
        require(ok, "finalize refused");
        // the following plain rounds: the new assignment, no transition, no new entries
        a.certEpoch = a.authEpoch;
        a.hasBlockHash = false;
        a.blockHash = bytes32(0);
        a.transitionCount = 0;
        a.bodyID = bytes32(0);
        a.genesisID = bytes32(0);
        a.frozenID = bytes32(0);
        a.commitID = bytes32(0);
        a.frozenParent = bytes32(0);
        a.successorTR = bytes32(0);
        a.assignment = zeroProjection();
        a.update = emptyUpdate(a.rootEpoch);
        _round = a;
    }

    function zeroProjection() internal pure returns (SealRegistry.AssignmentProjection memory p) {}

    function _next(OpenArgs memory a) internal pure returns (OpenArgs memory b) {
        b = a;
        b.n = a.n + 1;
        b.rootRound = a.rootRound + 1;
        b.timestamp = a.timestamp + 1;
    }
}
