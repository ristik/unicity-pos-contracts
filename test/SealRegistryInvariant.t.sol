// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {SealRegistry} from "../src/SealRegistry.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";

/// @notice Drives the registry with a_sys and arbitrary other senders. System calls are built from the
/// current state so that valid transitions happen often, with one field sometimes corrupted; stranger
/// calls use arbitrary arguments. Every call is low level, so the handler itself never reverts.
contract SealRegistryHandler is SealRegistryBase {
    uint256 public strangerCallsThatChangedState;
    uint256 public successfulOpens;
    uint256 public successfulFinalizes;
    uint256 public successfulAcknowledgements;
    uint256 public maxRoundSeen;
    uint256 public maxClockSeen;
    uint256 public maxAssignmentRootEpoch;
    uint256 public maxAssignmentShardEpoch;

    constructor() {
        // The invariant contract installs the registry; the handler only calls it.
    }

    function setUp() public override {}

    function systemOpen(
        uint8 roundStep,
        uint8 rootStep,
        bool hasBlockHash,
        bytes32 blockHash,
        uint8 corrupt
    ) external {
        OpenArgs memory a = currentPayload();
        a.n = uint64(uintWord("round.authorized") + 1 + (roundStep % 3));
        a.rootRound = uint64(uintWord("clock.rootRound") + (rootStep % 3));
        a.hasBlockHash = hasBlockHash;
        a.blockHash = hasBlockHash ? blockHash : bytes32(0);
        if (corrupt % 8 == 0) a.transitionCount = 1;
        if (corrupt % 8 == 1) a.shardConfHash = blockHash;
        if (corrupt % 8 == 2) a.rootEpoch += 1;
        if (corrupt % 8 == 3 && a.rootRound > 0) a.rootRound -= 1;
        (bool ok,) = callAs(A_SYS, openCalldata(a));
        if (ok) {
            successfulOpens++;
            record();
        }
    }

    /// The payload a_sys would send next against the stored assignment, with an empty B1 update.
    function currentPayload() internal view returns (OpenArgs memory a) {
        a = firstPayload();
        a.rootEpoch = uint64(uintWord("assignment.rootEpoch"));
        a.certEpoch = uint64(uintWord("assignment.epoch"));
        a.authEpoch = a.certEpoch;
        a.activeConfHash = word("assignment.activeConfHash");
        a.rootRound = uint64(uintWord("clock.rootRound"));
        a.update = emptyUpdate(tipEpoch());
    }

    function systemFinalize(uint8 wrongRound, bytes32 commitment) external {
        uint64 n = uint64(uintWord("outcomes.round"));
        if (wrongRound % 5 == 0) n += 1;
        tryImportEmpty(uint64(uintWord("outcomes.round"))); // the mandatory import; a refused one only makes finalize refuse
        (bool ok,) = callAs(A_SYS, finalizeCalldata(n, commitment));
        if (ok) {
            successfulFinalizes++;
            record();
        }
    }

    /// Generates root-only, ordinary assignment and multi-step supersession acknowledgements from
    /// the current storage base. This keeps valid transitions reachable under the invariant fuzzer.
    function systemAssignmentAck(uint8 kind, uint8 spanSelector, bytes32 seed) external {
        if (uintWord("phase") != 2) return;
        uint64 oldRoot = uint64(uintWord("assignment.rootEpoch"));
        uint64 oldShard = uint64(uintWord("assignment.epoch"));
        uint64 rootDelta = kind % 3 == 2 ? uint64(2 + spanSelector % 3) : 1;
        uint64 shardDelta = kind % 3 == 0 ? 0 : rootDelta;
        if (
            oldRoot > type(uint64).max - rootDelta || oldShard > type(uint64).max - shardDelta
                || uintWord("round.authorized") >= type(uint64).max
                || uintWord("clock.rootRound") >= type(uint64).max
        ) return;

        bytes32 oldHash = word("assignment.activeConfHash");
        bytes32 newHash = shardDelta == 0 ? oldHash : keccak256(abi.encode(seed, oldRoot, oldShard));
        if (shardDelta != 0 && newHash == oldHash) {
            newHash = keccak256(abi.encode(seed, "changed"));
        }
        uint64 span = rootDelta > 1 ? rootDelta : 0;
        bytes32 spanCommitment = span == 0 ? bytes32(0) : keccak256(abi.encode(seed, oldRoot, span));
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            oldRoot,
            oldShard,
            oldHash,
            oldRoot + rootDelta,
            oldShard + shardDelta,
            newHash,
            span,
            spanCommitment
        );
        OpenArgs memory a = firstPayload();
        a.n = uint64(uintWord("round.authorized") + 1);
        // The origin round advances by the epoch delta, so every new interval starts after the tip.
        a.rootRound = uint64(uintWord("clock.rootRound") + rootDelta);
        a.update = advanceUpdate(tipEpoch(), a.rootRound, rootDelta, 2);
        a.rootEpoch = oldRoot + rootDelta;
        a.certEpoch = oldShard;
        a.authEpoch = oldShard + shardDelta;
        a.hasBlockHash = true;
        a.blockHash = keccak256(abi.encode(seed, a.n));
        a.transitionCount = 1;
        a.bodyID = keccak256(abi.encode("body", seed));
        a.genesisID = keccak256(abi.encode("genesis", seed));
        a.frozenID = keccak256(abi.encode("frozen", seed));
        a.commitID = keccak256(abi.encode("commit", seed));
        a.frozenParent = keccak256(abi.encode("parent", seed));
        a.successorTR = keccak256(abi.encode("successor", seed));
        a.activeConfHash = newHash;
        a.assignment = p;
        (bool ok,) = callAs(A_SYS, openCalldata(a));
        if (!ok) return;
        successfulOpens++;
        successfulAcknowledgements++;
        record();
        tryImportEmpty(a.n);
        (ok,) = callAs(A_SYS, finalizeCalldata(a.n, keccak256(abi.encode("outcome", seed))));
        if (ok) {
            successfulFinalizes++;
            record();
        }
    }

    /// A random payload almost never satisfies O2 to O10, so half of the calls use the payload a_sys
    /// would send next. Only the caller check can refuse those.
    function strangerOpen(address caller, uint256 seed, bool acceptablePayload) external {
        if (caller == A_SYS) return;
        OpenArgs memory a = randomArgs(seed);
        if (acceptablePayload) {
            a = currentPayload();
            a.n = uint64(uintWord("round.authorized") + 1);
        }
        bytes32[FIELD_COUNT] memory before = allWords();
        bytes32 b1Before = b1DigestLight();
        (bool ok,) = callAs(caller, openCalldata(a));
        if (ok || !sameWords(before, allWords()) || b1Before != b1DigestLight()) {
            strangerCallsThatChangedState++;
        }
    }

    function strangerFinalize(address caller, uint64 n, bytes32 commitment) external {
        if (caller == A_SYS) return;
        bytes32[FIELD_COUNT] memory before = allWords();
        bytes32 b1Before = b1DigestLight();
        (bool ok,) = callAs(caller, finalizeCalldata(n, commitment));
        if (ok || !sameWords(before, allWords()) || b1Before != b1DigestLight()) {
            strangerCallsThatChangedState++;
        }
    }

    function sameWords(bytes32[FIELD_COUNT] memory a, bytes32[FIELD_COUNT] memory b)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    function record() internal {
        uint256 round = uintWord("round.authorized");
        uint256 clock = uintWord("clock.rootRound");
        require(round >= maxRoundSeen, "round decreased");
        require(clock >= maxClockSeen, "clock decreased");
        maxRoundSeen = round;
        maxClockSeen = clock;
        maxAssignmentRootEpoch = uintWord("assignment.rootEpoch");
        maxAssignmentShardEpoch = uintWord("assignment.epoch");
    }
}

contract SealRegistryInvariantTest is SealRegistryBase {
    SealRegistryHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new SealRegistryHandler();
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = SealRegistryHandler.systemOpen.selector;
        selectors[1] = SealRegistryHandler.systemFinalize.selector;
        selectors[2] = SealRegistryHandler.strangerOpen.selector;
        selectors[3] = SealRegistryHandler.strangerFinalize.selector;
        selectors[4] = SealRegistryHandler.systemAssignmentAck.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_genesisIdentityAndActiveHashStayValid() public view {
        assertEq(b1Word("b1.initialized"), 1);
        assertEq(b1Word("b1.wCert"), W_CERT);
        assertEq(bytes32(b1Word("b1.profileHash")), PROFILE_HASH);
        assertEq(b1Word("b1.network"), NETWORK);
        assertEq(word("genesisCommitment"), GENESIS_COMMITMENT);
        assertEq(word("config.shardConfHash"), FULL_SHARD_CONF_HASH);
        assertTrue(word("assignment.activeConfHash") != bytes32(0));
    }

    function invariant_assignmentEpochsNeverRegressAndStayOrdered() public view {
        uint256 rootEpoch = uintWord("assignment.rootEpoch");
        uint256 shardEpoch = uintWord("assignment.epoch");
        assertGe(rootEpoch, handler.maxAssignmentRootEpoch());
        assertGe(shardEpoch, handler.maxAssignmentShardEpoch());
        assertGe(rootEpoch - ROOT_EPOCH, shardEpoch - SHARD_EPOCH);
    }

    function invariant_supersessionCommitmentHasAdvancedAssignment() public view {
        if (word("assignment.spanCommitment") != bytes32(0)) {
            assertGt(uintWord("assignment.rootEpoch"), ROOT_EPOCH);
            assertGt(uintWord("assignment.epoch"), SHARD_EPOCH);
            assertTrue(word("assignment.activeConfHash") != FULL_SHARD_CONF_HASH);
        }
    }

    function invariant_ackCursorMatchesSuccessfulAcknowledgements() public view {
        assertEq(uintWord("transition.cursor"), handler.successfulAcknowledgements());
        assertEq(word("inbox.consumed"), bytes32(0));
    }

    /// The ring is never empty or over K_max, its epochs are consecutive and its intervals contiguous
    /// with exactly one open tail, which is the assignment's root epoch once a block has opened.
    function invariant_ringIsAContiguousLiveSetWithOneOpenTail() public view {
        uint256 count = b1Word("b1.count");
        assertGe(count, 1);
        assertLe(count, kMax());
        assertLt(b1Word("b1.head"), kMax());
        uint256[] memory es = liveEpochs();
        for (uint256 i = 0; i < es.length; i++) {
            assertEq(ent(es[i], 0), bytes32(uint256(1)), "live entry present");
            bool last = i == es.length - 1;
            assertEq(uint256(ent(es[i], 6)), last ? 0 : 1, "only the tail is open");
            if (!last) {
                assertEq(es[i + 1], es[i] + 1, "consecutive epochs");
                assertEq(ent(es[i], 5), ent(es[i + 1], 4), "end is the next start");
            }
        }
        assertEq(es[es.length - 1], uintWord("assignment.rootEpoch"), "tail is the root epoch");
        // No stale words for epochs that have left the window.
        for (uint256 e = 0; e < es[0] && e < TRACK_EPOCHS; e++) {
            assertEntryAbsent(e, TRACK_MEMBERS);
        }
    }

    function invariant_phaseIsOpenOrFinalized() public view {
        uint256 phase = uintWord("phase");
        assertTrue(phase == 1 || phase == 2);
    }

    function invariant_roundAndClockNeverDecrease() public view {
        assertGe(uintWord("round.authorized"), handler.maxRoundSeen());
        assertGe(uintWord("clock.rootRound"), handler.maxClockSeen());
    }

    function invariant_outcomesTrackTheAuthorizedRound() public view {
        assertEq(uintWord("outcomes.round"), uintWord("round.authorized"));
        if (uintWord("phase") == 1) assertEq(word("outcomes.commitment"), bytes32(0));
    }

    function invariant_strangersNeverChangeState() public view {
        assertEq(handler.strangerCallsThatChangedState(), 0);
    }

    function invariant_finalizesNeverExceedOpens() public view {
        assertLe(handler.successfulFinalizes(), handler.successfulOpens());
    }

    /// Recorded so a run shows the handler reached real transitions rather than only refusals.
    function afterInvariant() public view {
        assertGt(handler.successfulOpens(), 0, "the handler must reach successful opens");
    }
}
