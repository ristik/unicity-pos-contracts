// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";

/// @notice Drives the registry with a_sys and arbitrary other senders. System calls are built from the
/// current state so that valid transitions happen often, with one field sometimes corrupted; stranger
/// calls use arbitrary arguments. Every call is low level, so the handler itself never reverts.
contract SealRegistryHandler is SealRegistryBase {
    uint256 public strangerCallsThatChangedState;
    uint256 public successfulOpens;
    uint256 public successfulFinalizes;
    uint256 public maxRoundSeen;
    uint256 public maxClockSeen;

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
        OpenArgs memory a = firstPayload();
        a.n = uint64(uintWord("round.authorized") + 1 + (roundStep % 3));
        a.rootRound = uint64(uintWord("clock.rootRound") + (rootStep % 3));
        a.hasBlockHash = hasBlockHash;
        a.blockHash = hasBlockHash ? blockHash : bytes32(0);
        if (corrupt % 8 == 0) a.transitionCount = 1;
        if (corrupt % 8 == 1) a.shardConfHash = blockHash;
        if (corrupt % 8 == 2) a.rootEpoch = ROOT_EPOCH + 1;
        if (corrupt % 8 == 3 && a.rootRound > 0) a.rootRound -= 1;
        (bool ok,) = callAs(A_SYS, openCalldata(a));
        if (ok) {
            successfulOpens++;
            record();
        }
    }

    function systemFinalize(uint8 wrongRound, bytes32 commitment) external {
        uint64 n = uint64(uintWord("outcomes.round"));
        if (wrongRound % 5 == 0) n += 1;
        (bool ok,) = callAs(A_SYS, finalizeCalldata(n, commitment));
        if (ok) {
            successfulFinalizes++;
            record();
        }
    }

    /// A random payload almost never satisfies O2 to O10, so half of the calls use the payload a_sys
    /// would send next. Only the caller check can refuse those.
    function strangerOpen(address caller, OpenArgs memory a, bool acceptablePayload) external {
        if (caller == A_SYS) return;
        if (acceptablePayload) {
            a = firstPayload();
            a.n = uint64(uintWord("round.authorized") + 1);
            a.rootRound = uint64(uintWord("clock.rootRound"));
        }
        bytes32[FIELD_COUNT] memory before = allWords();
        (bool ok,) = callAs(caller, openCalldata(a));
        if (ok || !sameWords(before, allWords())) strangerCallsThatChangedState++;
    }

    function strangerFinalize(address caller, uint64 n, bytes32 commitment) external {
        if (caller == A_SYS) return;
        bytes32[FIELD_COUNT] memory before = allWords();
        (bool ok,) = callAs(caller, finalizeCalldata(n, commitment));
        if (ok || !sameWords(before, allWords())) strangerCallsThatChangedState++;
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
    }
}

contract SealRegistryInvariantTest is SealRegistryBase {
    SealRegistryHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new SealRegistryHandler();
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = SealRegistryHandler.systemOpen.selector;
        selectors[1] = SealRegistryHandler.systemFinalize.selector;
        selectors[2] = SealRegistryHandler.strangerOpen.selector;
        selectors[3] = SealRegistryHandler.strangerFinalize.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_genesisWordsNeverChange() public view {
        assertEq(uintWord("layoutVersion"), 1);
        assertEq(word("genesisCommitment"), GENESIS_COMMITMENT);
        assertEq(word("config.shardConfHash"), FULL_SHARD_CONF_HASH);
        assertEq(uintWord("assignment.epoch"), SHARD_EPOCH);
        assertEq(uintWord("assignment.rootEpoch"), ROOT_EPOCH);
    }

    function invariant_inertCursorsStayZero() public view {
        assertEq(word("transition.cursor"), bytes32(0));
        assertEq(word("inbox.consumed"), bytes32(0));
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
