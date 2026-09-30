// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {SealRegistry} from "../src/SealRegistry.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";
import {Vm} from "forge-std/Vm.sol";

/// @notice Unit, boundary and malicious-caller tests for the H3 assignment-aware registry projection.
/// Each refusal test first establishes that the unmodified call would succeed, then checks its error
/// and proves every stored word stayed unchanged.
contract SealRegistryTest is SealRegistryBase {
    // ---------------------------------------------------------------- identity and genesis

    function test_slotKeysMatchTheIndependentVector() public pure {
        // Printed by bft-core `go test ./docs/design/models/f4aregistry/ -run TestSlotKeys -v`.
        bytes32[FIELD_COUNT] memory want = [
            bytes32(0x79b704796b8c2ee2cf835e5113e27bbaf138c9831ce0b1cc259966898323094a),
            0x1dc271a4e4328f3a46506e6e6e1db1488418d59ca41e005534ed0eda129e6150,
            0xabe1d0722ec7cab6bc8be8343a4900e571bdb46fad619947267449a2b9aa7497,
            0x7671d07e8accfd833bdccd596ad3a1c4a402a090b727f511a073a2498c590ae5,
            0xe77628dabc86b477c0db337bda981ad320031675934be9c596d69ebbc20f1a24,
            0xbcc6e80fb08120fa6610a12120697a935440b6f731eb387496a45ae31fc4f093,
            0x1333275c0dde98dea1f7569da4a9013691786d62030b101d14f0f6d68f27fd66,
            0xc3adc23527bab9702dd784bd0b145d2ab1a7dce35235a0db3dbfd3da7a53143d,
            0x1dfe98fa5011e0dbfdfc5efa804744e3497514271b58499de63781a9941c9a51,
            0x459cf503c328e501962bcf0cd8ca53327ab531deeb9155c48d827d2478932c6c,
            0x8af142b0300add3b2aec220298bb445eb0c9884bb45fcd5059be6fcd18e7090d,
            0xbee6419aa5a12f10d4794669dbd882527b590089e967b14012543a23e0b78e72,
            0xe58f62addabf9360d9fcddf3db70a93d2b2ba476996540ecefbbed5ee3cc9c80,
            0x14386166497930a3efb28f5976da18bcbf7bec69c7b2c449c3ce32552f037844,
            0xa0cbe06c0b5a76b8d67341bd1bd8f162e5d5c6aea162604a10cec0dce4e0d060,
            0x47a3f86feb14af4a7e5a1a1fb3362c95b32dfbf03a7a3ca31717f8e829382b3c,
            0xe39f0827feecb5f38ffbd452e7c3556ecd0ba586a94434c3f5a10f846cbbfcea,
            0x1b118c38b50e4765caa320a933997b81ec1218283e0c260e18a4609340314deb,
            0x80ce058bdccaa08590781edd25c9005041ebaba94b6a8941896d46eb60394931,
            0x2d5c30492e4b770265db26c3b2d89794cb0435f97f91a351ae818c18236222a7,
            0xa6dfb02f4e0457f6dc0ca8f4fd82b31c4a0df5261e0214610377f2af855a5ee5,
            0x435c00c3e0bb551759ef849ef59de7b0a62c300b5c1aa3011d4363b09ddef85a,
            0x9071048d24ef915056944fc390854c5afc82c7b780af60912f32c98b8a009850,
            0x902fa8def05f8c67caa8c59344f53ee4ebbc428d5073e5fbf37e23543232cae5,
            0xf64ae08ca348865e7c42acf81d3a418af899eeafa1c21504ea348c15d212c4b8,
            0xdedd17782b4935024a9ff293bbd39d406d127447bf3b1d6ed496032fa0cd58e5,
            0xa17f343c4f400f901a88319ee38011c1770dfd251fb8f2afb0e66b3ac0e3d1a5,
            0xecd1c378aba52fc330dbbc613de4db55413282426cdedf09fd6ed57a76bc90b5,
            0xf4f5ae5954831b1d1559d70dc2cabdc751ef64cc34ab0750efbd97479665f06a,
            0xaf0d5400378db3d13018c5af67f324d41d95126cd3f97f3e3b4ac05ba9afdaeb
        ];
        string[FIELD_COUNT] memory names = fieldNames();
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            assertEq(slotKey(names[i]), want[i], names[i]);
        }
    }

    function test_selectorsAreTheSpecifiedSignatures() public pure {
        assertEq(SealRegistry.open.selector, bytes4(keccak256(bytes(OPEN_SIGNATURE))));
        assertEq(SealRegistry.open.selector, bytes4(0x45cf8245), "pinned v2 open selector");
        assertEq(SealRegistry.finalize.selector, bytes4(keccak256(bytes(FINALIZE_SIGNATURE))));
    }

    function test_openCalldataHasThirtyTwoStaticWords() public pure {
        bytes memory projected = openCalldata(firstPayload());
        assertEq(projected.length, 4 + 32 * 32);
        assertEq(projected.length - (4 + 22 * 32), 10 * 32, "320-byte assignment witness growth");
    }

    function test_genesisIsExactlySevenWords() public view {
        string[FIELD_COUNT] memory names = fieldNames();
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            bytes32 got = vm.load(A_SR, slotKey(names[i]));
            bytes32 name = keccak256(bytes(names[i]));
            if (name == keccak256("layoutVersion")) {
                assertEq(got, bytes32(uint256(2)));
            } else if (name == keccak256("genesisCommitment")) {
                assertEq(got, GENESIS_COMMITMENT);
            } else if (name == keccak256("config.shardConfHash")) {
                assertEq(got, FULL_SHARD_CONF_HASH);
            } else if (name == keccak256("assignment.epoch")) {
                assertEq(got, bytes32(uint256(SHARD_EPOCH)));
            } else if (name == keccak256("assignment.rootEpoch")) {
                assertEq(got, bytes32(uint256(ROOT_EPOCH)));
            } else if (name == keccak256("assignment.activeConfHash")) {
                assertEq(got, FULL_SHARD_CONF_HASH);
            } else if (name == keccak256("phase")) {
                assertEq(got, bytes32(uint256(2)));
            } else {
                assertEq(got, bytes32(0), names[i]);
            }
        }
    }

    // ---------------------------------------------------------------- successful transitions

    /// §9.2: first post-genesis payload, system-only.
    function test_firstPayloadOpenThenFinalizeWritesExactlyTheSpecifiedWords() public {
        OpenArgs memory a = firstPayload();
        bytes32[FIELD_COUNT] memory genesis = allWords();
        openAsSystem(a);

        assertEq(uintWord("origin.rootEpoch"), a.rootEpoch);
        assertEq(uintWord("origin.timestamp"), a.timestamp);
        assertEq(word("origin.treeRoot"), a.treeRoot);
        assertEq(word("origin.identity"), a.originIdentity);
        assertEq(word("origin.trHash"), a.trHash);
        assertEq(uintWord("certified.round"), a.certifiedRound);
        assertEq(word("certified.stateHash"), a.stateHash);
        assertEq(uintWord("certified.hasBlockHash"), 0);
        assertEq(word("certified.blockHash"), bytes32(0));
        assertEq(uintWord("clock.rootRound"), a.rootRound);
        assertEq(uintWord("round.authorized"), a.n);
        assertEq(word("input.commitment"), a.inputCommitment);
        assertEq(uintWord("outcomes.round"), a.n);
        assertEq(word("outcomes.commitment"), bytes32(0));
        assertEq(uintWord("phase"), 1);
        assertGenesisAndCursorsUnchanged(genesis);

        bytes32 r1 = keccak256("R1");
        finalizeAsSystem(1, r1);
        assertEq(word("outcomes.commitment"), r1);
        assertEq(uintWord("phase"), 2);
        assertEq(uintWord("outcomes.round"), 1);
        assertGenesisAndCursorsUnchanged(genesis);
    }

    /// §9.2a: round 1 timed out; the first payload is authorized for round 2 against genesis state.
    function test_firstExecutionAfterAnInitialTimeout() public {
        OpenArgs memory a = firstPayload();
        a.n = 2;
        a.rootRound = 7;
        openAsSystem(a);
        finalizeAsSystem(2, keccak256("R2'"));
        assertEq(uintWord("round.authorized"), 2);
        assertEq(uintWord("clock.rootRound"), 7);
        assertEq(uintWord("certified.round"), 0);
    }

    /// §9.3 and §9.4: an ordinary block, then a repeat authorization that skips shard round 3 and
    /// root rounds 7 and 8.
    function test_roundAndRootRoundJumps() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));

        OpenArgs memory b = firstPayload();
        b.n = 2;
        b.rootRound = 6;
        b.certifiedRound = 1;
        b.stateHash = keccak256("S1");
        b.hasBlockHash = true;
        b.blockHash = keccak256("B1");
        openAsSystem(b);
        assertEq(uintWord("certified.hasBlockHash"), 1);
        assertEq(word("certified.blockHash"), keccak256("B1"));
        finalizeAsSystem(2, keccak256("R2"));

        OpenArgs memory d = b;
        d.n = 4;
        d.rootRound = 9;
        d.certifiedRound = 2;
        d.stateHash = keccak256("S2");
        d.blockHash = keccak256("B2");
        openAsSystem(d);
        finalizeAsSystem(4, keccak256("R4"));
        assertEq(uintWord("round.authorized"), 4);
        assertEq(uintWord("clock.rootRound"), 9);
        assertEq(uintWord("certified.round"), 2);
    }

    /// O5 allows an equal root round: only a smaller one is stale.
    function test_equalRootRoundIsNotStale() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        OpenArgs memory b = firstPayload();
        b.n = 2;
        openAsSystem(b);
        assertEq(uintWord("clock.rootRound"), 5);
    }

    /// A present block hash may be any value, zero included: O10 constrains only the null encoding.
    function test_presentBlockHashMayBeZero() public {
        OpenArgs memory a = firstPayload();
        a.hasBlockHash = true;
        a.blockHash = bytes32(0);
        openAsSystem(a);
        assertEq(uintWord("certified.hasBlockHash"), 1);
    }

    // ---------------------------------------------------------------- open refusals O1 to O10

    function test_O1_publicCallerCannotOpen() public {
        OpenArgs memory a = firstPayload();
        premiseOpenSucceeds(a);
        assertRefused(address(0xBEEF), openCalldata(a), SealRegistry.NotSystemCaller.selector);
        // The stock EIP-4788 system caller is not a_sys either.
        assertRefused(
            0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE,
            openCalldata(a),
            SealRegistry.NotSystemCaller.selector
        );
    }

    function test_O2_uninitializedRegistryRefusesOpen() public {
        OpenArgs memory a = firstPayload();
        premiseOpenSucceeds(a);
        setWord("layoutVersion", bytes32(0));
        assertRefused(A_SYS, openCalldata(a), SealRegistry.NotInitialized.selector);
        setWord("layoutVersion", bytes32(uint256(3)));
        assertRefused(A_SYS, openCalldata(a), SealRegistry.NotInitialized.selector);
        setWord("layoutVersion", bytes32(uint256(2)));
        setWord("genesisCommitment", bytes32(0));
        assertRefused(A_SYS, openCalldata(a), SealRegistry.NotInitialized.selector);
    }

    function test_O2_codeWithNoGenesisStorageRefusesOpen() public {
        address bare = address(0xC0DE);
        vm.etch(bare, type(SealRegistry).runtimeCode);
        vm.prank(A_SYS);
        (bool ok, bytes memory ret) = bare.call(openCalldata(firstPayload()));
        assertFalse(ok);
        assertEq(bytes4(ret), SealRegistry.NotInitialized.selector);
    }

    function test_O3_openWithoutFinalizeBlocksTheNextOpen() public {
        openAsSystem(firstPayload());
        OpenArgs memory b = firstPayload();
        b.n = 2;
        b.rootRound = 6;
        assertRefused(A_SYS, openCalldata(b), SealRegistry.PreviousNotFinalized.selector);
    }

    function test_O4_roundMustExceedTheAuthorizedRound() public {
        OpenArgs memory zero = firstPayload();
        zero.n = 0;
        assertRefused(A_SYS, openCalldata(zero), SealRegistry.RoundNotAhead.selector);

        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        // The same input again: a duplicate cannot advance anything twice.
        assertRefused(A_SYS, openCalldata(firstPayload()), SealRegistry.RoundNotAhead.selector);
    }

    function test_O5_staleRootRoundIsRefused() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        OpenArgs memory b = firstPayload();
        b.n = 2;
        b.rootRound = 4;
        // A separate value: assigning a memory struct copies the reference, not the fields.
        OpenArgs memory ok = firstPayload();
        ok.n = 2;
        ok.rootRound = 5;
        premiseOpenSucceeds(ok);
        assertRefused(A_SYS, openCalldata(b), SealRegistry.StaleRootRound.selector);
    }

    function test_O6_anotherConfigurationIsRefused() public {
        OpenArgs memory a = firstPayload();
        premiseOpenSucceeds(a);
        a.shardConfHash = keccak256("another configuration");
        assertRefused(A_SYS, openCalldata(a), SealRegistry.ConfigurationMismatch.selector);
    }

    function test_normalOpenRequiresTheCurrentActiveAssignmentHash() public {
        OpenArgs memory a = firstPayload();
        premiseOpenSucceeds(a);
        a.activeConfHash = keccak256("unacknowledged assignment");
        assertRefused(A_SYS, openCalldata(a), SealRegistry.ConfigurationMismatch.selector);
    }

    function test_O7_anotherShardEpochIsRefused() public {
        OpenArgs memory a = firstPayload();
        premiseOpenSucceeds(a);
        OpenArgs memory cert = firstPayload();
        cert.certEpoch = SHARD_EPOCH + 1;
        assertRefused(A_SYS, openCalldata(cert), SealRegistry.ShardEpochMismatch.selector);
        OpenArgs memory handoff = firstPayload();
        handoff.authEpoch = SHARD_EPOCH + 1;
        assertRefused(A_SYS, openCalldata(handoff), SealRegistry.ShardEpochMismatch.selector);
    }

    function test_O8_anotherRootEpochIsRefused() public {
        OpenArgs memory a = firstPayload();
        premiseOpenSucceeds(a);
        a.rootEpoch = ROOT_EPOCH + 1;
        assertRefused(A_SYS, openCalldata(a), SealRegistry.RootEpochMismatch.selector);
    }

    function test_O9_pendingTransitionsAreRefused() public {
        OpenArgs memory a = firstPayload();
        premiseOpenSucceeds(a);
        a.transitionCount = 1;
        a.rootEpoch = ROOT_EPOCH + 1;
        assertRefused(A_SYS, openCalldata(a), SealRegistry.InvalidTransition.selector);
        a.transitionCount = 2;
        assertRefused(A_SYS, openCalldata(a), SealRegistry.TransitionsUnsupported.selector);
    }

    function test_unchangedRootOnlyAcknowledgementPreservesAssignment() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        OpenArgs memory a = firstPayload();
        a.n = 2;
        a.rootEpoch = ROOT_EPOCH + 1;
        a.rootRound = 1;
        a.transitionCount = 1;
        a.bodyID = keccak256("body");
        a.genesisID = keccak256("genesis");
        a.frozenID = keccak256("frozen");
        a.commitID = keccak256("commit");
        a.frozenParent = keccak256("parent");
        a.successorTR = keccak256("tr");
        a.assignment = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            0,
            bytes32(0)
        );
        vm.recordLogs();
        openAsSystem(a);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(
            logs[0].topics[0],
            keccak256(
                "EpochAcknowledged(uint64,uint64,bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)"
            )
        );
        assertEq(uintWord("assignment.rootEpoch"), 2);
        assertEq(uintWord("assignment.epoch"), SHARD_EPOCH);
        assertEq(word("assignment.activeConfHash"), FULL_SHARD_CONF_HASH);
        assertEq(word("assignment.spanCommitment"), bytes32(0));
        assertEq(uintWord("transition.cursor"), 1);
        assertEq(word("transition.bodyID"), a.bodyID);
        assertEq(word("transition.genesisID"), a.genesisID);
        assertEq(word("transition.frozenID"), a.frozenID);
        assertEq(word("transition.commitID"), a.commitID);
        assertEq(word("transition.frozenParent"), a.frozenParent);
        assertEq(word("transition.successorTR"), a.successorTR);
        finalizeAsSystem(2, keccak256("R2"));
        a = firstPayload();
        a.n = 3;
        a.rootEpoch = 2;
        a.rootRound = 2;
        openAsSystem(a);
    }

    function test_ordinaryAssignmentAcknowledgementAdvancesBothEpochsByOne() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        bytes32 successor = keccak256("successor PDR");
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH + 1,
            successor,
            0,
            bytes32(0)
        );
        OpenArgs memory ack = assignmentAckPayload(p);
        openAsSystem(ack);
        assertEq(uintWord("assignment.rootEpoch"), ROOT_EPOCH + 1);
        assertEq(uintWord("assignment.epoch"), SHARD_EPOCH + 1);
        assertEq(word("config.shardConfHash"), FULL_SHARD_CONF_HASH, "genesis hash stays pinned");
        assertEq(word("assignment.activeConfHash"), successor);
        assertEq(word("assignment.spanCommitment"), bytes32(0));
        finalizeAsSystem(2, keccak256("R2"));

        OpenArgs memory next = firstPayload();
        next.n = 3;
        next.rootEpoch = ROOT_EPOCH + 1;
        next.rootRound = 7;
        next.certEpoch = SHARD_EPOCH + 1;
        next.authEpoch = SHARD_EPOCH + 1;
        next.activeConfHash = successor;
        openAsSystem(next);
        assertEq(word("origin.identity"), next.originIdentity);
    }

    function test_supersessionProjectionFoldsAVerifiedTwoStepSpan() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        bytes32 successor = keccak256("s+2 PDR");
        bytes32 spanCommitment = keccak256("verified H2 -> H3 chain");
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 2,
            SHARD_EPOCH + 2,
            successor,
            2,
            spanCommitment
        );
        openAsSystem(assignmentAckPayload(p));
        assertEq(uintWord("assignment.rootEpoch"), ROOT_EPOCH + 2);
        assertEq(uintWord("assignment.epoch"), SHARD_EPOCH + 2);
        assertEq(word("assignment.activeConfHash"), successor);
        assertEq(word("assignment.spanCommitment"), spanCommitment);
        finalizeAsSystem(2, keccak256("R3"));

        OpenArgs memory next = firstPayload();
        next.n = 3;
        next.rootEpoch = ROOT_EPOCH + 2;
        next.rootRound = 7;
        next.certEpoch = SHARD_EPOCH + 2;
        next.authEpoch = SHARD_EPOCH + 2;
        next.activeConfHash = successor;
        openAsSystem(next);
    }

    function test_invalidSupersessionSpansAreRefused() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        bytes32 successor = keccak256("successor");

        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH + 1,
            successor,
            1,
            keccak256("not a supersession")
        );
        assertRefused(
            A_SYS,
            openCalldata(assignmentAckPayload(p)),
            SealRegistry.InvalidSupersessionSpan.selector
        );

        p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 2,
            SHARD_EPOCH + 1,
            successor,
            2,
            keccak256("wrong shard delta")
        );
        assertRefused(
            A_SYS,
            openCalldata(assignmentAckPayload(p)),
            SealRegistry.InvalidSupersessionSpan.selector
        );

        p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 2,
            SHARD_EPOCH + 2,
            successor,
            2,
            bytes32(0)
        );
        assertRefused(
            A_SYS,
            openCalldata(assignmentAckPayload(p)),
            SealRegistry.InvalidSupersessionSpan.selector
        );

        p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 3,
            SHARD_EPOCH + 3,
            successor,
            2,
            keccak256("span count mismatch")
        );
        assertRefused(
            A_SYS,
            openCalldata(assignmentAckPayload(p)),
            SealRegistry.InvalidSupersessionSpan.selector
        );
    }

    function test_wrongOldAssignmentContextIsRefused() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            ROOT_EPOCH - 1,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH + 1,
            keccak256("successor"),
            0,
            bytes32(0)
        );
        assertRefused(
            A_SYS,
            openCalldata(assignmentAckPayload(p)),
            SealRegistry.AssignmentContextMismatch.selector
        );
    }

    function test_wrongNewAssignmentContextIsRefused() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH + 1,
            keccak256("projected successor"),
            0,
            bytes32(0)
        );
        OpenArgs memory ack = assignmentAckPayload(p);
        ack.activeConfHash = keccak256("different successor");
        assertRefused(A_SYS, openCalldata(ack), SealRegistry.AssignmentContextMismatch.selector);
    }

    function test_duplicateAssignmentAcknowledgementIsRefused() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            0,
            bytes32(0)
        );
        OpenArgs memory ack = assignmentAckPayload(p);
        openAsSystem(ack);
        finalizeAsSystem(2, keccak256("R2"));
        ack.n = 3; // reach the duplicate-ack guard instead of the earlier round guard
        assertRefused(A_SYS, openCalldata(ack), SealRegistry.DuplicateAcknowledgement.selector);
    }

    function test_assignmentAcknowledgementIsSystemOnly() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH + 1,
            keccak256("successor"),
            0,
            bytes32(0)
        );
        OpenArgs memory ack = assignmentAckPayload(p);
        assertRefused(address(0xBEEF), openCalldata(ack), SealRegistry.NotSystemCaller.selector);
        openAsSystem(ack);
    }

    function test_ackFailureAfterProjectionWritesRollsBackAtomically() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 2,
            SHARD_EPOCH + 2,
            keccak256("successor"),
            2,
            keccak256("verified span")
        );
        OpenArgs memory ack = assignmentAckPayload(p);
        ack.hasBlockHash = false;
        ack.blockHash = keccak256("noncanonical absent block hash");
        assertRefused(A_SYS, openCalldata(ack), SealRegistry.NonCanonicalNullBlockHash.selector);
    }

    function test_assignmentProjectionAbiAndHashVector() public pure {
        assertEq(
            SealRegistry.assignmentProjectionHash.selector,
            bytes4(
                keccak256(
                    bytes(
                        "assignmentProjectionHash((uint64,uint64,bytes32,uint64,uint64,bytes32,uint64,bytes32,bytes32))"
                    )
                )
            )
        );
        assertEq(
            SealRegistry.assignmentProjectionHash.selector,
            bytes4(0xaaebf335),
            "pinned projection selector"
        );
        SealRegistry.AssignmentProjection memory p = assignmentProjection(
            4, 2, keccak256("old"), 6, 4, keccak256("new"), 2, keccak256("H2/H3")
        );
        assertEq(
            p.projectionHash, 0x8a6712ca26e2085a0dc21ad07303ddc72665c61dc3290e5ce0abc3fda55acca1
        );
    }

    function test_gasAndWitnessGrowthMeasurement() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        uint256 snap = vm.snapshotState();

        SealRegistry.AssignmentProjection memory rootOnly = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 1,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            0,
            bytes32(0)
        );
        OpenArgs memory rootOnlyAck = assignmentAckPayload(rootOnly);
        uint256 beforeGas = gasleft();
        openAsSystem(rootOnlyAck);
        uint256 rootOnlyGas = beforeGas - gasleft();
        emit log_named_uint("v2 root-only ACK open gas", rootOnlyGas);

        vm.revertToState(snap);
        SealRegistry.AssignmentProjection memory superseding = assignmentProjection(
            ROOT_EPOCH,
            SHARD_EPOCH,
            FULL_SHARD_CONF_HASH,
            ROOT_EPOCH + 2,
            SHARD_EPOCH + 2,
            keccak256("s+2 PDR"),
            2,
            keccak256("verified H2 -> H3 chain")
        );
        OpenArgs memory supersedingAck = assignmentAckPayload(superseding);
        beforeGas = gasleft();
        openAsSystem(supersedingAck);
        uint256 supersedingGas = beforeGas - gasleft();
        emit log_named_uint("v2 superseding ACK open gas", supersedingGas);
        assertLt(rootOnlyGas, 500_000);
        assertLt(supersedingGas, 600_000);
    }

    function test_O10_nonCanonicalNullBlockHashIsRefused() public {
        OpenArgs memory a = firstPayload();
        premiseOpenSucceeds(a);
        a.blockHash = keccak256("not null");
        assertRefused(A_SYS, openCalldata(a), SealRegistry.NonCanonicalNullBlockHash.selector);
    }

    // ---------------------------------------------------------------- finalize refusals F1 to F3

    function test_F1_publicCallerCannotFinalizeAnOpenRound() public {
        openAsSystem(firstPayload());
        assertRefused(
            address(0xBEEF),
            finalizeCalldata(1, keccak256("R1")),
            SealRegistry.NotSystemCaller.selector
        );
    }

    function test_F2_finalizeWithoutOpenIsRefused() public {
        assertRefused(A_SYS, finalizeCalldata(0, keccak256("R")), SealRegistry.NotOpen.selector);
    }

    function test_F2_secondFinalizeIsRefused() public {
        openAsSystem(firstPayload());
        finalizeAsSystem(1, keccak256("R1"));
        assertRefused(
            A_SYS, finalizeCalldata(1, keccak256("R1 again")), SealRegistry.NotOpen.selector
        );
    }

    function test_F3_finalizeForAnotherRoundIsRefused() public {
        openAsSystem(firstPayload());
        assertRefused(
            A_SYS, finalizeCalldata(2, keccak256("R2")), SealRegistry.WrongOutcomeRound.selector
        );
        finalizeAsSystem(1, keccak256("R1"));
    }

    // ---------------------------------------------------------------- calldata, value and dispatch

    function test_outOfRangeUint64WordIsRefusedByTheDecoder() public {
        bytes memory good = openCalldata(firstPayload());
        premiseOpenSucceeds(firstPayload());
        // Every uint64 ABI word rejects high bits, including the assignment projection tuple.
        for (uint256 w = 0; w < 32; w++) {
            if (!isUint64Word(w)) continue;
            bytes memory bad = bytes.concat(good);
            setCalldataWord(bad, w, uint256(1) << 64);
            assertRefusedWithoutReason(A_SYS, bad, 0);
        }
    }

    function test_nonBooleanWordIsRefusedByTheDecoder() public {
        bytes memory bad = openCalldata(firstPayload());
        setCalldataWord(bad, 12, 2); // hasBlockHash
        assertRefusedWithoutReason(A_SYS, bad, 0);
    }

    function test_shortCalldataIsRefused() public {
        bytes memory good = openCalldata(firstPayload());
        bytes memory short = new bytes(good.length - 1);
        for (uint256 i = 0; i < short.length; i++) {
            short[i] = good[i];
        }
        assertRefusedWithoutReason(A_SYS, short, 0);
    }

    /// Recorded, not refused: Solidity's decoder ignores bytes after the static projection. Sending the
    /// exact projection is the execution client's obligation (#153 §6.1, §12).
    function test_trailingCalldataIsIgnoredByTheDecoder() public {
        bytes memory extended = bytes.concat(openCalldata(firstPayload()), bytes32(uint256(0xdead)));
        (bool ok,) = callAs(A_SYS, extended);
        assertTrue(ok);
        assertEq(uintWord("round.authorized"), 1);
    }

    function test_valueIsRefused() public {
        assertRefusedWithoutReason(A_SYS, openCalldata(firstPayload()), 1);
        assertRefusedWithoutReason(A_SYS, "", 1);
    }

    function test_unknownSelectorAndEmptyCalldataAreRefused() public {
        assertRefusedWithoutReason(A_SYS, "", 0);
        assertRefusedWithoutReason(
            A_SYS, abi.encodeWithSignature("upgrade(address)", address(1)), 0
        );
    }

    // ---------------------------------------------------------------- fuzzed malicious callers

    function testFuzz_publicCallerChangesNothingInEitherPhase(
        address caller,
        OpenArgs memory a,
        uint64 n,
        bytes32 c
    ) public {
        vm.assume(caller != A_SYS);
        OpenArgs memory valid = firstPayload();

        // Finalized phase: a well-formed open and an arbitrary one.
        assertRefused(caller, openCalldata(valid), SealRegistry.NotSystemCaller.selector);
        assertRefused(caller, openCalldata(a), SealRegistry.NotSystemCaller.selector);
        assertRefused(caller, finalizeCalldata(n, c), SealRegistry.NotSystemCaller.selector);

        // Open phase, where a_sys's finalize would succeed.
        openAsSystem(valid);
        assertRefused(caller, finalizeCalldata(1, c), SealRegistry.NotSystemCaller.selector);
        assertRefused(caller, finalizeCalldata(n, c), SealRegistry.NotSystemCaller.selector);
    }

    /// Any open from a_sys either reverts and changes nothing, or succeeds and changes only the §6.2
    /// fields, leaving immutable genesis words and the acknowledgement cursor unchanged.
    function testFuzz_systemOpenRevertsCleanlyOrWritesOnlyItsFields(OpenArgs memory a) public {
        bytes32[FIELD_COUNT] memory before = allWords();
        (bool ok,) = callAs(A_SYS, openCalldata(a));
        if (!ok) {
            assertWordsEqual(before, allWords());
            return;
        }
        assertGenesisAndCursorsUnchanged(before);
        assertGt(uintWord("round.authorized"), uint256(before[13]));
        assertGe(uintWord("clock.rootRound"), uint256(before[7]));
        assertEq(uintWord("phase"), 1);
        assertEq(a.transitionCount, 0);
        assertEq(a.shardConfHash, FULL_SHARD_CONF_HASH);
    }

    // ---------------------------------------------------------------- code properties

    /// The runtime code contains none of the opcodes #153 §2.2 excludes, and no BALANCE or SELFBALANCE.
    function test_runtimeCodeExcludesForbiddenOpcodes() public pure {
        bytes memory code = type(SealRegistry).runtimeCode;
        assertGt(code.length, 0);
        uint256 i = 0;
        while (i < code.length) {
            uint8 op = uint8(code[i]);
            assertTrue(op != 0xf4, "DELEGATECALL");
            assertTrue(op != 0xf2, "CALLCODE");
            assertTrue(op != 0xf0, "CREATE");
            assertTrue(op != 0xf5, "CREATE2");
            assertTrue(op != 0xff, "SELFDESTRUCT");
            assertTrue(op != 0x31, "BALANCE");
            assertTrue(op != 0x47, "SELFBALANCE");
            assertTrue(op != 0xf1, "CALL");
            assertTrue(op != 0xfa, "STATICCALL");
            i += 1 + (op >= 0x60 && op <= 0x7f ? op - 0x5f : 0);
        }
    }

    /// No Solidity state variables: the compiled storage layout is empty.
    function test_noSolidityStorageLayout() public view {
        string memory artifact = vm.readFile("out/SealRegistry.sol/SealRegistry.json");
        string[] memory entries = vm.parseJsonKeys(artifact, ".storageLayout");
        bool sawStorage;
        for (uint256 i = 0; i < entries.length; i++) {
            if (keccak256(bytes(entries[i])) == keccak256("storage")) sawStorage = true;
        }
        assertTrue(sawStorage, "the artifact carries a storage layout");
        bytes memory storageEntries = vm.parseJson(artifact, ".storageLayout.storage");
        assertEq(abi.decode(storageEntries, (bytes[])).length, 0, "no storage variables");
    }

    // ---------------------------------------------------------------- helpers

    function assignmentAckPayload(SealRegistry.AssignmentProjection memory p)
        internal
        pure
        returns (OpenArgs memory a)
    {
        a = firstPayload();
        a.n = 2;
        a.rootRound = 6;
        a.rootEpoch = p.newRootEpoch;
        a.certEpoch = p.oldShardEpoch;
        a.authEpoch = p.newShardEpoch;
        a.hasBlockHash = true;
        a.blockHash = keccak256("frozen parent block");
        a.transitionCount = 1;
        a.bodyID = keccak256("ack body");
        a.genesisID = keccak256("ack genesis");
        a.frozenID = keccak256("ack frozen");
        a.commitID = keccak256("ack commit");
        a.frozenParent = keccak256("ack frozen parent");
        a.successorTR = keccak256("ack successor TR");
        a.activeConfHash = p.newActiveConfHash;
        a.assignment = p;
    }

    function premiseOpenSucceeds(OpenArgs memory a) internal {
        uint256 snap = vm.snapshotState();
        (bool ok, bytes memory ret) = callAs(A_SYS, openCalldata(a));
        if (!ok) emit log_named_bytes("premise open reverted", ret);
        assertTrue(ok, "premise: the unmodified open succeeds");
        vm.revertToState(snap);
    }

    function assertGenesisAndCursorsUnchanged(bytes32[FIELD_COUNT] memory before) internal view {
        assertEq(word("layoutVersion"), before[0]);
        assertEq(word("genesisCommitment"), before[1]);
        assertEq(word("config.shardConfHash"), before[2]);
        assertEq(word("assignment.epoch"), before[3]);
        assertEq(word("assignment.rootEpoch"), before[4]);
        assertEq(word("assignment.activeConfHash"), before[5]);
        assertEq(word("assignment.spanCommitment"), before[6]);
        assertEq(word("transition.cursor"), before[22]);
        assertEq(word("inbox.consumed"), before[23]);
        assertEq(word("transition.cursor"), bytes32(0));
        assertEq(word("inbox.consumed"), bytes32(0));
    }

    function isUint64Word(uint256 w) internal pure returns (bool) {
        return w == 0 || w == 1 || w == 2 || w == 3 || w == 8 || w == 9 || w == 10 || w == 15
            || w == 23 || w == 24 || w == 26 || w == 27 || w == 29;
    }

    function setCalldataWord(bytes memory data, uint256 w, uint256 value) internal pure {
        uint256 offset = 4 + 32 * w;
        for (uint256 i = 0; i < 32; i++) {
            data[offset + i] = bytes1(uint8(value >> (8 * (31 - i))));
        }
    }
}
