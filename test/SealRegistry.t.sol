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
        // keccak256("unicity.seal-registry/" || name), printed by `cast keccak`; no layoutVersion word
        // and no version in the prefix: one fresh layout.
        bytes32[FIELD_COUNT] memory want = [
            bytes32(0xe4756cc967765a03ac699a0196af5ec73c15ae2739f43da745666a02a12a2bc0),
            0x4d19b7530faa2fa3495319b01857830cdc6ca35a5b20c4084d10119118d44afe,
            0xd1358cd157e8920f4cfe36f79ae73373716b602bf47f574ea08d5281befa59ef,
            0x52ff97c9251b51e7f509a2b0fc46b23b06051f0336a4c2214c3a1b91f9bd79ad,
            0xd56125ba33c296e14f68d6694333af40f3cc48fa5a36f9e92163bf6a6a427ce1,
            0x6e517af5ad1ad5851bf185b4a61f1b629012f215c3641f90755230b1dfdc00db,
            0x2d4c56cc2e5e6359278ccd26c935f31d15bedaeff39fc3c6a82ab884c5969c32,
            0x184dca1edd98a90c34df33b3efbfe84d04606a0e83fd64f7c8fbf5b5d1d59a19,
            0x0544846a1c10d375249e56211500ec3eea84925b04f998de1e3f88362b84c172,
            0x3ff2245574ffd2dbff36514765e4712bea443ea47427e517cb0336bfb485864b,
            0x6f5040705d0fea67fa3c2f792d45109a88512fc6966f2168f7c4c2973d0d2471,
            0xfa726923769d08d9f56554ed7bae9419ebffeebb6eca2743f544002227466012,
            0xb1fe9535d8cd5cb453076d468874d238efe22d2a230923709c3b5011420a815b,
            0x10bbcc4389d544c5a6aa241a5a0558461be04c33b27a73035671c2944f498784,
            0xa0f08189724ae2bfb150fa140a6488830ddc10e8fdd94a55a0815e79eaf49a27,
            0x250f2a1a88d823a14236a8068855c03dc5dc9076e6b0917b688be3c276b8bdb1,
            0x22e2eb405e136cd16718e3c00d060333168f5e2545670217d461f5d019b06d87,
            0x9814a3b8474ed9091981ace9b8cbd4a6520c2d32b1c0dcd03f05164d1a562592,
            0xbd46d80656ebd65ff40d271a180003a97a8f7200d2b0562e68a0b3455cd447d1,
            0xdf6054d2856db510df05f205217ce7e44e297a6e8637b87280ec2ea8c9f4c7ee,
            0xa20cac25b5a8a5560378675c46b953deb71e952d3a217adf06a367755ed9e14c,
            0xdbba6e361c4e690f76de59e333754674890220c3d931a423324e3db092908f97,
            0xd14c69282b27a736ce28f3d4c57008f9d3a70bcf058e146df265bab878414f2a,
            0x80b36647f19b9ab7294c125a56d9634ef5f7f4c0d437e92c65d79c607967900d,
            0xabe73c5aa5a967f9e6da6c1be32abfce1b66e460b44f649067486102b6538bc3,
            0xed1d3da064f55047710c1067080e0914ea5f3e1526c4c70cdb7c2dc768a23db9,
            0x3d757b6a4784611a540ddb25254ed92d49550a4d59419156b8efcecab4b7e8ab,
            0x21bb45ea32d44dc2e8e963e554010b26131eebc932bbf8789c4f13b84054261e,
            0x56d9e67e7cd6c7be08d7d04ecc09d9cff4704c1c8469af99237930ab4f868ef4
        ];
        string[FIELD_COUNT] memory names = fieldNames();
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            assertEq(slotKey(names[i]), want[i], names[i]);
        }
    }

    function test_selectorsAreTheSpecifiedSignatures() public pure {
        assertEq(SealRegistry.open.selector, bytes4(keccak256(bytes(OPEN_SIGNATURE))));
        assertEq(SealRegistry.open.selector, bytes4(0x724236c0), "pinned B1 open selector");
        assertEq(SealRegistry.finalize.selector, bytes4(keccak256(bytes(FINALIZE_SIGNATURE))));
    }

    /// 23 scalars and the 9-word assignment projection form a 32-word static head, then the offset of
    /// the dynamic update; an empty update is five words (four fields and a zero array length).
    function test_openCalldataIsThirtyThreeHeadWordsAndAFiveWordEmptyUpdate() public pure {
        bytes memory projected = openCalldata(firstPayload());
        assertEq(projected.length, 4 + 33 * 32 + 5 * 32);
        assertEq(uint256(bytes32(slice(projected, 4 + 32 * 32, 32))), 33 * 32, "update offset");
    }

    function test_operationalGenesisWordsAreTheSixSpecifiedOnes() public view {
        string[FIELD_COUNT] memory names = fieldNames();
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            bytes32 got = vm.load(A_SR, slotKey(names[i]));
            bytes32 name = keccak256(bytes(names[i]));
            if (name == keccak256("genesisCommitment")) {
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

    function test_b1FixedGenesisWordsAndNoLayoutVersion() public view {
        assertEq(b1Word("b1.network"), NETWORK);
        assertEq(b1Word("b1.wCert"), W_CERT);
        assertEq(bytes32(b1Word("b1.profileHash")), PROFILE_HASH);
        assertEq(b1Word("b1.initialized"), 1);
        assertEq(b1Word("b1.head"), 0);
        assertEq(b1Word("b1.count"), 1);
        assertEq(queueAt(0), ROOT_EPOCH);
        assertEntryStored(genesisEntry(), 8);
        assertEq(uint256(vm.load(A_SR, keccak256("unicity.seal-registry/layoutVersion"))), 0);
        assertEq(uint256(vm.load(A_SR, keccak256("unicity.seal-registry.v1/layoutVersion"))), 0);
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
        vm.store(A_SR, fixedSlot("b1.initialized"), bytes32(0));
        assertRefused(A_SYS, openCalldata(a), SealRegistry.NotInitialized.selector);
        vm.store(A_SR, fixedSlot("b1.initialized"), bytes32(uint256(2)));
        assertRefused(A_SYS, openCalldata(a), SealRegistry.NotInitialized.selector);
        vm.store(A_SR, fixedSlot("b1.initialized"), bytes32(uint256(1)));
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
        a.rootRound = 6;
        a.update = advanceUpdate(ROOT_EPOCH, 6, 1, 3);
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
        a.rootRound = 7;
        a.update = emptyUpdate(2);
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
        next.update = emptyUpdate(ROOT_EPOCH + 1);
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
        next.update = emptyUpdate(ROOT_EPOCH + 2);
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
        // Each acknowledgement now inserts a 3-member interval (35 fresh words) as well.
        assertLt(rootOnlyGas, 1_100_000);
        assertLt(supersedingGas, 1_900_000);
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
        uint256 seed,
        uint64 n,
        bytes32 c
    ) public {
        vm.assume(caller != A_SYS);
        OpenArgs memory valid = firstPayload();
        OpenArgs memory a = randomArgs(seed);

        // Finalized phase: a well-formed open and an arbitrary one.
        assertRefused(caller, openCalldata(valid), SealRegistry.NotSystemCaller.selector);
        assertRefused(caller, openCalldata(a), SealRegistry.NotSystemCaller.selector);
        assertRefused(caller, finalizeCalldata(n, c), SealRegistry.NotSystemCaller.selector);

        // Open phase, where a_sys's finalize would succeed.
        openAsSystem(valid);
        assertRefused(caller, finalizeCalldata(1, c), SealRegistry.NotSystemCaller.selector);
        assertRefused(caller, finalizeCalldata(n, c), SealRegistry.NotSystemCaller.selector);
    }

    /// Any open from a_sys either reverts and changes nothing (operational or B1 words), or succeeds
    /// and changes only the §6.2 fields and the ring, leaving immutable genesis words and the
    /// acknowledgement cursor unchanged.
    function testFuzz_systemOpenRevertsCleanlyOrWritesOnlyItsFields(uint256 seed) public {
        OpenArgs memory a = randomArgs(seed);
        bytes32[FIELD_COUNT] memory before = allWords();
        bytes32 b1Before = b1Digest();
        (bool ok,) = callAs(A_SYS, openCalldata(a));
        if (!ok) {
            assertWordsEqual(before, allWords());
            assertEq(b1Before, b1Digest(), "refused open changed B1 words");
            return;
        }
        assertGenesisAndCursorsUnchanged(before);
        assertGt(uintWord("round.authorized"), uint256(before[fieldIndex("round.authorized")]));
        assertGe(uintWord("clock.rootRound"), uint256(before[fieldIndex("clock.rootRound")]));
        assertEq(uintWord("phase"), 1);
        assertEq(a.shardConfHash, FULL_SHARD_CONF_HASH);
        assertEq(b1Word("b1.wCert"), W_CERT);
        assertEq(b1Word("b1.initialized"), 1);
        assertGe(b1Word("b1.count"), 1);
        assertLe(b1Word("b1.count"), kMax());
    }

    // ---------------------------------------------------------------- code properties

    /// The runtime code contains none of the opcodes #153 §2.2 excludes, and no BALANCE or SELFBALANCE.
    /// The compiler may append a data region (deduplicated 32-byte constants read with CODECOPY), so
    /// the scan covers exactly the instructions the source map lists and never decodes data as code.
    function test_runtimeCodeExcludesForbiddenOpcodes() public view {
        bytes memory code = type(SealRegistry).runtimeCode;
        assertGt(code.length, 0);
        string memory artifact = vm.readFile("out/SealRegistry.sol/SealRegistry.json");
        bytes memory sourceMap = bytes(vm.parseJsonString(artifact, ".deployedBytecode.sourceMap"));
        uint256 instructions = 1;
        for (uint256 k = 0; k < sourceMap.length; k++) {
            if (sourceMap[k] == ";") instructions++;
        }
        uint256 i = 0;
        for (uint256 n = 0; n < instructions; n++) {
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
        assertLe(i, code.length, "instructions end inside the code");
        // What follows the instructions is constant data, not executable: it must be only the
        // CODECOPY-read region (the code never jumps into it, so execution cannot reach it).
        assertLt(code.length - i, 1024, "data region is small");
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
        uint64 delta = p.newRootEpoch - p.oldRootEpoch;
        // Even refused (invalid) projections carry a well-formed update when the span is small.
        if (delta >= 1 && delta <= 4) {
            a.update = advanceUpdate(p.oldRootEpoch, a.rootRound, delta, 3);
        }
    }

    function premiseOpenSucceeds(OpenArgs memory a) internal {
        uint256 snap = vm.snapshotState();
        (bool ok, bytes memory ret) = callAs(A_SYS, openCalldata(a));
        if (!ok) emit log_named_bytes("premise open reverted", ret);
        assertTrue(ok, "premise: the unmodified open succeeds");
        vm.revertToState(snap);
    }

    function assertGenesisAndCursorsUnchanged(bytes32[FIELD_COUNT] memory before) internal view {
        assertEq(word("genesisCommitment"), before[0]);
        assertEq(word("config.shardConfHash"), before[1]);
        assertEq(word("assignment.epoch"), before[2]);
        assertEq(word("assignment.rootEpoch"), before[3]);
        assertEq(word("assignment.activeConfHash"), before[4]);
        assertEq(word("assignment.spanCommitment"), before[5]);
        assertEq(word("transition.cursor"), before[fieldIndex("transition.cursor")]);
        assertEq(word("inbox.consumed"), before[fieldIndex("inbox.consumed")]);
        assertEq(word("transition.cursor"), bytes32(0));
        assertEq(word("inbox.consumed"), bytes32(0));
    }

    function fieldIndex(string memory name) internal pure returns (uint256) {
        string[FIELD_COUNT] memory names = fieldNames();
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            if (keccak256(bytes(names[i])) == keccak256(bytes(name))) return i;
        }
        revert("unknown field");
    }

    function slice(bytes memory data, uint256 from, uint256 len)
        internal
        pure
        returns (bytes memory r)
    {
        r = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            r[i] = data[from + i];
        }
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
