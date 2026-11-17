// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {SealRegistry} from "../src/SealRegistry.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";
import {RootRecord, RecordKind} from "../src/p85/P85Types.sol";

/// @notice The privileged importRootRecords step: prefix rule, log and content identity, payload shapes, anchors, target checks,
/// closure and retirement keys, and the finalize gate. Each refusal changes one thing, is asserted by its error selector and proves
/// every fixed registry word unchanged.
contract RootRecordsImportTest is SealRegistryBase {
    SealRegistry internal reg;

    function setUp() public override {
        super.setUp();
        reg = SealRegistry(A_SR);
    }

    // ---------------------------------------------------------------- builders

    function rec(uint64 index, bytes32 pred, RecordKind kind, uint64 p, uint64 t, bytes memory data)
        internal
        pure
        returns (RootRecord memory)
    {
        return RootRecord(
            index, keccak256(abi.encode(index, pred, kind, p, t, data)), pred, kind, p, t, data
        );
    }

    function closureData(uint64 hRound, bytes32 hRecord) internal pure returns (bytes memory) {
        return abi.encode(
            keccak256("asg"), hRound, hRecord, keccak256("root"), keccak256("ed"), keccak256("kh")
        );
    }

    /// @dev A linked chain of `n` SessionClosed records anchored at (index+1, 1000+index+1).
    function chain(uint64 from, bytes32 pred, uint64 n)
        internal
        pure
        returns (SealRegistry.ImportedRecord[] memory es)
    {
        es = new SealRegistry.ImportedRecord[](n);
        for (uint64 i = 0; i < n; i++) {
            RootRecord memory r = rec(
                from + i,
                pred,
                RecordKind.SessionClosed,
                from + i + 1,
                1_000 + from + i + 1,
                abi.encode(keccak256(abi.encode("result", from + i)))
            );
            es[i] = SealRegistry.ImportedRecord(r, 0);
            pred = r.recordID;
        }
    }

    function tipOf(SealRegistry.ImportedRecord[] memory es) internal pure returns (bytes32) {
        return es.length == 0 ? bytes32(0) : es[es.length - 1].record.recordID;
    }

    function importCall(
        uint64 n,
        uint64 p,
        uint64 t,
        uint64 target,
        bytes32 tip,
        SealRegistry.ImportedRecord[] memory es
    ) internal pure returns (bytes memory) {
        return abi.encodeCall(SealRegistry.importRootRecords, (n, p, t, target, tip, es));
    }

    function importOk(
        uint64 n,
        uint64 p,
        uint64 t,
        uint64 target,
        bytes32 tip,
        SealRegistry.ImportedRecord[] memory es
    ) internal {
        (bool ok, bytes memory ret) = callAs(A_SYS, importCall(n, p, t, target, tip, es));
        if (!ok) {
            emit log_named_bytes("import reverted", ret);
            fail();
        }
    }

    function nextRound(OpenArgs memory a) internal pure returns (OpenArgs memory b) {
        b = a;
        b.n = a.n + 1;
        b.rootRound = a.rootRound + 1;
        b.timestamp = a.timestamp + 1;
    }

    function opened() internal returns (OpenArgs memory a) {
        a = firstPayload();
        openAsSystem(a);
    }

    // ---------------------------------------------------------------- acceptance

    function test_genesisUcTimeAndEmptyLog() public view {
        assertEq(reg.recordCount(), 0);
        assertEq(reg.recordTargetCount(), 0);
        assertEq(reg.progress(), 0);
        assertEq(reg.ucTime(), GENESIS_UC_TIME);
    }

    function test_importStoresTheLogAndFinalizeFollows() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory es = chain(0, bytes32(0), 3);
        importOk(a.n, 3, 1_003, 3, tipOf(es), es);
        assertEq(reg.recordCount(), 3);
        assertEq(reg.recordTargetCount(), 3);
        assertEq(reg.progress(), 3);
        assertEq(reg.ucTime(), 1_003);
        for (uint64 i = 0; i < 3; i++) {
            RootRecord memory r = reg.recordAt(i);
            assertEq(r.index, i);
            assertEq(r.recordID, es[i].record.recordID);
            assertEq(r.predecessor, es[i].record.predecessor);
            assertEq(uint8(r.kind), uint8(RecordKind.SessionClosed));
            assertEq(r.progress, i + 1);
            assertEq(r.ucTime, 1_000 + i + 1);
            assertEq(r.data, es[i].record.data);
        }
        finalizeAsSystem(a.n, keccak256("R1"));
        assertEq(uintWord("phase"), 2);
    }

    function test_everyKindRoundTripsWithItsExactPayload() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory es = new SealRegistry.ImportedRecord[](5);
        bytes[5] memory payloads = [
            abi.encode(keccak256("r")),
            abi.encode(keccak256("r"), uint64(100), uint64(100), uint64(101)),
            abi.encode(
                keccak256("r"),
                keccak256("k"),
                uint64(100),
                uint64(101),
                uint64(130),
                uint64(130),
                uint64(131),
                uint64(3),
                uint64(2)
            ),
            closureData(100, keccak256("h")),
            abi.encode(uint64(7), uint64(1), keccak256("ref"))
        ];
        RecordKind[5] memory kinds = [
            RecordKind.SessionClosed,
            RecordKind.Ack,
            RecordKind.RecoveryAck,
            RecordKind.Closure,
            RecordKind.Retirement
        ];
        bytes32 pred;
        for (uint64 i = 0; i < 5; i++) {
            RootRecord memory r = rec(i, pred, kinds[i], 10, 1_010, payloads[i]);
            es[i] = SealRegistry.ImportedRecord(r, kinds[i] == RecordKind.Closure ? 1 : 0);
            pred = r.recordID;
        }
        importOk(a.n, 10, 1_010, 5, pred, es);
        for (uint64 i = 0; i < 5; i++) {
            RootRecord memory r = reg.recordAt(i);
            assertEq(uint8(r.kind), uint8(kinds[i]));
            assertEq(r.data, payloads[i]);
        }
    }

    function test_aBacklogIsImportedInPrefixesOfThirtyTwo() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory all = chain(0, bytes32(0), 40);
        SealRegistry.ImportedRecord[] memory first = new SealRegistry.ImportedRecord[](32);
        for (uint256 i = 0; i < 32; i++) {
            first[i] = all[i];
        }
        // the target is the whole log; the first block must carry exactly 32
        importOk(a.n, 40, 1_040, 40, tipOf(all), first);
        assertEq(reg.recordCount(), 32);
        assertEq(reg.recordTargetCount(), 40);
        finalizeAsSystem(a.n, keccak256("R1"));

        OpenArgs memory b = nextRound(a);
        openAsSystem(b);
        SealRegistry.ImportedRecord[] memory rest = new SealRegistry.ImportedRecord[](8);
        for (uint256 i = 0; i < 8; i++) {
            rest[i] = all[32 + i];
        }
        importOk(b.n, 40, 1_040, 40, tipOf(all), rest);
        assertEq(reg.recordCount(), 40);
        finalizeAsSystem(b.n, keccak256("R2"));
    }

    function test_anEmptyBatchIsMandatoryAndAccepted() public {
        OpenArgs memory a = opened();
        importEmptyAsSystem(a.n);
        assertEq(uintWord("records.importedRound"), a.n);
        finalizeAsSystem(a.n, keccak256("R1"));
    }

    function test_theTargetMayRunAheadOfTheImportedTail() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory all = chain(0, bytes32(0), 3);
        SealRegistry.ImportedRecord[] memory none = new SealRegistry.ImportedRecord[](0);
        // an empty batch cannot skip a pending record
        assertRefused(
            A_SYS,
            importCall(a.n, 3, 1_003, 3, tipOf(all), none),
            SealRegistry.RecordPrefixInvalid.selector
        );
    }

    // ---------------------------------------------------------------- finalize gate and provenance

    function test_finalizeWithoutImportIsRefused() public {
        OpenArgs memory a = opened();
        assertRefused(
            A_SYS, finalizeCalldata(a.n, keccak256("R1")), SealRegistry.RecordImportMissing.selector
        );
    }

    function test_aSecondImportInOneRoundIsRefused() public {
        OpenArgs memory a = opened();
        importEmptyAsSystem(a.n);
        SealRegistry.ImportedRecord[] memory none = new SealRegistry.ImportedRecord[](0);
        assertRefused(
            A_SYS,
            importCall(a.n, 0, GENESIS_UC_TIME, 0, bytes32(0), none),
            SealRegistry.RecordImportDuplicate.selector
        );
    }

    function test_onlyTheSystemCallerMayImport() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory none = new SealRegistry.ImportedRecord[](0);
        assertRefused(
            address(0xBEEF),
            importCall(a.n, 0, GENESIS_UC_TIME, 0, bytes32(0), none),
            SealRegistry.NotSystemCaller.selector
        );
    }

    function test_importNeedsAnOpenRoundOfTheSameNumber() public {
        SealRegistry.ImportedRecord[] memory none = new SealRegistry.ImportedRecord[](0);
        assertRefused(
            A_SYS,
            importCall(1, 0, GENESIS_UC_TIME, 0, bytes32(0), none),
            SealRegistry.NotOpen.selector
        );
        OpenArgs memory a = opened();
        assertRefused(
            A_SYS,
            importCall(a.n + 1, 0, GENESIS_UC_TIME, 0, bytes32(0), none),
            SealRegistry.WrongOutcomeRound.selector
        );
    }

    // ---------------------------------------------------------------- prefix rule

    function test_aShortOrLongBatchIsNotTheRequiredPrefix() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory three = chain(0, bytes32(0), 3);
        SealRegistry.ImportedRecord[] memory two = chain(0, bytes32(0), 2);
        assertRefused(
            A_SYS,
            importCall(a.n, 3, 1_003, 3, tipOf(three), two),
            SealRegistry.RecordPrefixInvalid.selector
        );
        assertRefused(
            A_SYS,
            importCall(a.n, 2, 1_002, 2, tipOf(two), three),
            SealRegistry.RecordPrefixInvalid.selector
        );
    }

    // ---------------------------------------------------------------- identity and content

    function _single(RootRecord memory r, uint64 closedEpoch)
        internal
        pure
        returns (SealRegistry.ImportedRecord[] memory es)
    {
        es = new SealRegistry.ImportedRecord[](1);
        es[0] = SealRegistry.ImportedRecord(r, closedEpoch);
    }

    function _refuseSingle(RootRecord memory r, uint64 closedEpoch, bytes4 err) internal {
        OpenArgs memory a = opened();
        assertRefused(A_SYS, importCall(a.n, 5, 1_005, 1, r.recordID, _single(r, closedEpoch)), err);
    }

    function _validSingle() internal pure returns (RootRecord memory) {
        return rec(0, bytes32(0), RecordKind.SessionClosed, 5, 1_005, abi.encode(keccak256("r")));
    }

    function test_theControlImportIsAcceptedBeforeEachIsolatedRefusal() public {
        OpenArgs memory a = opened();
        RootRecord memory r = _validSingle();
        importOk(a.n, 5, 1_005, 1, r.recordID, _single(r, 0));
        assertEq(reg.recordCount(), 1);
    }

    function test_wrongIndexPredecessorAndIdentifierAreRefused() public {
        RootRecord memory r = _validSingle();
        r.index = 1;
        r.recordID =
            keccak256(abi.encode(r.index, r.predecessor, r.kind, r.progress, r.ucTime, r.data));
        _refuseSingle(r, 0, SealRegistry.RecordInvalid.selector);
    }

    function test_wrongPredecessorIsRefused() public {
        RootRecord memory r = _validSingle();
        r.predecessor = keccak256("not the tip");
        r.recordID =
            keccak256(abi.encode(r.index, r.predecessor, r.kind, r.progress, r.ucTime, r.data));
        _refuseSingle(r, 0, SealRegistry.RecordInvalid.selector);
    }

    function test_aRecordIdentifierThatIsNotItsContentIsRefused() public {
        RootRecord memory r = _validSingle();
        r.recordID = keccak256("forged");
        _refuseSingle(r, 0, SealRegistry.RecordInvalid.selector);
    }

    function test_retaggedAnchorsOrDataChangeTheIdentifier() public {
        RootRecord memory r = _validSingle();
        r.progress = 4; // content changed, identifier kept
        _refuseSingle(r, 0, SealRegistry.RecordInvalid.selector);
    }

    function test_unknownKindIsRefused() public {
        RootRecord memory r = _validSingle();
        r.kind = RecordKind.None;
        r.recordID =
            keccak256(abi.encode(r.index, r.predecessor, r.kind, r.progress, r.ucTime, r.data));
        _refuseSingle(r, 0, SealRegistry.RecordInvalid.selector);
    }

    function test_payloadWidthIsExact() public {
        RootRecord memory r = rec(
            0,
            bytes32(0),
            RecordKind.SessionClosed,
            5,
            1_005,
            abi.encodePacked(keccak256("r"), uint8(0))
        );
        _refuseSingle(r, 0, SealRegistry.RecordInvalid.selector);
    }

    function test_aUint64PayloadWordWithHighBitsIsRefused() public {
        RootRecord memory r = rec(
            0,
            bytes32(0),
            RecordKind.Ack,
            5,
            1_005,
            abi.encode(keccak256("r"), uint256(type(uint64).max) + 1, uint64(1), uint64(2))
        );
        _refuseSingle(r, 0, SealRegistry.RecordInvalid.selector);
    }

    function test_onlyAClosureCarriesAClosedEpoch() public {
        _refuseSingle(_validSingle(), 1, SealRegistry.RecordInvalid.selector);
    }

    // ---------------------------------------------------------------- anchors and targets

    function test_anchorsAboveTheCurrentValuesAreRefused() public {
        OpenArgs memory a = opened();
        RootRecord memory r = _validSingle();
        assertRefused(
            A_SYS,
            importCall(a.n, 4, 1_005, 1, r.recordID, _single(r, 0)),
            SealRegistry.RecordAnchorInvalid.selector
        );
        assertRefused(
            A_SYS,
            importCall(a.n, 5, 1_004, 1, r.recordID, _single(r, 0)),
            SealRegistry.RecordAnchorInvalid.selector
        );
    }

    function test_recordAnchorsMustNotDecrease() public {
        OpenArgs memory a = opened();
        RootRecord memory r0 =
            rec(0, bytes32(0), RecordKind.SessionClosed, 5, 1_005, abi.encode(keccak256("a")));
        RootRecord memory lowerProgress =
            rec(1, r0.recordID, RecordKind.SessionClosed, 4, 1_006, abi.encode(keccak256("b")));
        RootRecord memory lowerTime =
            rec(1, r0.recordID, RecordKind.SessionClosed, 6, 1_004, abi.encode(keccak256("b")));
        SealRegistry.ImportedRecord[] memory es = new SealRegistry.ImportedRecord[](2);
        es[0] = SealRegistry.ImportedRecord(r0, 0);
        es[1] = SealRegistry.ImportedRecord(lowerProgress, 0);
        assertRefused(
            A_SYS,
            importCall(a.n, 6, 1_006, 2, lowerProgress.recordID, es),
            SealRegistry.RecordAnchorInvalid.selector
        );
        es[1] = SealRegistry.ImportedRecord(lowerTime, 0);
        assertRefused(
            A_SYS,
            importCall(a.n, 6, 1_006, 2, lowerTime.recordID, es),
            SealRegistry.RecordAnchorInvalid.selector
        );
    }

    function test_currentProgressTimeAndTargetNeverDecrease() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory es = chain(0, bytes32(0), 3);
        importOk(a.n, 3, 1_003, 3, tipOf(es), es);
        finalizeAsSystem(a.n, keccak256("R1"));
        OpenArgs memory b = nextRound(a);
        openAsSystem(b);
        SealRegistry.ImportedRecord[] memory none = new SealRegistry.ImportedRecord[](0);
        bytes32 tip = tipOf(es);
        assertRefused(
            A_SYS,
            importCall(b.n, 2, 1_003, 3, tip, none),
            SealRegistry.RecordAnchorInvalid.selector
        );
        assertRefused(
            A_SYS,
            importCall(b.n, 3, 1_002, 3, tip, none),
            SealRegistry.RecordAnchorInvalid.selector
        );
        assertRefused(
            A_SYS,
            importCall(b.n, 3, 1_003, 2, tip, none),
            SealRegistry.RecordAnchorInvalid.selector
        );
        importOk(b.n, 3, 1_003, 3, tip, none); // equal values are accepted
    }

    function test_anUnchangedTargetCountNeedsAnUnchangedTip() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory es = chain(0, bytes32(0), 3);
        importOk(a.n, 3, 1_003, 3, tipOf(es), es);
        finalizeAsSystem(a.n, keccak256("R1"));
        OpenArgs memory b = nextRound(a);
        openAsSystem(b);
        SealRegistry.ImportedRecord[] memory none = new SealRegistry.ImportedRecord[](0);
        assertRefused(
            A_SYS,
            importCall(b.n, 3, 1_003, 3, keccak256("another tip"), none),
            SealRegistry.RecordTargetInvalid.selector
        );
    }

    function test_targetZeroNeedsAZeroTip() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory none = new SealRegistry.ImportedRecord[](0);
        assertRefused(
            A_SYS,
            importCall(a.n, 0, GENESIS_UC_TIME, 0, keccak256("tip"), none),
            SealRegistry.RecordTargetInvalid.selector
        );
    }

    function test_theTailMustEqualTheTargetTipWhenCaughtUp() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory es = chain(0, bytes32(0), 2);
        assertRefused(
            A_SYS,
            importCall(a.n, 2, 1_002, 2, keccak256("other"), es),
            SealRegistry.RecordTargetInvalid.selector
        );
    }

    // ---------------------------------------------------------------- keys

    function _two(RootRecord memory a, uint64 ea, RootRecord memory b, uint64 eb)
        internal
        pure
        returns (SealRegistry.ImportedRecord[] memory es)
    {
        es = new SealRegistry.ImportedRecord[](2);
        es[0] = SealRegistry.ImportedRecord(a, ea);
        es[1] = SealRegistry.ImportedRecord(b, eb);
    }

    function test_aClosureKeyIsFixedByTheFirstRecord() public {
        OpenArgs memory a = opened();
        bytes memory d = closureData(100, keccak256("h"));
        RootRecord memory c0 = rec(0, bytes32(0), RecordKind.Closure, 5, 1_005, d);
        // the same key (epoch, H record, hRound) with other digests is still the same key
        bytes memory d2 = abi.encode(
            keccak256("other"),
            uint64(100),
            keccak256("h"),
            keccak256("r2"),
            keccak256("e2"),
            keccak256("k2")
        );
        RootRecord memory c1 = rec(1, c0.recordID, RecordKind.Closure, 6, 1_006, d2);
        assertRefused(
            A_SYS,
            importCall(a.n, 6, 1_006, 2, c1.recordID, _two(c0, 1, c1, 1)),
            SealRegistry.RecordDuplicateKey.selector
        );
        // another closed epoch, another H record or another round is another key
        RootRecord memory c2 = rec(1, c0.recordID, RecordKind.Closure, 6, 1_006, d2);
        importOk(a.n, 6, 1_006, 2, c2.recordID, _two(c0, 1, c2, 2));
        assertEq(reg.recordCount(), 2);
    }

    function test_aRetirementKeyIsFixedByTheFirstRecord() public {
        OpenArgs memory a = opened();
        bytes memory d = abi.encode(uint64(7), uint64(1), keccak256("ref"));
        RootRecord memory r0 = rec(0, bytes32(0), RecordKind.Retirement, 5, 1_005, d);
        RootRecord memory r1 = rec(1, r0.recordID, RecordKind.Retirement, 6, 1_006, d);
        assertRefused(
            A_SYS,
            importCall(a.n, 6, 1_006, 2, r1.recordID, _two(r0, 0, r1, 0)),
            SealRegistry.RecordDuplicateKey.selector
        );
        // a later generation of the same identity is another key
        bytes memory d2 = abi.encode(uint64(7), uint64(2), keccak256("ref"));
        RootRecord memory r2 = rec(1, r0.recordID, RecordKind.Retirement, 6, 1_006, d2);
        importOk(a.n, 6, 1_006, 2, r2.recordID, _two(r0, 0, r2, 0));
    }

    function test_aKeyLoggedInAnEarlierBlockStaysTaken() public {
        OpenArgs memory a = opened();
        bytes memory d = closureData(100, keccak256("h"));
        RootRecord memory c0 = rec(0, bytes32(0), RecordKind.Closure, 5, 1_005, d);
        importOk(a.n, 5, 1_005, 1, c0.recordID, _single(c0, 1));
        finalizeAsSystem(a.n, keccak256("R1"));
        OpenArgs memory b = nextRound(a);
        openAsSystem(b);
        RootRecord memory c1 = rec(1, c0.recordID, RecordKind.Closure, 6, 1_006, d);
        assertRefused(
            A_SYS,
            importCall(b.n, 6, 1_006, 2, c1.recordID, _single(c1, 1)),
            SealRegistry.RecordDuplicateKey.selector
        );
    }

    function _closureWith(
        bytes32 hRecord,
        uint64 hRound,
        bytes32 terminalRoot,
        bytes32 exposureDigest
    ) internal pure returns (bytes memory) {
        return abi.encode(
            keccak256("asg"), hRound, hRecord, terminalRoot, exposureDigest, keccak256("kh")
        );
    }

    /// @dev The closure key is (closed epoch, H record, H round): changing only the H round or only the H record is another key, and
    /// repeating the key with any other field changed is the same key.
    function test_theClosureKeyDistinguishesTheHRecordAndTheHRoundAlone() public {
        OpenArgs memory a = opened();
        bytes32 h = keccak256("h");
        bytes32 root = keccak256("root");
        bytes32 ed = keccak256("ed");
        RootRecord memory c0 =
            rec(0, bytes32(0), RecordKind.Closure, 5, 1_005, _closureWith(h, 100, root, ed));
        // only the H round differs
        RootRecord memory c1 =
            rec(1, c0.recordID, RecordKind.Closure, 6, 1_006, _closureWith(h, 101, root, ed));
        // only the H record differs
        RootRecord memory c2 = rec(
            2,
            c1.recordID,
            RecordKind.Closure,
            7,
            1_007,
            _closureWith(keccak256("h2"), 100, root, ed)
        );
        SealRegistry.ImportedRecord[] memory es = new SealRegistry.ImportedRecord[](3);
        es[0] = SealRegistry.ImportedRecord(c0, 1);
        es[1] = SealRegistry.ImportedRecord(c1, 1);
        es[2] = SealRegistry.ImportedRecord(c2, 1);
        importOk(a.n, 7, 1_007, 3, c2.recordID, es);
        assertEq(reg.recordCount(), 3);
        finalizeAsSystem(a.n, keccak256("R1"));

        // the first key again, with another terminal root and another exposure digest, is the same key
        OpenArgs memory b = nextRound(a);
        openAsSystem(b);
        RootRecord memory same = rec(
            3,
            c2.recordID,
            RecordKind.Closure,
            8,
            1_008,
            _closureWith(h, 100, keccak256("another root"), keccak256("another digest"))
        );
        assertRefused(
            A_SYS,
            importCall(b.n, 8, 1_008, 4, same.recordID, _single(same, 1)),
            SealRegistry.RecordDuplicateKey.selector
        );
        // and the second key (round only) again
        RootRecord memory sameRound = rec(
            3, c2.recordID, RecordKind.Closure, 8, 1_008, _closureWith(h, 101, root, keccak256("x"))
        );
        assertRefused(
            A_SYS,
            importCall(b.n, 8, 1_008, 4, sameRound.recordID, _single(sameRound, 1)),
            SealRegistry.RecordDuplicateKey.selector
        );
    }

    /// @dev With the target ahead of the imported tail the tail rule is silent, so the unchanged-count/unchanged-tip rule is the only
    /// guard: 70 records, 32 per block, the second block repeats the target count with another tip.
    function test_anUnchangedTargetCountNeedsAnUnchangedTipWhileTheLogIsStillBehind() public {
        OpenArgs memory a = opened();
        SealRegistry.ImportedRecord[] memory all = chain(0, bytes32(0), 70);
        SealRegistry.ImportedRecord[] memory first = new SealRegistry.ImportedRecord[](32);
        for (uint256 i = 0; i < 32; i++) {
            first[i] = all[i];
        }
        importOk(a.n, 70, 1_070, 70, tipOf(all), first);
        finalizeAsSystem(a.n, keccak256("R1"));

        OpenArgs memory b = nextRound(a);
        openAsSystem(b);
        SealRegistry.ImportedRecord[] memory second = new SealRegistry.ImportedRecord[](32);
        for (uint256 i = 0; i < 32; i++) {
            second[i] = all[32 + i];
        }
        // 64 of 70 imported afterwards: the tail rule does not apply, the tip rule does
        assertRefused(
            A_SYS,
            importCall(b.n, 70, 1_070, 70, keccak256("another tip"), second),
            SealRegistry.RecordTargetInvalid.selector
        );
        importOk(b.n, 70, 1_070, 70, tipOf(all), second); // control: the same call with the unchanged tip is accepted
        assertEq(reg.recordCount(), 64);
    }

    /// @dev The registry stores every word of an accepted record under R(i, j) (briefs/p85-pr1c-control-records.md section 6).
    function _assertStoredWords(SealRegistry.ImportedRecord memory e) internal view {
        RootRecord memory r = e.record;
        bytes32 entry = keccak256("unicity.seal-registry/records.entry");
        assertEq(
            vm.load(A_SR, keccak256(abi.encode(entry, r.index, uint64(0)))),
            r.recordID,
            "R(i,0) recordID"
        );
        assertEq(
            vm.load(A_SR, keccak256(abi.encode(entry, r.index, uint64(1)))),
            r.predecessor,
            "R(i,1) predecessor"
        );
        assertEq(
            uint256(vm.load(A_SR, keccak256(abi.encode(entry, r.index, uint64(2))))),
            uint256(uint8(r.kind)),
            "R(i,2) kind"
        );
        assertEq(
            uint256(vm.load(A_SR, keccak256(abi.encode(entry, r.index, uint64(3))))),
            r.progress,
            "R(i,3) progress"
        );
        assertEq(
            uint256(vm.load(A_SR, keccak256(abi.encode(entry, r.index, uint64(4))))),
            r.ucTime,
            "R(i,4) ucTime"
        );
        assertEq(
            uint256(vm.load(A_SR, keccak256(abi.encode(entry, r.index, uint64(5))))),
            r.data.length,
            "R(i,5) data length"
        );
        for (uint256 k; k < r.data.length / 32; k++) {
            bytes32 w;
            bytes memory d = r.data;
            // forge-lint: disable-next-line(unsafe-typecast)
            assembly ("memory-safe") {
                w := mload(add(add(d, 0x20), mul(k, 0x20)))
            }
            assertEq(
                vm.load(A_SR, keccak256(abi.encode(entry, r.index, uint64(6 + k)))),
                w,
                "R(i,6+k) payload word"
            );
        }
        assertEq(
            uint256(vm.load(A_SR, keccak256(abi.encode(entry, r.index, uint64(15))))),
            e.closedEpoch,
            "R(i,15) closedEpoch"
        );
    }

    // ---------------------------------------------------------------- views

    function test_recordAtOutsideTheCountReverts() public {
        vm.expectRevert(SealRegistry.RecordIndexOutOfRange.selector);
        reg.recordAt(0);
    }

    // ---------------------------------------------------------------- bft-core's import vectors

    string internal constant IMPORT_VECTORS = "/test/p85/fixtures/root-records-import-vectors.json";

    function _ip(uint256 sc, uint256 b, string memory tail) internal pure returns (string memory) {
        return string.concat(".scenarios[", vm.toString(sc), "].blocks[", vm.toString(b), "]", tail);
    }

    function _entries(string memory json, uint256 sc, uint256 b)
        internal
        view
        returns (SealRegistry.ImportedRecord[] memory es)
    {
        uint256 n;
        while (vm.keyExistsJson(
                json, _ip(sc, b, string.concat(".entries[", vm.toString(n), "].index"))
            )) ++n;
        es = new SealRegistry.ImportedRecord[](n);
        for (uint256 i = 0; i < n; i++) {
            string memory e = _ip(sc, b, string.concat(".entries[", vm.toString(i), "]"));
            es[i].record = RootRecord(
                uint64(vm.parseJsonUint(json, string.concat(e, ".index"))),
                vm.parseJsonBytes32(json, string.concat(e, ".recordId")),
                vm.parseJsonBytes32(json, string.concat(e, ".predecessor")),
                RecordKind(uint8(vm.parseJsonUint(json, string.concat(e, ".kind")))),
                uint64(vm.parseJsonUint(json, string.concat(e, ".progress"))),
                uint64(vm.parseJsonUint(json, string.concat(e, ".ucTime"))),
                vm.parseJsonBytes(json, string.concat(e, ".data"))
            );
            es[i].closedEpoch = uint64(vm.parseJsonUint(json, string.concat(e, ".closedEpoch")));
        }
    }

    /// @dev The projection's own import calls, block by block: the registry accepts exactly them, recomputes every record identifier,
    /// and reads back what the projection ordered.
    function test_theProjectionsImportBlocksAreAcceptedAndReadBack() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), IMPORT_VECTORS));
        for (uint256 sc; vm.keyExistsJson(json, _ip(sc, 0, ".n")); ++sc) {
            uint256 snap = vm.snapshotState();
            OpenArgs memory a = firstPayload();
            uint256 expectCount;
            for (uint256 b; vm.keyExistsJson(json, _ip(sc, b, ".n")); ++b) {
                if (b != 0) a = nextRound(a);
                assertEq(
                    a.n, vm.parseJsonUint(json, _ip(sc, b, ".n")), "round numbers follow the vector"
                );
                openAsSystem(a);
                SealRegistry.ImportedRecord[] memory es = _entries(json, sc, b);
                importOk(
                    a.n,
                    uint64(vm.parseJsonUint(json, _ip(sc, b, ".progress"))),
                    uint64(vm.parseJsonUint(json, _ip(sc, b, ".ucTime"))),
                    uint64(vm.parseJsonUint(json, _ip(sc, b, ".targetCount"))),
                    vm.parseJsonBytes32(json, _ip(sc, b, ".targetTip")),
                    es
                );
                finalizeAsSystem(a.n, keccak256(abi.encode("R", sc, b)));
                for (uint256 i; i < es.length; i++) {
                    _assertStoredWords(es[i]);
                    RootRecord memory r = reg.recordAt(uint64(expectCount + i));
                    assertEq(r.recordID, es[i].record.recordID);
                    assertEq(r.data, es[i].record.data);
                    assertEq(r.progress, es[i].record.progress);
                    assertEq(r.ucTime, es[i].record.ucTime);
                }
                expectCount += es.length;
                assertEq(reg.recordCount(), expectCount);
                assertEq(
                    reg.recordTargetCount(), vm.parseJsonUint(json, _ip(sc, b, ".targetCount"))
                );
                assertEq(reg.progress(), vm.parseJsonUint(json, _ip(sc, b, ".progress")));
                assertEq(reg.ucTime(), vm.parseJsonUint(json, _ip(sc, b, ".ucTime")));
            }
            vm.revertToState(snap);
        }
    }

    // ---------------------------------------------------------------- validator-registry kinds 6 to 8

    /// @dev RootRecord with a raw kind byte: the same ABI, so a kind outside the enum can be sent.
    struct RawRecord {
        uint64 index;
        bytes32 recordID;
        bytes32 predecessor;
        uint8 kind;
        uint64 progress;
        uint64 ucTime;
        bytes data;
    }

    struct RawImported {
        RawRecord record;
        uint64 closedEpoch;
    }

    function _rawSingle(uint8 kind, bytes memory data)
        internal
        pure
        returns (RawImported[] memory es)
    {
        es = new RawImported[](1);
        es[0] = RawImported(
            RawRecord(
                0,
                keccak256(abi.encode(uint64(0), bytes32(0), kind, uint64(5), uint64(1_005), data)),
                bytes32(0),
                kind,
                5,
                1_005,
                data
            ),
            0
        );
    }

    /// @dev Imports one record of a raw kind into a fresh open round; true when the registry accepts it.
    function _importsRaw(uint8 kind, bytes memory data) internal returns (bool ok) {
        uint256 snap = vm.snapshotState();
        OpenArgs memory a = opened();
        RawImported[] memory es = _rawSingle(kind, data);
        (ok,) = callAs(
            A_SYS,
            abi.encodeWithSelector(
                SealRegistry.importRootRecords.selector,
                a.n,
                uint64(5),
                uint64(1_005),
                uint64(1),
                es[0].record.recordID,
                es
            )
        );
        if (ok) {
            RootRecord memory r = reg.recordAt(0);
            assertEq(uint8(r.kind), kind);
            assertEq(r.data, data);
        }
        vm.revertToState(snap);
    }

    function _boundary(uint64 changes, uint64 installed, uint256 recovered, uint256 bitmap)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            keccak256("r"), changes, installed, uint64(9), uint64(1_234), recovered, bitmap
        );
    }

    function _rejected(bytes32 r, uint256 reason, uint64 member, uint256 ready)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(r, reason, member, ready);
    }

    function _holder(uint256 holder, uint64 id, uint64 gen) internal pure returns (bytes memory) {
        return abi.encode(holder, id, gen, keccak256("ref"));
    }

    function test_theRegistryKindsAreAcceptedAndReadBack() public {
        assertTrue(_importsRaw(6, _boundary(5, 5, 0, 0xffff)), "Boundary primary");
        assertTrue(_importsRaw(6, _boundary(5, 6, 1, 0)), "Boundary recovery");
        assertTrue(_importsRaw(7, _rejected(keccak256("r"), 1, 0, 7)), "OutputRejected Expired");
        assertTrue(_importsRaw(7, _rejected(keccak256("r"), 2, 0, 0)), "OutputRejected Invalidated");
        assertTrue(_importsRaw(7, _rejected(keccak256("r"), 3, 4, 0)), "OutputRejected Invalid");
        assertTrue(
            _importsRaw(8, _holder(7, type(uint64).max, type(uint64).max)), "HolderRetirement"
        );
    }

    /// @dev Each cross-field rule of schema v1 section 7, refused alone.
    function test_theRegistryKindsCrossFieldRulesAreRefused() public {
        bytes32 r = keccak256("r");
        bytes[17] memory bad = [
            _boundary(5, 6, 0, 0), // installed != changes for a primary
            _boundary(5, 5, 1, 0), // installed != changes + 1 for a recovery
            _boundary(5, 5, 2, 0), // recovered not a bool
            _boundary(5, 5, 0, 0x10000), // bitmap above 16 bits
            abi.encode(
                bytes32(0), uint64(5), uint64(5), uint64(9), uint64(1), uint256(0), uint256(0)
            ), // zero result
            abi.encode(
                r, uint256(1) << 64, uint64(5), uint64(9), uint64(1), uint256(0), uint256(0)
            ), // a uint64 above 64 bits
            abi.encodePacked(_boundary(5, 5, 0, 0), uint256(0)), // eight words
            _rejected(r, 0, 0, 0), // reason 0
            _rejected(r, 4, 0, 0), // reason 4
            _rejected(r, 1, 3, 0), // member outside Invalid
            _rejected(r, 3, 0, 1), // bitmap outside Expired
            _rejected(r, 1, 0, 0x10000), // bitmap above 16 bits
            _rejected(bytes32(0), 2, 0, 0), // zero result
            abi.encode(r, uint256(1), uint256(1) << 64, uint256(0)), // member above 64 bits (and outside Invalid)
            _holder(8, 1, 1), // holder 8
            abi.encode(uint256(0), uint256(1) << 64, uint64(1), r), // id above 64 bits
            abi.encodePacked(_holder(0, 1, 1), uint256(0)) // five words
        ];
        uint8[17] memory kinds = [6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8];
        for (uint256 i; i < bad.length; ++i) {
            assertFalse(_importsRaw(kinds[i], bad[i]), string.concat("case ", vm.toString(i)));
        }
        assertFalse(_importsRaw(9, abi.encode(r)), "kind 9");
    }

    function test_aHolderRetirementKeyIsFixedByTheFirstRecord() public {
        OpenArgs memory a = opened();
        RootRecord memory first =
            rec(0, bytes32(0), RecordKind.HolderRetirement, 5, 1_005, _holder(0, 7, 1));
        importOk(a.n, 5, 1_005, 1, first.recordID, _single(first, 0));
        // the v2 dedup key of schema v1 (encoding.json "retirement v2 dedup key": holder 0, id 7, generation 1) holds index + 1
        bytes32 key = keccak256(
            abi.encode(
                keccak256("unicity.seal-registry/records.retirement.v2"),
                uint256(0),
                uint64(7),
                uint64(1)
            )
        );
        assertEq(key, 0xac23f3e3ea63434732ba84a3e1a54563d2effcc245ef48fdbdcd922eb29feb76);
        assertEq(uint256(vm.load(A_SR, key)), 1);
        finalizeAsSystem(a.n, keccak256("R1"));

        a = nextRound(a);
        openAsSystem(a);
        // another holder, and the pre-VR key of the same (id, generation), are other keys
        RootRecord memory other =
            rec(1, first.recordID, RecordKind.HolderRetirement, 6, 1_006, _holder(1, 7, 1));
        RootRecord memory legacy = rec(
            2,
            other.recordID,
            RecordKind.Retirement,
            6,
            1_006,
            abi.encode(uint64(7), uint64(1), keccak256("ref"))
        );
        SealRegistry.ImportedRecord[] memory es = new SealRegistry.ImportedRecord[](2);
        es[0] = SealRegistry.ImportedRecord(other, 0);
        es[1] = SealRegistry.ImportedRecord(legacy, 0);
        importOk(a.n, 6, 1_006, 3, legacy.recordID, es);
        finalizeAsSystem(a.n, keccak256("R2"));

        a = nextRound(a);
        openAsSystem(a);
        RootRecord memory again =
            rec(3, legacy.recordID, RecordKind.HolderRetirement, 7, 1_007, _holder(0, 7, 1));
        assertRefused(
            A_SYS,
            importCall(a.n, 7, 1_007, 4, again.recordID, _single(again, 0)),
            SealRegistry.RecordDuplicateKey.selector
        );
    }

    /// @dev The frozen record.decode vectors (bft-core testvectors/validator-registry/encoding.json, copied to test/vr/fixtures):
    /// every one gets the production verdict of the registry's import.
    function test_theFrozenRecordDecodeVectorsGetTheRegistrysVerdict() public {
        string memory json =
            vm.readFile(string.concat(vm.projectRoot(), "/test/vr/fixtures/encoding.json"));
        uint256 n;
        uint256 accepted;
        for (uint256 i;; ++i) {
            string memory vp = string.concat(".vectors[", vm.toString(i), "]");
            if (!vm.keyExistsJson(json, vp)) break;
            if (
                keccak256(bytes(vm.parseJsonString(json, string.concat(vp, ".op"))))
                    != keccak256("record.decode")
            ) continue;
            uint8 kind = uint8(vm.parseJsonUint(json, string.concat(vp, ".input.kind")));
            bytes memory data = vm.parseJsonBytes(json, string.concat(vp, ".input.data"));
            bool ok = vm.parseJsonBool(json, string.concat(vp, ".expect.ok"));
            assertEq(
                _importsRaw(kind, data), ok, vm.parseJsonString(json, string.concat(vp, ".name"))
            );
            ++n;
            if (ok) ++accepted;
        }
        assertEq(n, 25);
        assertEq(accepted, 8);
    }
}
