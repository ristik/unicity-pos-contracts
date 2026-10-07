// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {SealRegistry} from "../src/SealRegistry.sol";
import {B1Entry, B1Member, B1Update} from "../src/B1Layout.sol";
import {B1GenesisBuilder, B1GenesisParams, B1Word} from "../src/B1GenesisBuilder.sol";

/// @notice Shared fixture: the registry's runtime code placed at a_sr with the genesis words of
/// bft-core #153 §5.4 plus the B1 genesis entry and queue, and helpers that address storage by the
/// specification's slot names. The B1 slot helpers (qSlot, eSlot, mSlot) are written out here from the
/// design text, independently of src/B1Layout.sol, so layout tests compare two derivations.
///
/// The genesis values are #153's worked vector (§5.4): genesisCommitment and fullShardConfHash from
/// bft-core docs/design/models/f4aregistry, shard epoch 0, root epoch 1. That vector was built with a
/// placeholder registry code hash, so these are storage fixtures, not this contract's deployable
/// genesis record; building G with this contract's code hash is the Go construction of §5.3.
abstract contract SealRegistryBase is Test {
    address internal constant A_SYS = 0xff00000000000000000000000000000000000001;
    address internal constant A_SR = 0xff00000000000000000000000000000000000002;

    bytes32 internal constant GENESIS_COMMITMENT =
        0x071a4f34498689e1f26353434c92f763ddaaba8de9cc634aa68af6e1bf65eab8;
    bytes32 internal constant FULL_SHARD_CONF_HASH =
        0x3a2c73649214e56d5e98d1c2d06cff56e7a5d67037a25bcf0e43fcaff8987a6b;
    uint64 internal constant SHARD_EPOCH = 0;
    uint64 internal constant ROOT_EPOCH = 1;

    uint256 internal constant FIELD_COUNT = 29;

    // The fixture profile: W_cert = 3 gives K_max = 4 live intervals.
    uint64 internal constant W_CERT = 3;
    uint16 internal constant NETWORK = 7;
    bytes32 internal constant PROFILE_HASH = keccak256("fixture execution profile");
    /// Genesis entry: root genesis epoch ROOT_EPOCH, open, starting at root round 1.
    uint64 internal constant GENESIS_START = 1;
    /// Epochs and members the refusal digest tracks (state outside it is covered by dedicated tests).
    uint256 internal constant TRACK_EPOCHS = 12;
    uint256 internal constant TRACK_MEMBERS = 4;

    /// @dev The open arguments in ABI order: 23 scalars, the static assignment projection (9 words)
    /// and the dynamic B1 update, so the head is 33 words and the update tail follows.
    struct OpenArgs {
        uint64 n;
        uint64 rootRound;
        uint64 rootEpoch;
        uint64 timestamp;
        bytes32 treeRoot;
        bytes32 originIdentity;
        bytes32 trHash;
        bytes32 shardConfHash;
        uint64 certifiedRound;
        uint64 certEpoch;
        uint64 authEpoch;
        bytes32 stateHash;
        bool hasBlockHash;
        bytes32 blockHash;
        bytes32 inputCommitment;
        uint64 transitionCount;
        bytes32 bodyID;
        bytes32 genesisID;
        bytes32 frozenID;
        bytes32 commitID;
        bytes32 frozenParent;
        bytes32 successorTR;
        bytes32 activeConfHash;
        SealRegistry.AssignmentProjection assignment;
        B1Update update;
    }

    string internal constant OPEN_SIGNATURE =
        "open(uint64,uint64,uint64,uint64,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,bytes32,bool,bytes32,bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,(uint64,uint64,bytes32,uint64,uint64,bytes32,uint64,bytes32,bytes32),(uint64,bool,uint64,(uint64,uint64,bytes32,bytes32,uint64,bool,uint64,uint64,bytes32,(uint64,bytes32[4],bytes32[2],uint64)[])[]))";
    string internal constant FINALIZE_SIGNATURE = "finalize(uint64,bytes32)";

    /// @dev Never deployed on chain: the genesis builder runs the runtime's entry checks off chain.
    B1GenesisBuilder internal builder;
    /// @dev W_cert of the installed profile; a subclass may change it before super.setUp().
    uint64 internal wCertFixture = W_CERT;

    function setUp() public virtual {
        builder = new B1GenesisBuilder();
        vm.etch(A_SR, type(SealRegistry).runtimeCode);
        installGenesis();
    }

    function kMax() internal view returns (uint256) {
        return uint256(wCertFixture) + 1;
    }

    /// @dev Installs the genesis allocation the genesis builder produces: six operational words and
    /// the B1 profile, queue, genesis entry and its members. The active assignment starts at the
    /// immutable genesis hash.
    function installGenesis() internal {
        B1Word[] memory ws = builder.words(genesisParams());
        for (uint256 i = 0; i < ws.length; i++) {
            vm.store(A_SR, ws[i].slot, ws[i].value);
        }
    }

    function genesisParams() internal view returns (B1GenesisParams memory p) {
        p = B1GenesisParams({
            genesisCommitment: GENESIS_COMMITMENT,
            shardConfHash: FULL_SHARD_CONF_HASH,
            shardEpoch: SHARD_EPOCH,
            rootEpoch: ROOT_EPOCH,
            network: NETWORK,
            wCert: wCertFixture,
            deltaEv: wCertFixture > 10 ? wCertFixture : 10,
            deltaHold: (wCertFixture > 10 ? wCertFixture : 10) + 10,
            profileHash: PROFILE_HASH,
            gSys: 0,
            gRest: 0,
            entry: genesisEntry()
        });
        p.gRest = builder.gRestBound(kMax());
        p.gSys = builder.minGSys(kMax(), p.gRest);
    }

    function genesisEntry() internal pure returns (B1Entry memory) {
        return B1Entry({
            epoch: ROOT_EPOCH,
            bodyKind: 1,
            bodyID: keccak256("genesis body"),
            activationCommitID: bytes32(0),
            start: GENESIS_START,
            hasEnd: false,
            end: 0,
            signingScheme: 1,
            signingConfigHash: keccak256("genesis signing config"),
            members: members(3, 0xA0)
        });
    }

    // ---------------------------------------------------------------- B1 entries and slots

    /// @dev m members with strictly increasing raw node IDs [0x76, seed, j] and 33-byte compressed
    /// key-shaped values (prefix 02/03; the registry does not check curve points).
    function members(uint256 m, uint8 seed) internal pure returns (B1Member[] memory ms) {
        ms = new B1Member[](m);
        for (uint256 j = 0; j < m; j++) {
            ms[j] = member(seed, uint8(j));
        }
    }

    function member(uint8 seed, uint8 j) internal pure returns (B1Member memory mem) {
        mem.nodeIDLength = 3;
        mem.nodeID[0] = bytes32(abi.encodePacked(bytes1(0x76), bytes1(seed), bytes1(j)));
        bytes32 h = keccak256(abi.encode("key", seed, j));
        mem.key[0] = bytes32(abi.encodePacked(bytes1(uint8(2 + (j & 1))), bytes31(h)));
        mem.key[1] = bytes32(abi.encodePacked(bytes1(h[31])));
        mem.weight = 1 + (uint64(j) % 5);
    }

    function entry(uint64 epoch, uint64 start, uint64 end, uint256 m)
        internal
        pure
        returns (B1Entry memory en)
    {
        en = B1Entry({
            epoch: epoch,
            bodyKind: 1,
            bodyID: keccak256(abi.encode("body", epoch)),
            activationCommitID: keccak256(abi.encode("activation", epoch)),
            start: start,
            hasEnd: end != 0,
            end: end,
            signingScheme: 1,
            signingConfigHash: keccak256(abi.encode("signing config", epoch)),
            members: members(m, uint8(epoch))
        });
    }

    function totalWeight(B1Member[] memory ms) internal pure returns (uint256 t) {
        for (uint256 j = 0; j < ms.length; j++) {
            t += ms[j].weight;
        }
    }

    function qSlot(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("unicity.seal-registry/b1.queue"), i));
    }

    function eSlot(uint256 e, uint256 f) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("unicity.seal-registry/b1.entry"), e, f));
    }

    function mSlot(uint256 e, uint256 j, uint256 f) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("unicity.seal-registry/b1.member"), e, j, f));
    }

    function fixedSlot(string memory name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("unicity.seal-registry/", name));
    }

    function b1Word(string memory name) internal view returns (uint256) {
        return uint256(vm.load(A_SR, fixedSlot(name)));
    }

    function ent(uint256 e, uint256 f) internal view returns (bytes32) {
        return vm.load(A_SR, eSlot(e, f));
    }

    function memW(uint256 e, uint256 j, uint256 f) internal view returns (bytes32) {
        return vm.load(A_SR, mSlot(e, j, f));
    }

    function queueAt(uint256 i) internal view returns (uint256) {
        return uint256(vm.load(A_SR, qSlot(i)));
    }

    /// @dev Epochs in queue order, head first.
    function liveEpochs() internal view returns (uint256[] memory es) {
        uint256 head = b1Word("b1.head");
        uint256 count = b1Word("b1.count");
        es = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            es[i] = queueAt((head + i) % (b1Word("b1.wCert") + 1));
        }
    }

    function tipEpoch() internal view returns (uint64) {
        uint256[] memory es = liveEpochs();
        return uint64(es[es.length - 1]);
    }

    /// @dev Requires every one of the 11 + 8m words of an entry to equal the independent expectation,
    /// and the member words from m up to maxMembers to be zero (no stale tail).
    function assertEntryStored(B1Entry memory en, uint256 maxMembers) internal view {
        uint256 e = en.epoch;
        assertEq(ent(e, 0), bytes32(uint256(1)), "present");
        assertEq(ent(e, 1), bytes32(uint256(en.bodyKind)), "bodyKind");
        assertEq(ent(e, 2), en.bodyID, "bodyID");
        assertEq(ent(e, 3), en.activationCommitID, "activationCommitID");
        assertEq(ent(e, 4), bytes32(uint256(en.start)), "start");
        assertEq(ent(e, 5), bytes32(uint256(en.end)), "end");
        assertEq(ent(e, 6), bytes32(uint256(en.hasEnd ? 1 : 0)), "hasEnd");
        assertEq(ent(e, 7), bytes32(uint256(en.signingScheme)), "signingScheme");
        assertEq(ent(e, 8), en.signingConfigHash, "signingConfigHash");
        assertEq(ent(e, 9), bytes32(en.members.length), "memberCount");
        assertEq(ent(e, 10), bytes32(totalWeight(en.members)), "totalWeight");
        for (uint256 j = 0; j < en.members.length; j++) {
            B1Member memory x = en.members[j];
            assertEq(memW(e, j, 0), bytes32(uint256(x.nodeIDLength)), "nodeIDLength");
            for (uint256 w = 0; w < 4; w++) {
                assertEq(memW(e, j, 1 + w), x.nodeID[w], "nodeID word");
            }
            assertEq(memW(e, j, 5), x.key[0], "key word 0");
            assertEq(memW(e, j, 6), x.key[1], "key word 1");
            assertEq(memW(e, j, 7), bytes32(uint256(x.weight)), "weight");
        }
        for (uint256 j = en.members.length; j < maxMembers; j++) {
            for (uint256 f = 0; f < 8; f++) {
                assertEq(memW(e, j, f), bytes32(0), "stale member word");
            }
        }
    }

    /// @dev Every metadata and member word (up to maxMembers) of epoch e is zero.
    function assertEntryAbsent(uint256 e, uint256 maxMembers) internal view {
        for (uint256 f = 0; f < 11; f++) {
            assertEq(ent(e, f), bytes32(0), "stale entry word");
        }
        for (uint256 j = 0; j < maxMembers; j++) {
            for (uint256 f = 0; f < 8; f++) {
                assertEq(memW(e, j, f), bytes32(0), "stale member word");
            }
        }
    }

    /// @dev A digest of the tracked B1 words, so a refusal can be shown to leave all of them intact.
    function b1Digest() internal view returns (bytes32 d) {
        d = keccak256(
            abi.encode(
                b1Word("b1.network"),
                b1Word("b1.wCert"),
                b1Word("b1.profileHash"),
                b1Word("b1.initialized"),
                b1Word("b1.head"),
                b1Word("b1.count")
            )
        );
        for (uint256 i = 0; i < kMax() + 2; i++) {
            d = keccak256(abi.encode(d, queueAt(i)));
        }
        for (uint256 e = 0; e < TRACK_EPOCHS; e++) {
            for (uint256 f = 0; f < 11; f++) {
                d = keccak256(abi.encode(d, ent(e, f)));
            }
            for (uint256 j = 0; j < TRACK_MEMBERS; j++) {
                for (uint256 f = 0; f < 8; f++) {
                    d = keccak256(abi.encode(d, memW(e, j, f)));
                }
            }
        }
    }

    /// @dev Bounded pseudo-random arguments around the first payload: some fields perturbed, the
    /// update carrying 0 to 2 entries of up to 3 members. Fuzzing OpenArgs directly would let the
    /// fuzzer build megabyte-sized nested arrays, so the fuzz tests draw a seed instead.
    function randomArgs(uint256 seed) internal pure returns (OpenArgs memory a) {
        a = firstPayload();
        uint256 r = seed;
        r = _step(r);
        a.n = uint64(r % 4);
        r = _step(r);
        a.rootRound = uint64(r % 10);
        r = _step(r);
        a.rootEpoch = uint64(1 + r % 2);
        r = _step(r);
        if (r % 4 == 0) a.shardConfHash = bytes32(r);
        r = _step(r);
        a.certEpoch = uint64(r % 2);
        r = _step(r);
        a.authEpoch = uint64(r % 2);
        r = _step(r);
        a.hasBlockHash = r % 2 == 0;
        r = _step(r);
        a.blockHash = r % 3 == 0 ? bytes32(r) : bytes32(0);
        r = _step(r);
        a.transitionCount = uint64(r % 5 == 0 ? 1 + (r >> 8) % 2 : 0);
        r = _step(r);
        if (r % 3 == 0) a.bodyID = bytes32(r);
        r = _step(r);
        if (r % 4 == 0) a.activeConfHash = bytes32(r);
        r = _step(r);
        a.update.priorTipEpoch = uint64(1 + r % 2);
        r = _step(r);
        a.update.hasOldTipEnd = r % 2 == 0;
        r = _step(r);
        a.update.oldTipEnd = uint64(r % 10);
        r = _step(r);
        uint256 count = r % 3;
        a.update.newEntries = new B1Entry[](count);
        for (uint256 i = 0; i < count; i++) {
            r = _step(r);
            uint64 start = uint64(r % 10);
            r = _step(r);
            uint64 end = r % 3 == 0 ? 0 : uint64(r % 13);
            r = _step(r);
            a.update.newEntries[i] = entry(uint64(1 + r % 4), start, end, (r >> 8) % 4);
        }
    }

    function _step(uint256 r) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(r)));
    }

    /// @dev A cheaper digest for long-running handlers: profile words, queue and entry metadata only.
    function b1DigestLight() internal view returns (bytes32 d) {
        d = keccak256(
            abi.encode(
                b1Word("b1.head"), b1Word("b1.count"), b1Word("b1.initialized"), b1Word("b1.wCert")
            )
        );
        for (uint256 i = 0; i < kMax() + 2; i++) {
            d = keccak256(abi.encode(d, queueAt(i)));
        }
        for (uint256 e = 0; e < TRACK_EPOCHS; e++) {
            for (uint256 f = 0; f < 11; f++) {
                d = keccak256(abi.encode(d, ent(e, f)));
            }
        }
    }

    /// @dev An update with no new entries, bound to the given parent tip.
    function emptyUpdate(uint64 tip) internal pure returns (B1Update memory u) {
        u = B1Update({
            priorTipEpoch: tip, hasOldTipEnd: false, oldTipEnd: 0, newEntries: new B1Entry[](0)
        });
    }

    /// @dev The update an honest projection supplies when the epoch advances by `delta` at origin
    /// round O with the stored tip as parent: delta consecutive entries, the i-th starting at
    /// O - delta + i, the last open; the former tip closes where the first starts.
    function advanceUpdate(uint64 tip, uint64 O, uint64 delta, uint256 m)
        internal
        pure
        returns (B1Update memory u)
    {
        B1Entry[] memory es = new B1Entry[](delta);
        for (uint64 i = 1; i <= delta; i++) {
            uint64 start = O - delta + i;
            es[i - 1] = entry(tip + i, start, i == delta ? 0 : start + 1, m);
        }
        u = B1Update({
            priorTipEpoch: tip, hasOldTipEnd: true, oldTipEnd: O - delta + 1, newEntries: es
        });
    }

    /// @dev The 30 fixed registry slot names, in artifact order.
    function fieldNames() internal pure returns (string[FIELD_COUNT] memory names) {
        names = [
            "genesisCommitment",
            "config.shardConfHash",
            "assignment.epoch",
            "assignment.rootEpoch",
            "assignment.activeConfHash",
            "assignment.spanCommitment",
            "clock.rootRound",
            "origin.rootEpoch",
            "origin.timestamp",
            "origin.treeRoot",
            "origin.identity",
            "origin.trHash",
            "round.authorized",
            "input.commitment",
            "certified.round",
            "certified.stateHash",
            "certified.hasBlockHash",
            "certified.blockHash",
            "phase",
            "outcomes.round",
            "outcomes.commitment",
            "transition.cursor",
            "inbox.consumed",
            "transition.bodyID",
            "transition.genesisID",
            "transition.frozenID",
            "transition.commitID",
            "transition.frozenParent",
            "transition.successorTR"
        ];
    }

    function slotKey(string memory name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("unicity.seal-registry/", name));
    }

    function word(string memory name) internal view returns (bytes32) {
        return vm.load(A_SR, slotKey(name));
    }

    function uintWord(string memory name) internal view returns (uint256) {
        return uint256(word(name));
    }

    function setWord(string memory name, bytes32 value) internal {
        vm.store(A_SR, slotKey(name), value);
    }

    function allWords() internal view returns (bytes32[FIELD_COUNT] memory words) {
        string[FIELD_COUNT] memory names = fieldNames();
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            words[i] = vm.load(A_SR, slotKey(names[i]));
        }
    }

    function assertWordsEqual(bytes32[FIELD_COUNT] memory a, bytes32[FIELD_COUNT] memory b)
        internal
        pure
    {
        string[FIELD_COUNT] memory names = fieldNames();
        for (uint256 i = 0; i < FIELD_COUNT; i++) {
            assertEq(a[i], b[i], names[i]);
        }
    }

    function openCalldata(OpenArgs memory a) internal pure returns (bytes memory) {
        return bytes.concat(
            SealRegistry.open.selector,
            abi.encode(
                a.n,
                a.rootRound,
                a.rootEpoch,
                a.timestamp,
                a.treeRoot,
                a.originIdentity,
                a.trHash,
                a.shardConfHash,
                a.certifiedRound,
                a.certEpoch,
                a.authEpoch,
                a.stateHash,
                a.hasBlockHash,
                a.blockHash,
                a.inputCommitment,
                a.transitionCount,
                a.bodyID,
                a.genesisID,
                a.frozenID,
                a.commitID,
                a.frozenParent,
                a.successorTR,
                a.activeConfHash,
                a.assignment,
                a.update
            )
        );
    }

    function finalizeCalldata(uint64 n, bytes32 commitment) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SealRegistry.finalize.selector, n, commitment);
    }

    function callAs(address from, bytes memory data) internal returns (bool ok, bytes memory ret) {
        vm.prank(from);
        (ok, ret) = A_SR.call(data);
    }

    /// @dev §9.2: the first post-genesis payload, authorized for shard round 1.
    function firstPayload() internal pure returns (OpenArgs memory a) {
        a = OpenArgs({
            n: 1,
            rootRound: 5,
            rootEpoch: ROOT_EPOCH,
            timestamp: 1_700_000_000,
            treeRoot: keccak256("U5"),
            originIdentity: keccak256("O5"),
            trHash: keccak256("T5"),
            shardConfHash: FULL_SHARD_CONF_HASH,
            certifiedRound: 0,
            certEpoch: SHARD_EPOCH,
            authEpoch: SHARD_EPOCH,
            stateHash: keccak256("S0"),
            hasBlockHash: false,
            blockHash: bytes32(0),
            inputCommitment: keccak256("X1"),
            transitionCount: 0,
            bodyID: bytes32(0),
            genesisID: bytes32(0),
            frozenID: bytes32(0),
            commitID: bytes32(0),
            frozenParent: bytes32(0),
            successorTR: bytes32(0),
            activeConfHash: FULL_SHARD_CONF_HASH,
            assignment: SealRegistry.AssignmentProjection({
                oldRootEpoch: 0,
                oldShardEpoch: 0,
                oldActiveConfHash: bytes32(0),
                newRootEpoch: 0,
                newShardEpoch: 0,
                newActiveConfHash: bytes32(0),
                supersessionSpan: 0,
                supersessionCommitment: bytes32(0),
                projectionHash: bytes32(0)
            }),
            update: emptyUpdate(ROOT_EPOCH)
        });
    }

    function assignmentProjection(
        uint64 oldRootEpoch,
        uint64 oldShardEpoch,
        bytes32 oldActiveConfHash,
        uint64 newRootEpoch,
        uint64 newShardEpoch,
        bytes32 newActiveConfHash,
        uint64 supersessionSpan,
        bytes32 supersessionCommitment
    ) internal pure returns (SealRegistry.AssignmentProjection memory p) {
        p = SealRegistry.AssignmentProjection({
            oldRootEpoch: oldRootEpoch,
            oldShardEpoch: oldShardEpoch,
            oldActiveConfHash: oldActiveConfHash,
            newRootEpoch: newRootEpoch,
            newShardEpoch: newShardEpoch,
            newActiveConfHash: newActiveConfHash,
            supersessionSpan: supersessionSpan,
            supersessionCommitment: supersessionCommitment,
            projectionHash: bytes32(0)
        });
        p.projectionHash = SealRegistry(A_SR).assignmentProjectionHash(p);
    }

    function openAsSystem(OpenArgs memory a) internal {
        (bool ok, bytes memory ret) = callAs(A_SYS, openCalldata(a));
        if (!ok) {
            emit log_named_bytes("open reverted", ret);
            fail();
        }
    }

    function finalizeAsSystem(uint64 n, bytes32 commitment) internal {
        (bool ok, bytes memory ret) = callAs(A_SYS, finalizeCalldata(n, commitment));
        if (!ok) {
            emit log_named_bytes("finalize reverted", ret);
            fail();
        }
    }

    /// @dev Requires data from `from` to revert with exactly `errorSelector` and change no field.
    function assertRefused(address from, bytes memory data, bytes4 errorSelector) internal {
        bytes32[FIELD_COUNT] memory before = allWords();
        bytes32 b1Before = b1Digest();
        (bool ok, bytes memory ret) = callAs(from, data);
        assertFalse(ok, "call must revert");
        assertEq(ret.length, 4, "a custom error with no arguments");
        assertEq(bytes4(ret), errorSelector, "revert reason");
        assertWordsEqual(before, allWords());
        assertEq(b1Before, b1Digest(), "B1 words changed");
    }

    /// @dev Requires data from `from` to revert with empty returndata (an ABI decoding or dispatch
    /// refusal, not a custom error) and change no field.
    function assertRefusedWithoutReason(address from, bytes memory data, uint256 value) internal {
        bytes32[FIELD_COUNT] memory before = allWords();
        bytes32 b1Before = b1Digest();
        vm.deal(from, value);
        vm.prank(from);
        (bool ok, bytes memory ret) = A_SR.call{value: value}(data);
        assertFalse(ok, "call must revert");
        assertEq(ret.length, 0, "no revert data");
        assertWordsEqual(before, allWords());
        assertEq(b1Before, b1Digest(), "B1 words changed");
    }
}
