// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {SealRegistry} from "../src/SealRegistry.sol";

/// @notice Shared fixture: the registry's runtime code placed at a_sr with exactly the six genesis
/// words of bft-core #153 §5.4, and helpers that address storage by the specification's slot names.
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

    uint256 internal constant FIELD_COUNT = 22;

    /// @dev The §6.1 open arguments, in order. Every field is a static type, so abi.encode of this
    /// struct is exactly the sixteen argument words of the flat signature.
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
    }

    string internal constant OPEN_SIGNATURE =
        "open(uint64,uint64,uint64,uint64,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,bytes32,bool,bytes32,bytes32,uint64)";
    string internal constant FINALIZE_SIGNATURE = "finalize(uint64,bytes32)";

    function setUp() public virtual {
        vm.etch(A_SR, type(SealRegistry).runtimeCode);
        installGenesis();
    }

    /// @dev §5.4: exactly these six words; every other field stays absent.
    function installGenesis() internal {
        setWord("layoutVersion", bytes32(uint256(1)));
        setWord("genesisCommitment", GENESIS_COMMITMENT);
        setWord("config.shardConfHash", FULL_SHARD_CONF_HASH);
        setWord("assignment.epoch", bytes32(uint256(SHARD_EPOCH)));
        setWord("assignment.rootEpoch", bytes32(uint256(ROOT_EPOCH)));
        setWord("phase", bytes32(uint256(2)));
    }

    /// @dev The 22 field names of §4.2, in table order.
    function fieldNames() internal pure returns (string[FIELD_COUNT] memory names) {
        names = [
            "layoutVersion",
            "genesisCommitment",
            "config.shardConfHash",
            "assignment.epoch",
            "assignment.rootEpoch",
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
            "inbox.consumed"
        ];
    }

    function slotKey(string memory name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("unicity.seal-registry.v1/", name));
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
        return bytes.concat(SealRegistry.open.selector, abi.encode(a));
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
            transitionCount: 0
        });
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
        (bool ok, bytes memory ret) = callAs(from, data);
        assertFalse(ok, "call must revert");
        assertEq(ret.length, 4, "a custom error with no arguments");
        assertEq(bytes4(ret), errorSelector, "revert reason");
        assertWordsEqual(before, allWords());
    }

    /// @dev Requires data from `from` to revert with empty returndata (an ABI decoding or dispatch
    /// refusal, not a custom error) and change no field.
    function assertRefusedWithoutReason(address from, bytes memory data, uint256 value) internal {
        bytes32[FIELD_COUNT] memory before = allWords();
        vm.deal(from, value);
        vm.prank(from);
        (bool ok, bytes memory ret) = A_SR.call{value: value}(data);
        assertFalse(ok, "call must revert");
        assertEq(ret.length, 0, "no revert data");
        assertWordsEqual(before, allWords());
    }
}
