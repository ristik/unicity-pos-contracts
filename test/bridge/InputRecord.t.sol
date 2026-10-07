// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BridgeBase} from "./BridgeBase.sol";
import {InputRecord} from "../../src/bridge/InputRecord.sol";
import {IRBadOpening, IRMalformed, IRStateMismatch} from "../../src/bridge/BridgeErrors.sol";

/// @dev Exposes the internal opening so a revert surfaces as an external call failure.
contract InputRecordHarness {
    function open(bytes memory ir, bytes32 irHash, bytes32 state) external pure returns (uint64) {
        return InputRecord.open(ir, irHash, state);
    }
}

/// @notice The native InputRecord opening, against canonical openings produced by the SDK's own
///         encoder (golden `.inputRecords`) and an independently written builder for the mutations.
///         Every negative keeps the opening's hash equal to the anchor hash, so the shape check is the
///         only thing that can refuse it.
contract InputRecordTest is BridgeBase {
    InputRecordHarness internal h = new InputRecordHarness();

    function setUp() public {
        _loadGolden();
    }

    function _open(bytes memory ir) internal view returns (uint64) {
        return h.open(ir, sha256(ir), STATE);
    }

    function _refuse(bytes memory ir, bytes memory err) internal {
        // The hash matches the bytes; only the shape can refuse.
        bytes32 hash = sha256(ir); // a precompile call must not sit between expectRevert and the call
        vm.expectRevert(err);
        h.open(ir, hash, STATE);
    }

    function _refuseField(uint256 i, bytes memory field) internal {
        bytes[10] memory p = _parts();
        p[i] = field;
        _refuse(_build(TAG_ARRAY10, p), abi.encodeWithSelector(IRMalformed.selector));
    }

    // ---- positives -----------------------------------------------------------------------------

    function test_builderReproducesTheSdkEncoding() public view {
        // golden "all-set": round 100, epoch 3, summary "summary", time 1_700_000_100, fees 55.
        assertEq(_ok(), vm.parseJsonBytes(G, ".inputRecords[0].bytes"), "independent builder");
    }

    function test_sdkOpeningsParse() public view {
        uint256 n = 6;
        for (uint256 i = 0; i < n; ++i) {
            string memory p = string.concat(".inputRecords[", vm.toString(i), "]");
            bytes memory ir = vm.parseJsonBytes(G, string.concat(p, ".bytes"));
            assertEq(sha256(ir), vm.parseJsonBytes32(G, string.concat(p, ".hash")), "hash");
            bytes32 state = vm.parseJsonBytes32(G, string.concat(p, ".stateHash"));
            uint64 ts = h.open(ir, sha256(ir), state);
            assertEq(uint256(ts), vm.parseJsonUint(G, string.concat(p, ".timestamp")), "timestamp");
        }
    }

    function test_nullsAreAccepted() public view {
        bytes[10] memory p = _parts();
        p[3] = NULL;
        p[5] = NULL;
        p[7] = NULL;
        p[9] = NULL;
        assertEq(_open(_build(TAG_ARRAY10, p)), 1_700_000_100);
    }

    function test_summaryBounds() public {
        bytes[10] memory p = _parts();
        // A two-byte length that fits in one byte is not shortest form (0x58ff is).
        p[5] = bytes.concat(hex"5900ff", new bytes(255));
        _refuse(_build(TAG_ARRAY10, p), abi.encodeWithSelector(IRMalformed.selector));
        // One byte needs the immediate length 0x41.
        p[5] = bytes.concat(hex"5801", hex"00");
        _refuse(_build(TAG_ARRAY10, p), abi.encodeWithSelector(IRMalformed.selector));
        p[5] = bytes.concat(hex"5820", new bytes(32));
        assertEq(_open(_build(TAG_ARRAY10, p)), 1_700_000_100, "32-byte summary");
        p[5] = bytes.concat(hex"590100", new bytes(256));
        assertEq(_open(_build(TAG_ARRAY10, p)), 1_700_000_100, "256-byte summary");
        p[5] = bytes.concat(hex"590101", new bytes(257));
        _refuse(_build(TAG_ARRAY10, p), abi.encodeWithSelector(IRMalformed.selector));
        p[5] = hex"40";
        assertEq(_open(_build(TAG_ARRAY10, p)), 1_700_000_100, "empty summary");
    }

    function test_integerWidthsAreAccepted() public view {
        uint256[7] memory vals = [uint256(0), 23, 24, 255, 256, 65535, 65536];
        for (uint256 i = 0; i < vals.length; ++i) {
            bytes[10] memory p = _parts();
            p[6] = _uint(vals[i]);
            assertEq(_open(_build(TAG_ARRAY10, p)), uint64(vals[i]));
        }
        bytes[10] memory q = _parts();
        q[6] = _uint(type(uint32).max);
        assertEq(_open(_build(TAG_ARRAY10, q)), type(uint32).max);
        q[6] = _uint(uint256(type(uint32).max) + 1);
        assertEq(_open(_build(TAG_ARRAY10, q)), uint64(uint256(type(uint32).max) + 1));
        q[6] = _uint(type(uint64).max);
        assertEq(_open(_build(TAG_ARRAY10, q)), type(uint64).max);
    }

    // ---- the hash and state bindings -----------------------------------------------------------

    function test_hashMismatchIsBadOpening() public {
        bytes memory ir = _ok();
        vm.expectRevert(abi.encodeWithSelector(IRBadOpening.selector));
        h.open(ir, keccak256(ir), STATE);
        // a timestamp changed after the hash was taken
        bytes memory forged = new bytes(ir.length);
        for (uint256 i = 0; i < ir.length; ++i) {
            forged[i] = ir[i];
        }
        forged[forged.length - 1] ^= 0x01;
        bytes32 realHash = sha256(ir);
        vm.expectRevert(abi.encodeWithSelector(IRBadOpening.selector));
        h.open(forged, realHash, STATE);
    }

    function test_stateMismatchNamesBothRoots() public {
        bytes memory ir = _ok();
        bytes32 other = keccak256("other state");
        bytes32 hash = sha256(ir);
        vm.expectRevert(abi.encodeWithSelector(IRStateMismatch.selector, other, STATE));
        h.open(ir, hash, other);
    }

    /// @dev The hash binding is checked before the shape: an unauthenticated opening is never parsed
    ///      into a timestamp.
    function test_hashIsCheckedBeforeShape() public {
        bytes memory junk = hex"00";
        vm.expectRevert(abi.encodeWithSelector(IRBadOpening.selector));
        h.open(junk, bytes32(uint256(1)), STATE);
    }

    // ---- shape: tag, arity, version ------------------------------------------------------------

    function test_tagAndArity() public {
        bytes[10] memory p = _parts();
        _refuse(_build(hex"d9985b8a", p), abi.encodeWithSelector(IRMalformed.selector)); // 39003
        _refuse(_build(hex"d9985a89", p), abi.encodeWithSelector(IRMalformed.selector)); // arity 9
        _refuse(_build(hex"d9985a8b", p), abi.encodeWithSelector(IRMalformed.selector)); // arity 11
        _refuse(_build(hex"d9985a9f", p), abi.encodeWithSelector(IRMalformed.selector)); // indefinite
        _refuse(_build(hex"d9985a98", p), abi.encodeWithSelector(IRMalformed.selector)); // truncated head
        _refuse(_build(hex"da0000985a8a", p), abi.encodeWithSelector(IRMalformed.selector)); // 4-byte tag
        _refuse(_build(hex"8a", p), abi.encodeWithSelector(IRMalformed.selector)); // no tag
        _refuse(_build(hex"c0d9985a8a", p), abi.encodeWithSelector(IRMalformed.selector)); // nested tag
    }

    function test_version() public {
        _refuseField(0, _uint(0));
        _refuseField(0, _uint(2));
        _refuseField(0, hex"1801"); // not shortest
        _refuseField(0, hex"4101"); // byte string
        _refuseField(0, NULL);
    }

    // ---- shape: integer fields -----------------------------------------------------------------

    function test_integerFieldsAreShortestUnsigned() public {
        uint8[4] memory idx = [1, 2, 6, 8]; // round, epoch, timestamp, fees
        for (uint256 k = 0; k < idx.length; ++k) {
            uint256 i = idx[k];
            _refuseField(i, hex"1800"); // 0 in one extra byte
            _refuseField(i, hex"1817"); // 23 in one extra byte
            _refuseField(i, hex"190001"); // 1 in two bytes
            _refuseField(i, hex"1900ff"); // 255 in two bytes
            _refuseField(i, hex"1a0000ffff"); // 65535 in four bytes
            _refuseField(i, hex"1b00000000ffffffff"); // u32 max in eight bytes
            _refuseField(i, hex"20"); // negative
            _refuseField(i, hex"4101"); // byte string
            _refuseField(i, hex"6131"); // text string
            _refuseField(i, hex"f93c00"); // half float
            _refuseField(i, hex"c101"); // tagged
            _refuseField(i, NULL);
            _refuseField(i, hex"1c"); // reserved additional information
            _refuseField(i, hex"1f"); // indefinite
            _refuseField(i, hex"1a0000"); // truncated width
            // Reserved additional information 28..31 with enough data to read as a 16/32/64/128-byte
            // argument whose low eight bytes are 2^32 (a value that would pass the shortest-form test).
            _refuseField(i, bytes.concat(hex"1c", new bytes(8), hex"0000000100000000"));
            _refuseField(i, bytes.concat(hex"1d", new bytes(24), hex"0000000100000000"));
            _refuseField(i, bytes.concat(hex"1e", new bytes(56), hex"0000000100000000"));
            _refuseField(i, bytes.concat(hex"1f", new bytes(120), hex"0000000100000000"));
        }
    }

    // ---- shape: hash fields --------------------------------------------------------------------

    function test_hashFieldsAreExactlyThirtyTwoBytesOrNull() public {
        uint8[3] memory nullable = [3, 7, 9];
        for (uint256 k = 0; k < nullable.length; ++k) {
            uint256 i = nullable[k];
            _refuseField(i, bytes.concat(hex"581f", new bytes(31)));
            _refuseField(i, bytes.concat(hex"5821", new bytes(33)));
            _refuseField(i, hex"40"); // empty string is not null
            _refuseField(i, hex"60"); // empty text string
            _refuseField(i, bytes.concat(hex"7820", new bytes(32))); // 32-byte text string
            _refuseField(i, hex"01"); // integer
            _refuseField(i, hex"f5"); // true
            _refuseField(i, hex"f7"); // undefined
            _refuseField(i, bytes.concat(hex"5f", hex"4101", hex"ff")); // indefinite string
            _refuseField(i, bytes.concat(hex"590020", new bytes(32))); // 32 in two bytes
        }
        // stateHash is never null, and never a text string
        _refuseField(4, bytes.concat(hex"7820", new bytes(32)));
        _refuseField(4, NULL);
        _refuseField(4, bytes.concat(hex"581f", new bytes(31)));
        _refuseField(4, bytes.concat(hex"5821", new bytes(33)));
        _refuseField(4, hex"40");
    }

    /// @dev A hash field declares its own length: a field whose declared length is not 32 must be
    ///      refused as such, not read as 32 bytes. Each input below parses to a valid opening if the
    ///      declared length is ignored (the swallowed or leftover byte lands on a valid next field), so
    ///      only the length check can refuse it.
    function test_declaredHashLengthIsChecked() public {
        bytes[10] memory p = _parts();
        bytes memory head3 = bytes.concat(TAG_ARRAY10, p[0], p[1], p[2]);
        bytes memory tail59 = bytes.concat(p[5], p[6], p[7], p[8], p[9]);
        // previousHash declared 31 bytes: the 32-byte read swallows the first byte of the state field.
        _refuse(
            bytes.concat(head3, hex"581f", IR_PREV, p[4], tail59),
            abi.encodeWithSelector(IRMalformed.selector)
        );
        // stateHash declared 31 bytes over the 32 bytes of STATE.
        _refuse(
            bytes.concat(head3, p[3], hex"581f", STATE, tail59),
            abi.encodeWithSelector(IRMalformed.selector)
        );
        // stateHash declared 33 bytes: the 33rd byte (0x40, an empty summary) is read as the summary.
        _refuse(
            bytes.concat(head3, p[3], hex"5821", STATE, hex"40", p[6], p[7], p[8], p[9]),
            abi.encodeWithSelector(IRMalformed.selector)
        );
        // blockHash declared 33 bytes: the extra byte (5) is read as the fees and null as the last hash.
        _refuse(
            bytes.concat(head3, p[3], p[4], p[5], p[6], hex"5821", IR_BLOCK, hex"05", NULL),
            abi.encodeWithSelector(IRMalformed.selector)
        );
        // blockHash declared 31 bytes: the 32-byte read swallows the first byte of the fees field.
        _refuse(
            bytes.concat(head3, p[3], p[4], p[5], p[6], hex"581f", IR_BLOCK, hex"05", NULL),
            abi.encodeWithSelector(IRMalformed.selector)
        );
    }

    function test_summaryIsNullOrBytes() public {
        _refuseField(5, hex"01");
        _refuseField(5, hex"6161"); // text
        _refuseField(5, hex"5f4101ff"); // indefinite
        _refuseField(5, hex"80"); // array
        _refuseField(5, hex"f7");
    }

    // ---- shape: framing ------------------------------------------------------------------------

    function test_trailingBytes() public {
        _refuse(bytes.concat(_ok(), hex"00"), abi.encodeWithSelector(IRMalformed.selector));
        _refuse(bytes.concat(_ok(), hex"f6"), abi.encodeWithSelector(IRMalformed.selector));
        _refuse(bytes.concat(_ok(), _ok()), abi.encodeWithSelector(IRMalformed.selector));
    }

    function test_everyTruncationIsRefused() public {
        bytes memory ir = _ok();
        for (uint256 n = 0; n < ir.length; ++n) {
            bytes memory cut = new bytes(n);
            for (uint256 i = 0; i < n; ++i) {
                cut[i] = ir[i];
            }
            // A prefix hashes to its own hash, so the shape is what stops it.
            bytes32 hash = sha256(cut);
            vm.expectRevert(abi.encodeWithSelector(IRMalformed.selector));
            h.open(cut, hash, STATE);
        }
    }

    function test_noFieldOrderIsInterchangeable() public {
        // Swapping the (type-compatible) round and epoch keeps the shape valid but changes the
        // timestamp field's position not at all; swapping timestamp and fees must still parse: both
        // are unsigned. What a swap must NOT do is move the state hash or the timestamp unnoticed:
        // swapping the state hash with the block hash changes the state the opening opens to.
        bytes[10] memory p = _parts();
        (p[4], p[7]) = (p[7], p[4]);
        bytes memory ir = _build(TAG_ARRAY10, p);
        bytes32 hash = sha256(ir);
        vm.expectRevert(abi.encodeWithSelector(IRStateMismatch.selector, STATE, IR_BLOCK));
        h.open(ir, hash, STATE);
        // swapping timestamp and fees changes the returned time
        p = _parts();
        (p[6], p[8]) = (p[8], p[6]);
        assertEq(_open(_build(TAG_ARRAY10, p)), 55, "the time is the seventh field");
    }

    // ---- fuzz ----------------------------------------------------------------------------------

    function _isIrError(bytes4 sel) internal pure returns (bool) {
        return sel == IRMalformed.selector || sel == IRStateMismatch.selector
            || sel == IRBadOpening.selector;
    }

    /// @dev Whatever the bytes, with a matching hash the opening either returns or reverts with one
    ///      of its named errors: never a Panic and never an empty revert.
    function testFuzz_anyBytesAreOpenedOrRefusedByName(bytes memory ir) public view {
        try h.open(ir, sha256(ir), STATE) returns (uint64) {}
        catch (bytes memory err) {
            assertTrue(_isIrError(bytes4(err)), "named error");
        }
    }

    /// @dev A flipped byte of a canonical opening is refused by name, or it opens: a flip inside the
    ///      timestamp field (bytes 84..88 of the fixture: 0x1a and four value bytes) never opens to the
    ///      original time.
    function testFuzz_aFlippedByteNeverKeepsTheTimeThroughTheTimeField(uint256 pos, uint8 flip)
        public
        view
    {
        bytes memory ir = _ok();
        pos = bound(pos, 0, ir.length - 1);
        flip = uint8(bound(flip, 1, 255));
        bytes memory bad = new bytes(ir.length);
        for (uint256 i = 0; i < ir.length; ++i) {
            bad[i] = ir[i];
        }
        bad[pos] = bytes1(uint8(bad[pos]) ^ flip);
        try h.open(bad, sha256(bad), STATE) returns (uint64 ts) {
            if (pos >= 84 && pos < 89) assertTrue(ts != 1_700_000_100, "time field flip");
        } catch (bytes memory err) {
            assertTrue(_isIrError(bytes4(err)), "named error");
        }
    }

    /// @dev Every well-formed combination of widths and nulls opens to its timestamp.
    function testFuzz_wellFormedOpeningsReturnTheirTimestamp(
        uint64 round,
        uint64 epoch,
        uint64 ts,
        uint64 fees,
        uint8 nulls,
        uint8 summaryLen
    ) public view {
        bytes[10] memory p = _parts();
        p[1] = _uint(round);
        p[2] = _uint(epoch);
        p[6] = _uint(ts);
        p[8] = _uint(fees);
        if (nulls & 1 != 0) p[3] = NULL;
        if (nulls & 2 != 0) p[7] = NULL;
        if (nulls & 4 != 0) p[9] = NULL;
        if (nulls & 8 != 0) {
            p[5] = NULL;
        } else {
            bytes memory sm = new bytes(summaryLen);
            p[5] = summaryLen < 24
                ? bytes.concat(bytes1(uint8(0x40 + summaryLen)), sm)
                : bytes.concat(hex"58", bytes1(summaryLen), sm);
        }
        assertEq(_open(_build(TAG_ARRAY10, p)), ts);
    }
}
