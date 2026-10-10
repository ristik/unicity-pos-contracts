// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BridgeBase} from "./BridgeBase.sol";
import {UcScan} from "../../src/bridge/UcScan.sol";
import {Anchor} from "../../src/bridge/BridgeTypes.sol";
import {Cbor} from "../../src/bridge/Cbor.sol";
import {BudgetExceeded, CborMalformed, UCScanRejected} from "../../src/bridge/BridgeErrors.sol";

contract UcScanHarness {
    function scan(bytes memory uc, bytes memory shard, uint256 depth)
        external
        pure
        returns (uint256, uint256)
    {
        return UcScan.scan(uc, shard, depth);
    }
}

/// @notice The bounded certificate scan the gas gate prices, against the real UCs of the oracle.
contract UcScanTest is BridgeBase {
    UcScanHarness internal h = new UcScanHarness();

    function setUp() public {
        _loadGolden();
    }

    function test_goldenUcsScanToTheirSignatureAndStepCounts() public view {
        Anchor[] memory as_ = _goldenAnchors("return");
        assertEq(as_.length, 2);
        for (uint256 j = 0; j < as_.length; ++j) {
            (uint256 sigs, uint256 steps) = h.scan(as_[j].uc, as_[j].shard, 1);
            assertEq(sigs, 1, "one validator in the fixture committee");
            assertGe(steps, 1, "the depth-1 shard sibling is a step");
            assertLe(steps, 1 + 32);
        }
    }

    // ---- crafted certificates: only the shape the scan reads ---------------------------------------

    /// @dev `tag(39001,[1, IR, h, h, tag(39003,[1, shard, [sib]]), tag(39004,[1, 11, [step*]]),
    ///      tag(39005,[1,0,0,0,0,0,0, sigs])])` with an arbitrary item for every field the scan skips and
    ///      `sigCount` declared signature entries (the scan counts entries and reads no more).
    function _uc(bytes memory shard, uint256 siblings, uint256 steps, bytes memory sigsHead)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory sibs = Cbor.head(4, siblings);
        for (uint256 i = 0; i < siblings; ++i) {
            sibs = bytes.concat(sibs, hex"00");
        }
        bytes memory st = Cbor.head(4, steps);
        for (uint256 i = 0; i < steps; ++i) {
            st = bytes.concat(st, hex"00");
        }
        return bytes.concat(
            hex"d99859",
            hex"87",
            hex"01",
            hex"00",
            hex"40",
            hex"40",
            hex"d9985b",
            hex"83",
            hex"01",
            Cbor.bstr(shard),
            sibs,
            hex"d9985c",
            hex"83",
            hex"01",
            hex"0b",
            st,
            hex"d9985d",
            hex"88",
            hex"01",
            hex"000000000000",
            sigsHead
        );
    }

    function test_craftedBoundsAreExactlyTheirCaps() public {
        (uint256 sigs, uint256 steps) = h.scan(_uc(hex"40", 1, 32, Cbor.head(5, 64)), hex"40", 1);
        assertEq(sigs, 64);
        assertEq(steps, 33);
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        h.scan(_uc(hex"40", 1, 33, Cbor.head(5, 0)), hex"40", 1);
    }

    function test_signatureCountOverTheCapIsBudget() public {
        vm.expectRevert(abi.encodeWithSelector(BudgetExceeded.selector));
        // the declared count is bounded by the input length, so the certificate carries padding
        h.scan(bytes.concat(_uc(hex"40", 1, 1, Cbor.head(5, 65)), new bytes(100)), hex"40", 1);
    }

    function test_nullStepsAndNullSignaturesCountAsZero() public view {
        bytes memory uc = bytes.concat(
            hex"d99859",
            hex"87",
            hex"01",
            hex"00",
            hex"40",
            hex"40",
            hex"d9985b",
            hex"83",
            hex"01",
            hex"4140",
            hex"f6",
            hex"d9985c",
            hex"83",
            hex"01",
            hex"0b",
            hex"f6",
            hex"d9985d",
            hex"88",
            hex"01",
            hex"000000000000",
            hex"f6"
        );
        (uint256 sigs, uint256 steps) = h.scan(uc, hex"40", 0);
        assertEq(sigs, 0);
        assertEq(steps, 0);
    }

    function test_aShorterOrLongerArrayIsRefused() public {
        bytes memory uc = _uc(hex"40", 1, 1, Cbor.head(5, 1));
        bytes memory six = uc;
        six[3] = 0x86; // tag(39001) head is d99859, the array head follows
        vm.expectRevert(abi.encodeWithSelector(UCScanRejected.selector));
        h.scan(six, hex"40", 1);
    }

    function test_claimShardOfAnotherLengthIsRefused() public {
        bytes memory uc = _uc(hex"40", 1, 1, Cbor.head(5, 1));
        vm.expectRevert(abi.encodeWithSelector(UCScanRejected.selector));
        h.scan(uc, hex"4000", 1);
    }

    function test_wrongDepthIsRefused() public {
        Anchor memory a = _goldenAnchor("return");
        vm.expectRevert(abi.encodeWithSelector(UCScanRejected.selector));
        h.scan(a.uc, a.shard, 0);
    }

    function test_certificateOfAnotherShardIsRefused() public {
        Anchor memory a = _goldenAnchor("return");
        bytes memory other = a.shard[0] == 0x40 ? bytes(hex"c0") : bytes(hex"40");
        vm.expectRevert(abi.encodeWithSelector(UCScanRejected.selector));
        h.scan(a.uc, other, 1);
    }

    function test_everyTruncationIsRefusedWithANamedError() public view {
        Anchor memory a = _goldenAnchor("mint");
        for (uint256 n = 0; n < a.uc.length; ++n) {
            bytes memory cut = new bytes(n);
            for (uint256 i = 0; i < n; ++i) {
                cut[i] = a.uc[i];
            }
            try h.scan(cut, a.shard, 1) returns (
                uint256, uint256
            ) {
            // a truncation that still scans only drops bytes after the signature map head
            }
            catch (bytes memory err) {
                bytes4 sel = bytes4(err);
                assertTrue(
                    sel == CborMalformed.selector || sel == UCScanRejected.selector
                        || sel == BudgetExceeded.selector,
                    "named error"
                );
            }
        }
    }

    function testFuzz_anyBytesEndInAResultOrANamedError(bytes memory b) public view {
        try h.scan(b, hex"40", 1) returns (uint256, uint256) {}
        catch (bytes memory err) {
            bytes4 sel = bytes4(err);
            assertTrue(
                sel == CborMalformed.selector || sel == UCScanRejected.selector
                    || sel == BudgetExceeded.selector,
                "named error"
            );
        }
    }

    function testFuzz_aFlippedByteOfARealUcNeverPanics(uint256 pos, uint8 flip) public view {
        Anchor memory a = _goldenAnchor("return");
        bytes memory b = a.uc;
        pos = bound(pos, 0, b.length - 1);
        flip = uint8(bound(flip, 1, 255));
        b[pos] = bytes1(uint8(b[pos]) ^ flip);
        try h.scan(b, a.shard, 1) returns (uint256, uint256) {}
        catch (bytes memory err) {
            bytes4 sel = bytes4(err);
            assertTrue(
                sel == CborMalformed.selector || sel == UCScanRejected.selector
                    || sel == BudgetExceeded.selector,
                "named error"
            );
        }
    }
}
