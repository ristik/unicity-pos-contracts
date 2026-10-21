// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test, console} from "forge-std/Test.sol";
import {CertGroups} from "../../src/bridge/CertGroups.sol";
import {Cbor} from "../../src/bridge/Cbor.sol";
import {UcBuilder} from "./UcBuilder.sol";
import {Anchor} from "../../src/bridge/BridgeTypes.sol";
import {BudgetExceeded, UCScanRejected} from "../../src/bridge/BridgeErrors.sol";

contract CertGroupsHarness {
    function measure(Anchor[] memory a) external pure returns (CertGroups.Counts memory) {
        return CertGroups.measure(a);
    }

    function measureMasked(Anchor[] memory a, uint256 mask)
        external
        pure
        returns (CertGroups.Counts memory)
    {
        return CertGroups.measure(a, mask, CertGroups.MAX_ITEMS);
    }

    function shardDepth(bytes memory s) external pure returns (uint256) {
        return CertGroups.shardDepth(s);
    }
}

/// @notice The structural scan and the canonical first-occurrence grouping the batch price is computed from,
///         on hand-built CBOR (no native code, no vectors): counts E,S,Q,A,P,K,C, reordering invariance, exact-byte
///         identity under forced digest collisions, and the limits that bound the scan.
contract CertGroupsTest is Test, UcBuilder {
    CertGroupsHarness internal h = new CertGroupsHarness();

    function _claim(bytes memory shard, bytes memory uc, bytes32 root)
        internal
        pure
        returns (Anchor memory a)
    {
        a = Anchor(8, shard, bytes32(uint256(11)), root, bytes32(uint256(12)), uc, "");
    }

    function _one(bytes memory uc) internal pure returns (Anchor[] memory a) {
        a = new Anchor[](1);
        a[0] = _claim(hex"c0", uc, bytes32(uint256(1)));
    }

    function _c(Anchor[] memory a) internal view returns (CertGroups.Counts memory) {
        return h.measure(a);
    }

    function _claimBytes(Anchor memory a) internal pure returns (uint256) {
        return 106 + a.shard.length + a.uc.length;
    }

    // ---- counts ---------------------------------------------------------------------------

    function test_aSingleClaim_isPricedAtTheContractsSubtotal() public view {
        Anchor[] memory a = _one(_uc(hex"c0", 1, 3, 4, 5, 0xaa));
        CertGroups.Counts memory n = _c(a);
        assertEq(n.k, 1);
        assertEq(n.e, 1);
        assertEq(n.s, 1);
        assertEq(n.q, 5);
        assertEq(n.a, 1);
        assertEq(n.p, 1 + 3);
        assertEq(n.c, 4 + _claimBytes(a[0]));
        assertGt(n.items, 20);
        // 93,000 = 60,000 + 1,100 + 29,900 + 2,000 before bytes, signatures and paths
        assertEq(CertGroups.batchGas(n), 93_000 + 16 * n.c + 6_000 * 5 + 250 * 4);
    }

    function test_anExactDuplicate_payBytesAndTheScanPairsOnly() public view {
        bytes memory uc = _uc(hex"c0", 1, 3, 4, 5, 0xaa);
        Anchor[] memory a = new Anchor[](2);
        a[0] = _claim(hex"c0", uc, bytes32(uint256(1)));
        a[1] = _claim(hex"c0", uc, bytes32(uint256(1)));
        CertGroups.Counts memory n = _c(a);
        CertGroups.Counts memory one = _c(_one(uc));
        assertEq(n.k, 2);
        assertEq(n.e, 1);
        assertEq(n.s, 1);
        assertEq(n.q, 5);
        assertEq(n.a, 1);
        assertEq(n.p, one.p);
        assertEq(n.c, one.c + _claimBytes(a[1]));
        assertEq(
            CertGroups.batchGas(n) - CertGroups.batchGas(one), 16 * _claimBytes(a[1]) + 500 * 2
        );
    }

    function test_theSameUcWithAnotherExpectedTuple_isAnotherClaimUnderTheSameSeal() public view {
        bytes memory uc = _uc(hex"c0", 1, 3, 4, 5, 0xaa);
        Anchor[] memory a = new Anchor[](2);
        a[0] = _claim(hex"c0", uc, bytes32(uint256(1)));
        a[1] = _claim(hex"c0", uc, bytes32(uint256(2)));
        CertGroups.Counts memory n = _c(a);
        assertEq(n.a, 2);
        assertEq(n.s, 1);
        assertEq(n.q, 5);
        assertEq(n.e, 1);
        assertEq(n.p, 8); // two distinct claims pay their paths each
    }

    function test_theSameRootAndEpochWithAnotherSignatureWitness_isAnotherSeal() public view {
        Anchor[] memory a = new Anchor[](3);
        a[0] = _claim(hex"c0", _uc(hex"c0", 1, 0, 4, 3, 0xaa), bytes32(uint256(1)));
        a[1] = _claim(hex"c0", _uc(hex"c0", 1, 0, 4, 3, 0xab), bytes32(uint256(1))); // last byte differs
        a[2] = _claim(hex"c0", _uc(hex"c0", 1, 0, 4, 2, 0xaa), bytes32(uint256(1))); // one signature fewer
        CertGroups.Counts memory n = _c(a);
        assertEq(n.e, 1);
        assertEq(n.s, 3);
        assertEq(n.q, 3 + 3 + 2);
        assertEq(n.a, 3);
    }

    function test_distinctEpochsAreCounted_andTheEpochPriceIsPerDistinctEpoch() public view {
        Anchor[] memory a = new Anchor[](3);
        a[0] = _claim(hex"c0", _uc(hex"c0", 1, 0, 4, 1, 0xaa), bytes32(uint256(1)));
        a[1] = _claim(hex"c0", _uc(hex"c0", 1, 0, 9, 1, 0xaa), bytes32(uint256(1)));
        a[2] = _claim(hex"c0", _uc(hex"c0", 1, 0, 4, 1, 0xac), bytes32(uint256(1)));
        CertGroups.Counts memory n = _c(a);
        assertEq(n.e, 2);
        assertEq(n.s, 3);
        // one more epoch at equal C,K,Q,A,P costs exactly 29,900
        CertGroups.Counts memory m =
            CertGroups.Counts(n.k, n.c, n.e + 1, n.s, n.q, n.a, n.p, n.items); // a copy, not an alias
        assertEq(CertGroups.batchGas(m) - CertGroups.batchGas(n), 29_900);
    }

    function test_epochZeroIsAnEpoch() public view {
        CertGroups.Counts memory n = _c(_one(_uc(hex"c0", 1, 0, 0, 1, 0xaa)));
        assertEq(n.e, 1);
    }

    function test_shardsOfAnyDepth_andTheSameShardAtSeveralSeals() public view {
        Anchor[] memory a = new Anchor[](4);
        a[0] = _claim(hex"80", _uc(hex"80", 0, 1, 4, 1, 0xaa), bytes32(uint256(1))); // depth 0
        a[1] = _claim(hex"40", _uc(hex"40", 1, 1, 4, 1, 0xaa), bytes32(uint256(2))); // depth 1
        a[2] = _claim(hex"e0", _uc(hex"e0", 2, 1, 5, 1, 0xaa), bytes32(uint256(3))); // depth 2
        a[3] = _claim(hex"e0", _uc(hex"e0", 2, 1, 6, 1, 0xaa), bytes32(uint256(3))); // same shard, another round
        CertGroups.Counts memory n = _c(a);
        assertEq(n.a, 4);
        assertEq(n.e, 3);
        assertEq(n.p, (0 + 1) + (1 + 1) + (2 + 1) + (2 + 1));
    }

    // ---- order and collisions -------------------------------------------------------------

    function _mixed() internal pure returns (Anchor[] memory a) {
        bytes memory u1 = _uc(hex"c0", 1, 2, 4, 3, 0xaa);
        bytes memory u2 = _uc(hex"c0", 1, 2, 4, 3, 0xab);
        bytes memory u3 = _uc(hex"40", 1, 2, 7, 2, 0xaa);
        a = new Anchor[](5);
        a[0] = _claim(hex"c0", u1, bytes32(uint256(1)));
        a[1] = _claim(hex"c0", u1, bytes32(uint256(1)));
        a[2] = _claim(hex"c0", u1, bytes32(uint256(2)));
        a[3] = _claim(hex"c0", u2, bytes32(uint256(1)));
        a[4] = _claim(hex"40", u3, bytes32(uint256(1)));
    }

    function _same(CertGroups.Counts memory x, CertGroups.Counts memory y) internal pure {
        assertEq(x.k, y.k);
        assertEq(x.c, y.c);
        assertEq(x.e, y.e);
        assertEq(x.s, y.s);
        assertEq(x.q, y.q);
        assertEq(x.a, y.a);
        assertEq(x.p, y.p);
    }

    function test_reorderingTheOccurrences_changesNoCountAndNoPrice() public view {
        Anchor[] memory a = _mixed();
        CertGroups.Counts memory base = _c(a);
        assertEq(base.e, 2);
        assertEq(base.s, 3);
        assertEq(base.q, 3 + 3 + 2);
        assertEq(base.a, 4);
        uint256[5][4] memory perms = [
            [uint256(4), 3, 2, 1, 0],
            [uint256(2), 0, 4, 1, 3],
            [uint256(1), 0, 3, 4, 2],
            [uint256(3), 4, 0, 2, 1]
        ];
        for (uint256 p = 0; p < perms.length; ++p) {
            Anchor[] memory b = new Anchor[](5);
            for (uint256 i = 0; i < 5; ++i) {
                b[i] = a[perms[p][i]];
            }
            CertGroups.Counts memory x = _c(b);
            _same(x, base);
            assertEq(CertGroups.batchGas(x), CertGroups.batchGas(base));
        }
    }

    function test_aForcedDigestCollision_neverMergesDifferentSealsOrClaims() public view {
        Anchor[] memory a = _mixed();
        CertGroups.Counts memory normal = _c(a);
        // mask 0: every index digest is equal, so every pair is compared byte for byte
        CertGroups.Counts memory collided = h.measureMasked(a, 0);
        _same(collided, normal);
    }

    // ---- shard depth ----------------------------------------------------------------------

    function test_shardDepth() public view {
        assertEq(h.shardDepth(hex"80"), 0);
        assertEq(h.shardDepth(hex"c0"), 1);
        assertEq(h.shardDepth(hex"40"), 1 - 0 + 0); // 0x40: tz 6 -> 8-6-1 = 1
        assertEq(h.shardDepth(hex"a0"), 2);
        assertEq(h.shardDepth(hex"ff80"), 8);
        assertEq(h.shardDepth(hex"ff01"), 15);
        bytes memory max = new bytes(33);
        max[32] = 0x80;
        assertEq(h.shardDepth(max), 256);
    }

    function test_shardDepth_refusals() public {
        vm.expectRevert(UCScanRejected.selector);
        h.shardDepth("");
        vm.expectRevert(UCScanRejected.selector);
        h.shardDepth(hex"00");
        vm.expectRevert(UCScanRejected.selector);
        h.shardDepth(hex"ff00");
        bytes memory deep = new bytes(33);
        deep[32] = 0x01; // 8*33 - 0 - 1 = 263 > 256
        vm.expectRevert(UCScanRejected.selector);
        h.shardDepth(deep);
        vm.expectRevert(UCScanRejected.selector);
        h.shardDepth(new bytes(34));
    }

    // ---- structure and limits -------------------------------------------------------------

    function test_theCertificateMustCarryExactlyTheDerivedDepthOfSiblings() public {
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(_uc(hex"c0", 2, 0, 4, 1, 0xaa))); // depth 1, two siblings
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(_uc(hex"c0", 0, 0, 4, 1, 0xaa)));
    }

    function test_theCertificateMustNameTheClaimsShard() public {
        Anchor[] memory a = _one(_uc(hex"40", 1, 0, 4, 1, 0xaa)); // the UC names 0x40
        a[0].shard = hex"c0";
        vm.expectRevert(UCScanRejected.selector);
        h.measure(a);
    }

    function test_trailingBytesAndTruncationAreRefused() public {
        bytes memory uc = _uc(hex"c0", 1, 0, 4, 1, 0xaa);
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(bytes.concat(uc, hex"00")));
        bytes memory cut = new bytes(uc.length - 1);
        for (uint256 i = 0; i < cut.length; ++i) {
            cut[i] = uc[i];
        }
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(cut));
    }

    function test_indefiniteAndNonMinimalHeadsAreRefused() public {
        // indefinite array as the input record
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(_ucWith(hex"c0", 1, 0, hex"9fff", _seal(4, 1, 0xaa))));
        // 0x1800 is the integer 0 in a non-shortest form
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(_ucWith(hex"c0", 1, 0, hex"1800", _seal(4, 1, 0xaa))));
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(_ucWith(hex"c0", 1, 0, hex"190001", _seal(4, 1, 0xaa))));
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(_ucWith(hex"c0", 1, 0, hex"1a00000001", _seal(4, 1, 0xaa))));
    }

    function test_theEpochMustBeAnUnsignedInteger() public {
        // a negative integer is one byte with no payload, so the rest of the certificate stays aligned and only the epoch check can refuse it
        bytes memory bad = _ucWith(hex"c0", 1, 0, Cbor.uint_(5), _sealWithEpochItem(hex"20"));
        vm.expectRevert(UCScanRejected.selector);
        h.measure(_one(bad));
        // and the same certificate with an unsigned epoch is fine
        _c(_one(_ucWith(hex"c0", 1, 0, Cbor.uint_(5), _sealWithEpochItem(hex"00"))));
    }

    function _sealWithEpochItem(bytes memory epochItem) internal pure returns (bytes memory) {
        return bytes.concat(
            _tag(39005),
            Cbor.head(4, 8),
            Cbor.uint_(1),
            Cbor.uint_(3),
            Cbor.uint_(1000),
            epochItem,
            Cbor.uint_(1),
            Cbor.bstr32(bytes32(uint256(1))),
            Cbor.bstr32(bytes32(uint256(2))),
            hex"f6"
        );
    }

    function test_aNullSignatureMapIsEmpty_andTooManySignaturesAreOverTheBound() public {
        CertGroups.Counts memory n =
            _c(_one(_ucWith(hex"c0", 1, 0, Cbor.uint_(5), _sealWithEpochItem(Cbor.uint_(4)))));
        assertEq(n.q, 0);
        _c(_one(_uc(hex"c0", 1, 0, 4, 16, 0xaa))); // exactly 16
        vm.expectRevert(BudgetExceeded.selector);
        h.measure(_one(_uc(hex"c0", 1, 0, 4, 17, 0xaa)));
    }

    function test_unicityStepsAreBoundedAt32() public {
        _c(_one(_uc(hex"c0", 1, 32, 4, 1, 0xaa)));
        vm.expectRevert(BudgetExceeded.selector);
        h.measure(_one(_uc(hex"c0", 1, 33, 4, 1, 0xaa)));
    }

    function test_nestingIsBoundedAt16() public {
        // the UC tag and array already enclose the input record (native nesting counts from the UC root), so 14 nested arrays reach the
        // bound of 16 containers and a fifteenth does not fit
        _c(_one(_ucWith(hex"c0", 1, 0, _nested(14), _seal(4, 1, 0xaa))));
        vm.expectRevert(BudgetExceeded.selector);
        h.measure(_one(_ucWith(hex"c0", 1, 0, _nested(15), _seal(4, 1, 0xaa))));
    }

    function _nested(uint256 depth) internal pure returns (bytes memory b) {
        b = hex"00";
        for (uint256 i = 0; i < depth; ++i) {
            b = bytes.concat(Cbor.head(4, 1), b);
        }
    }

    // ---- the item bound: the native batch's 32,768 (owner §36) ---------------------------------------------

    function _denseUc(uint256 irItems) internal pure returns (bytes memory) {
        return _ucWith(
            hex"c0",
            1,
            0,
            bytes.concat(Cbor.head(4, irItems), _fill(irItems, 0x00)),
            _seal(4, 1, 0xaa)
        );
    }

    /// the item count of a UC whose input record is a single item, so a dense record of k items adds exactly k
    function _baseItems() internal view returns (uint256) {
        return _c(_one(_uc(hex"c0", 1, 0, 4, 1, 0xaa))).items;
    }

    /// The scan's item bound is the native batch's 32,768 over all occurrences (owner §36: no stricter bridge budget). A UC is at most
    /// 24,576 bytes, so the bound is reached only across anchors: exactly 32,768 is allowed, one more is refused.
    function test_theItemBoundIsTheNativeBatchs32768_overAnchors() public {
        uint256 base = _baseItems();
        uint256 each = 16_384 - base; // two of these are exactly 32,768
        Anchor[] memory two = new Anchor[](2);
        two[0] = _claim(hex"c0", _denseUc(each), bytes32(uint256(1)));
        two[1] = _claim(hex"c0", _denseUc(each), bytes32(uint256(2)));
        assertEq(_c(two).items, 32_768, "exactly the native bound");
        assertEq(CertGroups.MAX_ITEMS, 32_768);
        Anchor[] memory over = new Anchor[](2);
        over[0] = two[0];
        over[1] = _claim(hex"c0", _denseUc(each + 1), bytes32(uint256(2)));
        vm.expectRevert(BudgetExceeded.selector);
        h.measure(over);
    }

    /// Far more than the former 4,096-item bridge budget is admitted: it is charged, not capped.
    function test_theFormerBridgeItemBudgetIsGone() public view {
        uint256 base = _baseItems();
        CertGroups.Counts memory n = _c(_one(_denseUc(4097 - base)));
        assertEq(n.items, 4097);
        // an exact duplicate is the same claim for pricing but a second traversal for the count
        Anchor[] memory dup = new Anchor[](2);
        dup[0] = _claim(hex"c0", _denseUc(4097 - base), bytes32(uint256(1)));
        dup[1] = dup[0];
        CertGroups.Counts memory d = _c(dup);
        assertEq(d.a, 1);
        assertEq(d.items, 2 * 4097);
    }

    function test_aDenseContainerIsRefusedByItsDeclaredLength_beforeItIsWalked() public {
        // One UC (at most 24,576 bytes) cannot declare more children than the native 32,768 on its own: the first anchor walks 17,000
        // items, and the second declares 16,000, more than is left. It is refused at its head: the gas shows it was not walked.
        uint256 base = _baseItems();
        Anchor[] memory first = _one(_denseUc(17_000 - base));
        uint256 before = gasleft();
        h.measure(first);
        uint256 walkOne = before - gasleft();
        Anchor[] memory a = new Anchor[](2);
        a[0] = first[0];
        a[1] = _claim(hex"c0", _denseUc(16_000), bytes32(uint256(2)));
        before = gasleft();
        vm.expectRevert(BudgetExceeded.selector);
        h.measure(a);
        assertLt(
            before - gasleft(),
            walkOne + 1_500_000,
            "the second container is refused at its declared length, unwalked"
        );
    }

    function test_normalSixteenAnchorTokensAreFarBelowTheBudget() public view {
        CertGroups.Counts memory typical = _c(_sixteenSimple(hex"e0", 2, 16));
        assertLt(typical.items, 2048);
        console.log("16 anchors, depth 3, 16 signatures: CBOR items", typical.items);
        CertGroups.Counts memory shallow = _c(_sixteenSimple(hex"c0", 1, 4));
        console.log("16 anchors, depth 1, 4 signatures: CBOR items", shallow.items);
    }

    function _sixteenSimple(bytes memory shard, uint256 siblings, uint256 sigs)
        internal
        pure
        returns (Anchor[] memory a)
    {
        a = new Anchor[](16);
        for (uint256 i = 0; i < 16; ++i) {
            a[i] = _claim(shard, _uc(shard, siblings, 2, 4 + i, sigs, uint8(i)), bytes32(i));
        }
    }

    function test_claimCountAndShardLengthBounds() public {
        vm.expectRevert(BudgetExceeded.selector);
        h.measure(new Anchor[](0));
        Anchor[] memory many = new Anchor[](17);
        bytes memory uc = _uc(hex"c0", 1, 0, 4, 1, 0xaa);
        for (uint256 i = 0; i < 17; ++i) {
            many[i] = _claim(hex"c0", uc, bytes32(i));
        }
        vm.expectRevert(BudgetExceeded.selector);
        h.measure(many);
        Anchor[] memory sixteen = new Anchor[](16);
        for (uint256 i = 0; i < 16; ++i) {
            sixteen[i] = many[i];
        }
        CertGroups.Counts memory n = _c(sixteen);
        assertEq(n.k, 16);
        assertEq(n.a, 16);
        assertEq(n.s, 1);
        assertEq(CertGroups.scanGas(n.c, 16), 60_000 + 16 * n.c + 500 * 16 * 15);
    }

    function test_theUcByteBound() public {
        Anchor[] memory a = _one(_uc(hex"c0", 1, 0, 4, 1, 0xaa));
        a[0].uc = new bytes(24_577);
        vm.expectRevert(BudgetExceeded.selector);
        h.measure(a);
    }
}

/// @notice What the Solidity scan and grouping cost (execution gas, warm, in-memory), for the review of the scan allowance
///         (briefs/b1-any-age-contract-review.md). Printed with -vv; the assertions only keep the shapes honest.
contract CertGroupsGasTest is CertGroupsTest {
    function _spend(Anchor[] memory a)
        internal
        view
        returns (uint256 g, CertGroups.Counts memory n)
    {
        uint256 before = gasleft();
        n = CertGroups.measure(a);
        g = before - gasleft();
    }

    function _report(string memory label, Anchor[] memory a) internal view {
        (uint256 g, CertGroups.Counts memory n) = _spend(a);
        console.log(label);
        console.log("  solidity gas %d  allowance G_scan %d", g, CertGroups.scanGas(n.c, n.k));
        console.log("  K %d  C %d  E/S/Q", n.k, n.c);
        console.log("  %d / %d / %d", n.e, n.s, n.q);
        console.log("  A %d  P %d", n.a, n.p);
    }

    function _sixteen(bytes memory shard, uint256 siblings, uint256 sigs, bool distinctSeals)
        internal
        pure
        returns (Anchor[] memory a)
    {
        a = new Anchor[](16);
        for (uint256 i = 0; i < 16; ++i) {
            a[i] = _claim(
                shard,
                _uc(
                    shard,
                    siblings,
                    32,
                    distinctSeals ? 4 + i : 4,
                    sigs,
                    distinctSeals ? uint8(i) : 0xaa
                ),
                bytes32(i)
            );
        }
    }

    function test_gas_sixteenAnchors_eightShards_oneSeal() public view {
        _report("16 anchors, depth 3, 16 sigs, one shared seal", _sixteen(hex"e0", 2, 16, false));
    }

    function test_gas_sixteenAnchors_eightShards_sixteenSeals() public view {
        _report(
            "16 anchors, depth 3, 16 sigs, sixteen distinct seals", _sixteen(hex"e0", 2, 16, true)
        );
    }

    function test_gas_eightAnchors_deepShard_256Siblings() public view {
        bytes memory deep = new bytes(33);
        deep[32] = 0x80;
        Anchor[] memory a = new Anchor[](8);
        for (uint256 i = 0; i < 8; ++i) {
            a[i] = _claim(deep, _uc(deep, 256, 32, 4 + i, 16, uint8(i)), bytes32(i));
        }
        _report(
            "8 anchors, depth 256, 16 sigs, eight distinct seals (the deepest the bridge's 2,048 steps admit)",
            a
        );
    }

    /// The most the native batch's item bound lets the scan walk: 32,768 items over two claims.
    function test_gas_theItemBoundFilled() public view {
        uint256 base = _c(_one(_uc(hex"c0", 1, 0, 4, 1, 0xaa))).items;
        Anchor[] memory a = new Anchor[](2);
        a[0] = _claim(hex"c0", _denseUc(16_384 - base), bytes32(uint256(1)));
        a[1] = _claim(hex"c0", _denseUc(16_384 - base), bytes32(uint256(2)));
        uint256 before = gasleft();
        CertGroups.Counts memory n = CertGroups.measure(a);
        console.log("two claims filling the 32,768 item bound");
        console.log("  solidity gas %d for %d items", before - gasleft(), n.items);
    }

    function test_gas_sixteenExactDuplicates_ofOneMaximalClaim() public view {
        bytes memory ir = bytes.concat(Cbor.head(2, 12_000), new bytes(12_000));
        bytes memory uc = _ucWith(hex"c0", 1, 0, ir, _seal(4, 16, 0xaa));
        Anchor[] memory a = new Anchor[](16);
        for (uint256 i = 0; i < 16; ++i) {
            a[i] = _claim(hex"c0", uc, bytes32(uint256(1)));
        }
        _report("16 exact duplicates of one 12 KB claim", a);
    }

    /// Sixteen seals that differ only in the last signature byte, with every digest forced to collide: the worst case of the
    /// pairwise byte comparison (a real keccak never collides, so this is an upper bound on the grouping, not a reachable cost).
    function test_gas_sixteenNearIdenticalSeals_withForcedCollisions() public view {
        Anchor[] memory a = new Anchor[](16);
        for (uint256 i = 0; i < 16; ++i) {
            bytes memory uc = _uc(hex"c0", 1, 0, 4, 16, 0xaa);
            uc[uc.length - 1] = bytes1(uint8(i));
            a[i] = _claim(hex"c0", uc, bytes32(i));
        }
        uint256 before = gasleft();
        CertGroups.Counts memory n = CertGroups.measure(a, 0, CertGroups.MAX_ITEMS);
        console.log("16 near-identical seals, all digests forced to collide");
        console.log("  solidity gas %d  S %d A %d", before - gasleft(), n.s, n.a);
        before = gasleft();
        n = CertGroups.measure(a);
        console.log("  the same with the real digests: %d", before - gasleft());
    }
}
