// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test, Vm} from "forge-std/Test.sol";
import {KeyLib} from "../../src/p85/KeyLib.sol";

contract KeyLibHarness {
    function toAddress(bytes memory key) external view returns (address) {
        return KeyLib.toAddress(key);
    }

    function verify(bytes memory key, bytes32 digest, bytes memory sig)
        external
        view
        returns (bool)
    {
        return KeyLib.verify(key, digest, sig);
    }

    function recover(bytes32 digest, bytes memory sig) external pure returns (address) {
        return KeyLib.recover(digest, sig);
    }
}

contract KeyLibTest is Test {
    KeyLibHarness internal h = new KeyLibHarness();
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _compressed(uint256 pk) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(pk);
        return abi.encodePacked(uint8(2 + (w.publicKeyY & 1)), bytes32(w.publicKeyX));
    }

    function testFuzz_decompressionMatchesTheCurve(uint256 raw) public {
        uint256 pk = bound(raw, 1, N - 1);
        assertEq(h.toAddress(_compressed(pk)), vm.addr(pk));
    }

    function testFuzz_signaturesVerifyOnlyUnderTheirOwnKey(
        uint256 rawA,
        uint256 rawB,
        bytes32 digest
    ) public {
        uint256 a = bound(rawA, 1, N - 1);
        uint256 b = bound(rawB, 1, N - 1);
        vm.assume(a != b);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(a, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        assertTrue(h.verify(_compressed(a), digest, sig));
        assertFalse(h.verify(_compressed(b), digest, sig));
        assertFalse(h.verify(_compressed(a), keccak256(abi.encode(digest)), sig));
    }

    function test_highSAndBadVAndBadLengthAreRejected() public {
        bytes32 digest = keccak256("d");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0x77, digest);
        bytes memory key = _compressed(0x77);
        assertTrue(h.verify(key, digest, abi.encodePacked(r, s, v)));
        // the malleable twin (n - s, flipped v) recovers the same signer but must be rejected
        bytes32 highS = bytes32(N - uint256(s));
        uint8 flipped = v == 27 ? 28 : 27;
        assertEq(ecrecover(digest, flipped, r, highS), vm.addr(0x77), "twin is valid ECDSA");
        assertFalse(h.verify(key, digest, abi.encodePacked(r, highS, flipped)));
        assertFalse(h.verify(key, digest, abi.encodePacked(r, s, uint8(v + 2)))); // v not 27/28
        assertFalse(h.verify(key, digest, abi.encodePacked(r, s))); // 64 bytes
        assertFalse(h.verify(key, digest, bytes("")));
        assertEq(h.recover(digest, abi.encodePacked(bytes32(0), bytes32(0), uint8(27))), address(0));
    }

    function test_malformedKeysRevertWithTheirOwnErrors() public {
        vm.expectRevert(KeyLib.BadKeyLength.selector);
        h.toAddress(hex"02");
        bytes memory key = _compressed(0x77);
        key[0] = 0x05;
        vm.expectRevert(KeyLib.BadKeyPrefix.selector);
        h.toAddress(key);
        vm.expectRevert(KeyLib.KeyNotOnCurve.selector);
        h.toAddress(abi.encodePacked(uint8(2), bytes32(uint256(5))));
        // x >= p is not a field element
        vm.expectRevert(KeyLib.KeyNotOnCurve.selector);
        h.toAddress(abi.encodePacked(uint8(2), bytes32(type(uint256).max)));
    }
}
