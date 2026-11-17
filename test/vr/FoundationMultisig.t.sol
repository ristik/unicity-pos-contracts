// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "./VRBase.sol";
import {FoundationMultisig} from "../../src/vr/FoundationMultisig.sol";
import {VRC} from "../../src/vr/VRConstants.sol";

/// @notice The Foundation multisig (design section 3.5.5): 3-of-5 over EIP-712 call digests with a sequential nonce, nonce replay
/// refused, and a signer-set change only as a delayed self-call. It is VR's governor here: governance calls go through it.
contract FoundationMultisigTest is VRBase {
    FoundationMultisig internal ms;
    uint256[5] internal pks;
    address[5] internal signers;

    function setUp() public {
        // five signers in ascending address order
        uint256[5] memory cand = [uint256(0x5101), 0x5102, 0x5103, 0x5104, 0x5105];
        address[5] memory addrs;
        for (uint256 i = 0; i < 5; ++i) {
            addrs[i] = vm.addr(cand[i]);
        }
        for (uint256 i = 0; i < 5; ++i) {
            for (uint256 j = i + 1; j < 5; ++j) {
                if (addrs[j] < addrs[i]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (cand[i], cand[j]) = (cand[j], cand[i]);
                }
            }
        }
        pks = cand;
        signers = addrs;
        // the multisig reads the SealRegistry clock for its signer-change delay; the VR fixture provides it
        _setUpSealOnly();
        ms = new FoundationMultisig(signers);
        governor = address(ms);
        _setUpVRWithSeal();
    }

    function _setUpSealOnly() internal {
        // VRBase etches the mock SealRegistry in _setUpVR; the multisig is deployed before VR, so etch once here too
        address s = address(new MockSealShim());
        vm.etch(VRC.SEAL_REGISTRY, s.code);
        MockSealShim(VRC.SEAL_REGISTRY).set(progress, ucTime);
    }

    function _setUpVRWithSeal() internal {
        _setUpVR(5, 1, 5, 16);
    }

    function _sigs(address target, bytes memory data, uint64 nonce, uint256[] memory who)
        internal
        view
        returns (bytes[] memory out)
    {
        bytes32 d = ms.callDigest(target, data, nonce);
        out = new bytes[](who.length);
        for (uint256 i = 0; i < who.length; ++i) {
            out[i] = _sig(pks[who[i]], d);
        }
    }

    function _idx(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory x) {
        x = new uint256[](3);
        (x[0], x[1], x[2]) = (a, b, c);
    }

    function test_threeOfFiveQueuesAVRChange() public {
        bytes memory data = abi.encodeCall(
            vr.queue, (VRC.K_COMMITTEE_LIMITS, abi.encode(uint32(1), uint32(5), uint32(16)))
        );
        ms.execute(address(vr), data, _sigs(address(vr), data, 0, _idx(0, 2, 4)));
        assertEq(ms.nonce(), 1);
        assertEq(vr.change(1).state, VRC.CH_QUEUED);
    }

    function test_twoSignaturesAreNotEnough() public {
        bytes memory data = abi.encodeCall(vr.cancel, (1));
        uint256[] memory two = new uint256[](2);
        (two[0], two[1]) = (0, 1);
        bytes[] memory s = _sigs(address(vr), data, 0, two);
        vm.expectRevert(FoundationMultisig.BadSignatures.selector);
        ms.execute(address(vr), data, s);
    }

    function test_duplicateUnorderedOrForeignSignersAreRefused() public {
        bytes memory data = abi.encodeCall(
            vr.queue, (VRC.K_COMMITTEE_LIMITS, abi.encode(uint32(1), uint32(5), uint32(16)))
        );
        bytes[] memory dup = _sigs(address(vr), data, 0, _idx(0, 0, 1));
        vm.expectRevert(FoundationMultisig.BadSignatures.selector);
        ms.execute(address(vr), data, dup);
        bytes[] memory unordered = _sigs(address(vr), data, 0, _idx(2, 1, 0));
        vm.expectRevert(FoundationMultisig.BadSignatures.selector);
        ms.execute(address(vr), data, unordered);
        bytes[] memory s = _sigs(address(vr), data, 0, _idx(0, 1, 2));
        s[2] = _sig(0xBAD, ms.callDigest(address(vr), data, 0));
        vm.expectRevert(FoundationMultisig.BadSignatures.selector);
        ms.execute(address(vr), data, s);
        // a high-s signature is refused
        bytes[] memory h = _sigs(address(vr), data, 0, _idx(0, 1, 2));
        bytes memory x = h[0];
        bytes32 sv;
        assembly {
            sv := mload(add(x, 0x40))
        }
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 high = bytes32(n - uint256(sv));
        uint8 v = uint8(x[64]) == 27 ? 28 : 27;
        h[0] = abi.encodePacked(bytes32(_word(x, 0)), high, v);
        vm.expectRevert(FoundationMultisig.BadSignatures.selector);
        ms.execute(address(vr), data, h);
    }

    function _word(bytes memory b, uint256 off) internal pure returns (uint256 w) {
        assembly {
            w := mload(add(add(b, 0x20), off))
        }
    }

    function test_nonceReplayIsRefused() public {
        bytes memory data = abi.encodeCall(
            vr.queue, (VRC.K_COMMITTEE_LIMITS, abi.encode(uint32(1), uint32(5), uint32(16)))
        );
        bytes[] memory s = _sigs(address(vr), data, 0, _idx(1, 2, 3));
        ms.execute(address(vr), data, s);
        vm.expectRevert(FoundationMultisig.BadSignatures.selector);
        ms.execute(address(vr), data, s);
    }

    function test_aRevertingCallConsumesNoNonce() public {
        bytes memory data = abi.encodeCall(vr.cancel, (42)); // NotCancellable
        bytes[] memory s = _sigs(address(vr), data, 0, _idx(0, 1, 2));
        vm.expectRevert(FoundationMultisig.CallFailed.selector);
        ms.execute(address(vr), data, s);
        assertEq(ms.nonce(), 0);
    }

    function test_signerChangeIsADelayedSelfCall() public {
        address[5] memory next;
        for (uint256 i = 0; i < 5; ++i) {
            next[i] = address(uint160(0x1000 + i));
        }
        // not directly
        vm.expectRevert(FoundationMultisig.NotSelf.selector);
        ms.proposeSigners(next);
        bytes memory data = abi.encodeCall(ms.proposeSigners, (next));
        ms.execute(address(ms), data, _sigs(address(ms), data, 0, _idx(0, 1, 2)));
        assertTrue(ms.signersPending());
        vm.expectRevert(FoundationMultisig.DelayNotElapsed.selector);
        ms.applySigners();
        _advance(VRC.DELAY_ROUNDS, VRC.DELAY_SECONDS - 1);
        vm.expectRevert(FoundationMultisig.DelayNotElapsed.selector);
        ms.applySigners();
        // the old set still governs during the delay
        bytes memory q = abi.encodeCall(
            vr.queue, (VRC.K_COMMITTEE_LIMITS, abi.encode(uint32(1), uint32(5), uint32(16)))
        );
        ms.execute(address(vr), q, _sigs(address(vr), q, 1, _idx(2, 3, 4)));
        _advance(0, 1);
        ms.applySigners();
        assertEq(ms.signers()[0], next[0]);
        assertFalse(ms.isSigner(signers[0]));
        // the old signers can no longer act
        bytes memory c = abi.encodeCall(vr.cancel, (1));
        bytes[] memory old = _sigs(address(vr), c, 2, _idx(0, 1, 2));
        vm.expectRevert(FoundationMultisig.BadSignatures.selector);
        ms.execute(address(vr), c, old);
    }

    function test_stagedSignerChangeCanBeCancelled() public {
        address[5] memory next;
        for (uint256 i = 0; i < 5; ++i) {
            next[i] = address(uint160(0x1000 + i));
        }
        bytes memory data = abi.encodeCall(ms.proposeSigners, (next));
        ms.execute(address(ms), data, _sigs(address(ms), data, 0, _idx(0, 1, 2)));
        bytes memory cancel = abi.encodeCall(ms.cancelSigners, ());
        ms.execute(address(ms), cancel, _sigs(address(ms), cancel, 1, _idx(0, 1, 2)));
        assertFalse(ms.signersPending());
        _passDelays();
        vm.expectRevert(FoundationMultisig.NoPendingSigners.selector);
        ms.applySigners();
    }

    function test_badSignerSets() public {
        address[5] memory bad = signers;
        bad[3] = bad[2];
        vm.expectRevert(FoundationMultisig.BadSigners.selector);
        new FoundationMultisig(bad);
        bad = signers;
        bad[0] = address(0);
        vm.expectRevert(FoundationMultisig.BadSigners.selector);
        new FoundationMultisig(bad);
    }
}

/// @notice A clock-only SealRegistry stand-in for deploying the multisig before VR's fixture etches the full mock.
contract MockSealShim {
    uint64 public progress;
    uint64 public ucTime;

    function set(uint64 p, uint64 t) external {
        progress = p;
        ucTime = t;
    }
}
