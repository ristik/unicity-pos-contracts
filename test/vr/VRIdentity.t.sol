// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRBase} from "./VRBase.sol";
import {VRShared} from "../../src/vr/VRShared.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {Registration, Member, IdentityView, Binding} from "../../src/vr/VRTypes.sol";

/// @notice Identities and bindings (design section 3.1): registration with both proofs of possession, nonces, permanent key tombstones,
/// binding proposals, and the binding-snapshot rule (section 11: B staged after output A captured an earlier binding; A's captured
/// binding is installed and B stays staged), with the captured preimages retrievable from the write-once store (FD-16). The
/// registration-shape vectors (digest.registrationShape) run through VR's `register`.
contract VRIdentityTest is VRBase {
    address internal constant ALICE = address(0xA11CE);

    function setUp() public {
        _setUpVR(5, 1, 5, 16);
    }

    function _register(address who, Keys memory k, string memory tag) internal returns (uint64 id) {
        Registration memory r = _reg(k, tag, address(0xFEE1), vr.registrationNonce(who));
        bytes32 d = _regDigest(VRC.REGISTER_DOMAIN, who, 0, r);
        vm.prank(who);
        id = vr.register(r, _sig(k.rootPk, d), _sig(k.evmPk, d));
    }

    function _propose(uint64 id, Keys memory k, string memory tag, address payee)
        internal
        returns (bytes32 ref)
    {
        IdentityView memory v = vr.identity(id);
        Registration memory r = _reg(k, tag, payee, v.bindingNonce);
        bytes32 d = _regDigest(VRC.BINDING_DOMAIN, v.owner, id, r);
        vm.prank(v.owner);
        vr.proposeBinding(id, r, _sig(k.rootPk, d), _sig(k.evmPk, d));
        ref = vr.identity(id).stagedRef;
    }

    function test_registerWithProofsOfPossession() public {
        Keys memory k = _freshKeys();
        uint64 id = _register(ALICE, k, "alice");
        assertEq(id, 6);
        IdentityView memory v = vr.identity(id);
        assertEq(v.owner, ALICE);
        assertEq(v.generation, 1);
        assertEq(v.current.rootKey, k.rootKey);
        assertEq(v.current.rootKeyHash, keccak256(k.rootKey));
        assertEq(v.current.rootNodeWord, keccak256("root-alice"));
        assertEq(vr.ownerOf(id), ALICE);
        assertEq(vr.registrationNonce(ALICE), 1);
    }

    function test_registrationRefusals() public {
        Keys memory k = _freshKeys();
        Registration memory r = _reg(k, "a", address(0xFEE1), 0);
        bytes32 d = _regDigest(VRC.REGISTER_DOMAIN, ALICE, 0, r);
        bytes memory rs = _sig(k.rootPk, d);
        bytes memory es = _sig(k.evmPk, d);
        // wrong nonce
        r.nonce = 1;
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(VRShared.RegistrationRefused.selector, uint8(5)));
        vr.register(r, rs, es);
        r.nonce = 0;
        // a PoP by the wrong key, a PoP by another sender (the digest binds msg.sender)
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(VRShared.RegistrationRefused.selector, uint8(7)));
        vr.register(r, es, rs);
        vm.prank(address(0xB0B));
        vm.expectRevert(abi.encodeWithSelector(VRShared.RegistrationRefused.selector, uint8(7)));
        vr.register(r, rs, es);
        vm.prank(ALICE);
        vr.register(r, rs, es);
        // the keys are tombstoned: a second identity cannot reuse either
        Keys memory k2 = _freshKeys();
        k2.evmKey = k.rootKey;
        k2.evmPk = k.rootPk;
        Registration memory r2 = _reg(k2, "b", address(0xFEE1), 0);
        bytes32 d2 = _regDigest(VRC.REGISTER_DOMAIN, address(0xB0B), 0, r2);
        vm.prank(address(0xB0B));
        vm.expectRevert(abi.encodeWithSelector(VRShared.RegistrationRefused.selector, uint8(6)));
        vr.register(r2, _sig(k2.rootPk, d2), _sig(k2.evmPk, d2));
    }

    /// digest.registrationShape: VR refuses each malformed registration with the shape code before any signature check.
    function test_registrationShapeVectors() public {
        string memory json =
            vm.readFile(string.concat(vm.projectRoot(), "/test/vr/fixtures/encoding.json"));
        string[] memory ops = abi.decode(vm.parseJson(json, ".vectors[*].op"), (string[]));
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (keccak256(bytes(ops[i])) != keccak256("digest.registrationShape")) continue;
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            Registration memory r;
            r.rootNodeID = vm.parseJsonString(json, string.concat(p, ".input.rootNodeId"));
            r.rootKey = vm.parseJsonBytes(json, string.concat(p, ".input.rootKey"));
            r.evmNodeID = vm.parseJsonString(json, string.concat(p, ".input.evmNodeId"));
            r.evmKey = vm.parseJsonBytes(json, string.concat(p, ".input.evmKey"));
            r.payee = vm.parseJsonAddress(json, string.concat(p, ".input.payee"));
            r.nonce = uint64(vm.parseJsonUint(json, string.concat(p, ".input.nonce")));
            string memory e = vm.parseJsonString(json, string.concat(p, ".expect.error"));
            uint8 code;
            if (_has(e, "node id length")) code = 1;
            else if (_has(e, "rootKey == evmKey")) code = 3;
            else if (_has(e, "key")) code = 2;
            else if (_has(e, "zero payee")) code = 4;
            else revert(e);
            vm.expectRevert(abi.encodeWithSelector(VRShared.RegistrationRefused.selector, code));
            vr.register(r, "", "");
            ++n;
        }
        assertEq(n, 5, "digest.registrationShape vector count");
    }

    function _has(string memory s, string memory sub) internal pure returns (bool) {
        return vm.contains(s, sub);
    }

    function test_proposeBindingRules() public {
        Keys memory k = keysOf[2];
        // only the owner
        Keys memory n = _freshKeys();
        Registration memory r = _reg(n, "two-b", address(0xB002), 0);
        bytes32 d = _regDigest(VRC.BINDING_DOMAIN, address(0xA002), 2, r);
        vm.expectRevert(VRShared.NotOwner.selector);
        vr.proposeBinding(2, r, _sig(n.rootPk, d), _sig(n.evmPk, d));
        // an unchanged binding is refused
        Registration memory same = _reg(k, "2", address(0xB002), 0);
        bytes32 ds = _regDigest(VRC.BINDING_DOMAIN, address(0xA002), 2, same);
        vm.prank(address(0xA002));
        vm.expectRevert(abi.encodeWithSelector(VRShared.RegistrationRefused.selector, uint8(8)));
        vr.proposeBinding(2, same, _sig(k.rootPk, ds), _sig(k.evmPk, ds));
        // keeping the root key and changing the EVM key is a replacement (same identity, same role)
        Keys memory mixed = _freshKeys();
        mixed.rootKey = k.rootKey;
        mixed.rootPk = k.rootPk;
        bytes32 ref = _propose(2, mixed, "two-c", address(0xB002));
        assertTrue(ref != 0);
        assertEq(vr.identity(2).bindingNonce, 1);
        // another identity's key in any role is refused
        Keys memory theft = _freshKeys();
        theft.evmKey = keysOf[3].rootKey;
        theft.evmPk = keysOf[3].rootPk;
        Registration memory rt = _reg(theft, "two-d", address(0xB002), 1);
        bytes32 dt = _regDigest(VRC.BINDING_DOMAIN, address(0xA002), 2, rt);
        vm.prank(address(0xA002));
        vm.expectRevert(abi.encodeWithSelector(VRShared.RegistrationRefused.selector, uint8(6)));
        vr.proposeBinding(2, rt, _sig(theft.rootPk, dt), _sig(theft.evmPk, dt));
    }

    /// Section 11 binding snapshot: B is staged after output A captured an earlier binding X; A's captured X is installed, B stays.
    function test_bindingSnapshotCapturedThenLaterStagingSurvives() public {
        bytes32 x = _propose(3, _freshKeys(), "three-x", address(0xB003));
        // output A captures X for member 3 (generation 2)
        Member[] memory ms = _members();
        Binding memory bx = vr.binding(x);
        ms[2].generation = 2;
        ms[2].rootNodeWord = bx.rootNodeWord;
        ms[2].rootKeyHash = bx.rootKeyHash;
        ms[2].evmNodeWord = bx.evmNodeWord;
        ms[2].evmKeyHash = bx.evmKeyHash;
        ms[2].payee = bx.payee;
        module.setMembers(ms);
        bytes32 a = _rid("A");
        assertEq(_moduleReserve(a, true), VRC.ELECT_RESERVED);
        assertEq(vr.output(a).members[2].generation, 2);
        // the owner stages B while A is open
        bytes32 b = _propose(3, _freshKeys(), "three-b", address(0xB003));
        assertTrue(b != x);
        // the captured preimages stay retrievable (FD-16)
        assertEq(vr.binding(x).rootNodeID, "root-three-x");
        assertEq(vr.output(a).members[2].rootNodeWord, keccak256("root-three-x"));
        _acknowledge(a, 0);
        IdentityView memory v = vr.identity(3);
        assertEq(v.currentRef, x, "A's captured binding is installed");
        assertEq(v.generation, 2);
        assertEq(v.stagedRef, b, "B stays staged");
        assertEq(vr.committee()[2].rootNodeWord, keccak256("root-three-x"));
    }

    function test_capturedStagingIsCleared() public {
        bytes32 x = _propose(4, _freshKeys(), "four-x", address(0xB004));
        Member[] memory ms = _members();
        Binding memory bx = vr.binding(x);
        ms[3].generation = 2;
        ms[3].rootNodeWord = bx.rootNodeWord;
        ms[3].rootKeyHash = bx.rootKeyHash;
        ms[3].evmNodeWord = bx.evmNodeWord;
        ms[3].evmKeyHash = bx.evmKeyHash;
        ms[3].payee = bx.payee;
        module.setMembers(ms);
        bytes32 a = _rid("A");
        assertEq(_moduleReserve(a, true), VRC.ELECT_RESERVED);
        _acknowledge(a, 0);
        assertEq(vr.identity(4).currentRef, x);
        assertEq(
            vr.identity(4).stagedRef, bytes32(0), "staging equal to the captured binding is cleared"
        );
    }

    function test_outputCannotUseAnUnstagedGeneration() public {
        Member[] memory ms = _members();
        ms[0].generation = 2; // no staged binding
        module.setMembers(ms);
        bytes32 a = _rid("A");
        assertEq(_moduleReserve(a, true), VRC.ELECT_NO_CANDIDATE, "invalid output: the step fails");
        assertEq(vr.health(), VRC.FAULTED);
    }

    function test_endpointsAreOwnerOnlyAndBounded() public {
        vm.expectRevert(VRShared.NotOwner.selector);
        vr.setEndpoints(1, "x");
        vm.prank(address(0xA001));
        vm.expectRevert(VRShared.EndpointsTooLong.selector);
        vr.setEndpoints(1, new bytes(1025));
    }
}
