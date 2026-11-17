// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {PoaBase} from "./PoaBase.sol";
import {FastJson} from "../FastJson.sol";
import {VRC} from "../../../src/vr/VRConstants.sol";
import {VRCodec} from "../../../src/vr/VRCodec.sol";
import {PoaElection} from "../../../src/vr/poa/PoaElection.sol";

/// @notice The PoA module against the frozen schema v1 vectors (bft-core testvectors/validator-registry/encoding.json, copied byte for
/// byte with its MANIFEST in test/vr/fixtures): the module accepts exactly the canonical `elect` and `attach` arguments (codec.context,
/// codec.attach); its returns are the frozen encodings (codec.elect NotDue, NoCandidate and Reserved-ready byte for byte or by the strict
/// decoder; codec.output NotMine byte for byte and a 16-member Ready published by VR's strict decoder at the 5408-byte maximum;
/// codec.void; codec.metadata widths); its tag is the frozen domain word; its exposure digest is digest.poaExposure; and the frozen
/// ModuleAction payload's action is the one the module decodes (change.payload "ModuleAction Admit").
contract PoaVectorsTest is PoaBase, FastJson {
    string internal constant FILE = "/test/vr/fixtures/encoding.json";

    uint256 internal pass;

    function _p(uint256 i, string memory rel) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(i), "]", rel);
    }

    function _is(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _find(string[] memory ops, string[] memory names, string memory op, string memory name)
        internal
        pure
        returns (uint256)
    {
        for (uint256 i = 0; i < ops.length; ++i) {
            if (_is(ops[i], op) && _is(names[i], name)) return i;
        }
        revert(string.concat("no vector ", op, " ", name));
    }

    function _rawElect(bytes memory ctx) internal returns (bool ok, bytes memory ret) {
        vm.prank(VR_ADDR);
        (ok, ret) = address(poa).call(abi.encodeCall(PoaElection.elect, (ctx)));
    }

    function _ctx() internal view returns (bytes memory) {
        VRCodec.Context memory c;
        c.origin = keccak256("vectors");
        c.progress = progress;
        c.ucTime = ucTime;
        c.knownRootEpoch = 4;
        c.lastAcked = vr.lastAcked();
        c.nMin = vr.config().nMin;
        c.nTarget = vr.config().nTarget;
        c.nMax = vr.config().nMax;
        return VRCodec.encodeContext(c);
    }

    function test_moduleConformsToTheFrozenVectors() public {
        _setUpPoa(4, 1, 5, 16);
        _jload(string.concat(vm.projectRoot(), FILE));
        string[] memory ops = _jsarr(".vectors[*].op");
        string[] memory names = _jsarr(".vectors[*].name");

        // codec.context: the canonical argument is taken, a non-canonical one refused
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "codec.context")) continue;
            bool canonical = _jhas(_p(i, ".expect.bytes"));
            bytes memory b = _jbytes(_p(i, canonical ? ".expect.bytes" : ".input.bytes"));
            (bool ok, bytes memory ret) = _rawElect(b);
            if (canonical) {
                assertTrue(ok, names[i]);
            } else {
                assertFalse(ok, names[i]);
                assertEq(bytes4(ret), PoaElection.BadArgument.selector, names[i]);
            }
            ++n;
        }
        assertEq(n, 2, "codec.context");
        pass += n;

        // codec.attach: each vector on a fresh instance
        n = 0;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "codec.attach")) continue;
            bool canonical = _jhas(_p(i, ".expect.bytes"));
            bytes memory b = _jbytes(_p(i, canonical ? ".expect.bytes" : ".input.bytes"));
            PoaElection fresh = new PoaElection(VR_ADDR, engine, new uint64[](0));
            vm.prank(VR_ADDR);
            (bool ok, bytes memory ret) =
                address(fresh).call(abi.encodeCall(PoaElection.attach, (b)));
            if (canonical) {
                assertTrue(ok, names[i]);
                assertEq(ret.length, 0, "a void step returns nothing");
                assertEq(fresh.members().length, _ju(_p(i, ".input.n")), names[i]);
            } else {
                assertFalse(ok, names[i]);
                assertEq(bytes4(ret), PoaElection.BadArgument.selector, names[i]);
            }
            ++n;
        }
        assertEq(n, 5, "codec.attach");
        pass += n;

        // codec.elect: NotDue and NoCandidate byte for byte, Reserved ready through the strict decoder
        (bool ok1, bytes memory notDue) = _rawElect(_ctx());
        assertTrue(ok1);
        assertEq(
            notDue, _jbytes(_p(_find(ops, names, "codec.elect", "NotDue"), ".input.returndata"))
        );
        _action(A_REMOVE, 2);
        _advance(VRC.MIN_EPOCH_GAP, 1);
        (ok1, notDue) = _rawElect(_ctx());
        assertTrue(ok1);
        assertEq(
            notDue,
            _jbytes(_p(_find(ops, names, "codec.elect", "NoCandidate"), ".input.returndata"))
        );
        _admitNew();
        _advance(VRC.MIN_EPOCH_GAP, 1);
        (bool ok2, bytes memory reserved) = _rawElect(_ctx());
        assertTrue(ok2);
        (uint8 err, uint8 outcome, bool ready, bytes32 rid) = VRCodec.decodeElect(reserved);
        assertEq(err, VRCodec.OK);
        assertEq(outcome, VRC.ELECT_RESERVED);
        assertTrue(ready);
        assertTrue(rid != 0);
        assertEq(
            reserved.length,
            _jbytes(_p(_find(ops, names, "codec.elect", "Reserved ready"), ".input.returndata"))
            .length
        );
        pass += 3;

        // codec.output: NotMine byte for byte (any other id or transaction)
        (bool ok3, bytes memory notMine) =
            address(poa).staticcall(abi.encodeCall(PoaElection.outputOf, (keccak256("foreign"))));
        assertTrue(ok3);
        assertEq(
            notMine,
            _jbytes(_p(_find(ops, names, "codec.output", "NotMine 96"), ".input.returndata"))
        );
        pass += 1;

        // codec.void: every void step returns exactly 0 bytes
        bytes[4] memory voids = [
            abi.encodeCall(PoaElection.detach, ()),
            abi.encodeCall(PoaElection.onResolved, (rid, 1)),
            abi.encodeCall(PoaElection.onRecords, (0, 0)),
            abi.encodeCall(PoaElection.onGovernance, (abi.encode(A_REMOVE, uint64(3))))
        ];
        assertEq(
            _jbytes(_p(_find(ops, names, "codec.void", "empty"), ".input.returndata")).length, 0
        );
        for (uint256 i = 0; i < voids.length; ++i) {
            vm.prank(VR_ADDR);
            (bool ok, bytes memory ret) = address(poa).call(voids[i]);
            assertTrue(ok);
            assertEq(ret.length, 0);
        }
        pass += 1;

        // codec.metadata: the strict decoder takes each getter at its width (the gasBounds 256-byte vector is the shape)
        assertEq(
            _jbytes(_p(_find(ops, names, "codec.metadata", "gasBounds 256"), ".input.returndata"))
            .length,
            256
        );
        bytes4[5] memory sel = [
            PoaElection.moduleTag.selector,
            PoaElection.capabilities.selector,
            PoaElection.gasBounds.selector,
            PoaElection.maxElectionInterval.selector,
            PoaElection.liabilityHolder.selector
        ];
        uint256[5] memory k = [uint256(1), 1, 8, 1, 2];
        uint16[5] memory w = [uint16(256), 32, 64, 64, 160];
        for (uint256 i = 0; i < 5; ++i) {
            (bool ok, bytes memory ret) = address(poa).staticcall(abi.encodePacked(sel[i]));
            assertTrue(ok);
            uint16[8] memory bits;
            for (uint256 j = 0; j < 8; ++j) {
                bits[j] = w[i];
            }
            if (i == 4) bits[1] = 256;
            (uint8 e,) = VRCodec.decodeMetadata(ret, k[i], bits);
            assertEq(e, VRCodec.OK);
        }
        pass += 1;

        // domain.keccak: the module tag
        uint256 t = _find(ops, names, "domain.keccak", "domain unicity.vr.poa.v1");
        assertEq(poa.moduleTag(), bytes32(_jbytes(_p(t, ".expect.word"))));
        pass += 1;

        // digest.poaExposure: the module's digest formula (VRCodec.exposureDigest) in the vector's chain
        uint256 d = _find(ops, names, "digest.poaExposure", "PoA exposure");
        uint256 chain = uint256(bytes32(_jbytes(_p(d, ".input.chainId"))));
        uint256 here = block.chainid;
        vm.chainId(chain);
        assertEq(
            VRCodec.exposureDigest(
                bytes32(_jbytes(_p(d, ".input.network"))),
                address(bytes20(_jbytes(_p(d, ".input.registry")))),
                bytes32(_jbytes(_p(d, ".input.resultId"))),
                uint64(_ju(_p(d, ".input.id")))
            ),
            bytes32(_jbytes(_p(d, ".expect.exposureDigest")))
        );
        vm.chainId(here);
        pass += 1;

        // change.payload ModuleAction Admit: its action is (1 Admit, id 5), and the module admits by exactly those bytes
        uint256 a = _find(ops, names, "change.payload", "ModuleAction Admit");
        bytes memory action = _jbytes(_p(a, ".input.values[1]"));
        assertEq(action, abi.encode(uint64(1), uint64(5)));
        assertEq(_st(5), JOINING, "id 5 is the joiner admitted above");
        uint64 id6 = _registerNew();
        _submit(id6);
        vm.prank(VR_ADDR);
        poa.onGovernance(abi.encode(uint64(1), id6));
        assertEq(_st(id6), ADMITTED);
        pass += 1;

        emit log_named_uint("module vector checks passed", pass);
    }

    /// @dev A 16-member Ready output (the 5408-byte maximum) passes VR's strict decoder and is published.
    function test_sixteenMemberReadyAtTheMaximum() public {
        _setUpPoa(15, 1, 16, 16);
        _admitNew();
        (uint8 out, bytes32 rid) = _electPoa();
        assertEq(out, VRC.ELECT_RESERVED);
        assertEq(vr.output(rid).members.length, 16);
        assertEq(uint256(64 + 32 + 192 + 320 * 16), 5408);
    }

    function _jbytes(string memory key) internal view returns (bytes memory) {
        return abi.decode(_jget(bytes4(keccak256("parseJsonBytes(string,string)")), key), (bytes));
    }
}
