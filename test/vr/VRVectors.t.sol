// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {VRCodec} from "../../src/vr/VRCodec.sol";
import {VRChanges} from "../../src/vr/VRChanges.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {Member} from "../../src/vr/VRTypes.sol";

/// @notice Exposes the production codec and change libraries to the vector consumer (calldata in, codes out).
contract VRCodecHarness {
    function elect(bytes calldata r) external pure returns (uint8 err) {
        (err,,,) = VRCodec.decodeElect(r);
    }

    function output(bytes calldata r) external pure returns (uint8 err) {
        (err,,,) = VRCodec.decodeOutput(r);
    }

    function adoption(bytes calldata r) external pure returns (uint8 err) {
        (err,) = VRCodec.decodeAdoption(r);
    }

    function void_(bytes calldata r) external pure returns (uint8) {
        return VRCodec.decodeVoid(r.length);
    }

    function metadata(bytes calldata r, uint256 k, uint16 width) external pure returns (uint8 err) {
        uint16[8] memory bits;
        for (uint256 i = 0; i < 8; ++i) {
            bits[i] = width;
        }
        (err,) = VRCodec.decodeMetadata(r, k, bits);
    }

    function context(bytes calldata b) external pure returns (uint8 err) {
        (err,) = VRCodec.decodeContext(b);
    }

    function encodeContext(VRCodec.Context calldata c) external pure returns (bytes memory) {
        return VRCodec.encodeContext(c);
    }

    function attach(bytes calldata b)
        external
        pure
        returns (uint8 err, bytes memory reencoded, uint8 holderIndex, uint256 n, bytes memory init)
    {
        VRCodec.AttachContext memory a;
        (err, a) = VRCodec.decodeAttachContext(b);
        if (err == VRCodec.OK) {
            reencoded = VRCodec.encodeAttachContext(a);
            holderIndex = a.holderIndex;
            n = a.committee.length;
            init = a.initData;
        }
    }

    function record(uint8 kind, bytes calldata d) external pure returns (bool) {
        return VRCodec.recordWellFormed(kind, d);
    }

    function payload(uint8 kind, bytes calldata p) external pure returns (uint8) {
        return VRChanges.checkPayload(kind, p);
    }

    function queueCheck(uint8 kind, bytes calldata p, VRChanges.Env calldata env)
        external
        pure
        returns (uint8)
    {
        return VRChanges.check(kind, p, env);
    }

    function partition(bytes calldata pdr) external pure returns (bool ok, uint32 p) {
        return VRChanges.pdrPartition(pdr);
    }

    function fees(uint64 maxGas, uint64 systemGas, uint64 f, uint64 d, address c)
        external
        pure
        returns (uint8)
    {
        return VRChanges.validateFees(maxGas, systemGas, f, d, c);
    }

    /// @dev vrschema SelectBinding over the production `fits`/`take`: ascending ids, scopes given as strings.
    function select(
        uint64[] calldata ids,
        uint8[] calldata kinds,
        uint256[] calldata sizes,
        bytes32[] calldata scopes,
        bool[] calldata performed
    ) external pure returns (bool[] memory bound) {
        VRChanges.Selection memory sel;
        bound = new bool[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            if (!VRChanges.fits(sel, kinds[i], sizes[i], scopes[i], performed[i])) continue;
            VRChanges.take(sel, kinds[i], sizes[i], scopes[i]);
            bound[i] = true;
        }
    }
}

/// @notice VT-02 consumer of the frozen VR schema v1 vectors (bft-core testvectors/validator-registry, copied byte for byte with their
/// MANIFEST): VRCodec (codec.*), the root-record decoder (record.decode), the change payload decoder, queue checks, scopes and binding
/// selection (change.*), and the fee profile (fee.validate). Every vector of each consumed op must match; the counts are asserted so a
/// regenerated file that drops or adds vectors is noticed.
contract VRVectorsTest is Test {
    string internal constant DIR = "/test/vr/fixtures/";
    VRCodecHarness internal h;

    function setUp() public {
        h = new VRCodecHarness();
    }

    // ---- json helpers ----

    function _json(string memory f) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), DIR, f));
    }

    function _p(uint256 i, string memory rel) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(i), "]", rel);
    }

    function _is(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _starts(string memory a, string memory prefix) internal pure returns (bool) {
        bytes memory x = bytes(a);
        bytes memory p = bytes(prefix);
        if (x.length < p.length) return false;
        for (uint256 i = 0; i < p.length; ++i) {
            if (x[i] != p[i]) return false;
        }
        return true;
    }

    function _codec(string memory name) internal pure returns (uint8) {
        string[11] memory names = [
            "OK",
            "Oversize",
            "Envelope",
            "Length",
            "Narrow",
            "Bool",
            "Range",
            "Order",
            "Count",
            "ResultIdZeroness",
            "Padding"
        ];
        for (uint256 i = 0; i < names.length; ++i) {
            if (_is(name, names[i])) return uint8(i);
        }
        revert(string.concat("unknown codec result ", name));
    }

    /// @dev Maps a vrschema queue/decoder error text to the VRChanges refusal code.
    function _changeCode(string memory e) internal pure returns (uint8) {
        if (bytes(e).length == 0) return VRChanges.OK;
        if (_starts(e, "vrschema: unknown kind")) return VRChanges.UNKNOWN_KIND;
        if (_is(e, "TooManyPending")) return VRChanges.TOO_MANY_PENDING;
        if (_is(e, "vrschema: oversize")) return VRChanges.OVERSIZE;
        if (_starts(e, "vrschema: wrong length")) return VRChanges.LENGTH;
        if (_is(e, "vrschema: non-canonical ABI offset")) return VRChanges.OFFSET;
        if (_is(e, "vrschema: nonzero ABI padding")) return VRChanges.PADDING;
        if (_starts(e, "vrschema: non-canonical narrow")) return VRChanges.NARROW;
        if (_starts(e, "vrschema: value out of range")) return VRChanges.RANGE;
        if (_is(e, "ZeroParameter")) return VRChanges.ZERO_PARAMETER;
        if (_is(e, "NoOrdinaryCapacity")) return VRChanges.NO_ORDINARY_CAPACITY;
        if (_is(e, "InvalidParentBaseFee")) return VRChanges.INVALID_PARENT_BASE_FEE;
        if (_is(e, "UnsupportedProfile")) return VRChanges.UNSUPPORTED_PROFILE;
        if (_is(e, "ZeroFeeCollector")) return VRChanges.ZERO_FEE_COLLECTOR;
        if (_is(e, "ScheduleTooEarly")) return VRChanges.SCHEDULE_TOO_EARLY;
        if (_is(e, "ScheduleTooSoon")) return VRChanges.SCHEDULE_TOO_SOON;
        if (_is(e, "NotInCommittee")) return VRChanges.NOT_IN_COMMITTEE;
        if (_is(e, "TooManyForceRemoves")) return VRChanges.TOO_MANY_FORCE_REMOVES;
        if (_is(e, "UnreadableScope")) return VRChanges.UNREADABLE_SCOPE;
        revert(string.concat("unmapped change error ", e));
    }

    struct Count {
        uint256 pass;
    }

    function _ops(string memory json) internal pure returns (string[] memory ops) {
        ops = abi.decode(vm.parseJson(json, ".vectors[*].op"), (string[]));
    }

    // ---- codec.* ----

    function test_codecVectors() public view {
        string memory json = _json("encoding.json");
        string[] memory ops = _ops(json);
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_starts(ops[i], "codec.")) continue;
            string memory name = vm.parseJsonString(json, _p(i, ".name"));
            if (_is(ops[i], "codec.context")) {
                _contextVector(json, i, name);
            } else if (_is(ops[i], "codec.attach")) {
                _attachVector(json, i, name);
            } else {
                bytes memory r = vm.parseJsonBytes(json, _p(i, ".input.returndata"));
                assertEq(r.length, vm.parseJsonUint(json, _p(i, ".input.size")), name);
                uint8 want = _codec(vm.parseJsonString(json, _p(i, ".expect.result")));
                uint8 got;
                if (_is(ops[i], "codec.elect")) {
                    got = h.elect(r);
                } else if (_is(ops[i], "codec.output")) {
                    got = h.output(r);
                } else if (_is(ops[i], "codec.adoption")) {
                    got = h.adoption(r);
                } else if (_is(ops[i], "codec.void")) {
                    got = h.void_(r);
                } else if (_is(ops[i], "codec.metadata")) {
                    got = _starts(name, "gasBounds") ? h.metadata(r, 8, 64) : h.metadata(r, 1, 32);
                } else {
                    revert(string.concat("unconsumed op ", ops[i]));
                }
                assertEq(got, want, name);
            }
            ++n;
        }
        assertEq(n, 55, "codec.* vector count");
    }

    function _contextVector(string memory json, uint256 i, string memory name) internal view {
        if (vm.keyExistsJson(json, _p(i, ".expect.bytes"))) {
            VRCodec.Context memory c;
            c.origin = vm.parseJsonBytes32(json, _p(i, ".input.origin"));
            c.progress = uint64(vm.parseJsonUint(json, _p(i, ".input.progress")));
            c.ucTime = uint64(vm.parseJsonUint(json, _p(i, ".input.ucTime")));
            c.knownRootEpoch = uint64(vm.parseJsonUint(json, _p(i, ".input.knownRootEpoch")));
            c.lastAcked = vm.parseJsonBytes32(json, _p(i, ".input.lastAcked"));
            c.nMin = uint32(vm.parseJsonUint(json, _p(i, ".input.nMin")));
            c.nTarget = uint32(vm.parseJsonUint(json, _p(i, ".input.nTarget")));
            c.nMax = uint32(vm.parseJsonUint(json, _p(i, ".input.nMax")));
            c.dueWork = uint32(vm.parseJsonUint(json, _p(i, ".input.dueWork")));
            c.forceRemoved = uint16(vm.parseJsonUint(json, _p(i, ".input.forceRemoved")));
            bytes memory want = vm.parseJsonBytes(json, _p(i, ".expect.bytes"));
            assertEq(h.encodeContext(c), want, name);
            assertEq(h.context(want), VRCodec.OK, name);
        } else {
            bytes memory b = vm.parseJsonBytes(json, _p(i, ".input.bytes"));
            assertEq(h.context(b), _codec(vm.parseJsonString(json, _p(i, ".expect.result"))), name);
        }
    }

    function _attachVector(string memory json, uint256 i, string memory name) internal view {
        if (vm.keyExistsJson(json, _p(i, ".expect.bytes"))) {
            bytes memory want = vm.parseJsonBytes(json, _p(i, ".expect.bytes"));
            assertEq(want.length, vm.parseJsonUint(json, _p(i, ".expect.size")), name);
            (uint8 err, bytes memory re, uint8 hi, uint256 n, bytes memory init) = h.attach(want);
            assertEq(err, VRCodec.OK, name);
            assertEq(re, want, string.concat(name, ": VR's encoder reproduces the bytes"));
            assertEq(hi, vm.parseJsonUint(json, _p(i, ".input.holderIndex")), name);
            assertEq(n, vm.parseJsonUint(json, _p(i, ".input.n")), name);
            assertEq(init, vm.parseJsonBytes(json, _p(i, ".input.initData")), name);
        } else {
            bytes memory b = vm.parseJsonBytes(json, _p(i, ".input.bytes"));
            (uint8 err,,,,) = h.attach(b);
            assertEq(err, _codec(vm.parseJsonString(json, _p(i, ".expect.result"))), name);
        }
    }

    // ---- record.decode ----

    function test_recordDecodeVectors() public view {
        string memory json = _json("encoding.json");
        string[] memory ops = _ops(json);
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "record.decode")) continue;
            string memory name = vm.parseJsonString(json, _p(i, ".name"));
            uint8 kind = uint8(vm.parseJsonUint(json, _p(i, ".input.kind")));
            bytes memory d = vm.parseJsonBytes(json, _p(i, ".input.data"));
            assertEq(h.record(kind, d), vm.parseJsonBool(json, _p(i, ".expect.ok")), name);
            ++n;
        }
        assertEq(n, 32, "record.decode vector count");
    }

    // ---- change.payload, change.canonicality, change.queue ----

    function test_changePayloadVectors() public view {
        string memory json = _json("encoding.json");
        string[] memory ops = _ops(json);
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "change.payload") && !_is(ops[i], "change.canonicality")) continue;
            string memory name = vm.parseJsonString(json, _p(i, ".name"));
            uint8 kind = uint8(vm.parseJsonUint(json, _p(i, ".input.kind")));
            if (vm.keyExistsJson(json, _p(i, ".expect.payload"))) {
                bytes memory p = vm.parseJsonBytes(json, _p(i, ".expect.payload"));
                assertEq(h.payload(kind, p), VRChanges.OK, name);
                assertEq(
                    keccak256(p), vm.parseJsonBytes32(json, _p(i, ".expect.payloadHash")), name
                );
                assertEq(p.length, vm.parseJsonUint(json, _p(i, ".expect.size")), name);
            } else {
                bytes memory p = vm.parseJsonBytes(json, _p(i, ".input.payload"));
                bool ok = vm.parseJsonBool(json, _p(i, ".expect.ok"));
                if (ok) {
                    assertEq(h.payload(kind, p), VRChanges.OK, name);
                } else {
                    assertEq(
                        h.payload(kind, p),
                        _changeCode(vm.parseJsonString(json, _p(i, ".expect.error"))),
                        name
                    );
                }
            }
            ++n;
        }
        assertEq(n, 20, "change.payload + change.canonicality vector count");
    }

    function test_changeQueueVectors() public view {
        string memory json = _json("encoding.json");
        string[] memory ops = _ops(json);
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "change.queue")) continue;
            string memory name = vm.parseJsonString(json, _p(i, ".name"));
            VRChanges.Env memory env;
            env.knownRootEpoch = uint64(vm.parseJsonUint(json, _p(i, ".input.knownRootEpoch")));
            env.ucTime = uint64(vm.parseJsonUint(json, _p(i, ".input.ucTime")));
            env.pending = vm.parseJsonUint(json, _p(i, ".input.pending"));
            env.pendingForce = vm.parseJsonUint(json, _p(i, ".input.pendingForceRemove"));
            uint256[] memory c = vm.parseJsonUintArray(json, _p(i, ".input.committee"));
            env.committee = new uint64[](c.length);
            for (uint256 k = 0; k < c.length; ++k) {
                env.committee[k] = uint64(c[k]);
            }
            env.maxGas = uint64(vm.parseJsonUint(json, _p(i, ".input.maxGas")));
            env.systemGas = uint64(vm.parseJsonUint(json, _p(i, ".input.systemGas")));
            uint8 kind = uint8(vm.parseJsonUint(json, _p(i, ".input.kind")));
            bytes memory p = vm.parseJsonBytes(json, _p(i, ".input.payload"));
            uint8 want = vm.parseJsonBool(json, _p(i, ".expect.ok"))
                ? VRChanges.OK
                : _changeCode(vm.parseJsonString(json, _p(i, ".expect.error")));
            assertEq(h.queueCheck(kind, p, env), want, name);
            ++n;
        }
        assertEq(n, 22, "change.queue vector count");
    }

    // ---- change.scope, change.binding (statemachine.json) ----

    function test_changeScopeVectors() public view {
        string memory json = _json("statemachine.json");
        string[] memory ops = _ops(json);
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "change.scope")) continue;
            string memory name = vm.parseJsonString(json, _p(i, ".name"));
            bytes memory pdr = vm.parseJsonBytes(json, _p(i, ".input.pdr"));
            string memory want = vm.parseJsonString(json, _p(i, ".expect.scope"));
            (bool ok, uint32 part) = h.partition(pdr);
            if (_is(want, "UnreadableScope")) {
                assertFalse(ok, name);
            } else {
                assertTrue(ok, name);
                assertEq(string.concat("partition:", vm.toString(part)), want, name);
            }
            ++n;
        }
        assertEq(n, 5, "change.scope vector count");
    }

    function test_changeBindingVectors() public view {
        string memory json = _json("statemachine.json");
        string[] memory ops = _ops(json);
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "change.binding")) continue;
            string memory name = vm.parseJsonString(json, _p(i, ".name"));
            uint256[] memory idsRaw =
                abi.decode(vm.parseJson(json, _p(i, ".input.scheduled[*].id")), (uint256[]));
            uint256 m = idsRaw.length;
            uint64[] memory ids = new uint64[](m);
            uint8[] memory kinds = new uint8[](m);
            uint256[] memory sizes = new uint256[](m);
            bytes32[] memory scopes = new bytes32[](m);
            bool[] memory performed = new bool[](m);
            for (uint256 k = 0; k < m; ++k) {
                string memory e = string.concat(".input.scheduled[", vm.toString(k), "]");
                ids[k] = uint64(idsRaw[k]);
                kinds[k] = uint8(vm.parseJsonUint(json, _p(i, string.concat(e, ".kind"))));
                sizes[k] = vm.parseJsonUint(json, _p(i, string.concat(e, ".payloadSize")));
                string memory sc = vm.parseJsonString(json, _p(i, string.concat(e, ".scope")));
                scopes[k] = bytes(sc).length == 0 ? bytes32(0) : keccak256(bytes(sc));
                if (vm.keyExistsJson(json, _p(i, string.concat(e, ".performed")))) {
                    performed[k] = vm.parseJsonBool(json, _p(i, string.concat(e, ".performed")));
                }
            }
            bool[] memory bound = h.select(ids, kinds, sizes, scopes, performed);
            uint256[] memory wantBound = vm.parseJsonUintArray(json, _p(i, ".expect.bound"));
            uint256 nb;
            for (uint256 k = 0; k < m; ++k) {
                if (!bound[k]) continue;
                assertEq(ids[k], wantBound[nb], name);
                ++nb;
            }
            assertEq(nb, wantBound.length, name);
            ++n;
        }
        assertEq(n, 8, "change.binding vector count");
    }

    // ---- fee.validate (arithmetic.json) ----

    function test_feeValidateVectors() public view {
        string memory json = _json("arithmetic.json");
        string[] memory ops = _ops(json);
        uint256 n;
        for (uint256 i = 0; i < ops.length; ++i) {
            if (!_is(ops[i], "fee.validate")) continue;
            string memory name = vm.parseJsonString(json, _p(i, ".name"));
            uint8 got = h.fees(
                uint64(vm.parseJsonUint(json, _p(i, ".input.maxGas"))),
                uint64(vm.parseJsonUint(json, _p(i, ".input.systemGas"))),
                uint64(vm.parseUint(vm.parseJsonString(json, _p(i, ".input.baseFeeFloor")))),
                uint64(vm.parseJsonUint(json, _p(i, ".input.changeDenominator"))),
                vm.parseJsonAddress(json, _p(i, ".input.feeCollector"))
            );
            uint8 want = vm.parseJsonBool(json, _p(i, ".expect.ok"))
                ? VRChanges.OK
                : _changeCode(vm.parseJsonString(json, _p(i, ".expect.error")));
            assertEq(got, want, name);
            ++n;
        }
        assertEq(n, 8, "fee.validate vector count");
    }

    function test_manifestPinsTheNewFixtures() public view {
        string memory manifest =
            vm.readFile(string.concat(vm.projectRoot(), DIR, "MANIFEST.sha256"));
        _checkPinned(manifest, "statemachine.json");
        _checkPinned(manifest, "arithmetic.json");
    }

    function _checkPinned(string memory manifest, string memory file) internal view {
        bytes memory data = vm.readFileBinary(string.concat(vm.projectRoot(), DIR, file));
        string memory line = string.concat(vm.toString(sha256(data)), "  ", file);
        // vm.toString(bytes32) is 0x-prefixed; the manifest is bare hex
        bytes memory l = bytes(line);
        bytes memory bare = new bytes(l.length - 2);
        for (uint256 i = 2; i < l.length; ++i) {
            bare[i - 2] = l[i];
        }
        assertTrue(vm.contains(manifest, string(bare)), string.concat(file, " is not pinned"));
    }
}
