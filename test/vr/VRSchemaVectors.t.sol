// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

/// @notice A consumer of the ValidatorRegistry schema v1 encoding vectors (bft-core #1156, VT-16).
/// bft-core testvectors/validator-registry/encoding.json, produced by the Go reference package
/// vrschema, is copied byte for byte to test/vr/fixtures/encoding.json with its MANIFEST.sha256.
/// Every vector is {name, op, input, expect}; this test iterates them by op and recomputes in
/// Solidity the domain words, the ERC-7201 slots, every EVM-side digest, the registration proofs
/// of possession, the change payload encodings and the root-record widths and word types. It
/// proves the frozen formulas are the ones Solidity computes; it is not VRCodec conformance (that
/// comes with VT-02). The ops not consumed here (codec.*, change.queue, control.*, handoff.*,
/// record.gas, digest.registrationShape) are left to VT-02.
///
/// Refresh after a regeneration in bft-core: copy encoding.json and MANIFEST.sha256 from bft-core
/// testvectors/validator-registry/ into test/vr/fixtures/ unchanged. test_manifestPinsTheFixtures
/// recomputes the sha256 of each Go-produced fixture with the sha256 precompile and compares it
/// with its manifest line.
contract VRSchemaVectorsTest is Test {
    string internal constant FIXTURES = "/test/vr/fixtures/";

    // Domain words (bft-core vrschema/constants.go): Solidity derives them from the texts, the
    // vectors give the words.
    string internal constant MEMBERS_TEXT = "unicity.vr.members.v1";
    string internal constant CHANGES_TEXT = "unicity.vr.changes.v1";
    string internal constant OUTPUT_TEXT = "unicity.vr.output.v1";
    string internal constant NATIVE_RESULT_TEXT = "unicity.vr.native-result.v1";
    string internal constant REGISTRY_NATIVE_TEXT = "unicity.vr.registry-native.v1";
    string internal constant REGISTER_TEXT = "unicity.vr.register";
    string internal constant BINDING_TEXT = "unicity.vr.binding";
    string internal constant P85_EXPOSURE_TEXT = "unicity.p85.exposure";
    string internal constant RETIREMENT_V2_TEXT = "unicity.seal-registry/records.retirement.v2";
    string internal constant RULE_PREFIX = "unicity.rule/";

    bytes32 internal constant MEMBERS_DOMAIN = keccak256(bytes(MEMBERS_TEXT));
    bytes32 internal constant CHANGES_DOMAIN = keccak256(bytes(CHANGES_TEXT));
    bytes32 internal constant OUTPUT_DOMAIN = keccak256(bytes(OUTPUT_TEXT));
    bytes32 internal constant NATIVE_RESULT_DOMAIN = keccak256(bytes(NATIVE_RESULT_TEXT));
    bytes32 internal constant REGISTRY_NATIVE_TAG = keccak256(bytes(REGISTRY_NATIVE_TEXT));
    bytes32 internal constant REGISTER_DOMAIN = keccak256(bytes(REGISTER_TEXT));
    bytes32 internal constant BINDING_DOMAIN = keccak256(bytes(BINDING_TEXT));
    bytes32 internal constant P85_EXPOSURE_DOMAIN = keccak256(bytes(P85_EXPOSURE_TEXT));
    bytes32 internal constant RETIREMENT_V2_DOMAIN = keccak256(bytes(RETIREMENT_V2_TEXT));

    uint256 internal constant MAX_CHANGE_PAYLOAD = 16 * 1024;
    uint8 internal constant CHANGE_KINDS = 10;
    uint8 internal constant RECORD_KINDS = 9;
    uint8 internal constant MAX_HOLDERS = 8;
    uint8 internal constant REJ_EXPIRED = 1;
    uint8 internal constant REJ_INVALID = 3;

    uint256 internal constant SECP256K1_P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant SECP256K1_N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// The parsed vector file: the raw JSON plus every vector's op and name, by index.
    struct Vectors {
        string json;
        string[] ops;
        string[] names;
    }

    // ---------------------------------------------------------------------------------------------
    // file
    // ---------------------------------------------------------------------------------------------

    function test_fileHeader() public view {
        Vectors memory v = _load();
        assertEq(vm.parseJsonString(v.json, ".schema"), "unicity.vr.schema/v1");
        assertEq(vm.parseJsonUint(v.json, ".version"), 1);
        assertEq(vm.parseJsonString(v.json, ".file"), "encoding.json");
        assertEq(v.ops.length, v.names.length);
        assertGt(v.ops.length, 0);
    }

    function test_manifestPinsTheFixtures() public view {
        string memory manifest = vm.readFile(_fixture("MANIFEST.sha256"));
        _checkPinned(manifest, "encoding.json");
        _checkPinned(manifest, "storage-flat.json");
    }

    // ---------------------------------------------------------------------------------------------
    // domains and namespaces
    // ---------------------------------------------------------------------------------------------

    function test_domainKeccak() public view {
        Vectors memory v = _load();
        string[9] memory used = [
            MEMBERS_TEXT,
            CHANGES_TEXT,
            OUTPUT_TEXT,
            NATIVE_RESULT_TEXT,
            REGISTRY_NATIVE_TEXT,
            REGISTER_TEXT,
            BINDING_TEXT,
            P85_EXPOSURE_TEXT,
            RETIREMENT_V2_TEXT
        ];
        uint256 seen;
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "domain.keccak")) continue;
            string memory text = vm.parseJsonString(v.json, _p(i, ".input.text"));
            bytes32 word = vm.parseJsonBytes32(v.json, _p(i, ".expect.word"));
            assertEq(keccak256(bytes(text)), word, v.names[i]);
            for (uint256 k; k < used.length; ++k) {
                if (_is(text, used[k])) seen |= 1 << k;
            }
            ++n;
        }
        assertGt(n, 0, "no domain.keccak vectors");
        assertEq(
            seen, (1 << used.length) - 1, "a domain this test uses has no domain.keccak vector"
        );
    }

    function test_domainErc7201() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "domain.erc7201")) continue;
            string memory id = vm.parseJsonString(v.json, _p(i, ".input.id"));
            bytes32 slot =
                keccak256(abi.encode(uint256(keccak256(bytes(id))) - 1)) & ~bytes32(uint256(0xff));
            assertEq(slot, vm.parseJsonBytes32(v.json, _p(i, ".expect.slot")), v.names[i]);
            ++n;
        }
        assertGt(n, 0, "no domain.erc7201 vectors");
    }

    function test_domainRuleId() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "domain.ruleId")) continue;
            string memory name = vm.parseJsonString(v.json, _p(i, ".input.name"));
            assertEq(
                keccak256(bytes(string.concat(RULE_PREFIX, name))),
                vm.parseJsonBytes32(v.json, _p(i, ".expect.ruleId")),
                v.names[i]
            );
            ++n;
        }
        assertGt(n, 0, "no domain.ruleId vectors");
    }

    // ---------------------------------------------------------------------------------------------
    // digests
    // ---------------------------------------------------------------------------------------------

    function test_digestMember() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "digest.member")) continue;
            bytes memory words = abi.encode(
                _u64(v, i, ".input.id"),
                _u64(v, i, ".input.generation"),
                _u64(v, i, ".input.weight"),
                _u64(v, i, ".input.rawWeight"),
                _b32(v, i, ".input.rootNodeWord"),
                _b32(v, i, ".input.rootKeyHash"),
                _b32(v, i, ".input.evmNodeWord"),
                _b32(v, i, ".input.evmKeyHash"),
                _addr(v, i, ".input.payee"),
                _b32(v, i, ".input.exposureDigest")
            );
            assertEq(words.length, 320, v.names[i]);
            assertEq(words, _bytes(v, i, ".expect.words"), v.names[i]);
            assertEq(keccak256(words), _b32(v, i, ".expect.hash"), v.names[i]);
            ++n;
        }
        assertGt(n, 0, "no digest.member vectors");
    }

    function test_digestMembers() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "digest.members")) continue;
            bytes32[] memory hs = vm.parseJsonBytes32Array(v.json, _p(i, ".input.memberHashes"));
            bytes memory enc = abi.encode(MEMBERS_DOMAIN, hs.length);
            for (uint256 k; k < hs.length; ++k) {
                enc = bytes.concat(enc, hs[k]);
            }
            assertEq(keccak256(enc), _b32(v, i, ".expect.membersDigest"), v.names[i]);
            ++n;
        }
        assertGt(n, 0, "no digest.members vectors");
    }

    function test_digestChanges() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "digest.changes")) continue;
            uint256 count;
            while (vm.keyExistsJson(v.json, _p(i, _idx(".input.changes", count)))) {
                ++count;
            }
            bytes memory enc = abi.encode(CHANGES_DOMAIN, count);
            uint64 last;
            for (uint256 k; k < count; ++k) {
                string memory c = _idx(".input.changes", k);
                uint64 id = _u64(v, i, string.concat(c, ".id"));
                uint8 kind = _u8(v, i, string.concat(c, ".kind"));
                assertTrue(k == 0 || id > last, "changes not strictly ascending");
                assertTrue(kind >= 1 && kind <= CHANGE_KINDS, "unknown change kind");
                last = id;
                enc = bytes.concat(
                    enc, abi.encode(id, kind, _b32(v, i, string.concat(c, ".payloadHash")))
                );
            }
            assertEq(keccak256(enc), _b32(v, i, ".expect.changesDigest"), v.names[i]);
            ++n;
        }
        assertGt(n, 0, "no digest.changes vectors");
    }

    function test_digestOutputCommit() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "digest.outputCommit")) continue;
            bool native = vm.parseJsonBool(v.json, _p(i, ".input.native"));
            bytes32 tag = _b32(v, i, ".input.moduleTag");
            if (native) assertEq(tag, REGISTRY_NATIVE_TAG, "native output with a module tag");
            bytes memory enc = bytes.concat(
                abi.encode(
                    OUTPUT_DOMAIN,
                    _b32(v, i, ".input.network"),
                    _b32(v, i, ".input.chainId"),
                    _addr(v, i, ".input.registry"),
                    _b32(v, i, ".input.resultId"),
                    _b32(v, i, ".input.predecessor"),
                    _u64(v, i, ".input.attempt")
                ),
                abi.encode(
                    tag,
                    native,
                    _b32(v, i, ".input.snapshotDigest"),
                    _b32(v, i, ".input.policyDigest"),
                    _b32(v, i, ".input.membersDigest"),
                    _b32(v, i, ".input.kDigest"),
                    _b32(v, i, ".input.changesDigest")
                )
            );
            assertEq(enc.length, 14 * 32);
            assertEq(keccak256(enc), _b32(v, i, ".expect.outputCommit"), v.names[i]);
            ++n;
        }
        assertGt(n, 0, "no digest.outputCommit vectors");
    }

    function test_digestNativeResultId() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "digest.nativeResultId")) continue;
            bytes32 id = keccak256(
                abi.encode(
                    NATIVE_RESULT_DOMAIN,
                    _b32(v, i, ".input.network"),
                    _b32(v, i, ".input.chainId"),
                    _addr(v, i, ".input.registry"),
                    _b32(v, i, ".input.lastAcked"),
                    _u64(v, i, ".input.attempt"),
                    _b32(v, i, ".input.origin")
                )
            );
            assertEq(id, _b32(v, i, ".expect.resultId"), v.names[i]);
            ++n;
        }
        assertGt(n, 0, "no digest.nativeResultId vectors");
    }

    /// The registration digest, and both proofs of possession recovered to the address of the full
    /// public key decompressed from the 33-byte key (not only to a nonzero address).
    function test_digestRegisterAndBinding() public view {
        Vectors memory v = _load();
        uint256 reg;
        uint256 bind;
        for (uint256 i; i < v.ops.length; ++i) {
            bool binding = _is(v.ops[i], "digest.binding");
            if (!binding && !_is(v.ops[i], "digest.register")) continue;
            uint64 id = _u64(v, i, ".input.id");
            if (binding) {
                assertGt(id, 0, "binding for id 0");
                ++bind;
            } else {
                assertEq(id, 0, "register with a nonzero id");
                ++reg;
            }
            bytes memory rootKey = _bytes(v, i, ".input.rootKey");
            bytes memory evmKey = _bytes(v, i, ".input.evmKey");
            bytes32 digest = keccak256(
                bytes.concat(
                    abi.encode(
                        binding ? BINDING_DOMAIN : REGISTER_DOMAIN,
                        _b32(v, i, ".input.network"),
                        _b32(v, i, ".input.chainId"),
                        _addr(v, i, ".input.registry"),
                        _addr(v, i, ".input.sender"),
                        id
                    ),
                    abi.encode(
                        keccak256(bytes(_str(v, i, ".input.rootNodeId"))),
                        keccak256(rootKey),
                        keccak256(bytes(_str(v, i, ".input.evmNodeId"))),
                        keccak256(evmKey),
                        _addr(v, i, ".input.payee"),
                        _u64(v, i, ".input.nonce")
                    )
                )
            );
            assertEq(digest, _b32(v, i, ".expect.digest"), v.names[i]);
            assertTrue(keccak256(rootKey) != keccak256(evmKey), "rootKey == evmKey");
            _checkPoP(digest, _bytes(v, i, ".expect.rootPoP"), rootKey, v.names[i]);
            _checkPoP(digest, _bytes(v, i, ".expect.evmPoP"), evmKey, v.names[i]);
        }
        assertGt(reg, 0, "no digest.register vectors");
        assertGt(bind, 0, "no digest.binding vectors");
    }

    function test_digestPoaExposure() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "digest.poaExposure")) continue;
            // The P85 custody ExposureID (src/p85/CustodyStorage.sol _createExposure) with
            // deployment (network, chain id, VR) and the output's resultId as the assignment.
            bytes32 d = keccak256(
                abi.encode(
                    P85_EXPOSURE_DOMAIN,
                    _b32(v, i, ".input.network"),
                    uint256(_b32(v, i, ".input.chainId")),
                    _addr(v, i, ".input.registry"),
                    _b32(v, i, ".input.resultId"),
                    _u64(v, i, ".input.id")
                )
            );
            assertEq(d, _b32(v, i, ".expect.exposureDigest"), v.names[i]);
            ++n;
        }
        assertGt(n, 0, "no digest.poaExposure vectors");
    }

    function test_digestRetirementV2Key() public view {
        Vectors memory v = _load();
        uint256 n;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "digest.retirementV2Key")) continue;
            uint8 holder = _u8(v, i, ".input.holder");
            assertLt(holder, MAX_HOLDERS, v.names[i]);
            bytes32 key = keccak256(
                abi.encode(
                    RETIREMENT_V2_DOMAIN,
                    holder,
                    _u64(v, i, ".input.id"),
                    _u64(v, i, ".input.generation")
                )
            );
            assertEq(key, _b32(v, i, ".expect.key"), v.names[i]);
            ++n;
        }
        assertGt(n, 0, "no digest.retirementV2Key vectors");
    }

    // ---------------------------------------------------------------------------------------------
    // change payloads
    // ---------------------------------------------------------------------------------------------

    /// Accepted payloads (expect.payload present) are re-encoded with abi.encode from the typed
    /// values and decoded back into the frozen types. Refused payloads are only listed here: the
    /// strict decoder that refuses them (canonical offsets, zero padding, no trailing words) is
    /// VRCodec, VT-02; Solidity's own abi.decode is laxer on offsets and padding.
    function test_changePayload() public view {
        Vectors memory v = _load();
        uint256 kinds;
        uint256 accepted;
        uint256 refused;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "change.payload")) continue;
            if (vm.keyExistsJson(v.json, _p(i, ".expect.payload"))) {
                kinds |= 1 << _checkChange(v, i);
                ++accepted;
            } else {
                assertFalse(vm.parseJsonBool(v.json, _p(i, ".expect.ok")), v.names[i]);
                assertGt(bytes(_str(v, i, ".expect.error")).length, 0, v.names[i]);
                _bytes(v, i, ".input.payload");
                ++refused;
            }
        }
        assertGt(accepted, 0, "no accepted change.payload vectors");
        assertGt(refused, 0, "no refused change.payload vectors");
        assertEq(kinds, ((1 << (CHANGE_KINDS + 1)) - 1) & ~uint256(1), "a change kind is missing");
    }

    // ---------------------------------------------------------------------------------------------
    // root records
    // ---------------------------------------------------------------------------------------------

    function test_recordWidth() public view {
        Vectors memory v = _load();
        uint256 kinds;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "record.width")) continue;
            uint8 kind = _u8(v, i, ".input.kind");
            string[] memory types = vm.parseJsonStringArray(v.json, _p(i, ".input.types"));
            assertEq(_join(types), _recordTypes(kind), v.names[i]);
            assertEq(_u(v, i, ".expect.width"), 32 * types.length, v.names[i]);
            assertEq(_u(v, i, ".expect.width"), _recordWidth(kind), v.names[i]);
            assertEq(kinds & (1 << kind), 0, "duplicate record.width kind");
            kinds |= 1 << kind;
        }
        assertEq(kinds, ((1 << (RECORD_KINDS + 1)) - 1) & ~uint256(1), "a record kind is missing");
    }

    /// Every record.decode vector gets a Solidity verdict: the kind's exact width, abi.decode into
    /// the frozen word types (which refuses dirty narrow words and bools), a re-encode that must
    /// give back the payload, and the kind 6 to 8 range rules of vrschema/records.go.
    function test_recordDecode() public view {
        Vectors memory v = _load();
        uint256 accepted;
        uint256 refused;
        uint256 newKinds;
        for (uint256 i; i < v.ops.length; ++i) {
            if (!_is(v.ops[i], "record.decode")) continue;
            uint8 kind = _u8(v, i, ".input.kind");
            bytes memory data = _bytes(v, i, ".input.data");
            bool ok = vm.parseJsonBool(v.json, _p(i, ".expect.ok"));
            bool verdict;
            try this.decodeRecord(kind, data) returns (bool b) {
                verdict = b;
            } catch {
                verdict = false;
            }
            assertEq(verdict, ok, v.names[i]);
            if (ok) {
                assertEq(_u(v, i, ".expect.width"), data.length, v.names[i]);
                if (kind >= 6) newKinds |= 1 << kind;
                ++accepted;
            } else {
                ++refused;
            }
        }
        assertGt(accepted, 0, "no accepted record.decode vectors");
        assertGt(refused, 0, "no refused record.decode vectors");
        assertEq(
            newKinds,
            (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9),
            "a kind 6 to 9 has no accepted vector"
        );
    }

    /// The Solidity verdict on one root-record payload (external so a strict abi.decode revert is a
    /// refusal).
    function decodeRecord(uint8 kind, bytes calldata data) external pure returns (bool) {
        if (kind == 0 || kind > RECORD_KINDS || data.length != _recordWidth(kind)) return false;
        bytes memory back;
        if (kind == 1) {
            bytes32 a = abi.decode(data, (bytes32));
            back = abi.encode(a);
        } else if (kind == 2) {
            (bytes32 a, uint64 b, uint64 c, uint64 d) =
                abi.decode(data, (bytes32, uint64, uint64, uint64));
            back = abi.encode(a, b, c, d);
        } else if (kind == 3) {
            (bytes32 a, bytes32 b, uint64 c, uint64 d, uint64 e) =
                abi.decode(data[:160], (bytes32, bytes32, uint64, uint64, uint64));
            (uint64 f, uint64 g, uint64 h, uint64 k) =
                abi.decode(data[160:], (uint64, uint64, uint64, uint64));
            back = bytes.concat(abi.encode(a, b, c, d, e), abi.encode(f, g, h, k));
        } else if (kind == 4) {
            (bytes32 a, uint64 b, bytes32 c, bytes32 d, bytes32 e, bytes32 f) =
                abi.decode(data, (bytes32, uint64, bytes32, bytes32, bytes32, bytes32));
            back = abi.encode(a, b, c, d, e, f);
        } else if (kind == 5) {
            (uint64 a, uint64 b, bytes32 c) = abi.decode(data, (uint64, uint64, bytes32));
            back = abi.encode(a, b, c);
        } else if (kind == 6) {
            (
                bytes32 resultId,
                uint64 changesEpoch,
                uint64 installedRootEpoch,
                uint64 installedShardEpoch,
                uint64 activationRound,
                bool recovered,
                uint16 rejectedBitmap
            ) = abi.decode(data, (bytes32, uint64, uint64, uint64, uint64, bool, uint16));
            back = abi.encode(
                resultId,
                changesEpoch,
                installedRootEpoch,
                installedShardEpoch,
                activationRound,
                recovered,
                rejectedBitmap
            );
            // A primary boundary installs J (= changesEpoch), a recovery K = J + 1.
            if (resultId == bytes32(0)) return false;
            if (uint256(installedRootEpoch) != uint256(changesEpoch) + (recovered ? 1 : 0)) {
                return false;
            }
        } else if (kind == 7) {
            (bytes32 resultId, uint8 reason, uint64 memberId, uint16 readyBitmap) =
                abi.decode(data, (bytes32, uint8, uint64, uint16));
            back = abi.encode(resultId, reason, memberId, readyBitmap);
            if (resultId == bytes32(0) || reason < REJ_EXPIRED || reason > REJ_INVALID) {
                return false;
            }
            if (memberId != 0 && reason != REJ_INVALID) return false;
            if (readyBitmap != 0 && reason != REJ_EXPIRED) return false;
        } else if (kind == 8) {
            (uint8 holder, uint64 id, uint64 generation, bytes32 refDigest) =
                abi.decode(data, (uint8, uint64, uint64, bytes32));
            back = abi.encode(holder, id, generation, refDigest);
            if (holder >= MAX_HOLDERS) return false;
        } else {
            (bytes32 resultId, uint64 deadline, uint16 missedBitmap) =
                abi.decode(data, (bytes32, uint64, uint16));
            back = abi.encode(resultId, deadline, missedBitmap);
            if (resultId == bytes32(0) || missedBitmap == 0) return false;
        }
        return keccak256(back) == keccak256(data);
    }

    // ---------------------------------------------------------------------------------------------
    // change payload helpers
    // ---------------------------------------------------------------------------------------------

    /// Checks one accepted change.payload vector and returns its kind.
    function _checkChange(Vectors memory v, uint256 i) internal pure returns (uint8 kind) {
        kind = _u8(v, i, ".input.kind");
        string memory name = v.names[i];
        assertEq(
            _join(vm.parseJsonStringArray(v.json, _p(i, ".input.types"))), _changeTypes(kind), name
        );
        assertEq(
            _join(vm.parseJsonStringArray(v.json, _p(i, ".input.fields"))),
            _changeFields(kind),
            name
        );
        bytes memory enc = _encodeChange(v, i, kind);
        bytes memory payload = _bytes(v, i, ".expect.payload");
        assertEq(enc, payload, name);
        assertEq(keccak256(enc), _b32(v, i, ".expect.payloadHash"), name);
        assertEq(enc.length, _u(v, i, ".expect.size"), name);
        assertLe(enc.length, MAX_CHANGE_PAYLOAD, name);
        assertEq(_roundTripChange(kind, payload), payload, name);
    }

    /// abi.encode of the kind's typed values (vrschema/changes.go ChangePayloadTypes).
    function _encodeChange(Vectors memory v, uint256 i, uint8 kind)
        internal
        pure
        returns (bytes memory)
    {
        if (kind == 1) return abi.encode(_vAddr(v, i, 0), _vB32(v, i, 1), _vBytes(v, i, 2));
        if (kind == 2) return abi.encode(_vAddr(v, i, 0), _vBytes(v, i, 1));
        if (kind == 3) return abi.encode(_vAddr(v, i, 0), _vB32(v, i, 1));
        if (kind == 4) return abi.encode(_vU32(v, i, 0), _vU32(v, i, 1), _vU32(v, i, 2));
        if (kind == 5) return abi.encode(_vU64(v, i, 0), _vU64(v, i, 1), _vAddr(v, i, 2));
        if (kind == 6) {
            return abi.encode(
                _vU32(v, i, 0), _vBytes(v, i, 1), _vB32(v, i, 2), _vBytes(v, i, 3), _vBytes(v, i, 4)
            );
        }
        if (kind == 7) return abi.encode(_vBytes(v, i, 0), _vBytes(v, i, 1));
        if (kind == 8) {
            return abi.encode(_vU32(v, i, 0), _vBytes(v, i, 1), _vB32(v, i, 2), _vBytes(v, i, 3));
        }
        if (kind == 9) {
            return abi.encode(
                _vB32(v, i, 0), _vB32(v, i, 1), _vU64(v, i, 2), _vU64(v, i, 3), _vStr(v, i, 4)
            );
        }
        if (kind == 10) return abi.encode(_vU64(v, i, 0));
        revert("unknown change kind");
    }

    /// abi.decode into the kind's frozen types and abi.encode back.
    function _roundTripChange(uint8 kind, bytes memory p) internal pure returns (bytes memory) {
        if (kind == 1) {
            (address a, bytes32 b, bytes memory c) = abi.decode(p, (address, bytes32, bytes));
            return abi.encode(a, b, c);
        }
        if (kind == 2) {
            (address a, bytes memory b) = abi.decode(p, (address, bytes));
            return abi.encode(a, b);
        }
        if (kind == 3) {
            (address a, bytes32 b) = abi.decode(p, (address, bytes32));
            return abi.encode(a, b);
        }
        if (kind == 4) {
            (uint32 a, uint32 b, uint32 c) = abi.decode(p, (uint32, uint32, uint32));
            return abi.encode(a, b, c);
        }
        if (kind == 5) {
            (uint64 a, uint64 b, address c) = abi.decode(p, (uint64, uint64, address));
            return abi.encode(a, b, c);
        }
        if (kind == 6) {
            (uint32 a, bytes memory b, bytes32 c, bytes memory d, bytes memory e) =
                abi.decode(p, (uint32, bytes, bytes32, bytes, bytes));
            return abi.encode(a, b, c, d, e);
        }
        if (kind == 7) {
            (bytes memory a, bytes memory b) = abi.decode(p, (bytes, bytes));
            return abi.encode(a, b);
        }
        if (kind == 8) {
            (uint32 a, bytes memory b, bytes32 c, bytes memory d) =
                abi.decode(p, (uint32, bytes, bytes32, bytes));
            return abi.encode(a, b, c, d);
        }
        if (kind == 9) {
            (bytes32 a, bytes32 b, uint64 c, uint64 d, string memory e) =
                abi.decode(p, (bytes32, bytes32, uint64, uint64, string));
            return abi.encode(a, b, c, d, e);
        }
        if (kind == 10) return abi.encode(abi.decode(p, (uint64)));
        revert("unknown change kind");
    }

    function _changeTypes(uint8 kind) internal pure returns (string memory) {
        if (kind == 1) return "address,bytes32,bytes";
        if (kind == 2) return "address,bytes";
        if (kind == 3) return "address,bytes32";
        if (kind == 4) return "uint32,uint32,uint32";
        if (kind == 5) return "uint64,uint64,address";
        if (kind == 6) return "uint32,bytes,bytes32,bytes,bytes";
        if (kind == 7) return "bytes,bytes";
        if (kind == 8) return "uint32,bytes,bytes32,bytes";
        if (kind == 9) return "bytes32,bytes32,uint64,uint64,string";
        if (kind == 10) return "uint64";
        revert("unknown change kind");
    }

    function _changeFields(uint8 kind) internal pure returns (string memory) {
        if (kind == 1) return "module,codeHash,initData";
        if (kind == 2) return "module,action";
        if (kind == 3) return "governor,codeHash";
        if (kind == 4) return "nMin,nTarget,nMax";
        if (kind == 5) return "baseFeeFloor,changeDenominator,feeCollector";
        if (kind == 6) return "partition,shard,expectedOldPdrHash,successorPdr,pops";
        if (kind == 7) return "pdr,pops";
        if (kind == 8) return "partition,shard,expectedOldPdrHash,successorPdr";
        if (kind == 9) return "ruleId,releaseDigest,rootEpoch,notBeforeUcTime,label";
        if (kind == 10) return "id";
        revert("unknown change kind");
    }

    // ---------------------------------------------------------------------------------------------
    // record helpers
    // ---------------------------------------------------------------------------------------------

    function _recordTypes(uint8 kind) internal pure returns (string memory) {
        if (kind == 1) return "bytes32";
        if (kind == 2) return "bytes32,uint64,uint64,uint64";
        if (kind == 3) return "bytes32,bytes32,uint64,uint64,uint64,uint64,uint64,uint64,uint64";
        if (kind == 4) return "bytes32,uint64,bytes32,bytes32,bytes32,bytes32";
        if (kind == 5) return "uint64,uint64,bytes32";
        if (kind == 6) return "bytes32,uint64,uint64,uint64,uint64,bool,uint16";
        if (kind == 7) return "bytes32,uint8,uint64,uint16";
        if (kind == 8) return "uint8,uint64,uint64,bytes32";
        if (kind == 9) return "bytes32,uint64,uint16";
        revert("unknown record kind");
    }

    function _recordWidth(uint8 kind) internal pure returns (uint256) {
        if (kind == 1) return 32;
        if (kind == 2) return 128;
        if (kind == 3) return 288;
        if (kind == 4) return 192;
        if (kind == 5) return 96;
        if (kind == 6) return 224;
        if (kind == 7) return 128;
        if (kind == 8) return 128;
        if (kind == 9) return 96;
        revert("unknown record kind");
    }

    // ---------------------------------------------------------------------------------------------
    // proofs of possession
    // ---------------------------------------------------------------------------------------------

    /// A 65-byte r || s || v signature over the digest itself: v in {27, 28}, low s, and ecrecover
    /// returns the address of the compressed key.
    function _checkPoP(bytes32 digest, bytes memory sig, bytes memory key, string memory name)
        internal
        view
    {
        assertEq(sig.length, 65, name);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        assertTrue(v == 27 || v == 28, name);
        assertGt(uint256(r), 0, name);
        assertGt(uint256(s), 0, name);
        assertLe(uint256(s), SECP256K1_N_HALF, name);
        address signer = ecrecover(digest, v, r, s);
        assertTrue(signer != address(0), name);
        assertEq(signer, _compressedKeyAddress(key), name);
    }

    /// The Ethereum address of a 33-byte compressed secp256k1 key: y = sqrt(x^3 + 7) by the modexp
    /// precompile (p = 3 mod 4), parity from the prefix, address = keccak256(x || y)[12:].
    function _compressedKeyAddress(bytes memory key) internal view returns (address) {
        assertEq(key.length, 33, "compressed key length");
        uint8 prefix = uint8(key[0]);
        assertTrue(prefix == 2 || prefix == 3, "compressed key prefix");
        uint256 x;
        assembly ("memory-safe") {
            x := mload(add(key, 33))
        }
        assertLt(x, SECP256K1_P, "x not in the field");
        uint256 y2 = addmod(mulmod(mulmod(x, x, SECP256K1_P), x, SECP256K1_P), 7, SECP256K1_P);
        (bool ok, bytes memory out) = address(5)
            .staticcall(
                abi.encode(
                    uint256(32), uint256(32), uint256(32), y2, (SECP256K1_P + 1) / 4, SECP256K1_P
                )
            );
        assertTrue(ok && out.length == 32, "modexp");
        uint256 y = abi.decode(out, (uint256));
        assertEq(mulmod(y, y, SECP256K1_P), y2, "key not on the curve");
        if (y & 1 != prefix & 1) y = SECP256K1_P - y;
        return address(uint160(uint256(keccak256(abi.encode(x, y)))));
    }

    // ---------------------------------------------------------------------------------------------
    // manifest
    // ---------------------------------------------------------------------------------------------

    /// The fixture's sha256 (computed here by the precompile) is its MANIFEST.sha256 line.
    function _checkPinned(string memory manifest, string memory file) internal view {
        string[] memory lines = vm.split(manifest, "\n");
        uint256 found;
        for (uint256 k; k < lines.length; ++k) {
            string[] memory parts = vm.split(lines[k], "  ");
            if (parts.length != 2 || !_is(parts[1], file)) continue;
            bytes32 want = vm.parseBytes32(string.concat("0x", parts[0]));
            assertEq(sha256(vm.readFileBinary(_fixture(file))), want, file);
            ++found;
        }
        assertEq(found, 1, string.concat("MANIFEST.sha256 does not list ", file, " once"));
    }

    // ---------------------------------------------------------------------------------------------
    // JSON helpers
    // ---------------------------------------------------------------------------------------------

    function _load() internal view returns (Vectors memory v) {
        v.json = vm.readFile(_fixture("encoding.json"));
        // A wildcard path matches one value per vector; parseJson returns them as an ABI array.
        v.ops = abi.decode(vm.parseJson(v.json, ".vectors[*].op"), (string[]));
        v.names = abi.decode(vm.parseJson(v.json, ".vectors[*].name"), (string[]));
    }

    function _fixture(string memory file) internal view returns (string memory) {
        return string.concat(vm.projectRoot(), FIXTURES, file);
    }

    function _p(uint256 i, string memory rel) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(i), "]", rel);
    }

    function _idx(string memory path, uint256 k) internal pure returns (string memory) {
        return string.concat(path, "[", vm.toString(k), "]");
    }

    function _is(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _join(string[] memory parts) internal pure returns (string memory out) {
        for (uint256 k; k < parts.length; ++k) {
            out = k == 0 ? parts[k] : string.concat(out, ",", parts[k]);
        }
    }

    function _u(Vectors memory v, uint256 i, string memory rel) internal pure returns (uint256) {
        return vm.parseJsonUint(v.json, _p(i, rel));
    }

    function _u64(Vectors memory v, uint256 i, string memory rel) internal pure returns (uint64) {
        uint256 x = _u(v, i, rel);
        assertLe(x, type(uint64).max, rel);
        return uint64(x);
    }

    function _u8(Vectors memory v, uint256 i, string memory rel) internal pure returns (uint8) {
        uint256 x = _u(v, i, rel);
        assertLe(x, type(uint8).max, rel);
        return uint8(x);
    }

    function _b32(Vectors memory v, uint256 i, string memory rel) internal pure returns (bytes32) {
        return vm.parseJsonBytes32(v.json, _p(i, rel));
    }

    function _addr(Vectors memory v, uint256 i, string memory rel) internal pure returns (address) {
        return vm.parseJsonAddress(v.json, _p(i, rel));
    }

    function _bytes(Vectors memory v, uint256 i, string memory rel)
        internal
        pure
        returns (bytes memory)
    {
        return vm.parseJsonBytes(v.json, _p(i, rel));
    }

    function _str(Vectors memory v, uint256 i, string memory rel)
        internal
        pure
        returns (string memory)
    {
        return vm.parseJsonString(v.json, _p(i, rel));
    }

    // input.values[k] of a change.payload vector, by the field's type
    function _val(uint256 k) internal pure returns (string memory) {
        return _idx(".input.values", k);
    }

    function _vAddr(Vectors memory v, uint256 i, uint256 k) internal pure returns (address) {
        return _addr(v, i, _val(k));
    }

    function _vB32(Vectors memory v, uint256 i, uint256 k) internal pure returns (bytes32) {
        return _b32(v, i, _val(k));
    }

    function _vBytes(Vectors memory v, uint256 i, uint256 k) internal pure returns (bytes memory) {
        return _bytes(v, i, _val(k));
    }

    function _vStr(Vectors memory v, uint256 i, uint256 k) internal pure returns (string memory) {
        return _str(v, i, _val(k));
    }

    function _vU64(Vectors memory v, uint256 i, uint256 k) internal pure returns (uint64) {
        return _u64(v, i, _val(k));
    }

    function _vU32(Vectors memory v, uint256 i, uint256 k) internal pure returns (uint32) {
        uint256 x = _u(v, i, _val(k));
        assertLe(x, type(uint32).max, _val(k));
        return uint32(x);
    }
}
