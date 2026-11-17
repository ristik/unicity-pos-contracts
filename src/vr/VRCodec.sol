// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// The decoders return (error code, decoded values) tuples with explicit default values on refusal; `(l + 31) / 32 * 32` rounds a
// length up to whole words on purpose.
// forge-lint: disable-start(boolean-cst, calls-loop, divide-before-multiply, unsafe-typecast)

import {VRC} from "./VRConstants.sol";
import {Member} from "./VRTypes.sol";

/// @title VRCodec
/// @notice The strict, bounded codec of the ValidatorRegistry module interface (schema v1 sections 4 and 5; bft-core vrschema/packed.go
/// and digests.go). Solidity's `abi.decode` is too lenient for consensus input (it accepts any offset, trailing bytes, dirty padding
/// in some positions and reverts instead of classifying), so every module return is decoded here from the raw returndata, returning a
/// frozen error code instead of reverting. The decoders refuse, in this order: Oversize (size above the step's cap), Envelope (fewer
/// than 64 bytes, not whole words, offset != 32 or length != size - 64), Length (not the exact content length), then non-canonical
/// content (Narrow, Bool, Range, Order, Count, ResultIdZeroness, Padding).
///
/// The encoders are the exact inverse. Modules use `pack*` to build their returns and `decodeContext`/`decodeAttachContext` to read
/// VR's arguments; VR uses the decoders and `encodeContext`/`encodeAttachContext`.
library VRCodec {
    // Frozen decoder verdicts (vrschema CodecError).
    uint8 internal constant OK = 0;
    uint8 internal constant OVERSIZE = 1;
    uint8 internal constant ENVELOPE = 2;
    uint8 internal constant LENGTH = 3;
    uint8 internal constant NARROW = 4;
    uint8 internal constant BOOL = 5;
    uint8 internal constant RANGE = 6;
    uint8 internal constant ORDER = 7;
    uint8 internal constant COUNT = 8;
    uint8 internal constant ZERO = 9; // ResultIdZeroness
    uint8 internal constant PADDING = 10;

    uint256 internal constant MEMBER_WORDS = 10;
    uint256 internal constant HEADER_WORDS = 12; // AttachContext header

    struct OutputHeader {
        bytes32 resultId;
        bytes32 predecessor;
        uint64 attempt;
        bytes32 snapshotDigest;
        bytes32 policyDigest;
    }

    struct Context {
        bytes32 origin;
        uint64 progress;
        uint64 ucTime;
        uint64 knownRootEpoch;
        bytes32 lastAcked;
        uint32 nMin;
        uint32 nTarget;
        uint32 nMax;
        uint32 dueWork;
        uint16 forceRemoved; // bit i: committee()[i] (ascending id) has a Scheduled ForceRemove
    }

    struct AttachContext {
        bytes32 lastAcked;
        uint64 knownRootEpoch;
        uint64 progress;
        uint64 ucTime;
        uint64 identityCount;
        address namespace; // liabilityNamespace = VR
        address previousModule;
        bytes32 previousTag;
        uint8 holderIndex; // NO_HOLDER (0xff) when the module is not a liability holder
        Member[] committee;
        bytes initData;
    }

    // ------------------------------------------------------------------------------------------
    // words
    // ------------------------------------------------------------------------------------------

    /// @dev Word `i` of `b` (the caller guarantees 32 * (i + 1) <= b.length).
    function wordAt(bytes memory b, uint256 i) internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), shl(5, i)))
        }
    }

    function _envelope(bytes memory ret, uint256 cap) private pure returns (uint8, uint256) {
        uint256 n = ret.length;
        if (n > cap) return (OVERSIZE, 0);
        if (n < 64 || n % 32 != 0) return (ENVELOPE, 0);
        if (wordAt(ret, 0) != 32 || wordAt(ret, 1) != n - 64) return (ENVELOPE, 0);
        return (OK, n - 64);
    }

    // ------------------------------------------------------------------------------------------
    // module returns (VR side)
    // ------------------------------------------------------------------------------------------

    /// @notice `elect`: exactly 64 + 96 bytes; outcome 0..3; ready a canonical bool set only with Reserved; resultId nonzero iff Reserved.
    function decodeElect(bytes memory ret)
        internal
        pure
        returns (uint8 err, uint8 outcome, bool ready, bytes32 resultId)
    {
        uint256 c;
        (err, c) = _envelope(ret, VRC.MAX_RET_ELECT);
        if (err != OK) return (err, 0, false, 0);
        if (c != 96) return (LENGTH, 0, false, 0);
        uint256 o = wordAt(ret, 2);
        if (o > type(uint8).max) return (NARROW, 0, false, 0);
        if (o > VRC.ELECT_NO_CANDIDATE) return (RANGE, 0, false, 0);
        uint256 r = wordAt(ret, 3);
        if (r > 1) return (BOOL, 0, false, 0);
        resultId = bytes32(wordAt(ret, 4));
        bool reserved = o == VRC.ELECT_RESERVED;
        if (reserved != (resultId != 0)) return (ZERO, 0, false, 0);
        if (r == 1 && !reserved) return (RANGE, 0, false, 0);
        // forge-lint: disable-next-line(unsafe-typecast)
        return (OK, uint8(o), r == 1, resultId);
    }

    /// @notice `outputOf`: Ready is exactly 64 + 32 + 192 + 320n with 1 <= n <= 16 equal to the header's count and strictly ascending
    /// ids; Pending and NotMine are exactly 64 + 32. The header and members are returned only for Ready.
    function decodeOutput(bytes memory ret)
        internal
        pure
        returns (uint8 err, uint8 status, OutputHeader memory h, Member[] memory ms)
    {
        uint256 c;
        (err, c) = _envelope(ret, VRC.MAX_RET_READY);
        if (err != OK) return (err, 0, h, ms);
        if (c < 32) return (LENGTH, 0, h, ms);
        uint256 s = wordAt(ret, 2);
        if (s > type(uint8).max) return (NARROW, 0, h, ms);
        if (s > VRC.STATUS_NOT_MINE) return (RANGE, 0, h, ms);
        if (s != VRC.STATUS_READY) {
            if (ret.length > VRC.MAX_RET_PENDING || c != 32) return (LENGTH, 0, h, ms);
            // forge-lint: disable-next-line(unsafe-typecast)
            return (OK, uint8(s), h, ms);
        }
        if (c < 224 || (c - 224) % 320 != 0) return (LENGTH, 0, h, ms);
        uint256 n = wordAt(ret, 8);
        if (n > type(uint64).max) return (NARROW, 0, h, ms);
        if (n < 1 || n > VRC.MAX_COMMITTEE || n != (c - 224) / 320) return (COUNT, 0, h, ms);
        uint256 attempt = wordAt(ret, 5);
        if (attempt > type(uint64).max) return (NARROW, 0, h, ms);
        h.resultId = bytes32(wordAt(ret, 3));
        h.predecessor = bytes32(wordAt(ret, 4));
        // forge-lint: disable-next-line(unsafe-typecast)
        h.attempt = uint64(attempt);
        h.snapshotDigest = bytes32(wordAt(ret, 6));
        h.policyDigest = bytes32(wordAt(ret, 7));
        ms = new Member[](n);
        for (uint256 i = 0; i < n; ++i) {
            (uint8 e, Member memory m) = decodeMemberAt(ret, 9 + MEMBER_WORDS * i);
            if (e != OK) return (e, 0, h, new Member[](0));
            if (i > 0 && ms[i - 1].id >= m.id) return (ORDER, 0, h, new Member[](0));
            ms[i] = m;
        }
        return (OK, VRC.STATUS_READY, h, ms);
    }

    /// @notice `adoptionReady`: exactly 64 + 32, status Ready or NotReady.
    function decodeAdoption(bytes memory ret) internal pure returns (uint8 err, uint8 status) {
        uint256 c;
        (err, c) = _envelope(ret, VRC.MAX_RET_ADOPTION);
        if (err != OK) return (err, 0);
        if (c != 32) return (LENGTH, 0);
        uint256 s = wordAt(ret, 2);
        if (s > type(uint8).max) return (NARROW, 0);
        if (s != VRC.STATUS_READY && s != VRC.STATUS_NOT_READY) return (RANGE, 0);
        // forge-lint: disable-next-line(unsafe-typecast)
        return (OK, uint8(s));
    }

    /// @notice A void step returns exactly nothing.
    function decodeVoid(uint256 returnSize) internal pure returns (uint8) {
        return returnSize == 0 ? OK : OVERSIZE;
    }

    /// @notice A metadata getter returns exactly `k` static words (at most 32 x 8 bytes); `bits[i]` is word i's width (256: any word,
    /// 160: an address).
    function decodeMetadata(bytes memory ret, uint256 k, uint16[8] memory bits)
        internal
        pure
        returns (uint8 err, uint256[8] memory out)
    {
        if (ret.length > VRC.MAX_RET_METADATA) return (OVERSIZE, out);
        if (ret.length != 32 * k) return (LENGTH, out);
        for (uint256 i = 0; i < k; ++i) {
            uint256 w = wordAt(ret, i);
            if (bits[i] < 256 && w >> bits[i] != 0) return (NARROW, out);
            out[i] = w;
        }
        return (OK, out);
    }

    /// @notice One member of ten words starting at word `at` of `b`: four uint64 words, four free words, an address, a free word.
    function decodeMemberAt(bytes memory b, uint256 from)
        internal
        pure
        returns (uint8 err, Member memory m)
    {
        uint256 id = wordAt(b, from);
        uint256 generation = wordAt(b, from + 1);
        uint256 weight = wordAt(b, from + 2);
        uint256 raw = wordAt(b, from + 3);
        if ((id | generation | weight | raw) > type(uint64).max) return (NARROW, m);
        uint256 payee = wordAt(b, from + 8);
        if (payee > type(uint160).max) return (NARROW, m);
        // forge-lint: disable-start(unsafe-typecast)
        m.id = uint64(id);
        m.generation = uint64(generation);
        m.weight = uint64(weight);
        m.rawWeight = uint64(raw);
        m.payee = address(uint160(payee));
        // forge-lint: disable-end(unsafe-typecast)
        m.rootNodeWord = bytes32(wordAt(b, from + 4));
        m.rootKeyHash = bytes32(wordAt(b, from + 5));
        m.evmNodeWord = bytes32(wordAt(b, from + 6));
        m.evmKeyHash = bytes32(wordAt(b, from + 7));
        m.exposureDigest = bytes32(wordAt(b, from + 9));
        return (OK, m);
    }

    // ------------------------------------------------------------------------------------------
    // module returns (module side)
    // ------------------------------------------------------------------------------------------

    /// @notice The content of `elect`'s return; a function returning it as `bytes` produces the exact envelope.
    function packElect(uint8 outcome, bool ready, bytes32 resultId)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(uint256(outcome), ready, resultId);
    }

    function packStatus(uint8 status) internal pure returns (bytes memory) {
        return abi.encode(uint256(status));
    }

    function packOutput(OutputHeader memory h, Member[] memory ms)
        internal
        pure
        returns (bytes memory out)
    {
        out = abi.encode(
            uint256(VRC.STATUS_READY),
            h.resultId,
            h.predecessor,
            uint256(h.attempt),
            h.snapshotDigest,
            h.policyDigest,
            ms.length
        );
        for (uint256 i = 0; i < ms.length; ++i) {
            out = bytes.concat(out, memberWords(ms[i]));
        }
    }

    // ------------------------------------------------------------------------------------------
    // arguments
    // ------------------------------------------------------------------------------------------

    function limitsWord(uint32 nMin, uint32 nTarget, uint32 nMax) internal pure returns (uint256) {
        return (uint256(nMin) << 64) | (uint256(nTarget) << 32) | uint256(nMax);
    }

    /// @notice The 256-byte `elect` argument (schema section 5.6).
    function encodeContext(Context memory c) internal pure returns (bytes memory) {
        return abi.encode(
            c.origin,
            uint256(c.progress),
            uint256(c.ucTime),
            uint256(c.knownRootEpoch),
            c.lastAcked,
            limitsWord(c.nMin, c.nTarget, c.nMax),
            uint256(c.dueWork),
            uint256(c.forceRemoved)
        );
    }

    /// @notice The module-side strict decoder of the `elect` argument.
    function decodeContext(bytes memory b) internal pure returns (uint8 err, Context memory c) {
        if (b.length != 256) return (LENGTH, c);
        uint256 p = wordAt(b, 1);
        uint256 t = wordAt(b, 2);
        uint256 e = wordAt(b, 3);
        if ((p | t | e) > type(uint64).max) return (NARROW, c);
        uint256 lw = wordAt(b, 5);
        if (lw >> 96 != 0) return (NARROW, c);
        uint256 d = wordAt(b, 6);
        if (d > type(uint32).max) return (NARROW, c);
        uint256 f = wordAt(b, 7);
        if (f > type(uint16).max) return (NARROW, c);
        // forge-lint: disable-start(unsafe-typecast)
        c.origin = bytes32(wordAt(b, 0));
        c.progress = uint64(p);
        c.ucTime = uint64(t);
        c.knownRootEpoch = uint64(e);
        c.lastAcked = bytes32(wordAt(b, 4));
        c.nMin = uint32(lw >> 64);
        c.nTarget = uint32(lw >> 32);
        c.nMax = uint32(lw);
        c.dueWork = uint32(d);
        c.forceRemoved = uint16(f);
        // forge-lint: disable-end(unsafe-typecast)
        return (OK, c);
    }

    /// @notice The `attach`/`adoptionReady` argument (schema section 5.7): 12 header words, n x 10 member words, initData padded.
    function encodeAttachContext(AttachContext memory a) internal pure returns (bytes memory out) {
        out = abi.encode(
            VRC.ATTACH_CONTEXT_VERSION,
            a.lastAcked,
            uint256(a.knownRootEpoch),
            uint256(a.progress),
            uint256(a.ucTime),
            uint256(a.identityCount),
            a.namespace,
            a.previousModule,
            a.previousTag,
            uint256(a.holderIndex),
            a.committee.length,
            a.initData.length
        );
        for (uint256 i = 0; i < a.committee.length; ++i) {
            out = bytes.concat(out, memberWords(a.committee[i]));
        }
        uint256 pad = (32 - (a.initData.length % 32)) % 32;
        out = bytes.concat(out, a.initData, new bytes(pad));
    }

    /// @notice The module-side strict decoder of the attach context.
    function decodeAttachContext(bytes memory b)
        internal
        pure
        returns (uint8 err, AttachContext memory a)
    {
        if (b.length < HEADER_WORDS * 32 || b.length % 32 != 0) return (LENGTH, a);
        if (wordAt(b, 0) != VRC.ATTACH_CONTEXT_VERSION) return (RANGE, a);
        uint256 e = wordAt(b, 2);
        uint256 p = wordAt(b, 3);
        uint256 t = wordAt(b, 4);
        uint256 ic = wordAt(b, 5);
        if ((e | p | t | ic) > type(uint64).max) return (NARROW, a);
        uint256 ns = wordAt(b, 6);
        uint256 prev = wordAt(b, 7);
        if ((ns | prev) > type(uint160).max) return (NARROW, a);
        uint256 h = wordAt(b, 9);
        if (h > type(uint8).max) return (NARROW, a);
        if (h >= VRC.MAX_HOLDERS && h != VRC.NO_HOLDER) return (RANGE, a);
        uint256 n = wordAt(b, 10);
        if (n < 1 || n > VRC.MAX_COMMITTEE) return (COUNT, a);
        uint256 l = wordAt(b, 11);
        if (l > VRC.MAX_CHANGE_PAYLOAD) return (OVERSIZE, a);
        uint256 start = HEADER_WORDS * 32 + n * MEMBER_WORDS * 32;
        if (b.length != start + (l + 31) / 32 * 32) return (LENGTH, a);
        a.committee = new Member[](n);
        for (uint256 i = 0; i < n; ++i) {
            (uint8 me, Member memory m) = decodeMemberAt(b, HEADER_WORDS + MEMBER_WORDS * i);
            if (me != OK) return (me, a);
            if (i > 0 && a.committee[i - 1].id >= m.id) return (ORDER, a);
            a.committee[i] = m;
        }
        bytes memory init = new bytes(l);
        assembly ("memory-safe") {
            mcopy(add(init, 0x20), add(add(b, 0x20), start), l)
        }
        a.initData = init;
        for (uint256 i = start + l; i < b.length; ++i) {
            if (b[i] != 0) return (PADDING, a);
        }
        // forge-lint: disable-start(unsafe-typecast)
        a.lastAcked = bytes32(wordAt(b, 1));
        a.knownRootEpoch = uint64(e);
        a.progress = uint64(p);
        a.ucTime = uint64(t);
        a.identityCount = uint64(ic);
        a.namespace = address(uint160(ns));
        a.previousModule = address(uint160(prev));
        a.previousTag = bytes32(wordAt(b, 8));
        a.holderIndex = uint8(h);
        // forge-lint: disable-end(unsafe-typecast)
        return (OK, a);
    }

    // ------------------------------------------------------------------------------------------
    // root records (schema section 7)
    // ------------------------------------------------------------------------------------------

    /// @notice Width and canonical words of a record (vrschema CheckRecordPayload plus the cross-field rules of kinds 6 to 8).
    function recordWellFormed(uint8 kind, bytes memory d) internal pure returns (bool) {
        uint256 words;
        if (kind == VRC.REC_SESSION_CLOSED) words = 1;
        else if (kind == VRC.REC_ACK || kind == VRC.REC_OUTPUT_REJECTED) words = 4;
        else if (kind == VRC.REC_RECOVERY_ACK) words = 9;
        else if (kind == VRC.REC_CLOSURE) words = 6;
        else if (kind == VRC.REC_RETIREMENT) words = 3;
        else if (kind == VRC.REC_BOUNDARY) words = 7;
        else if (kind == VRC.REC_HOLDER_RETIREMENT) words = 4;
        else return false;
        if (d.length != 32 * words) return false;
        uint64 max = type(uint64).max;
        if (kind == VRC.REC_ACK) {
            return (wordAt(d, 1) | wordAt(d, 2) | wordAt(d, 3)) <= max;
        }
        if (kind == VRC.REC_RECOVERY_ACK) {
            for (uint256 i = 2; i < 9; ++i) {
                if (wordAt(d, i) > max) return false;
            }
            return true;
        }
        if (kind == VRC.REC_CLOSURE) return wordAt(d, 1) <= max;
        if (kind == VRC.REC_RETIREMENT) return (wordAt(d, 0) | wordAt(d, 1)) <= max;
        if (kind == VRC.REC_BOUNDARY) {
            if ((wordAt(d, 1) | wordAt(d, 2) | wordAt(d, 3) | wordAt(d, 4)) > max) return false;
            if (wordAt(d, 5) > 1 || wordAt(d, 6) > type(uint16).max || wordAt(d, 0) == 0) {
                return false;
            }
            uint256 expect = wordAt(d, 1) + wordAt(d, 5);
            return wordAt(d, 2) == expect;
        }
        if (kind == VRC.REC_OUTPUT_REJECTED) {
            uint256 reason = wordAt(d, 1);
            if (reason > type(uint8).max || wordAt(d, 2) > max || wordAt(d, 3) > type(uint16).max) {
                return false;
            }
            if (wordAt(d, 0) == 0) return false; // zero result id (vrschema DecodeOutputRejected)
            if (reason < VRC.REJ_EXPIRED || reason > VRC.REJ_INVALID) return false;
            if (wordAt(d, 2) != 0 && reason != VRC.REJ_INVALID) return false;
            if (wordAt(d, 3) != 0 && reason != VRC.REJ_EXPIRED) return false;
            return true;
        }
        if (kind == VRC.REC_HOLDER_RETIREMENT) {
            return wordAt(d, 0) < VRC.MAX_HOLDERS && (wordAt(d, 1) | wordAt(d, 2)) <= max;
        }
        return true;
    }

    // ------------------------------------------------------------------------------------------
    // digests (schema section 4)
    // ------------------------------------------------------------------------------------------

    function memberWords(Member memory m) internal pure returns (bytes memory) {
        return abi.encode(
            uint256(m.id),
            uint256(m.generation),
            uint256(m.weight),
            uint256(m.rawWeight),
            m.rootNodeWord,
            m.rootKeyHash,
            m.evmNodeWord,
            m.evmKeyHash,
            m.payee,
            m.exposureDigest
        );
    }

    function memberHash(Member memory m) internal pure returns (bytes32) {
        return keccak256(memberWords(m));
    }

    /// @notice keccak256(MEMBERS_DOMAIN, n, h_1 .. h_n) over members strictly ascending by id (the caller guarantees the order).
    function membersDigest(Member[] memory ms) internal pure returns (bytes32) {
        bytes32[] memory hs = new bytes32[](ms.length);
        for (uint256 i = 0; i < ms.length; ++i) {
            hs[i] = memberHash(ms[i]);
        }
        return keccak256(abi.encodePacked(VRC.MEMBERS_DOMAIN, ms.length, hs));
    }

    /// @notice keccak256(CHANGES_DOMAIN, n_c, (id, kind, payloadHash) ...) over changes strictly ascending by id.
    function changesDigest(uint64[] memory ids, uint8[] memory kinds, bytes32[] memory hashes)
        internal
        pure
        returns (bytes32)
    {
        bytes memory b = abi.encode(VRC.CHANGES_DOMAIN, ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            b = bytes.concat(b, abi.encode(uint256(ids[i]), uint256(kinds[i]), hashes[i]));
        }
        return keccak256(b);
    }

    struct CommitInput {
        bytes32 network;
        address registry;
        bytes32 resultId;
        bytes32 predecessor;
        uint64 attempt;
        bytes32 moduleTag;
        bool native;
        bytes32 snapshotDigest;
        bytes32 policyDigest;
        bytes32 membersDigest;
        bytes32 kDigest;
        bytes32 changesDigest;
    }

    function outputCommit(CommitInput memory c) internal view returns (bytes32) {
        return keccak256(
            bytes.concat(
                abi.encode(
                    VRC.OUTPUT_DOMAIN,
                    c.network,
                    block.chainid,
                    c.registry,
                    c.resultId,
                    c.predecessor,
                    uint256(c.attempt)
                ),
                abi.encode(
                    c.moduleTag,
                    c.native,
                    c.snapshotDigest,
                    c.policyDigest,
                    c.membersDigest,
                    c.kDigest,
                    c.changesDigest
                )
            )
        );
    }

    function nativeResultId(
        bytes32 network,
        address registry,
        bytes32 lastAcked,
        uint64 attempt,
        bytes32 origin
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                VRC.NATIVE_RESULT_DOMAIN,
                network,
                block.chainid,
                registry,
                lastAcked,
                uint256(attempt),
                origin
            )
        );
    }

    /// @notice The per-exposure digest in the VR deployment domain (schema section 4.7, FD-6): the custody `ExposureID` formula with
    /// deployment (network, chain id, VR address) and the output's result id.
    function exposureDigest(bytes32 network, address registry, bytes32 resultId, uint64 id)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(VRC.EXPOSURE_DOMAIN, network, block.chainid, registry, resultId, uint256(id))
        );
    }
}
