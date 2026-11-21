// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// Wire widths bound every cast. Fixed byte casts select a decoded prefix.
// forge-lint: disable-start(unsafe-typecast)

import {NB2Config} from "./NB2Config.sol";
import {NB2Gap} from "./NB2Gap.sol";
import {NB2VaultBase} from "./NB2VaultBase.sol";
import {FlatBindings} from "./verifier/flat/FlatBindings.sol";
import {FlatNative} from "./verifier/flat/FlatNative.sol";
import {FlatPacket} from "./verifier/flat/FlatPacket.sol";
import {FlatReceipts} from "./verifier/flat/FlatReceipts.sol";
import {INativeBridgeRecovery11} from "./verifier/flat/NativeBridgeRecovery11.sol";
import {FlatClaim, BadPacket, BadPredecessor, BadStep} from "./verifier/flat/FlatTypes.sol";

/// @dev The recovery verifier's public bindings read by the vault constructor.
interface IRecoveryBindings {
    function DOMAIN() external view returns (bytes32);
    function VAULT() external view returns (address);
    function ORDINARY() external view returns (address);
    function ORDINARY_HASH() external view returns (bytes32);
    function RECEIPTS() external view returns (address);
    function RECEIPTS_HASH() external view returns (bytes32);
    function PINS() external view returns (bytes32);
    function GENERATION() external view returns (bytes32);
}

/// @notice The cold settlement route of NB2 v1.1 (bft-core docs/design/nb2-continuation-v1.1.md section 6): `redeemRecovered(bytes)`
///         pays a certified `NB2Complete11` or `NB2Gap11` verdict through the very routine ordinary `redeem` ends in
///         (`NB2VaultBase._finish`), under the same guard, signed start, recent buffers, liability and seal. A session adds no
///         persistent state: the receipt is checked against the pinned recovery verifier and its pinned receipt helper, and the
///         gap prefix it proves must fold to a head that is currently stored.
///
///         The selector is served by the fallback, as the recovery verifier serves its entry points, so that the canonical-ABI
///         rule of section 3 (offset 32, exact length, zero padding, no trailing bytes) is `BadPacket()` and so that the ordinary
///         route's dispatch is byte-for-byte the ordinary-only vault's.
abstract contract NB2VaultRecovered is NB2VaultBase {
    uint256 private constant MAX_RECEIPT = 65536;
    uint256 private constant MAX_GAPS = 1024;
    uint256 private constant SEGMENT_LIMIT = 1 << 48;
    bytes4 internal constant REDEEM_RECOVERED = bytes4(keccak256("redeemRecovered(bytes)"));

    address public immutable RECOVERY;
    FlatReceipts public immutable RECEIPTS;
    bytes32 public immutable RECOVERY_RUNTIME;
    bytes32 public immutable RECOVERY_GENERATION;
    bytes32 public immutable RECOVERY_PINS;
    uint16 private immutable _NETWORK;
    uint32 private immutable _EVM_PARTITION;
    bytes32 private immutable _SHARD_PREFIX;
    bytes1 private immutable _SHARD_TAIL;
    uint256 private immutable _SHARD_LEN;

    constructor(
        bytes memory gamma,
        uint256 kSet,
        uint256 bSet,
        address recovery,
        bytes32 recoveryRuntime,
        bytes32 expectedProfile
    ) NB2VaultBase(gamma, kSet, bSet, 2) {
        NB2Config.Config memory c = NB2Config.decode(gamma, kSet, bSet, 2);
        if (
            c.profile != expectedProfile || expectedProfile == 0 || recovery == address(0)
                || recoveryRuntime == 0
        ) {
            revert NB2Config.BadConfig(13);
        }
        (bytes32 generation, bytes32 pins, address receipts) =
            _bindRecovery(recovery, recoveryRuntime, c);
        RECOVERY = recovery;
        RECEIPTS = FlatReceipts(receipts);
        RECOVERY_RUNTIME = recoveryRuntime;
        RECOVERY_GENERATION = generation;
        RECOVERY_PINS = pins;
        _NETWORK = uint16(c.network);
        _EVM_PARTITION = uint32(c.evmPartition);
        bytes memory shard = c.evmShard;
        bytes32 prefix;
        assembly ("memory-safe") {
            prefix := mload(add(shard, 32))
        }
        _SHARD_PREFIX = prefix;
        _SHARD_TAIL = shard.length == 33 ? shard[32] : bytes1(0);
        _SHARD_LEN = shard.length;
    }

    /// @dev Pins the recovery verifier and its receipt helper at construction and returns its generation and dependency pins.
    ///      The production implementation requires the recovery verifier's exact runtime hash, that it is bound to this vault,
    ///      this Γ domain, this ordinary verifier and this receipt helper.
    function _bindRecovery(address recovery, bytes32 runtimeHash, NB2Config.Config memory c)
        internal
        view
        virtual
        returns (bytes32 generation, bytes32 pins, address receipts)
    {
        IRecoveryBindings r = IRecoveryBindings(recovery);
        receipts = r.RECEIPTS();
        if (
            recovery.codehash != runtimeHash || r.VAULT() != address(this) || r.DOMAIN() != D
                || r.ORDINARY() != c.verifier || r.ORDINARY_HASH() != c.verifierCodeHash
                || receipts.codehash != r.RECEIPTS_HASH() || receipts.code.length == 0
        ) revert NB2Config.BadConfig(14);
        generation = r.GENERATION();
        pins = r.PINS();
        if (generation == 0 || pins == 0) revert NB2Config.BadConfig(14);
    }

    /// @dev The pinned recovery verifier still has the pinned runtime. Test adapters whose fixture runtime hash is a
    ///      placeholder override this and nothing else of the check.
    function _recoveryIntact() internal view virtual returns (bool) {
        return RECOVERY.codehash == RECOVERY_RUNTIME;
    }

    fallback() external {
        if (msg.sig != REDEEM_RECOVERED) revert BadPacket();
        _redeemRecovered(FlatPacket.argument(msg.data));
    }

    /// @dev Section 6 stages for redeemRecovered, in order: guard (the caller's `Reentrancy()` precedes framing), framing,
    ///      receipt authentication, future index, endpoint range and staleness, gap fold and the stored-head comparison,
    ///      the buffer scans and the shared settlement.
    function _redeemRecovered(bytes calldata b) private {
        // Entry. The guard is taken before any argument is read.
        _enter();
        (
            uint8 kind,
            uint256 receiptPos,
            uint256 receiptEnd,
            uint256 count,
            bytes32 startHead,
            uint256 gapsPos
        ) = _frame(b);
        bytes32 session = _session(b);
        Verdict memory v = _authenticate(b[receiptPos:receiptEnd], kind, session, startHead);

        uint256 acc = _loadA();
        uint256 c = (acc >> C_SHIFT) & C_MAX;
        // Section 6: a > c is FutureIndex whatever the receipt kind.
        if (v.minSegment > c) revert FutureIndex(uint64(v.minSegment), uint64(c));
        uint256 end = v.start + count;
        if (end >= SEGMENT_LIMIT) revert BadStep();
        if (end != c && (c == 0 || end != c - 1)) revert StaleEndpoint(uint64(end), uint64(c));
        // Fold the suffix. A Gap receipt always compares, even with no suffix. Only a fresh Complete with no suffix
        // (a == e) is headless.
        if (count != 0 || kind == 2) {
            bytes32 x = _foldFrom(v.eta, v.start, count, v.head, b, gapsPos);
            bytes32 stored;
            assembly ("memory-safe") {
                stored := sload(add(SLOT_HEAD, and(end, 1)))
            }
            if (x != stored) revert ChainMismatch();
        }
        uint256 m = (acc >> M_SHIFT) & 0xff;
        uint256 p = c & 1;
        uint256 eta = uint256(v.eta);
        uint256 bucket = eta >> (256 - LOGB);
        _scan(p, m, bucket, eta);
        if (end != c) _scan(p ^ 1, K, bucket, eta);
        address recipient = _checkVerdict(
            v.domain, v.asset, false, uint256(uint160(v.recipient)), v.amount, acc & Q_MASK
        );
        _finish(acc, c, m, p, bucket, eta, recipient, v.amount);
    }

    struct Verdict {
        bytes32 domain;
        bytes32 eta;
        uint256 minSegment;
        bytes32 asset;
        address recipient;
        uint256 amount;
        uint256 start;
        bytes32 head;
    }

    /// @dev Cold packet: `w || u64(N) || Rpage || u8(kind) || blob(receipt) || u16(gapCount) || [startHead] || gaps`. The start
    ///      head is present only for a Complete receipt with at least one gap. Every length is bounded before it is used.
    function _frame(bytes calldata b)
        private
        view
        returns (
            uint8 kind,
            uint256 receiptPos,
            uint256 receiptEnd,
            uint256 count,
            bytes32 startHead,
            uint256 gapsPos
        )
    {
        if (b.length < 43 + 4 || uint16(bytes2(b[0:2])) != 0x0101 || uint64(bytes8(b[2:10])) < 14) revert BadPacket();
        kind = uint8(b[42]);
        if (kind != 1 && kind != 2) revert BadPacket();
        uint256 len = uint32(bytes4(b[43:47]));
        if (len > MAX_RECEIPT || b.length - 47 < len) revert BadPacket();
        receiptPos = 47;
        receiptEnd = 47 + len;
        uint256 p = receiptEnd;
        if (b.length - p < 2) revert BadPacket();
        count = uint16(bytes2(b[p:p + 2]));
        p += 2;
        if (count > MAX_GAPS) revert BadPacket();
        if (kind == 1 && count != 0) {
            if (b.length - p < 32) revert BadPacket();
            startHead = bytes32(b[p:p + 32]);
            p += 32;
        }
        if (b.length - p != count * (65 + (LOGK << 5))) revert BadPacket();
        gapsPos = p;
    }

    function _session(bytes calldata b) private view returns (bytes32) {
        return FlatBindings.session(
            RECOVERY_GENERATION,
            D,
            address(this),
            RECOVERY,
            RECOVERY_RUNTIME,
            RECOVERY_PINS,
            uint64(bytes8(b[2:10])),
            bytes32(b[10:42])
        );
    }

    /// @dev The certified event: the receipt proof must authenticate under the pinned helper and the configured EVM shard, be
    ///      emitted by the pinned recovery verifier for exactly this session and kind, carry a valid cursor and have a
    ///      successful B1 certificate check of its own. Every failure is BadPredecessor.
    function _authenticate(bytes calldata proof, uint8 kind, bytes32 session, bytes32 startHead)
        private
        view
        returns (Verdict memory v)
    {
        // Per-call dependency recheck; the code of an immutable graph does not change.
        if (!_recoveryIntact()) revert BadPredecessor();
        bytes memory data = _receipt(
            proof,
            kind == 1
                ? INativeBridgeRecovery11.NB2Complete11.selector
                : INativeBridgeRecovery11.NB2Gap11.selector,
            session,
            kind == 1 ? 224 : 288
        );
        uint256 seq = uint256(_word(data, 0));
        uint256 minSegment = uint256(_word(data, 96));
        uint256 recipient = uint256(_word(data, 160));
        uint256 start = kind == 1 ? minSegment : uint256(_word(data, 224));
        if (
            seq == 0 || seq > type(uint64).max || minSegment > start || start >= SEGMENT_LIMIT
                || recipient > type(uint160).max || minSegment > type(uint64).max
        ) {
            revert BadPredecessor();
        }
        v.domain = _word(data, 32);
        v.eta = _word(data, 64);
        v.minSegment = minSegment;
        v.asset = _word(data, 128);
        v.recipient = address(uint160(recipient));
        v.amount = uint256(_word(data, 192));
        v.start = start;
        v.head = kind == 1 ? startHead : _word(data, 256);
        if (
            v.domain != D || v.asset != ASSET_UCT || v.amount == 0 || v.recipient == address(0)
                || v.recipient == address(this)
        ) {
            revert BadPredecessor();
        }
    }

    function _receipt(bytes calldata proof, bytes32 topic, bytes32 session, uint256 width)
        private
        view
        returns (bytes memory)
    {
        try RECEIPTS.receipt(
            FlatReceipts.ReceiptEnv(_NETWORK, _EVM_PARTITION, _shard(), RECOVERY), proof
        ) returns (
            FlatClaim memory claim, bytes32[] memory topics, bytes memory data
        ) {
            if (
                topics.length != 2 || topics[0] != topic || topics[1] != session
                    || data.length != width || !FlatNative.singleton(claim)
            ) {
                revert BadPredecessor();
            }
            return data;
        } catch {
            revert BadPredecessor();
        }
    }

    /// @dev Section 11.1 step 3 for a cold packet: folds the proofs at `gapsPos` for eta from `head0` through
    ///      j = start .. start + count - 1, H_{j+1} = H_E(ARCHIVE_STEP || D || u64(j) || H_j || M_j). A proof that is not a gap of
    ///      eta is BadGapProof(i) with i zero-based within this call.
    function _foldFrom(
        bytes32 eta,
        uint256 start,
        uint256 count,
        bytes32 head0,
        bytes calldata b,
        uint256 gapsPos
    ) private view returns (bytes32 x) {
        uint256 h = LOGK;
        uint256 plen = 65 + (h << 5);
        bytes32 d = D;
        uint256 o;
        uint256 st;
        x = head0;
        assembly ("memory-safe") {
            o := add(b.offset, gapsPos)
            st := mload(0x40)
            mstore(st, ARCHIVE_STEP)
        }
        unchecked {
            for (uint256 i = 0; i < count; ++i) {
                (bool ok, bytes32 mj) = NB2Gap.rootAt(uint256(eta), o, h, st + 0xa0);
                if (!ok) revert BadGapProof(i);
                assembly ("memory-safe") {
                    mstore(add(st, 0x28), add(start, i))
                    mstore(add(st, 0x20), d)
                    mstore(add(st, 0x48), x)
                    mstore(add(st, 0x68), mj)
                    x := keccak256(st, 136)
                }
                o += plen;
            }
        }
    }

    function _shard() private view returns (bytes memory out) {
        out = new bytes(_SHARD_LEN);
        bytes32 prefix = _SHARD_PREFIX;
        assembly ("memory-safe") {
            mstore(add(out, 32), prefix)
        }
        if (_SHARD_LEN == 33) out[32] = _SHARD_TAIL;
    }

    function _word(bytes memory data, uint256 p) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(data, 32), p))
        }
    }
}
