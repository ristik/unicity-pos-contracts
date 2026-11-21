// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice Γ of native bridge v2 (bft-core docs/design/native-bridge-v2.md section 4): the strict decoder the vault constructor
///         runs, and the section 4.2 identity derivations. Every failure is `BadConfig(field)` with the index of the first
///         failing Γ field (0..18), or 19 for array-level failures (not an array of 19, trailing bytes, any scan error, more
///         than 1024 bytes). The field checks and their order follow the NB2-03 reference (bft-core nb2ref/config.go,
///         DecodeConfig then Construct).
library NB2Config {
    /// @notice Raised by the vault constructor for a refused Γ (section 13.3).
    error BadConfig(uint256 field);

    /// @dev a_UCT = H_U(UTF8("unicity-nb2-asset:native-uct")) (section 4.2).
    bytes32 internal constant ASSET_UCT =
        0x87b0b8b600fcd942cc3383bac1dbb80fd69d54af700cf48faa4525451a7b1845;

    uint256 internal constant ARITY = 19;
    uint256 internal constant ARRAY_FIELD = 19;
    uint256 internal constant MAX_BYTES = 1024;
    uint256 internal constant MAX_DEPTH = 16;
    uint256 internal constant MAX_K = 64;
    uint256 internal constant QMAX_LIMIT = (1 << 144) - 1;

    /// @notice The decoded fields of Γ that the vault uses or checks.
    struct Config {
        /// @dev Γ version: 1 for the v2 bridge generation, 2 for NB2 v1.1 (fresh generation).
        uint256 version;
        uint256 network;
        uint256 evmPartition;
        bytes evmShard;
        bytes32 profile;
        bytes32 rootGenesis;
        bytes32 executionGenesis;
        uint256 chainId;
        address vault;
        bytes32 asset;
        bytes32 ty;
        bytes32 aid;
        address verifier;
        bytes32 verifierCodeHash;
        uint256 k;
        uint256 b;
        uint256 qmax;
    }

    /// @notice Decodes Γ strictly (section 4.1) for a build whose admitted K and B sets are the bit masks `kSet` and `bSet`
    ///         (bit x set: x admitted). Reverts `BadConfig(field)`. Does not check the environment (see `checkEnvironment`).
    function decode(bytes memory g, uint256 kSet, uint256 bSet)
        internal
        pure
        returns (Config memory c)
    {
        return decode(g, kSet, bSet, 1);
    }

    /// @notice As `decode`, for Γ version 1 (native bridge v2) or 2 (NB2 v1.1; same 19 fields, version 2).
    function decode(bytes memory g, uint256 kSet, uint256 bSet, uint256 version)
        internal
        pure
        returns (Config memory c)
    {
        c.version = version;
        if (g.length > MAX_BYTES) revert BadConfig(ARRAY_FIELD);
        (uint256 end, bool ok) = _skip(g, 0, 0);
        if (!ok || end != g.length) revert BadConfig(ARRAY_FIELD);
        (uint256 major, uint256 arg, uint256 pos,) = _head(g, 0);
        if (major != 4 || arg != ARITY) revert BadConfig(ARRAY_FIELD);

        uint256[ARITY] memory fieldAt;
        for (uint256 i = 0; i < ARITY; i++) {
            fieldAt[i] = pos;
            (pos,) = _skip(g, pos, 1);
        }

        // 0: the domain literal; 1: the version.
        (bool isB, uint256 off, uint256 len) = _bstr(g, fieldAt[0]);
        if (!isB || len != 15 || _word(g, off) >> 136 != 0x554e49434954595f4e42325f434647) {
            revert BadConfig(0);
        }
        if (_uintIn(g, fieldAt[1], version, version) != version) revert BadConfig(1);
        c.network = _uintIn(g, fieldAt[2], 1, 65535);
        if (c.network == 0) revert BadConfig(2);
        c.rootGenesis = _fixed32(g, fieldAt[3], 3);
        c.executionGenesis = _fixed32(g, fieldAt[4], 4);
        c.chainId = _uintIn(g, fieldAt[5], 1, type(uint64).max);
        if (c.chainId == 0) revert BadConfig(5);
        uint256 evmPartition = _uintIn(g, fieldAt[6], 1, type(uint32).max);
        if (evmPartition == 0) revert BadConfig(6);
        c.evmPartition = evmPartition;
        (isB, off, len) = _bstr(g, fieldAt[7]);
        if (!isB || !_canonicalShard(g, off, len)) revert BadConfig(7);
        c.evmShard = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            c.evmShard[i] = g[off + i];
        }
        uint256 aggPartition = _uintIn(g, fieldAt[8], 1, type(uint32).max);
        if (aggPartition == 0 || aggPartition == evmPartition) revert BadConfig(8);
        // the 20 high bytes of the fixed 20-byte field
        // forge-lint: disable-next-line(unsafe-typecast)
        c.vault = address(bytes20(_fixedN(g, fieldAt[9], 20, 9)));
        c.asset = _fixed32(g, fieldAt[10], 10);
        c.ty = _fixed32(g, fieldAt[11], 11);
        c.aid = _fixed32(g, fieldAt[12], 12);
        c.profile = _fixed32(g, fieldAt[13], 13);
        // the 20 high bytes of the fixed 20-byte field
        // forge-lint: disable-next-line(unsafe-typecast)
        c.verifier = address(bytes20(_fixedN(g, fieldAt[14], 20, 14)));
        c.verifierCodeHash = _fixed32(g, fieldAt[15], 15);
        // 16 then 17, each complete before the next field is read: K's range, power of two and build set, then B's range,
        // power of two, B <= K and build set.
        c.k = _uintIn(g, fieldAt[16], 2, MAX_K);
        if (c.k == 0 || c.k & (c.k - 1) != 0 || (kSet >> c.k) & 1 == 0) revert BadConfig(16);
        c.b = _uintIn(g, fieldAt[17], 2, MAX_K);
        if (c.b == 0 || !_admits(c.k, c.b, kSet, bSet)) revert BadConfig(17);
        // 18: Qmax, an Amount (section 3): 1..32 bytes, no leading zero, at most 2^144 - 1.
        (isB, off, len) = _bstr(g, fieldAt[18]);
        if (!isB || len == 0 || len > 32 || uint8(g[off]) == 0) revert BadConfig(18);
        c.qmax = _word(g, off) >> (256 - 8 * len);
        if (c.qmax > QMAX_LIMIT) revert BadConfig(18);
    }

    /// @notice The constructor's environment checks after `decode`, in the reference's order: asset, ty, aid (section 4.2), then
    ///         vault20 == self, chainId == block.chainid and verifierCodeHash32 == EXTCODEHASH(verifier20).
    function checkEnvironment(Config memory c, address self) internal view {
        if (c.asset != ASSET_UCT) revert BadConfig(10);
        bytes memory dstr = identityString(c.network, c.rootGenesis, c.executionGenesis, c.chainId);
        bytes memory tag =
            c.version == 1 ? bytes("unicity-native-nb2:") : bytes("unicity-native-nb2-11:");
        if (c.ty != sha256(bytes.concat("unicity-bridge:", tag, dstr))) {
            revert BadConfig(11);
        }
        if (c.aid != sha256(bytes.concat("unicity-bridge-coin:", tag, dstr))) {
            revert BadConfig(12);
        }
        if (c.vault != self) revert BadConfig(9);
        if (c.chainId != block.chainid) revert BadConfig(5);
        if (c.verifier.codehash != c.verifierCodeHash) revert BadConfig(15);
    }

    /// @notice Dstr = networkDecimal ":" rootGenesisHex ":" executionGenesisHex ":" chainIdDecimal (section 4.2).
    function identityString(
        uint256 network,
        bytes32 rootGenesis,
        bytes32 executionGenesis,
        uint256 chainId
    ) internal pure returns (bytes memory) {
        return bytes.concat(
            _decimal(network),
            ":",
            _hex(rootGenesis),
            ":",
            _hex(executionGenesis),
            ":",
            _decimal(chainId)
        );
    }

    // ------------------------------------------------------------------------------------------------ admitted parameters

    /// @dev The reference's Params.Admits: both powers of two, 2 <= B <= K <= 64, both in the build's sets.
    function _admits(uint256 k, uint256 b, uint256 kSet, uint256 bSet) private pure returns (bool) {
        return k >= 2 && k <= MAX_K && k & (k - 1) == 0 && b >= 2 && b <= k && b & (b - 1) == 0
            && (kSet >> k) & 1 == 1 && (bSet >> b) & 1 == 1;
    }

    /// @dev A canonical native shard ID: 1..33 bytes, last byte nonzero, at most 256 prefix bits before the terminator bit.
    function _canonicalShard(bytes memory g, uint256 off, uint256 len) private pure returns (bool) {
        if (len == 0 || len > 33) return false;
        uint256 last = uint8(g[off + len - 1]);
        if (last == 0) return false;
        uint256 tz = 0;
        while ((last >> tz) & 1 == 0) tz++;
        return 8 * len - tz - 1 <= 256;
    }

    // forge-lint: disable-start(boolean-cst)
    // ------------------------------------------------------------------------------------------------ strict CBOR (section 3)

    /// @dev One item head at pos: (major, argument, position after the head, ok). Shortest heads only; no indefinite lengths.
    function _head(bytes memory g, uint256 pos)
        private
        pure
        returns (uint256 major, uint256 arg, uint256 next, bool ok)
    {
        uint256 n = g.length;
        if (pos >= n) return (0, 0, pos, false);
        uint256 ib = uint8(g[pos]);
        major = ib >> 5;
        uint256 ai = ib & 31;
        next = pos + 1;
        if (ai < 24) return (major, ai, next, true);
        if (ai > 27) return (major, 0, next, false);
        uint256 w = 1 << (ai - 24);
        if (n - next < w) return (major, 0, next, false);
        for (uint256 i = 0; i < w; i++) {
            arg = (arg << 8) | uint8(g[next + i]);
        }
        next += w;
        ok =
        !((ai == 24 && arg < 24) || (ai == 25 && arg <= 0xff) || (ai == 26 && arg <= 0xffff)
                || (ai == 27 && arg <= 0xffffffff));
    }

    /// @dev Skips one strict item at pos at the given depth: (end, ok). Negative integers, text strings, maps, floats and simple
    ///      values other than null are forbidden; a container whose children would sit above depth 16 fails.
    function _skip(bytes memory g, uint256 pos, uint256 depth)
        private
        pure
        returns (uint256, bool)
    {
        if (pos < g.length) {
            uint256 ib = uint8(g[pos]);
            uint256 mj = ib >> 5;
            if (mj == 1 || mj == 3 || mj == 5 || (mj == 7 && ib != 0xf6)) return (pos, false);
        }
        (uint256 major, uint256 arg, uint256 next, bool ok) = _head(g, pos);
        if (!ok) return (next, false);
        uint256 rest = g.length - next;
        if (major == 2) {
            if (arg > rest) return (next, false);
            return (next + arg, true);
        }
        if (major == 4 || major == 6) {
            if (depth + 1 > MAX_DEPTH) return (next, false);
            uint256 kids = major == 6 ? 1 : arg;
            if (kids > rest) return (next, false);
            for (uint256 i = 0; i < kids; i++) {
                (next, ok) = _skip(g, next, depth + 1);
                if (!ok) return (next, false);
            }
            return (next, true);
        }
        // major 0 (uint) or the null simple value
        return (next, true);
    }

    /// @dev The uint at pos when it lies in [lo, hi], else 0 (every caller's lo is at least 1, so 0 means failure).
    // forge-lint: disable-end(boolean-cst)

    function _uintIn(bytes memory g, uint256 pos, uint256 lo, uint256 hi)
        private
        pure
        returns (uint256)
    {
        (uint256 major, uint256 arg,,) = _head(g, pos);
        if (major != 0 || arg < lo || arg > hi) return 0;
        return arg;
    }

    function _bstr(bytes memory g, uint256 pos)
        private
        pure
        returns (bool isBytes, uint256 off, uint256 len)
    {
        (uint256 major, uint256 arg, uint256 next,) = _head(g, pos);
        return (major == 2, next, arg);
    }

    function _fixedN(bytes memory g, uint256 pos, uint256 n, uint256 field)
        private
        pure
        returns (bytes32)
    {
        (bool isB, uint256 off, uint256 len) = _bstr(g, pos);
        if (!isB || len != n) revert BadConfig(field);
        return bytes32(_word(g, off) & ~(type(uint256).max >> (8 * n)));
    }

    function _fixed32(bytes memory g, uint256 pos, uint256 field) private pure returns (bytes32) {
        return _fixedN(g, pos, 32, field);
    }

    /// @dev The 32 bytes at payload offset off (reads past the end are masked by the callers).
    function _word(bytes memory g, uint256 off) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(g, 32), off))
        }
    }

    // ------------------------------------------------------------------------------------------------ text

    function _decimal(uint256 v) private pure returns (bytes memory out) {
        if (v == 0) return "0";
        uint256 n = 0;
        for (uint256 t = v; t != 0; t /= 10) {
            n++;
        }
        out = new bytes(n);
        for (; v != 0; v /= 10) {
            // a decimal digit
            // forge-lint: disable-next-line(unsafe-typecast)
            out[--n] = bytes1(uint8(48 + (v % 10)));
        }
    }

    function _hex(bytes32 v) private pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            uint8 x = uint8(v[i]);
            out[2 * i] = digits[x >> 4];
            out[2 * i + 1] = digits[x & 15];
        }
    }
}
