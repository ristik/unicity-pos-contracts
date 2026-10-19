// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// @title RootVoteCbor
/// @notice The fixed-schema deterministic CBOR the root consensus signs for a scheme 2 vote, byte for byte as bft-core's
/// `votesig` writes it (shortest-form heads, definite lengths, no maps), so that evidence verifies the message the roots signed.
///
///   Dv  = "root-vote/" + lowercase hex(G)            Dt = "root-timeout/" + lowercase hex(G)
///   VI  = C([N, Dv, epoch, round, parent, exec])      with `timestamp` appended exactly when it is non-zero
///   VH  = sha256(VI)
///   PV  = C(["UNICITY_POS_VOTE", N, Dv, VH, commitHash|null, commitRound])
///   vote digest = sha256(PV)                          (the signer hashes PV itself; no signed-message prefix)
///   PT  = C(["UNICITY_POS_TIMEOUT", N, Dt, epoch, round, highQcRound, anchor|null, author])
///   seal bytes (native UnicitySeal.SigBytes, tag 39005) = C(39005([1, N, commitRound, commitEpoch, timestamp, VH, commitHash, null]))
///
/// Every encoder writes into a buffer sized for its largest message and trims it; nothing here parses CBOR.
library RootVoteCbor {
    error DomainTooLong();
    error AuthorTooLong();

    string internal constant VOTE_TAG = "UNICITY_POS_VOTE";
    string internal constant TIMEOUT_TAG = "UNICITY_POS_TIMEOUT";
    string internal constant VOTE_PREFIX = "root-vote/";
    string internal constant TIMEOUT_PREFIX = "root-timeout/";
    uint256 internal constant SEAL_TAG = 39005;
    uint256 internal constant MAX_AUTHOR = 128;

    // --- domains -------------------------------------------------------------------------------

    function voteDomain(bytes32 genesis) internal pure returns (bytes memory) {
        return _domain(bytes(VOTE_PREFIX), genesis);
    }

    function timeoutDomain(bytes32 genesis) internal pure returns (bytes memory) {
        return _domain(bytes(TIMEOUT_PREFIX), genesis);
    }

    function _domain(bytes memory prefix, bytes32 genesis) private pure returns (bytes memory out) {
        out = new bytes(prefix.length + 64);
        for (uint256 i = 0; i < prefix.length; ++i) {
            out[i] = prefix[i];
        }
        bytes16 digits = "0123456789abcdef";
        for (uint256 i = 0; i < 32; ++i) {
            uint8 b = uint8(genesis[i]);
            out[prefix.length + 2 * i] = digits[b >> 4];
            out[prefix.length + 2 * i + 1] = digits[b & 0x0f];
        }
    }

    // --- messages ------------------------------------------------------------------------------

    /// @notice VI. `domain` is Dv.
    function voteInfo(
        uint64 network,
        bytes memory domain,
        uint64 epoch,
        uint64 round,
        uint64 parent,
        bytes32 exec,
        uint64 timestamp
    ) internal pure returns (bytes memory out) {
        out = _buffer(domain.length + 160);
        uint256 p = _head(out, 0, 4, timestamp == 0 ? 6 : 7);
        p = _head(out, p, 0, network);
        p = _text(out, p, domain);
        p = _head(out, p, 0, epoch);
        p = _head(out, p, 0, round);
        p = _head(out, p, 0, parent);
        p = _bytes32(out, p, exec);
        if (timestamp != 0) p = _head(out, p, 0, timestamp);
        _trim(out, p);
    }

    /// @notice PV. A non-committing vote passes `committing` false with a zero hash and round.
    function votePreimage(
        uint64 network,
        bytes memory domain,
        bytes32 voteInfoHash,
        bool committing,
        bytes32 commitHash,
        uint64 commitRound
    ) internal pure returns (bytes memory out) {
        out = _buffer(domain.length + 120);
        uint256 p = _head(out, 0, 4, 6);
        p = _text(out, p, bytes(VOTE_TAG));
        p = _head(out, p, 0, network);
        p = _text(out, p, domain);
        p = _bytes32(out, p, voteInfoHash);
        p = committing ? _bytes32(out, p, commitHash) : _null(out, p);
        p = _head(out, p, 0, commitRound);
        _trim(out, p);
    }

    /// @notice The native UnicitySeal with its signature map null, which is both the committing vote's LedgerCommitInfo and the bytes its seal
    /// signature covers (`UnicitySeal.SigBytes`). Its previous hash is VH.
    function sealSigBytes(
        uint64 network,
        uint64 commitRound,
        uint64 commitEpoch,
        uint64 timestamp,
        bytes32 voteInfoHash,
        bytes32 commitHash
    ) internal pure returns (bytes memory out) {
        out = _buffer(120);
        uint256 p = _head(out, 0, 6, SEAL_TAG);
        p = _head(out, p, 4, 8);
        p = _head(out, p, 0, 1);
        p = _head(out, p, 0, network);
        p = _head(out, p, 0, commitRound);
        p = _head(out, p, 0, commitEpoch);
        p = _head(out, p, 0, timestamp);
        p = _bytes32(out, p, voteInfoHash);
        p = _bytes32(out, p, commitHash);
        p = _null(out, p);
        _trim(out, p);
    }

    /// @notice PT of a normal timeout (`hasAnchor` false) or of the first round after an epoch change (the anchor names a genesis ID, epoch
    /// and slot). `domain` is Dt. Timeouts carry no slashing rule here: this exists so that the digest the roots sign is reproducible.
    function timeoutPreimage(
        uint64 network,
        bytes memory domain,
        uint64 epoch,
        uint64 round,
        uint64 highQcRound,
        bool hasAnchor,
        bytes32 anchorGenesis,
        uint64 anchorEpoch,
        uint64 anchorSlot,
        bytes memory author
    ) internal pure returns (bytes memory out) {
        if (author.length > MAX_AUTHOR) revert AuthorTooLong();
        out = _buffer(domain.length + author.length + 160);
        uint256 p = _head(out, 0, 4, 8);
        p = _text(out, p, bytes(TIMEOUT_TAG));
        p = _head(out, p, 0, network);
        p = _text(out, p, domain);
        p = _head(out, p, 0, epoch);
        p = _head(out, p, 0, round);
        p = _head(out, p, 0, highQcRound);
        if (hasAnchor) {
            p = _head(out, p, 4, 3);
            p = _bytes32(out, p, anchorGenesis);
            p = _head(out, p, 0, anchorEpoch);
            p = _head(out, p, 0, anchorSlot);
        } else {
            p = _null(out, p);
        }
        p = _text(out, p, author);
        _trim(out, p);
    }

    // --- writer --------------------------------------------------------------------------------

    function _buffer(uint256 size) private pure returns (bytes memory) {
        return new bytes(size);
    }

    function _trim(bytes memory b, uint256 length) private pure {
        assembly ("memory-safe") {
            mstore(b, length)
        }
    }

    function _put(bytes memory b, uint256 p, uint256 value) private pure returns (uint256) {
        assembly ("memory-safe") {
            mstore8(add(add(b, 0x20), p), value)
        }
        return p + 1;
    }

    /// @dev A CBOR head in shortest form: major type `major`, argument `n`.
    function _head(bytes memory b, uint256 p, uint256 major, uint256 n)
        private
        pure
        returns (uint256)
    {
        uint256 m = major << 5;
        if (n < 24) {
            return _put(b, p, m | n);
        }
        if (n < 0x100) {
            p = _put(b, p, m | 24);
            return _put(b, p, n);
        }
        if (n < 0x10000) {
            p = _put(b, p, m | 25);
            p = _put(b, p, n >> 8);
            return _put(b, p, n);
        }
        if (n < 0x100000000) {
            p = _put(b, p, m | 26);
            for (uint256 s = 24;; s -= 8) {
                p = _put(b, p, n >> s);
                if (s == 0) break;
            }
            return p;
        }
        p = _put(b, p, m | 27);
        for (uint256 s = 56;; s -= 8) {
            p = _put(b, p, n >> s);
            if (s == 0) break;
        }
        return p;
    }

    function _null(bytes memory b, uint256 p) private pure returns (uint256) {
        return _put(b, p, 0xf6);
    }

    function _bytes32(bytes memory b, uint256 p, bytes32 v) private pure returns (uint256) {
        p = _head(b, p, 2, 32);
        assembly ("memory-safe") {
            mstore(add(add(b, 0x20), p), v)
        }
        return p + 32;
    }

    function _text(bytes memory b, uint256 p, bytes memory s) private pure returns (uint256) {
        p = _head(b, p, 3, s.length);
        for (uint256 i = 0; i < s.length; ++i) {
            p = _put(b, p, uint8(s[i]));
        }
        return p;
    }
}
