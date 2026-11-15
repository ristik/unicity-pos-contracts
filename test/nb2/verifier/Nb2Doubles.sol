// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Nb2Cert} from "../../../src/nb2/verifier/Nb2Cert.sol";
import {Nb2Crypto} from "../../../src/nb2/verifier/Nb2Crypto.sol";

/// @notice Test double of CERT_BATCH_V2 at 0x0100 (ureth crates/unicity/b1 batch.rs), etched at that address. It is NOT the
///         native batch: it models the authority half the token verifier delegates (the epoch entry of each seal, the root
///         round inside the entry's interval, the network, the weighted quorum under the upstream seal rule over
///         SHA-256(seal with a null signature map)) plus the claim's binding to its UC, from a trust history the test loads
///         (script/nb2/trust-fixture.py over the pinned vectors' trust bundles). The certificate's encoding and folds reuse
///         the verifier's own acceptance (Nb2Cert): the double is not an independent check of those.
contract CertBatchDouble {
    struct Member {
        bytes32 id; // keccak of the node ID
        address key;
        uint256 weight;
    }

    struct Epoch {
        bool exists;
        uint256 start;
        uint256 end; // 0: open
        uint256 total;
    }

    uint256 public network;
    mapping(uint256 => Epoch) internal epochs;
    mapping(uint256 => Member[]) internal members;
    uint256[] internal loaded;

    function nb2Reset(uint256 network_) external {
        for (uint256 i; i < loaded.length; ++i) {
            delete epochs[loaded[i]];
            delete members[loaded[i]];
        }
        delete loaded;
        network = network_;
    }

    function nb2Epoch(uint256 epoch, uint256 start, uint256 end, uint256 total) external {
        epochs[epoch] = Epoch(true, start, end, total);
        loaded.push(epoch);
    }

    function nb2Member(uint256 epoch, bytes calldata id, bytes calldata key33) external {
        uint256 p;
        assembly ("memory-safe") {
            p := key33.offset
        }
        members[epoch].push(Member(keccak256(id), Nb2Crypto.keyAddress(p), 1));
    }

    function nb2MemberWeight(uint256 epoch, uint256 index, uint256 weight) external {
        members[epoch][index].weight = weight;
    }

    /// @dev The native schedule of a request (b1ref limits.go): 60,000 + 16C + 500k(k-1) + 1,100 + 29,900E + 7,200Q + 2,000A
    ///      + 250P, over the request's claims (all distinct, as the verifier sends them).
    function nb2Schedule(bytes calldata req)
        external
        pure
        returns (uint256 gas, uint256 k, uint256 e, uint256 q, uint256 a, uint256 p)
    {
        uint256 base;
        assembly ("memory-safe") {
            base := req.offset
        }
        k = (uint256(uint8(req[2])) << 8) | uint8(req[3]);
        uint256 pos = base + 4;
        uint256[] memory seenEpochs = new uint256[](k);
        bytes32[] memory seenSeals = new bytes32[](k);
        uint256 se;
        uint256 ss;
        for (uint256 i; i < k; ++i) {
            (uint256 ucPos, uint256 ucLen, uint256 next) = _claimUc(pos);
            (, Nb2Cert.Uc memory u) = Nb2Cert.parse(ucPos, ucLen);
            bool found;
            for (uint256 j; j < se; ++j) {
                if (seenEpochs[j] == u.epoch) found = true;
            }
            if (!found) seenEpochs[se++] = u.epoch;
            bytes32 sh = Nb2Crypto.keccakCd(u.sealPos, ucPos + ucLen - u.sealPos);
            found = false;
            for (uint256 j; j < ss; ++j) {
                if (seenSeals[j] == sh) found = true;
            }
            if (!found) {
                seenSeals[ss++] = sh;
                q += u.sigCount;
            }
            p += u.sibCount + u.stepCount;
            pos = next;
        }
        e = se;
        a = k;
        gas = 60_000 + 16 * req.length + 500 * k * (k - 1) + 1_100 + 29_900 * e + 7_200 * q + 2_000
            * a + 250 * p;
    }

    function _claimUc(uint256 pos)
        internal
        pure
        returns (uint256 ucPos, uint256 ucLen, uint256 next)
    {
        uint256 sl;
        assembly ("memory-safe") {
            sl := shr(240, calldataload(add(pos, 4)))
        }
        uint256 lp = pos + 6 + sl + 96;
        assembly ("memory-safe") {
            ucLen := shr(224, calldataload(lp))
        }
        ucPos = lp + 4;
        next = ucPos + ucLen;
    }

    fallback(bytes calldata req) external returns (bytes memory) {
        require(
            req.length >= 4 && uint8(req[0]) == 2 && uint8(req[1]) == 0, "CertBatchDouble: header"
        );
        uint256 k = (uint256(uint8(req[2])) << 8) | uint8(req[3]);
        require(k >= 1 && k <= 16, "CertBatchDouble: count");
        uint256 base;
        assembly ("memory-safe") {
            base := req.offset
        }
        uint256 pos = base + 4;
        bool valid = true;
        for (uint256 i; i < k; ++i) {
            (uint256 ucPos, uint256 ucLen, uint256 next) = _claimUc(pos);
            valid = _claim(pos, ucPos, ucLen) && valid;
            pos = next;
        }
        require(pos == base + req.length, "CertBatchDouble: trailing");
        return abi.encode(uint256(2), valid);
    }

    function _claim(uint256 pos, uint256 ucPos, uint256 ucLen) internal view returns (bool) {
        (bool ok, Nb2Cert.Uc memory u) = Nb2Cert.parse(ucPos, ucLen);
        require(ok, "CertBatchDouble: malformed UC");
        uint256 partition;
        uint256 sl;
        bytes32 conf;
        bytes32 state;
        bytes32 irHash;
        assembly ("memory-safe") {
            partition := shr(224, calldataload(pos))
            sl := shr(240, calldataload(add(pos, 4)))
            let w := add(add(pos, 6), sl)
            conf := calldataload(w)
            state := calldataload(add(w, 32))
            irHash := calldataload(add(w, 64))
        }
        if (partition != u.partition || sl != u.shardLen) return false;
        if (Nb2Crypto.keccakCd(pos + 6, sl) != Nb2Crypto.keccakCd(u.shardPos, u.shardLen)) {
            return false;
        }
        if (
            conf != u.shardConfHash || state != u.stateHash
                || irHash != Nb2Crypto.sha256Cd(u.irPos, u.irLen)
        ) {
            return false;
        }
        if (!Nb2Cert.valid(u, u.partition, 0, 0) || !Nb2Cert.folds(u)) return false;
        Epoch memory e = epochs[u.epoch];
        if (!e.exists || u.network != network) return false;
        if (u.sealRound < e.start || (e.end != 0 && u.sealRound >= e.end)) return false;
        return _quorum(u, e);
    }

    function _quorum(Nb2Cert.Uc memory u, Epoch memory e) internal view returns (bool) {
        // SHA-256 of the tagged seal with its signature map replaced by null.
        uint256 plen = u.sigMapPos - u.sealPos;
        bytes memory msg_ = new bytes(plen + 1);
        uint256 sp = u.sealPos;
        assembly ("memory-safe") {
            calldatacopy(add(msg_, 32), sp, plen)
        }
        msg_[plen] = 0xf6;
        bytes32 digest = sha256(msg_);
        Member[] storage ms = members[u.epoch];
        uint256 q = u.sigMapPos + 1; // map head of at most 16 pairs
        uint256 good;
        for (uint256 i; i < u.sigCount; ++i) {
            (uint256 kp, uint256 kl, uint256 q2) = _str(q);
            (uint256 vp, uint256 vl, uint256 q3) = _str(q2);
            q = q3;
            if (kl == 0 || vl == 0) return false;
            bytes32 id = Nb2Crypto.keccakCd(kp, kl);
            for (uint256 j; j < ms.length; ++j) {
                if (ms[j].id != id) continue;
                if (vl == 65) {
                    bytes32 r;
                    bytes32 s;
                    uint256 v;
                    assembly ("memory-safe") {
                        r := calldataload(vp)
                        s := calldataload(add(vp, 32))
                        v := shr(248, calldataload(add(vp, 64)))
                    }
                    if (
                        v <= 1 && uint256(r) != 0 && uint256(r) < Nb2Crypto.N && uint256(s) != 0
                            && uint256(s) <= Nb2Crypto.HALF_N
                            && Nb2Crypto.recover(digest, v, r, s) == ms[j].key
                    ) good += ms[j].weight;
                }
                break;
            }
        }
        return good >= e.total - (e.total - 1) / 3;
    }

    /// @dev A text or byte string at q: (payload, length, next).
    function _str(uint256 q) internal pure returns (uint256 dp, uint256 len, uint256 next) {
        uint256 b;
        assembly ("memory-safe") {
            b := shr(248, calldataload(q))
        }
        uint256 ai = b & 31;
        if (ai < 24) {
            len = ai;
            dp = q + 1;
        } else {
            uint256 n = 1 << (ai - 24);
            assembly ("memory-safe") {
                len := shr(sub(256, shl(3, n)), calldataload(add(q, 1)))
            }
            dp = q + 1 + n;
        }
        next = dp + len;
    }
}

/// @notice Test double of the stateless RSMT membership at 0x0102 (ureth crates/unicity/b1 rsmt.rs), etched at that address.
contract MembershipDouble {
    fallback(bytes calldata req) external returns (bytes memory) {
        require(req.length >= 4 + 32 + 32 + 4 + 32, "MembershipDouble: short");
        require(
            uint8(req[0]) == 1 && uint8(req[1]) == 0 && uint8(req[2]) == 0 && uint8(req[3]) == 1,
            "header"
        );
        bytes32 root = bytes32(req[4:36]);
        bytes32 key = bytes32(req[36:68]);
        uint256 len = uint32(bytes4(req[68:72]));
        bytes calldata value = req[72:72 + len];
        bytes32 bitmap = bytes32(req[72 + len:104 + len]);
        bytes calldata sibs = req[104 + len:];
        uint256 count;
        for (uint256 d; d < 256; ++d) {
            if (uint256(bitmap) >> (255 - d) & 1 == 1) ++count;
        }
        require(sibs.length == 32 * count, "MembershipDouble: shape");
        bytes32 h = sha256(abi.encodePacked(uint8(0), key, value));
        uint256 idx = count;
        for (uint256 dd = 256; dd != 0;) {
            --dd;
            if (uint256(bitmap) >> (255 - dd) & 1 == 0) continue;
            --idx;
            bytes32 sib = bytes32(sibs[idx * 32:idx * 32 + 32]);
            bytes32 region = dd == 0 ? bytes32(0) : key & bytes32(type(uint256).max << (256 - dd));
            if (uint256(key) >> (255 - dd) & 1 == 0) {
                h = sha256(abi.encodePacked(uint8(1), uint8(dd), region, h, sib));
            } else {
                h = sha256(abi.encodePacked(uint8(1), uint8(dd), region, sib, h));
            }
        }
        return abi.encode(uint256(1), root != 0 && h == root);
    }
}
