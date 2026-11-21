// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// Certificate parsing bounds claim fields before narrowing. Loop indices start at zero.
// forge-lint: disable-start(unsafe-typecast,uninitialized-local)

import {Nb2Cbor as C} from "../Nb2Cbor.sol";
import {Nb2Cert} from "../Nb2Cert.sol";
import {Nb2Crypto} from "../Nb2Crypto.sol";
import {Nb2Evm} from "../Nb2Evm.sol";
import {FlatClaim, FlatHash, FlatWire as W, BadStep} from "./FlatTypes.sol";

contract FlatReceipts {
    struct ReceiptEnv {
        uint16 network;
        uint32 partition;
        bytes shard;
        address emitter;
    }

    function certificate(
        bytes calldata uc,
        uint16 network,
        uint32 partition,
        bytes32 sid,
        uint64 time
    ) external view returns (FlatClaim memory claim, bytes32 stateRoot) {
        Nb2Cert.Uc memory u = _certificate(uc, network, partition, uc[:0]);
        if (time > u.timestamp || !Nb2Cert.inShard(u, sid)) revert BadStep();
        return (_claim(u), u.stateHash);
    }

    function receipt(ReceiptEnv calldata env, bytes calldata proof)
        external
        view
        returns (FlatClaim memory claim, bytes32[] memory topics, bytes memory data)
    {
        uint256 p = W.offset(proof);
        if (proof.length > W.MAX_RECEIPT) revert BadStep();
        // Heads, node count and outer caps first; only then the scan, the UC and the header.
        W.boundReceipt(p, p + proof.length);
        if (C.scan(p, p + proof.length, false) != 0) revert BadStep();
        p = C.version(C.array(p, 6), 1);
        (uint256 ucPos, uint256 ucLen, uint256 next) = C.bstr(p);
        if (ucLen > 16384 || env.shard.length == 0) revert BadStep();
        Nb2Cert.Uc memory u =
            _certificate(W.slice(ucPos, ucLen), env.network, env.partition, env.shard);
        (uint256 headerPos, uint256 headerLen, uint256 q) = C.bstr(next);
        if (headerLen > 2048) revert BadStep();
        (bool ok, bytes32 root) =
            Nb2Evm.header(headerPos, headerLen, u.blockHashNull, u.blockHash, u.stateHash);
        if (!ok) revert BadStep();
        (uint256 txIndex, uint256 logIndex, uint256[] memory positions, uint256[] memory lengths) =
            _receiptPath(q);
        uint256 valuePos;
        uint256 valueLen;
        (ok, valuePos, valueLen) = Nb2Evm.trieValue(root, txIndex, positions, lengths);
        if (!ok) revert BadStep();
        (uint256 err, Nb2Evm.Log memory lg) = Nb2Evm.receiptLog(valuePos, valueLen, logIndex);
        if (err != 0 || lg.emitter != env.emitter) revert BadStep();
        topics = new bytes32[](lg.topicCount);
        for (uint256 i; i < topics.length; ++i) {
            topics[i] = Nb2Evm.topic(lg, i);
        }
        return (_claim(u), topics, W.slice(lg.dataPos, lg.dataLen));
    }

    function _receiptPath(uint256 p)
        private
        pure
        returns (uint256 txIndex, uint256 logIndex, uint256[] memory pos, uint256[] memory len)
    {
        (txIndex, p) = C.uintIn(p, 0, type(uint32).max);
        (logIndex, p) = C.uintIn(p, 0, type(uint32).max);
        (uint256 n, uint256 q) = C.anyArray(p);
        if (n == 0 || n > 65) revert BadStep();
        pos = new uint256[](n);
        len = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            (pos[i], len[i], q) = C.bstr(q);
            if (len[i] > (i + 1 == n ? 49152 : 1024)) revert BadStep();
        }
    }

    function _certificate(
        bytes calldata raw,
        uint16 network,
        uint32 partition,
        bytes calldata shard
    ) private view returns (Nb2Cert.Uc memory u) {
        bool ok;
        (ok, u) = Nb2Cert.parse(W.offset(raw), raw.length);
        if (
            !ok || u.network != network
                || !Nb2Cert.valid(u, partition, W.offset(shard), shard.length) || !Nb2Cert.folds(u)
        ) revert BadStep();
    }

    function _claim(Nb2Cert.Uc memory u) private view returns (FlatClaim memory claim) {
        claim.packed = Nb2Cert.claim(u, u.partition);
        bytes32 seal = Nb2Crypto.sha256Cd(u.sealPos, u.pos + u.len - u.sealPos);
        claim.key = keccak256(
            abi.encodePacked(
                FlatHash.CLAIM_KEY,
                seal,
                uint32(u.partition),
                uint16(u.shardLen),
                W.slice(u.shardPos, u.shardLen)
            )
        );
        claim.value = keccak256(abi.encodePacked(FlatHash.CLAIM_VALUE, sha256(claim.packed)));
    }
}
