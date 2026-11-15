// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The linter's boolean-cst and uninitialized-local flag every `return (false, ...)` and zero-initialised accumulator; the
// precompile calls in loops are bounded by the input; typecasts are range-checked before narrowing; CBOR encodings are
// self-delimiting, so packed concatenation does not collide.
// forge-lint: disable-start(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)

import {Nb2Rules as R} from "./Nb2Rules.sol";
import {Nb2Cert} from "./Nb2Cert.sol";
import {Nb2Evm} from "./Nb2Evm.sol";

/// @notice Section 6.2 steps 2 to 5 up to the emitter, for a deposit receipt and a SegmentSealed seal receipt alike
///         (bft-core nb2ref VerifyReceiptLog): the EVM UC for exactly Γ's partition and shard with no expected configuration
///         hash, the header bound to its input record, the receipt-trie path keyed by RLP(txIndex), the receipt's type and
///         status, logs[logIndex] and its emitter. The EVM UC's authority (epoch, interval, quorum) is the 0x0100 claim it
///         returns, which the caller judges with its other claims.
///
///         It also judges each aggregator certificate locally (`certificate`). It is a separate contract only for EIP-170: the token verifier creates it in its constructor and holds its
///         address as an immutable, so the token verifier's code hash pins it. Stateless; it reverts on nothing but a failed
///         precompile.
contract Nb2ReceiptVerifier {
    struct Env {
        uint256 network;
        uint256 evmPartition;
        bytes evmShard;
        address vault;
    }

    /// @notice One aggregator certificate of an inclusion proof, judged locally in the frozen order (encoding, network,
    ///         structure for `partition` and its own shard, folds): UnsupportedCertificateEncoding, SealNetwork,
    ///         CertStructure, SealRoot, or zero with its 0x0100 claim, its certified state root, IR timestamp and shard.
    function certificate(bytes calldata uc, uint256 network, uint256 partition)
        external
        view
        returns (
            bytes4 rule,
            bytes memory claim,
            bytes32 stateHash,
            uint256 timestamp,
            bytes memory shard
        )
    {
        uint256 ucPos;
        assembly ("memory-safe") {
            ucPos := uc.offset
        }
        (bool ok, Nb2Cert.Uc memory u) = Nb2Cert.parse(ucPos, uc.length);
        if (!ok) return (R.UNSUPPORTED_CERTIFICATE_ENCODING, claim, 0, 0, shard);
        if (u.network != network) return (R.SEAL_NETWORK, claim, 0, 0, shard);
        if (!Nb2Cert.valid(u, partition, 0, 0)) return (R.CERT_STRUCTURE, claim, 0, 0, shard);
        if (!Nb2Cert.folds(u)) return (R.SEAL_ROOT, claim, 0, 0, shard);
        claim = Nb2Cert.claim(u, partition);
        shard = new bytes(u.shardLen);
        uint256 sp = u.shardPos;
        uint256 sl = u.shardLen;
        assembly ("memory-safe") {
            calldatacopy(add(shard, 32), sp, sl)
        }
        return (0, claim, u.stateHash, u.timestamp, shard);
    }

    /// @notice `rule` is zero on success. DepositUC comes with no claim (no certificate passed its local checks); every
    ///         later rule comes with the EVM UC's claim, which the caller must judge before raising it.
    function receiptLog(
        Env calldata env,
        bytes calldata uc,
        bytes calldata headerRlp,
        uint256 txIndex,
        uint256 logIndex,
        bytes[] calldata nodes
    )
        external
        view
        returns (bytes4 rule, bytes memory claim, bytes32[] memory topics, bytes memory data)
    {
        uint256 ucPos;
        uint256 shardPos;
        bytes calldata shard = env.evmShard;
        assembly ("memory-safe") {
            ucPos := uc.offset
            shardPos := shard.offset
        }
        (bool ok, Nb2Cert.Uc memory u) = Nb2Cert.parse(ucPos, uc.length);
        if (
            !ok || u.network != env.network
                || !Nb2Cert.valid(u, env.evmPartition, shardPos, shard.length) || !Nb2Cert.folds(u)
        ) return (R.DEPOSIT_UC, claim, topics, data);
        claim = Nb2Cert.claim(u, env.evmPartition);
        uint256 hp;
        assembly ("memory-safe") {
            hp := headerRlp.offset
        }
        bytes32 receiptsRoot;
        (ok, receiptsRoot) =
            Nb2Evm.header(hp, headerRlp.length, u.blockHashNull, u.blockHash, u.stateHash);
        if (!ok) return (R.DEPOSIT_HEADER, claim, topics, data);
        uint256 n = nodes.length;
        uint256[] memory pos = new uint256[](n);
        uint256[] memory len = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            bytes calldata node = nodes[i];
            uint256 np;
            assembly ("memory-safe") {
                np := node.offset
            }
            pos[i] = np;
            len[i] = node.length;
        }
        uint256 vpos;
        uint256 vlen;
        (ok, vpos, vlen) = Nb2Evm.trieValue(receiptsRoot, txIndex, pos, len);
        if (!ok) return (R.RECEIPT_PATH, claim, topics, data);
        (uint256 err, Nb2Evm.Log memory lg) = Nb2Evm.receiptLog(vpos, vlen, logIndex);
        if ((err == 0 || err == 4) && lg.emitter != env.vault) {
            return (R.LOG_EMITTER, claim, topics, data);
        }
        if (err != 0) {
            rule = err == 1
                ? R.RECEIPT_TYPE
                : err == 2 ? R.RECEIPT_STATUS : err == 3 ? R.LOG_INDEX : R.LOG_TOPICS;
            return (rule, claim, topics, data);
        }
        topics = new bytes32[](lg.topicCount);
        for (uint256 i; i < lg.topicCount; ++i) {
            topics[i] = Nb2Evm.topic(lg, i);
        }
        data = new bytes(lg.dataLen);
        uint256 dp = lg.dataPos;
        uint256 dl = lg.dataLen;
        assembly ("memory-safe") {
            calldatacopy(add(data, 32), dp, dl)
        }
    }
}
// forge-lint: disable-end(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)
