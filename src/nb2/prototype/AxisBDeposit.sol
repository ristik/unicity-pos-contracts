// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {AxisBVerifierCore} from "./AxisBVerifierCore.sol";
import {Nb2ReceiptVerifier} from "../verifier/Nb2ReceiptVerifier.sol";
import {Nb2Cbor as C} from "../verifier/Nb2Cbor.sol";
import {AxisBCommitment as W} from "./AxisBCommitment.sol";
import {Nb2Rules as R} from "../verifier/Nb2Rules.sol";

/// @dev Isolate receipt checks to leave room for the parser and resumption
/// control under EIP-170. The root mint is bounded by the ordinary J cap.
contract AxisBDeposit is AxisBVerifierCore {
    bytes32 private constant PROGRESS = keccak256("AxisBProgress(bytes32,bytes32)");
    error InvalidState();

    constructor(bool testSet, Nb2ReceiptVerifier receipts) AxisBVerifierCore(testSet, receipts) {}

    function verify(bytes calldata gamma, bytes calldata mint) external view {
        uint256 p = _cdPos(mint);
        if (mint.length > MAX_JUSTIFICATION + 512) C.fail(R.INPUT_TOO_LARGE);
        bytes4 rule = C.scan(p, p + mint.length, false);
        if (rule != 0) C.fail(rule);
        Ctx memory ctx = _newCtx();
        ctx.cfg = _config(gamma);
        ctx.claims = new Claim[](1);
        ctx.claimIds = new bytes32[](16);
        Tok memory t;
        Step memory s = t.mint;
        uint256 q = C.tagged(p, TAG_MINT);
        q = C.array(q, 8);
        q = C.version(q, 2);
        (t.network, q) = C.uintIn(q, 1, type(uint16).max);
        q = _pred(ctx, s.recipient, q);
        (s.mask, q) = C.bytes32At(q);
        (t.ty, q) = C.bytes32At(q);
        (t.justNull, t.justPos, t.justLen, q) = C.nullable(q);
        (s.dataNull, s.dataPos, s.dataLen, q) = C.nullable(q);
        (s.dlSet, s.dl, q) = C.deadline(q);
        if (q != p + mint.length) C.fail(R.TRAILING);
        _rootMint(ctx, t);
        _flush(ctx);
    }

    function verifyProgress(
        bytes calldata gamma,
        address emitter,
        bytes32 session,
        bytes32 digest,
        bytes calldata proof
    ) external view {
        Ctx memory ctx = _newCtx();
        ctx.cfg = _config(gamma);
        ctx.cfg.vault = emitter;
        ctx.claims = new Claim[](1);
        ctx.claimIds = new bytes32[](16);
        uint256 offset = _cdPos(proof);
        if (proof.length > MAX_JUSTIFICATION || C.scan(offset, offset + proof.length, false) != 0) {
            revert W.InvalidWitness();
        }
        (Receipt memory receipt, uint256 end) = _depositProof(offset);
        if (end != offset + proof.length) revert W.InvalidWitness();
        (bytes32[] memory topics, bytes memory data) = _receiptLog(ctx, receipt);
        _flush(ctx);
        if (
            topics.length != 2 || topics[0] != PROGRESS || topics[1] != session || data.length != 32
                || _mword(data, 0) != digest
        ) revert InvalidState();
    }
}
