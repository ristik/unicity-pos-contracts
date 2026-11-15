// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {NativeBridgeVerifierV2} from "../../../src/nb2/verifier/NativeBridgeVerifierV2.sol";
import {Nb2Cbor as C} from "../../../src/nb2/verifier/Nb2Cbor.sol";
import {Nb2Rules as R} from "../../../src/nb2/verifier/Nb2Rules.sol";
import {Nb2Segment} from "../../../src/nb2/verifier/Nb2Segment.sol";
import {CertBatchDouble} from "./Nb2Doubles.sol";
import {Nb2Cert} from "../../../src/nb2/verifier/Nb2Cert.sol";
import {Nb2Crypto} from "../../../src/nb2/verifier/Nb2Crypto.sol";

/// @notice The verifier with metering of its two native calls. Test-only.
contract Nb2Harness is NativeBridgeVerifierV2 {
    constructor(bool testSet_) NativeBridgeVerifierV2(testSet_) {}

    struct Metered {
        bytes verdict;
        uint256 inside; // gas spent inside this call, measured here (no caller memory expansion)
        uint256 doubleGas; // gas spent calling the doubles (to be replaced by the native schedule)
        uint256 batchSchedule; // the native charge of every 0x0100 call
        uint256 memberSchedule; // the native charge of every 0x0102 call
        uint256 batchCalls;
        uint256 memberCalls;
    }

    function verifyMetered(bytes calldata gamma, bytes calldata evidence)
        external
        view
        returns (Metered memory m)
    {
        uint256 g0 = gasleft();
        Ctx memory ctx = _newCtx();
        (bytes32 d, bytes32 eta, uint64 a, bytes32 asset, address to, uint256 v) =
            _verify(ctx, gamma, evidence);
        m.inside = g0 - gasleft();
        m.verdict = abi.encode(d, eta, a, asset, to, v);
        m.doubleGas = ctx.meter[0];
        m.batchSchedule = ctx.meter[1];
        m.memberSchedule = ctx.meter[2];
        m.batchCalls = ctx.meter[3] >> 128;
        m.memberCalls = ctx.meter[3] & type(uint128).max;
    }

    function _certBatch(Ctx memory ctx, bytes memory req) internal view override returns (bool ok) {
        uint256 g = gasleft();
        ok = super._certBatch(ctx, req);
        (uint256 s,,,,,) = CertBatchDouble(CERT_BATCH).nb2Schedule(req);
        ctx.meter[0] += g - gasleft(); // the double and the schedule query, both replaced by the schedule
        ctx.meter[1] += s;
        ctx.meter[3] += 1 << 128;
    }

    function _membership(Ctx memory ctx, bytes memory req)
        internal
        view
        override
        returns (bool ok)
    {
        uint256 g = gasleft();
        ok = super._membership(ctx, req);
        ctx.meter[0] += g - gasleft();
        uint256 count = (req.length - 104 - 32) / 32;
        ctx.meter[2] += 2000 + 16 * req.length + 250 * (1 + count);
        ctx.meter[3] += 1;
    }
}

/// @notice The wallet's seal-receipt check (section 12.2) built from the verifier's own receipt path. Test-only.
contract SealReceiptHarness is NativeBridgeVerifierV2 {
    constructor(bool testSet_) NativeBridgeVerifierV2(testSet_) {}

    /// @notice VerifySealReceipt: a DepositProof container whose log is SegmentSealed(j) from the vault, verified as section
    ///         6.2 steps 2 to 5, topics [topic0(SegmentSealed), u256(j)] with j < 2^48, data of 128 + 32K bytes whose
    ///         identifiers are strictly sorted and whose heads link. Reverts with the inner rule (the wallet reports
    ///         SealReceipt wrapping it).
    function verifySealReceipt(bytes calldata gamma, bytes calldata receipt)
        external
        view
        returns (uint64 j, bytes32 headAfter)
    {
        Ctx memory ctx = _newCtx();
        ctx.cfg = _config(gamma);
        ctx.claims = new Claim[](1);
        ctx.claimIds = new bytes32[](16);
        uint256 p = _cdPos(receipt);
        if (receipt.length > MAX_JUSTIFICATION) C.fail(R.INPUT_TOO_LARGE);
        bytes4 e = C.scan(p, p + receipt.length, false);
        if (e != 0) C.fail(e);
        (Receipt memory r,) = _depositProof(p);
        (bytes32[] memory topics, bytes memory data) = _receiptLog(ctx, r);
        _require(ctx, topics.length == 2 && topics[0] == TOPIC_SEGMENT_SEALED, R.LOG_TOPICS);
        _require(ctx, uint256(topics[1]) >> 48 == 0, R.LOG_TOPICS);
        // forge-lint: disable-next-line(unsafe-typecast)
        j = uint64(uint256(topics[1]));
        uint256 k = ctx.cfg.k;
        _require(ctx, data.length == 128 + 32 * k, R.LOG_DATA);
        bytes4 segmentLog = bytes4(keccak256("SegmentLog()"));
        _require(
            ctx,
            uint256(_mword(data, 64)) == 0x60 && uint256(_mword(data, 96)) == 32 * k,
            segmentLog
        );
        bytes32[] memory z = new bytes32[](k);
        for (uint256 i; i < k; ++i) {
            z[i] = _mword(data, 128 + 32 * i);
        }
        (bool sorted, bytes32 m) = Nb2Segment.root(z);
        _require(ctx, sorted, segmentLog);
        headAfter = _mword(data, 32);
        _require(
            ctx, Nb2Segment.nextHead(ctx.cfg.d, j, _mword(data, 0), m) == headAfter, segmentLog
        );
        _flush(ctx);
    }
}

/// @notice Component costs for the NB2-05 report. Test-only.
contract Nb2Profile is NativeBridgeVerifierV2 {
    constructor() NativeBridgeVerifierV2(false) {}

    function pDecode(bytes calldata gamma, bytes calldata evidence)
        external
        view
        returns (uint256 g)
    {
        g = gasleft();
        Ctx memory ctx = _newCtx();
        ctx.cfg = _config(gamma);
        _evidence(ctx, evidence);
        g -= gasleft();
    }

    function pWalk(bytes calldata gamma, bytes calldata evidence)
        external
        view
        returns (uint256 g)
    {
        g = gasleft();
        Ctx memory ctx = _newCtx();
        ctx.cfg = _config(gamma);
        Tok memory t = _evidence(ctx, evidence);
        Tok[] memory chain = _walk(ctx, t);
        _initCtx(ctx, chain);
        _rootMint(ctx, chain[chain.length - 1]);
        g -= gasleft();
    }

    /// @notice The unlock rule over a given digest (the primitives' unlockRecovery vectors).
    function unlockCheck(bytes calldata key, bytes32 digest, bytes calldata unlock) external view {
        Ctx memory ctx = _newCtx();
        _unlockDigest(ctx, Nb2Crypto.keyAddress(_cdPos(key)), digest, _cdPos(unlock), unlock.length);
    }
}

/// @notice Primitive costs for the NB2-05 report (standalone, so the profilers stay below EIP-170). Test-only.
contract Nb2PrimitiveProfile {
    function _cdPos(bytes calldata b) internal pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := b.offset
        }
    }

    function pScan(bytes calldata evidence) external view returns (uint256 g) {
        g = gasleft();
        uint256 p = _cdPos(evidence);
        C.scan(p, p + evidence.length, true);
        g -= gasleft();
    }

    function pUc(bytes calldata uc) external view returns (uint256 g) {
        g = gasleft();
        bool ok;
        uint256 p = _cdPos(uc);
        Nb2Cert.Uc memory u;
        (ok, u) = Nb2Cert.parse(p, uc.length);
        ok = ok && Nb2Cert.valid(u, u.partition, 0, 0) && Nb2Cert.folds(u);
        Nb2Cert.claim(u, u.partition);
        g -= gasleft();
    }

    function pUcParse(bytes calldata uc) external view returns (uint256 g) {
        g = gasleft();
        Nb2Cert.parse(_cdPos(uc), uc.length);
        g -= gasleft();
    }

    function pKey(bytes calldata key) external view returns (uint256 g) {
        g = gasleft();
        Nb2Crypto.keyAddress(_cdPos(key));
        g -= gasleft();
    }
}
