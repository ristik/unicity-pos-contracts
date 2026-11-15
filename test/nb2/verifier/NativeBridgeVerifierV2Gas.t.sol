// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test, console} from "forge-std/Test.sol";
import {CertBatchDouble, MembershipDouble} from "./Nb2Doubles.sol";
import {Nb2Harness, Nb2Profile} from "./Nb2Harness.sol";

/// @notice Gas and evidence bytes of the token verifier (NB2-05 report). The natives are doubles, so each measurement removes
///         the gas spent in them and adds their native schedule (b1ref limits.go: CERT_BATCH_V2 and the RSMT membership) and
///         a warm precompile call (100) per call. Calldata is priced at Cancun rates (16 per nonzero, 4 per zero byte).
contract NativeBridgeVerifierV2GasTest is Test {
    string internal constant VECTORS = "test/nb2/vectors/nb2-vectors.json";
    string internal constant LARGE = "test/nb2/verifier/large.json";
    string internal constant TRUST = "test/nb2/verifier/trust.json";

    Nb2Harness internal h;

    function setUp() public {
        vm.etch(address(0x0100), type(CertBatchDouble).runtimeCode);
        vm.etch(address(0x0102), type(MembershipDouble).runtimeCode);
        string memory t = vm.readFile(TRUST);
        CertBatchDouble b = CertBatchDouble(payable(address(0x0100)));
        b.nb2Reset(vm.parseJsonUint(t, ".main.network"));
        uint256[] memory epochs = vm.parseJsonUintArray(t, ".main.epochs");
        uint256[] memory starts = vm.parseJsonUintArray(t, ".main.starts");
        uint256[] memory ends = vm.parseJsonUintArray(t, ".main.ends");
        uint256[] memory totals = vm.parseJsonUintArray(t, ".main.totals");
        for (uint256 i; i < epochs.length; ++i) {
            b.nb2Epoch(epochs[i], starts[i], ends[i], totals[i]);
        }
        uint256[] memory me = vm.parseJsonUintArray(t, ".main.memberEpochs");
        bytes[] memory ids = vm.parseJsonBytesArray(t, ".main.memberIds");
        bytes[] memory keys = vm.parseJsonBytesArray(t, ".main.memberKeys");
        for (uint256 i; i < me.length; ++i) {
            b.nb2Member(me[i], ids[i], keys[i]);
        }
        h = new Nb2Harness(false);
    }

    struct Row {
        uint256 total; // verifier execution with native schedules
        uint256 batch;
        uint256 member;
        uint256 calldataGas;
        uint256 bytes_;
    }

    function _measure(bytes memory gamma, bytes memory ev, bytes memory verdict)
        internal
        view
        returns (Row memory r)
    {
        Nb2Harness.Metered memory m = h.verifyMetered(gamma, ev);
        uint256 used = m.inside;
        assertEq(keccak256(m.verdict), keccak256(verdict), "verdict");
        uint256 calls = m.batchCalls + m.memberCalls;
        r.batch = m.batchSchedule;
        r.member = m.memberSchedule;
        r.total = used - m.doubleGas + m.batchSchedule + m.memberSchedule + 100 * calls;
        for (uint256 i; i < ev.length; ++i) {
            r.calldataGas += ev[i] == 0 ? 4 : 16;
        }
        r.bytes_ = ev.length;
    }

    function _log(string memory id, Row memory r) internal pure {
        console.log(
            string.concat(
                id,
                " bytes=",
                vm.toString(r.bytes_),
                " verifier=",
                vm.toString(r.total),
                " batch=",
                vm.toString(r.batch),
                " member=",
                vm.toString(r.member),
                " calldata=",
                vm.toString(r.calldataGas),
                " total=",
                vm.toString(r.total + r.calldataGas)
            )
        );
    }

    function _vector(string memory j, string memory id)
        internal
        pure
        returns (bytes memory ev, bytes memory verdict)
    {
        for (uint256 i;; ++i) {
            string memory b = string.concat(".verifier[", vm.toString(i), "]");
            if (
                keccak256(bytes(vm.parseJsonString(j, string.concat(b, ".id"))))
                    == keccak256(bytes(id))
            ) {
                return (
                    vm.parseJsonBytes(j, string.concat(b, ".evidence")),
                    vm.parseJsonBytes(j, string.concat(b, ".verdict.abi"))
                );
            }
        }
    }

    /// The design's reference token (deposit 100, transfer, split 60 + 40, split 40 into 15 + 25, transfers, burn) and the
    /// smallest returns, with their gas ceilings.
    function test_gasReferenceTokens() public view {
        string memory j = vm.readFile(VECTORS);
        bytes memory gamma = vm.parseJsonBytes(j, ".deployments.main.gamma");
        string[6] memory ids = [
            "ok-no-intermediate-transfer",
            "ok-legacy-receipt",
            "ok-split-60",
            "ok-split-40-15",
            "ok-split-40-25",
            "ok-lineage-depth-20"
        ];
        // Verifier execution with the native schedules, excluding calldata: measured + about 10 %.
        uint256[6] memory ceilings =
            [uint256(750_000), 900_000, 1_400_000, 1_850_000, 1_850_000, 14_500_000];
        for (uint256 i; i < ids.length; ++i) {
            (bytes memory ev, bytes memory verdict) = _vector(j, ids[i]);
            Row memory r = _measure(gamma, ev, verdict);
            _log(ids[i], r);
            assertLe(r.total, ceilings[i], "gas ceiling");
        }
    }

    function test_profile() public {
        string memory j = vm.readFile(VECTORS);
        bytes memory gamma = vm.parseJsonBytes(j, ".deployments.main.gamma");
        (bytes memory ev,) = _vector(j, "ok-legacy-receipt");
        Nb2Profile p = new Nb2Profile();
        console.log("scan", p.pScan(ev));
        console.log(
            "scan 33 items",
            p.pScan(
                hex"9820000102030405060708090a0b0c0d0e0f1011121314151617181818191819181a181b181c181d181e181f"
            )
        );
        uint256 decode = p.pDecode(gamma, ev);
        uint256 origin = p.pWalk(gamma, ev) - decode;
        console.log("config+decode", decode);
        console.log("origin (J, receipt, header, trie, log; its batch claim excluded)", origin);
        assertLe(origin, 210_000, "origin receipt ceiling");
        bytes memory uc = vm.parseJsonBytes(vm.readFile("test/nb2/verifier/profile-uc.json"), ".uc");
        console.log("uc parse", p.pUcParse(uc));
        console.log("uc parse+valid+folds+claim", p.pUc(uc));
        console.log(
            "key decompress",
            p.pKey(hex"03c3c8afe64023aa65a1d8e3334437cd09852c863089db75b9456e82f5d47ede22")
        );
    }

    /// Transfer chains and split lineages from the same deterministic "main" world as the vectors
    /// (script/nb2/large_tokens_test.go.txt, run in a bft-core checkout of the reference); a subset is committed.
    function test_gasLargeTokens() public view {
        if (!vm.exists(LARGE)) return;
        string memory l = vm.readFile(LARGE);
        bytes memory gamma = vm.parseJsonBytes(l, ".gamma");
        for (
            uint256 i; vm.keyExistsJson(l, string.concat(".tokens[", vm.toString(i), "].id")); ++i) {
            string memory b = string.concat(".tokens[", vm.toString(i), "]");
            Row memory r = _measure(
                gamma,
                vm.parseJsonBytes(l, string.concat(b, ".evidence")),
                vm.parseJsonBytes(l, string.concat(b, ".verdict"))
            );
            _log(vm.parseJsonString(l, string.concat(b, ".id")), r);
        }
    }
}
