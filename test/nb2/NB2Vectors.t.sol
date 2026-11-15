// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Test.sol";
import {NB2Gap} from "../../src/nb2/NB2Gap.sol";
import {
    INB2Vault,
    MockVerifierV2,
    NB2TestBase,
    ReenteringRecipient,
    RevertingRecipient
} from "./NB2TestBase.sol";

/// Calls the vault's gap-proof check on its own: a proof is valid for eta against root M (section 10.2).
contract GapCheck {
    error BadGapProof(uint256 position);

    function check(bytes32 eta, bytes calldata proof, bytes32 root, uint256 h) external pure {
        (bool ok, bytes32 r) = NB2Gap.root(uint256(eta), proof, h);
        if (!ok || r != root) revert BadGapProof(0);
    }
}

/// The NB2-03 shared vectors (native-bridge-plugins protocol/vectors/nb2/nb2-vectors.json, pinned by its sha256 and
/// converted by script/nb2-vectors.py) that apply to the vault: Γ at the constructor, the gap proofs, the chain folds and
/// every vault sequence, byte for byte: revert data, logs and the state after every step.
contract NB2VectorsTest is NB2TestBase {
    string internal constant FORGE = "test/nb2/vectors/nb2-vault-forge.json";
    string internal constant PINNED = "test/nb2/vectors/nb2-vectors.json";
    bytes internal constant MARKER = hex"deadbeef";

    struct Nb2Dep {
        string name;
        bool production;
        bytes gamma;
        bytes32 domain;
        uint256 K;
        uint256 B;
        bytes32 genesisHead;
        address vault;
        uint256 chainId;
        bytes32 verifierCodeHash;
        address verifier;
        uint256 qmax;
    }

    struct Nb2Cfg {
        string id;
        bool production;
        bytes gamma;
        address vault;
        uint256 chainId;
        bytes32 verifierCodeHash;
        bytes expectRevert;
        bytes32 domain;
    }

    struct Nb2Gap {
        string id;
        uint256 K;
        bytes32 eta;
        bytes32 root;
        bytes proof;
        bytes expectRevert;
    }

    struct Nb2Fold {
        string id;
        bytes32 domain;
        uint256 K;
        bytes32 eta;
        uint256 a;
        bytes history;
        bytes32 storedHead;
        bytes expectRevert;
    }

    struct Nb2Log {
        bytes32[] topics;
        bytes data;
    }

    struct Nb2State {
        uint256 deposits;
        uint256 segment;
        uint256 population;
        uint256 outstanding;
        bytes32 head;
        bytes32 previousHead;
        bytes32[] current;
        bytes32[] previous;
        bytes32 accounting;
        bytes32[] tags0;
        bytes32[] tags1;
    }

    struct Nb2Step {
        uint256 op;
        uint256 value;
        bytes firstOwner;
        bytes32 rho;
        bytes32 claimedEta;
        uint256 claimedStart;
        bytes history;
        bool verifierReverts;
        bytes verifierData;
        uint256 recipient;
        bytes expectRevert;
        bytes innerRevert;
        Nb2Log[] events;
        Nb2State post;
    }

    struct Nb2VaultVec {
        string id;
        string deployment;
        bool harness;
        Nb2State harnessState;
        Nb2Step[] steps;
        Nb2State finalState;
    }

    string internal constant T_DEP =
        "Nb2Dep(string name,bool production,bytes gamma,bytes32 domain,uint256 K,uint256 B,bytes32 genesisHead,address vault,uint256 chainId,bytes32 verifierCodeHash,address verifier,uint256 qmax)";
    string internal constant T_CFG =
        "Nb2Cfg(string id,bool production,bytes gamma,address vault,uint256 chainId,bytes32 verifierCodeHash,bytes expectRevert,bytes32 domain)";
    string internal constant T_GAP =
        "Nb2Gap(string id,uint256 K,bytes32 eta,bytes32 root,bytes proof,bytes expectRevert)";
    string internal constant T_FOLD =
        "Nb2Fold(string id,bytes32 domain,uint256 K,bytes32 eta,uint256 a,bytes history,bytes32 storedHead,bytes expectRevert)";
    string internal constant T_LOG = "Nb2Log(bytes32[] topics,bytes data)";
    string internal constant T_STATE =
        "Nb2State(uint256 deposits,uint256 segment,uint256 population,uint256 outstanding,bytes32 head,bytes32 previousHead,bytes32[] current,bytes32[] previous,bytes32 accounting,bytes32[] tags0,bytes32[] tags1)";
    string internal constant T_STEP =
        "Nb2Step(uint256 op,uint256 value,bytes firstOwner,bytes32 rho,bytes32 claimedEta,uint256 claimedStart,bytes history,bool verifierReverts,bytes verifierData,uint256 recipient,bytes expectRevert,bytes innerRevert,Nb2Log[] events,Nb2State post)";

    string internal json;

    function setUp() public {
        json = vm.readFile(FORGE);
    }

    /// The pinned file is the upstream one, and the forge-shaped file was converted from exactly it.
    function test_pinnedDigest() public view {
        bytes memory raw = vm.readFileBinary(PINNED);
        string memory pin = vm.readFile(string.concat(PINNED, ".sha256"));
        bytes32 want = vm.parseBytes32(string.concat("0x", vm.split(vm.trim(pin), " ")[0]));
        assertEq(sha256(raw), want, "nb2-vectors.json digest");
        assertEq(vm.parseJsonBytes32(json, ".sha256"), want, "converted from the pinned file");
    }

    // -------------------------------------------------------------------------------------------- deployment

    function _count(string memory path) internal view returns (uint256 n) {
        while (vm.keyExistsJson(json, string.concat(path, "[", vm.toString(n), "]"))) n++;
    }

    function _dep(string memory name) internal view returns (Nb2Dep memory d) {
        uint256 n = _count(".deployments");
        for (uint256 i = 0; i < n; i++) {
            d = abi.decode(
                vm.parseJsonType(json, string.concat(".deployments[", vm.toString(i), "]"), T_DEP),
                (Nb2Dep)
            );
            if (keccak256(bytes(d.name)) == keccak256(bytes(name))) return d;
        }
        revert(string.concat("no deployment ", name));
    }

    /// The preimage of a vector verifier code hash: the reference's fixture code hashes are keccak256 of short strings,
    /// so etching those bytes reproduces the exact EXTCODEHASH the constructor checks.
    function _codeFor(bytes32 h) internal pure returns (bytes memory) {
        if (h == keccak256("fixture-verifier-code")) return "fixture-verifier-code";
        if (h == keccak256("other")) return "other";
        revert("unknown verifier code hash");
    }

    /// Runs the constructor of the build at `target` and installs the runtime code; returns (ok, revert data).
    function _construct(bool production, bytes memory gamma, address target)
        internal
        returns (bool ok, bytes memory ret)
    {
        string memory art = production
            ? "NativeBridgeVaultV2.sol:NativeBridgeVaultV2"
            : "NativeBridgeVaultV2Test.sol:NativeBridgeVaultV2Test";
        vm.etch(target, bytes.concat(vm.getCode(art), abi.encode(gamma)));
        (ok, ret) = target.call("");
        if (ok) vm.etch(target, ret);
        else vm.etch(target, "");
    }

    function _deployVector(Nb2Dep memory d) internal returns (INB2Vault v) {
        vm.chainId(d.chainId);
        vm.etch(d.verifier, _codeFor(d.verifierCodeHash));
        (bool ok, bytes memory ret) = _construct(d.production, d.gamma, d.vault);
        assertTrue(ok, string.concat("deployment ", d.name, ": ", vm.toString(ret)));
        v = INB2Vault(d.vault);
        assertEq(v.domain(), d.domain, "D");
        assertEq(v.config(), d.gamma, "config()");
        (,,,, bytes32 head,) = v.state();
        assertEq(head, d.genesisHead, "H_0");
        // the codehash was checked at construction; the mock verifier takes over the address now
        vm.etch(d.verifier, type(MockVerifierV2).runtimeCode);
    }

    // -------------------------------------------------------------------------------------------- Γ at the constructor

    function test_configVectors() public {
        Nb2Dep memory main = _dep("main");
        uint256 n = _count(".config");
        assertGt(n, 20);
        for (uint256 i = 0; i < n; i++) {
            Nb2Cfg memory c = abi.decode(
                vm.parseJsonType(json, string.concat(".config[", vm.toString(i), "]"), T_CFG),
                (Nb2Cfg)
            );
            vm.chainId(c.chainId == 0 ? 31337 : c.chainId);
            vm.etch(main.verifier, _codeFor(c.verifierCodeHash));
            (bool ok, bytes memory ret) = _construct(c.production, c.gamma, c.vault);
            if (c.expectRevert.length == 0) {
                assertTrue(ok, c.id);
                assertEq(INB2Vault(c.vault).domain(), c.domain, c.id);
                assertEq(INB2Vault(c.vault).config(), c.gamma, c.id);
            } else {
                assertFalse(ok, c.id);
                assertEq(ret, c.expectRevert, c.id);
            }
        }
    }

    /// Every deployment's Γ is refused by the other build (section 4.1: never both).
    function test_buildsAreDisjoint() public {
        string[4] memory names = ["k4", "k8", "main", "sharded"];
        for (uint256 i = 0; i < names.length; i++) {
            Nb2Dep memory d = _dep(names[i]);
            vm.chainId(d.chainId);
            vm.etch(d.verifier, _codeFor(d.verifierCodeHash));
            (bool ok, bytes memory ret) = _construct(!d.production, d.gamma, d.vault);
            assertFalse(ok, d.name);
            assertEq(ret, abi.encodeWithSignature("BadConfig(uint256)", uint256(16)), d.name);
            (ok,) = _construct(d.production, d.gamma, d.vault);
            assertTrue(ok, d.name);
        }
    }

    // -------------------------------------------------------------------------------------------- gap proofs, chain folds

    function test_gapProofVectors() public {
        GapCheck g = new GapCheck();
        uint256 n = _count(".gapProofs");
        assertGt(n, 10);
        for (uint256 i = 0; i < n; i++) {
            Nb2Gap memory v = abi.decode(
                vm.parseJsonType(json, string.concat(".gapProofs[", vm.toString(i), "]"), T_GAP),
                (Nb2Gap)
            );
            uint256 h = 0;
            while ((1 << h) < v.K) h++;
            (bool ok, bytes memory ret) =
                address(g).call(abi.encodeCall(GapCheck.check, (v.eta, v.proof, v.root, h)));
            if (v.expectRevert.length == 0) assertTrue(ok, v.id);
            else assertEq(ret, v.expectRevert, v.id);
        }
    }

    /// Redeem step 3 on the real vault: the fold of `history` for eta from a must reach the stored head. The vault is put at
    /// c = a + P with H_c the vector's stored head; a passing fold reaches the verifier, which answers with a marker revert.
    function test_chainFoldVectors() public {
        uint256 n = _count(".chainFolds");
        assertGt(n, 5);
        string[2] memory names = ["k4", "k8"];
        for (uint256 i = 0; i < n; i++) {
            Nb2Fold memory f = abi.decode(
                vm.parseJsonType(json, string.concat(".chainFolds[", vm.toString(i), "]"), T_FOLD),
                (Nb2Fold)
            );
            Nb2Dep memory d;
            for (uint256 j = 0; j < names.length; j++) {
                d = _dep(names[j]);
                if (d.domain == f.domain) break;
            }
            if (d.domain != f.domain) d = _dep("main");
            assertEq(d.domain, f.domain, f.id);
            assertEq(d.K, f.K, f.id);
            uint256 snap = vm.snapshotState();
            INB2Vault v = _deployVector(d);
            uint256 h = 0;
            while ((1 << h) < d.K) h++;
            uint256 c = f.a + (f.history.length - 32) / (65 + 32 * h);
            vm.store(address(v), bytes32(0), bytes32(c << 152));
            vm.store(address(v), bytes32(1 + (c & 1)), f.storedHead);
            MockVerifierV2(d.verifier).set(true, MARKER);
            (bool ok, bytes memory ret) = address(v)
                .call(abi.encodeCall(INB2Vault.redeem, (hex"01", f.eta, uint64(f.a), f.history)));
            assertFalse(ok, f.id);
            if (f.expectRevert.length == 0) {
                assertEq(ret, abi.encodeWithSignature("VerifierRefused(bytes)", MARKER), f.id);
            } else {
                assertEq(ret, f.expectRevert, f.id);
            }
            vm.revertToStateAndDelete(snap);
        }
    }

    // -------------------------------------------------------------------------------------------- vault sequences

    /// One test per sequence (each runs in its own gas budget); 32 slots cover the file.
    uint256 internal constant VAULT_SLOTS = 32;

    function test_vaultVectorCount() public view {
        uint256 n = _count(".vault");
        assertGt(n, 25);
        assertLe(n, VAULT_SLOTS, "add test_vaultNN slots");
    }

    function test_vault00() public {
        _runVault(0);
    }

    function test_vault01() public {
        _runVault(1);
    }

    function test_vault02() public {
        _runVault(2);
    }

    function test_vault03() public {
        _runVault(3);
    }

    function test_vault04() public {
        _runVault(4);
    }

    function test_vault05() public {
        _runVault(5);
    }

    function test_vault06() public {
        _runVault(6);
    }

    function test_vault07() public {
        _runVault(7);
    }

    function test_vault08() public {
        _runVault(8);
    }

    function test_vault09() public {
        _runVault(9);
    }

    function test_vault10() public {
        _runVault(10);
    }

    function test_vault11() public {
        _runVault(11);
    }

    function test_vault12() public {
        _runVault(12);
    }

    function test_vault13() public {
        _runVault(13);
    }

    function test_vault14() public {
        _runVault(14);
    }

    function test_vault15() public {
        _runVault(15);
    }

    function test_vault16() public {
        _runVault(16);
    }

    function test_vault17() public {
        _runVault(17);
    }

    function test_vault18() public {
        _runVault(18);
    }

    function test_vault19() public {
        _runVault(19);
    }

    function test_vault20() public {
        _runVault(20);
    }

    function test_vault21() public {
        _runVault(21);
    }

    function test_vault22() public {
        _runVault(22);
    }

    function test_vault23() public {
        _runVault(23);
    }

    function test_vault24() public {
        _runVault(24);
    }

    function test_vault25() public {
        _runVault(25);
    }

    function test_vault26() public {
        _runVault(26);
    }

    function test_vault27() public {
        _runVault(27);
    }

    function test_vault28() public {
        _runVault(28);
    }

    function test_vault29() public {
        _runVault(29);
    }

    function test_vault30() public {
        _runVault(30);
    }

    function test_vault31() public {
        _runVault(31);
    }

    function _vec(uint256 i) internal view returns (Nb2VaultVec memory v) {
        string memory t = string.concat(
            "Nb2VaultVec(string id,string deployment,bool harness,Nb2State harnessState,Nb2Step[] steps,Nb2State finalState)",
            T_LOG,
            T_STATE,
            T_STEP
        );
        v = abi.decode(
            vm.parseJsonType(json, string.concat(".vault[", vm.toString(i), "]"), t), (Nb2VaultVec)
        );
    }

    function _runVault(uint256 i) internal {
        if (i >= _count(".vault")) return;
        Nb2VaultVec memory vv = _vec(i);
        Nb2Dep memory d = _dep(vv.deployment);
        uint256 snap = vm.snapshotState();
        INB2Vault v = _deployVector(d);
        if (vv.harness) _inject(v, d, vv.harnessState);
        address etched;
        for (uint256 s = 0; s < vv.steps.length; s++) {
            Nb2Step memory st = vv.steps[s];
            string memory where = string.concat(vv.id, " step ", vm.toString(s));
            bytes memory cd;
            uint256 value = 0;
            address rcp;
            if (st.op == 0) {
                cd = abi.encodeCall(INB2Vault.deposit, (st.firstOwner, st.rho));
                value = st.value;
                vm.deal(address(this), address(this).balance + value);
            } else {
                MockVerifierV2(d.verifier).set(st.verifierReverts, st.verifierData);
                if (!st.verifierReverts && st.verifierData.length >= 160) {
                    rcp = address(uint160(uint256(_word(st.verifierData, 128))));
                }
                etched = _recipient(v, rcp, st.recipient, etched);
                cd = abi.encodeCall(
                    INB2Vault.redeem, (hex"01", st.claimedEta, uint64(st.claimedStart), st.history)
                );
            }
            uint256 before = rcp == address(0) ? 0 : rcp.balance;
            vm.recordLogs();
            (bool ok, bytes memory ret) = address(v).call{value: value}(cd);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            if (st.expectRevert.length == 0) {
                assertTrue(ok, string.concat(where, ": ", vm.toString(ret)));
            } else {
                assertFalse(ok, where);
                assertEq(ret, st.expectRevert, where);
            }
            // forge records the logs of a reverted frame too; a failed transaction has none on chain (section 13.2)
            if (!ok) {
                assertEq(st.events.length, 0, where);
                delete logs;
            }
            assertEq(logs.length, st.events.length, string.concat(where, " log count"));
            for (uint256 l = 0; l < logs.length; l++) {
                assertEq(logs[l].emitter, address(v), where);
                assertEq(logs[l].topics, st.events[l].topics, where);
                assertEq(logs[l].data, st.events[l].data, where);
            }
            if (st.innerRevert.length != 0) {
                assertEq(
                    ReenteringRecipient(payable(rcp)).inner(),
                    st.innerRevert,
                    string.concat(where, " inner")
                );
            }
            if (ok && st.op == 1) {
                uint256 amount = uint256(_word(st.verifierData, 160));
                // the recipient receives exactly the verdict's amount (a re-entering one's inner call reverts)
                assertEq(rcp.balance - before, amount, string.concat(where, " payout"));
            }
            _checkState(v, d, st.post, where);
        }
        _checkState(v, d, vv.finalState, string.concat(vv.id, " final"));
        vm.revertToStateAndDelete(snap);
    }

    function _recipient(INB2Vault v, address rcp, uint256 mode, address etched)
        internal
        returns (address)
    {
        if (rcp == address(0) || rcp == address(v)) return etched;
        if (mode == 0) {
            if (etched == rcp) vm.etch(rcp, "");
            return etched == rcp ? address(0) : etched;
        }
        if (mode == 1) vm.etch(rcp, address(new RevertingRecipient()).code);
        else vm.etch(rcp, address(new ReenteringRecipient(v, mode == 3)).code);
        return rcp;
    }

    function _word(bytes memory b, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), off))
        }
    }

    // -------------------------------------------------------------------------------------------- state

    function _ids(address v, uint256 k, uint256 p, uint256 n)
        internal
        view
        returns (bytes32[] memory out)
    {
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = vm.load(v, bytes32(16 + p * k + i));
        }
    }

    function _checkState(INB2Vault v, Nb2Dep memory d, Nb2State memory s, string memory where)
        internal
        view
    {
        (uint64 deposits, uint64 seg, uint16 pop, uint256 q, bytes32 head, bytes32 prev) = v.state();
        assertEq(deposits, s.deposits, string.concat(where, " deposits"));
        assertEq(seg, s.segment, string.concat(where, " segment"));
        assertEq(pop, s.population, string.concat(where, " population"));
        assertEq(q, s.outstanding, string.concat(where, " outstanding"));
        assertEq(head, s.head, string.concat(where, " head"));
        assertEq(prev, s.previousHead, string.concat(where, " previousHead"));
        assertEq(
            vm.load(address(v), bytes32(0)), s.accounting, string.concat(where, " accounting word")
        );
        assertEq(s.tags0.length, 1, where);
        assertEq(s.tags1.length, 1, where);
        assertEq(
            vm.load(address(v), bytes32(uint256(3))),
            s.tags0[0],
            string.concat(where, " tag word 0")
        );
        assertEq(
            vm.load(address(v), bytes32(uint256(4))),
            s.tags1[0],
            string.concat(where, " tag word 1")
        );
        uint256 p = s.segment & 1;
        assertEq(
            _ids(address(v), d.K, p, s.population),
            s.current,
            string.concat(where, " current buffer")
        );
        assertEq(
            _ids(address(v), d.K, p ^ 1, s.segment == 0 ? 0 : d.K),
            s.previous,
            string.concat(where, " previous buffer")
        );
    }

    /// The reference's SetState: the accounting word, the heads by parity, the live identifiers and the tag words.
    function _inject(INB2Vault v, Nb2Dep memory d, Nb2State memory s) internal {
        address a = address(v);
        vm.store(a, bytes32(0), s.accounting);
        vm.store(a, bytes32(1 + (s.segment & 1)), s.head);
        if (s.segment > 0) vm.store(a, bytes32(1 + ((s.segment - 1) & 1)), s.previousHead);
        vm.store(a, bytes32(uint256(3)), s.tags0[0]);
        vm.store(a, bytes32(uint256(4)), s.tags1[0]);
        uint256 p = s.segment & 1;
        for (uint256 i = 0; i < s.current.length; i++) {
            vm.store(a, bytes32(16 + p * d.K + i), s.current[i]);
        }
        for (uint256 i = 0; i < s.previous.length; i++) {
            vm.store(a, bytes32(16 + (p ^ 1) * d.K + i), s.previous[i]);
        }
        _checkState(v, d, s, "harness");
    }
}
