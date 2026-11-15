// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {EchoVerifierV2, INB2Vault, NB2Ref, NB2TestBase} from "./NB2TestBase.sol";

/// Gas of the production vault (K = 64, B = 16) with the bake-off's stateless mock verifier: replay and settlement only, no token evidence.
///
/// test_gasCeilings runs in CI: four measured calls (deposit, plain redeem, redeem over ten historical segments, the sealing
/// redeem), each with the vault, the verifier and the recipient cooled first (vm.cool), so every account and slot is cold
/// as in a wallet's transaction. vm.lastFrameGas().gasTotalUsed is the transaction's gas (21,000 base and calldata
/// included). The figures are recorded in snapshots/NB2VaultGas.json and bounded by the ceilings below.
///
/// test_gasTable re-measures the NB2-02 bake-off rows (unicity-pos-contracts bench/nb2, RESULTS.md) on the real vault. It
/// only runs with NB2_GAS_TABLE=1 and `forge test --isolate`, which makes every top-level call its own transaction, so
/// vm.lastFrameGas().gasTotalUsed is the whole transaction's gas, as in the bake-off.
contract NB2VaultGasTest is NB2TestBase {
    uint256 internal constant K = 64;
    uint256 internal constant B = 16;
    uint256 internal constant AMOUNT = 1 ether;

    // CI ceilings (transaction gas, cold; measured 31,739 / 62,021 / 126,307 / 297,964): measured + about 5%.
    uint256 internal constant CEIL_DEPOSIT = 33_500;
    uint256 internal constant CEIL_REDEEM = 65_500;
    uint256 internal constant CEIL_REDEEM_P10 = 133_000;
    uint256 internal constant CEIL_SEAL = 313_000;

    function setUp() public {
        vm.deal(address(this), 1e40);
        vm.deal(RECIPIENT, 1);
    }

    // -------------------------------------------------------------------------------------------- helpers

    function _world() internal returns (World memory w) {
        w = deploy(K, B, (1 << 144) - 1);
        vm.etch(address(w.mock), type(EchoVerifierV2).runtimeCode);
        w.v.deposit{value: 1e30}(owner(), keccak256("first"));
    }

    function _cool(World memory w) internal {
        vm.cool(address(w.v));
        vm.cool(address(w.mock));
        vm.cool(RECIPIENT);
    }

    /// One measured redeem: (call gas, transaction gas, calldata bytes).
    function _measureRedeem(World memory w, bytes32 eta, uint256 a, bytes memory h)
        internal
        returns (uint256 gas, uint256 txGas, uint256 cdLen)
    {
        bytes memory ev = verdict(w, eta, a, RECIPIENT, AMOUNT);
        bytes memory cd = abi.encodeCall(INB2Vault.redeem, (ev, eta, uint64(a), h));
        _cool(w);
        w.v.redeem(ev, eta, uint64(a), h);
        Vm.Gas memory g = vm.lastFrameGas();
        gas = g.gasTotalUsed;
        cdLen = cd.length;
        txGas = gas;
        mirrorPaid(w, eta);
    }

    function _measureDeposit(World memory w, string memory tag)
        internal
        returns (uint256 gas, uint256 txGas)
    {
        bytes32 rho = keccak256(bytes(tag));
        _cool(w);
        w.v.deposit{value: 1 ether}(owner(), rho);
        gas = vm.lastFrameGas().gasTotalUsed;
        txGas = gas;
    }

    // -------------------------------------------------------------------------------------------- CI ceilings

    function test_gasCeilings() public {
        World memory w = _world();
        fill(w, 2 * K, B); // steady state: every slot nonzero from here on
        fill(w, 10 * K, B); // c = 12
        assertEq(w.c, 12);
        fill(w, K / 2, B); // m = K/2

        (uint256 gDeposit,) = _measureDeposit(w, "steady");
        vm.snapshotGasLastFrame("NB2VaultGas", "deposit");

        (uint256 gRedeem,,) = _measureRedeem(w, nextEta(w, B), w.c, "");
        vm.snapshotGasLastFrame("NB2VaultGas", "redeem_m32");

        bytes32 eta = nextEta(w, B);
        (, bytes memory h) = history(w, eta, w.c - 10, w.c);
        (uint256 gP10,,) = _measureRedeem(w, eta, w.c - 10, h);
        vm.snapshotGasLastFrame("NB2VaultGas", "redeem_P10_m33");

        fill(w, K - 1 - w.cur.length, B); // m = K-1
        (uint256 gSeal,,) = _measureRedeem(w, nextEta(w, B), w.c, "");
        vm.snapshotGasLastFrame("NB2VaultGas", "redeem_seal_uniform");
        assertEq(w.cur.length, 0, "sealed");
        checkState(w);

        assertLe(gDeposit, CEIL_DEPOSIT, "deposit ceiling");
        assertLe(gRedeem, CEIL_REDEEM, "plain redeem ceiling");
        assertLe(gP10, CEIL_REDEEM_P10, "ten-segment redeem ceiling");
        assertLe(gSeal, CEIL_SEAL, "sealing redeem ceiling");
    }

    // -------------------------------------------------------------------------------------------- the bake-off table

    struct Row {
        string name;
        uint256 txGas;
        uint256 bench;
    }

    Row[] internal rows;

    function _row(string memory name, uint256 txGas, uint256 bench) internal {
        rows.push(Row(name, txGas, bench));
    }

    /// The bake-off's identifier sequences: uniform, or ground into one bucket in sort-adversarial arrival order.
    function _adversarial(uint256 n) internal pure returns (uint256[] memory out) {
        uint256[] memory r = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            r[i] = i;
        }
        return _adv(r);
    }

    function _adv(uint256[] memory ranks) internal pure returns (uint256[] memory out) {
        uint256 n = ranks.length;
        out = new uint256[](n);
        if (n <= 8) {
            for (uint256 i = 0; i < n; i++) {
                out[i] = ranks[n - 1 - i];
            }
            return out;
        }
        uint256[] memory ev = new uint256[](n / 2);
        uint256[] memory od = new uint256[](n / 2);
        for (uint256 i = 0; i < n / 2; i++) {
            ev[i] = ranks[2 * i];
            od[i] = ranks[2 * i + 1];
        }
        ev = _adv(ev);
        od = _adv(od);
        for (uint256 i = 0; i < n / 2; i++) {
            out[i] = ev[i];
            out[n / 2 + i] = od[i];
        }
    }

    /// Bucket-5 identifier whose rank within its segment is perm[m] (sort-adversarial arrival).
    function _advEta(World memory w, uint256[] memory perm) internal pure returns (bytes32) {
        w.ctr++;
        uint256 x = uint256(keccak256(abi.encode("adv", w.ctr)));
        uint256 m = w.cur.length;
        return
            bytes32(
                (uint256(5) << 252) | (perm[m] << 244) | ((w.c & 0xffffffff) << 212) | (x >> 44)
            );
    }

    function _fillAdv(World memory w, uint256 target, uint256[] memory perm) internal {
        while (w.cur.length != target) pay(w, _advEta(w, perm));
    }

    function _print() internal view {
        for (uint256 i = 0; i < rows.length; i++) {
            int256 diff = int256(rows[i].txGas) - int256(rows[i].bench);
            console.log(
                string.concat(
                    "| ",
                    rows[i].name,
                    " | ",
                    vm.toString(rows[i].txGas),
                    " | ",
                    vm.toString(rows[i].bench),
                    " | ",
                    vm.toString(diff),
                    " |"
                )
            );
        }
    }

    function _table() internal view returns (bool) {
        return vm.envOr("NB2_GAS_TABLE", false);
    }

    function test_gasTable1_uniform() public {
        if (!_table()) return;
        {
            World memory w = deploy(K, B, (1 << 144) - 1);
            vm.etch(address(w.mock), type(EchoVerifierV2).runtimeCode);
            (, uint256 first) = _measureDeposit(w, "first");
            (, uint256 steady) = _measureDeposit(w, "steady");
            _row("deposit, first", first, 48_758);
            _row("deposit, steady", steady, 31_670);
        }
        World memory u = _world();
        fill(u, 2 * K, B); // steady state: segment 2
        (, uint256 cheapest,) = _measureRedeem(u, nextEta(u, B), u.c, "");
        _row("uniform, current, m = 0 (cheapest)", cheapest, 53_574);
        fill(u, K / 2 - 1, B);
        (, uint256 t,) = _measureRedeem(u, nextEta(u, B), u.c, "");
        _row("uniform, current, m = K/2 (typical)", t, 63_791);
        (, t,) = _measureRedeem(u, nextEta(u, B), u.c - 1, "");
        _row("uniform, previous, m = K/2 + 1", t, 78_083);
        fill(u, K - 2 - u.cur.length, B); // m = K-2
        (, t,) = _measureRedeem(u, nextEta(u, B), u.c - 1, "");
        _row("uniform, previous, m = K-2", t, 88_013);
        (, t,) = _measureRedeem(u, nextEta(u, B), u.c, "");
        _row("seal, uniform (m = K-1)", t, 299_630);
        _print();
    }

    function test_gasTable2_oneBucket() public {
        if (!_table()) return;
        uint256[] memory perm = _adversarial(K);
        World memory w = _world();
        for (uint256 i = 0; i < 2 * K; i++) {
            pay(w, _advEta(w, perm));
        }
        // the steady cheapest call, for the envelope: uniform, current, m = 0
        (, uint256 cheapest,) = _measureRedeem(w, nextEta(w, B), w.c, "");
        _fillAdv(w, K - 1, perm);
        (, uint256 seal,) = _measureRedeem(w, _advEta(w, perm), w.c, "");
        _row("seal, one bucket, sort-adversarial", seal, 342_766);
        // worst: previous endpoint, m = K-1, every identifier in the claimed bucket: 2K-1 reads, then the seal
        _fillAdv(w, K - 1, perm);
        (, uint256 worst,) = _measureRedeem(w, _advEta(w, perm), w.c - 1, "");
        _row("worst: previous, m = K-1, one bucket", worst, 487_339);
        _row("envelope (worst - cheapest), steady", worst - cheapest, 433_765);
        _print();
        assertLe(worst - cheapest, 500_000, "the gasReserve covers the measured envelope");
    }

    /// P historical segments, built by the reference; the vault's counter and endpoint head are moved there with vm.store,
    /// unmeasured, as in the bake-off.
    function test_gasTable3_history() public {
        if (!_table()) return;
        World memory w = _world();
        fill(w, 2 * K, B);
        uint256 base = w.c;
        uint256 n = 100;
        bytes32[][] memory segs = new bytes32[][](base + n);
        bytes32[] memory heads = new bytes32[](base + n + 1);
        for (uint256 j = 0; j < base; j++) {
            segs[j] = w.segs[j];
            heads[j] = w.heads[j];
        }
        heads[base] = w.heads[base];
        for (uint256 j = base; j < base + n; j++) {
            bytes32[] memory ids = new bytes32[](K);
            for (uint256 i = 0; i < K; i++) {
                ids[i] = keccak256(abi.encode("hist", j, i));
            }
            segs[j] = NB2Ref.sorted(ids);
            heads[j + 1] = NB2Ref.step(w.d, j, heads[j], NB2Ref.root(segs[j]));
        }
        w.segs = segs;
        w.heads = heads;
        w.c = base + n;
        uint256 acc = uint256(vm.load(address(w.v), bytes32(0)));
        acc = (acc & ~(uint256((1 << 56) - 1) << 144)) | (w.c << 152);
        vm.store(address(w.v), bytes32(0), bytes32(acc));
        vm.store(address(w.v), bytes32(1 + (w.c & 1)), heads[w.c]);
        vm.store(address(w.v), bytes32(1 + ((w.c - 1) & 1)), heads[w.c - 1]);
        uint256[3] memory ps = [uint256(1), 10, 100];
        uint256[3] memory bench = [uint256(72_852), 126_393, 661_926];
        for (uint256 i = 0; i < 3; i++) {
            bytes32 eta = nextEta(w, B);
            (, bytes memory h) = history(w, eta, w.c - ps[i], w.c);
            (, uint256 t, uint256 cdl) = _measureRedeem(w, eta, w.c - ps[i], h);
            _row(
                string.concat("P = ", vm.toString(ps[i]), " (calldata ", vm.toString(cdl), " B)"),
                t,
                bench[i]
            );
        }
        _print();
    }
}
