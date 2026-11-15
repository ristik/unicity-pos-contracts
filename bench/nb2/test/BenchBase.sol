// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test, Vm} from "forge-std/Test.sol";
import {MockVerifier} from "../src/MockVerifier.sol";
import {Ref} from "./Ref.sol";

interface IV {
    function redeem(bytes calldata evidence, bytes32 claimedEta, uint64 claimedStart, bytes calldata history) external;
    function deposit(bytes calldata firstOwner, bytes32 rho) external payable;
    function domain() external view returns (bytes32);
    function state()
        external
        view
        returns (
            uint64 deposits,
            uint64 segment,
            uint16 population,
            uint256 outstanding,
            bytes32 head,
            bytes32 previousHead
        );
}

/// Workload drivers of the NB2-02 bake-off. Every measured call is a top-level call of the test
/// contract, which forge runs (with --isolate) as its own transaction: the gas recorded is
/// vm.lastCallGas().gasTotalUsed, the whole transaction's gas (21,000 base and calldata included),
/// with every account and slot cold, as a wallet's transaction meets them.
contract BenchBase is Test {
    struct Cfg {
        string art;
        uint256 K;
        uint256 B;
        uint8 lay; // 0 tags, 1 sparse
        uint8 commit; // Ref.GAP, MP, RADIX, RAW
        bool imm;
        string lname;
        string cname;
        string form;
    }

    struct Run {
        IV v;
        bytes32 d;
        Cfg c;
        uint8 dist; // 0 uniform; one bucket: 1 random order, 2 descending arrival, 3 sort-adversarial
        uint256[] perm; // dist 3: arrival position -> rank within the segment
        uint256 ctr;
        uint256 bucket;
        uint256 seg; // mirror of c
        uint256 m; // mirror of m
        uint256[] cur; // identifiers paid into the current segment, in arrival order
        string file;
        string group;
    }

    bytes32 internal constant ASSET = 0x87b0b8b600fcd942cc3383bac1dbb80fd69d54af700cf48faa4525451a7b1845;
    bytes32 internal constant TOPIC_SEALED = 0x06e724201a1c72937156cbdb3b9522d26b3818ee33ace10cd7cda65bb9cae916;
    address internal constant RECIPIENT = address(0x00000000000000000000000000000000000BeeF0);
    uint256 internal constant AMOUNT = 1 ether;
    string internal constant DIR = "results/";

    MockVerifier internal verifier;

    function setUp() public virtual {
        verifier = new MockVerifier();
        vm.deal(RECIPIENT, 1);
        vm.deal(address(this), 1e40);
    }

    // ------------------------------------------------------------------ deployment and helpers
    function _gamma(uint256 k, uint256 b) internal pure returns (bytes memory g) {
        // Γ of a realistic encoded length (342 bytes, spec 4.1); its content is irrelevant here.
        g = new bytes(342);
        for (uint256 i = 0; i < 342; i++) {
            g[i] = bytes1(uint8(uint256(keccak256(abi.encode("gamma", k, b, i)))));
        }
    }

    function _owner() internal pure returns (bytes memory) {
        return bytes.concat(hex"d9987883014101582102", keccak256("key"));
    }

    function _start(Cfg memory c, uint8 dist, string memory group) internal returns (Run memory r) {
        r.c = c;
        r.dist = dist;
        r.group = group;
        r.v = IV(
            deployCode(string.concat(c.art, ".sol:", c.art), abi.encode(_gamma(c.K, c.B), address(verifier), c.K, c.B))
        );
        r.d = r.v.domain();
        r.bucket = 5 % c.B;
        r.cur = new uint256[](c.K);
        uint256[] memory ranks = new uint256[](c.K);
        for (uint256 i = 0; i < c.K; i++) {
            ranks[i] = i;
        }
        r.perm = _adversarial(ranks);
        r.file = string.concat(
            DIR, group, "_", c.art, "_K", vm.toString(c.K), "_B", vm.toString(c.B), "_d", vm.toString(dist), ".csv"
        );
        if (vm.exists(r.file)) vm.removeFile(r.file);
    }

    function _nextEta(Run memory r) internal pure returns (uint256 eta) {
        r.ctr++;
        // The sequence depends on (K, B, dist) only, so all candidates see the same identifiers.
        uint256 x = uint256(keccak256(abi.encode("eta", r.c.K, r.c.B, r.dist, r.ctr)));
        uint256 lb = Ref.log2(r.c.B);
        if (r.dist == 0) return x;
        uint256 hi = r.bucket << (256 - lb);
        if (r.dist == 1) return hi | (x >> lb);
        if (r.dist == 2) {
            return hi | (((type(uint256).max >> lb) - (r.ctr << 200)) & ~uint256((1 << 200) - 1)) | (x >> 56);
        }
        // dist 3: the arrival at position m of segment c has rank perm[m] among its segment
        return hi | (r.perm[r.m] << (248 - lb)) | ((r.seg & 0xffffffff) << (216 - lb)) | (x >> (40 + lb));
    }

    /// The worst arrival order for _sortRun on one bucket of n: every insertion-sorted chunk of 8
    /// arrives descending and every bottom-up merge interleaves its two runs element by element.
    function _adversarial(uint256[] memory ranks) internal pure returns (uint256[] memory out) {
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
        ev = _adversarial(ev);
        od = _adversarial(od);
        for (uint256 i = 0; i < n / 2; i++) {
            out[i] = ev[i];
            out[n / 2 + i] = od[i];
        }
    }

    function _calldataGas(bytes memory cd) internal pure returns (uint256 g) {
        for (uint256 i = 0; i < cd.length; i++) {
            g += cd[i] == 0 ? 4 : 16;
        }
    }

    function _evidence(Run memory r, uint256 eta, uint256 a) internal pure returns (bytes memory) {
        return abi.encode(r.d, bytes32(eta), uint64(a), ASSET, RECIPIENT, AMOUNT);
    }

    /// One measured redemption: (transaction gas, calldata bytes, calldata gas, refund).
    function _redeem(Run memory r, uint256 eta, uint256 a, bytes memory history)
        internal
        returns (uint256 gas, uint256 cdLen, uint256 cdGas, uint256 refund)
    {
        bytes memory ev = _evidence(r, eta, a);
        r.v.redeem(ev, bytes32(eta), uint64(a), history);
        Vm.Gas memory g = vm.lastCallGas();
        gas = g.gasTotalUsed;
        refund = uint256(uint64(g.gasRefunded));
        bytes memory cd = abi.encodeCall(IV.redeem, (ev, bytes32(eta), uint64(a), history));
        cdLen = cd.length;
        cdGas = _calldataGas(cd);
    }

    /// An unmeasured payment into the current segment (P = 0, current endpoint).
    function _pay(Run memory r) internal {
        uint256 eta = _nextEta(r);
        r.v.redeem(_evidence(r, eta, r.seg), bytes32(eta), uint64(r.seg), "");
        _mirror(r, eta);
    }

    function _mirror(Run memory r, uint256 eta) internal pure {
        r.cur[r.m] = eta;
        r.m++;
        if (r.m == r.c.K) {
            r.m = 0;
            r.seg++;
        }
    }

    function _fillTo(Run memory r, uint256 target) internal {
        while (r.m != target) _pay(r);
    }

    function _nextSegment(Run memory r) internal {
        uint256 s = r.seg;
        while (r.seg == s) _pay(r);
    }

    function _deposit(Run memory r, string memory phase) internal {
        r.v.deposit{value: 1e30}(_owner(), keccak256(abi.encode("rho", phase)));
        Vm.Gas memory g = vm.lastCallGas();
        bytes memory cd = abi.encodeCall(IV.deposit, (_owner(), keccak256(abi.encode("rho", phase))));
        _row(r, phase, "-", 0, 0, [g.gasTotalUsed, cd.length, _calldataGas(cd), uint256(uint64(g.gasRefunded)), 0]);
    }

    function _row(
        Run memory r,
        string memory phase,
        string memory endpoint,
        uint256 m,
        uint256 p,
        uint256[5] memory v // gas, calldata bytes, calldata gas, refund, history bytes
    )
        internal
    {
        string memory line = string.concat(
            r.group,
            ",",
            r.c.lname,
            ",",
            r.c.cname,
            ",",
            r.c.form,
            ",",
            vm.toString(r.c.K),
            ",",
            vm.toString(r.c.B),
            ","
        );
        line = string.concat(
            line, vm.toString(uint256(r.dist)), ",", phase, ",", endpoint, ",", vm.toString(m), ",", vm.toString(p)
        );
        for (uint256 i = 0; i < 5; i++) {
            line = string.concat(line, ",", vm.toString(v[i]));
        }
        vm.writeLine(r.file, line);
    }

    /// Checks the SegmentSealed log of the last call against the reference: exact length, strict
    /// order, the multiset of paid identifiers, the chain step and the vault's new head.
    function _checkSeal(Run memory r, uint256 lastEta) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] != TOPIC_SEALED) continue;
            found++;
            uint256 j = uint256(logs[i].topics[1]);
            (bytes32 hb, bytes32 ha, bytes memory ids) = abi.decode(logs[i].data, (bytes32, bytes32, bytes));
            assertEq(logs[i].data.length, 128 + 32 * r.c.K, "event length");
            uint256[] memory z = abi.decode(abi.encodePacked(uint256(32), r.c.K, ids), (uint256[]));
            for (uint256 q = 1; q < z.length; q++) {
                assertGt(z[q], z[q - 1], "sorted");
            }
            // same multiset as the paid identifiers (all distinct)
            uint256[] memory paid = new uint256[](r.c.K);
            for (uint256 q = 0; q + 1 < r.c.K; q++) {
                paid[q] = r.cur[q];
            }
            paid[r.c.K - 1] = lastEta;
            for (uint256 q = 0; q < r.c.K; q++) {
                bool hit;
                for (uint256 w = 0; w < r.c.K; w++) {
                    if (z[w] == paid[q]) hit = true;
                }
                assertTrue(hit, "paid id in segment");
            }
            assertEq(ha, Ref.step(r.d, j, hb, Ref.root(r.c.commit, z)), "chain step");
            (, uint64 seg,,, bytes32 head,) = r.v.state();
            assertEq(uint256(seg), j + 1, "segment advanced");
            assertEq(head, ha, "vault head");
        }
        assertEq(found, 1, "one seal");
    }

    // ------------------------------------------------------------------ workloads
    /// Recent buffers and settlement, P = 0: occupancy 0, 1, K/2, K-2 and K-1 (the K-1 payment seals),
    /// current and previous endpoint, in the first generation of each buffer and in steady state.
    function runRecent(Cfg memory c, uint8 dist) internal {
        Run memory r = _start(c, dist, "recent");
        _deposit(r, "deposit-first");
        _deposit(r, "deposit-steady");
        uint256[5] memory targets = [uint256(0), 1, c.K / 2, c.K - 2, c.K - 1];
        // Uniform cells are the mean of 16 claimed identifiers (one row each); a ground bucket is exact.
        for (uint256 ph = 0; ph < 3; ph++) {
            for (uint256 ti = 0; ti < 5; ti++) {
                _fillTo(r, targets[ti]);
                _cell(r, ph);
            }
            _nextSegment(r);
        }
    }

    function _cell(Run memory r, uint256 ph) internal {
        string[3] memory phases = ["gen0", "gen1", "steady"];
        uint256 samples = r.dist == 0 ? 16 : 1;
        for (uint256 ep = 0; ep < (ph == 0 ? 1 : 2); ep++) {
            for (uint256 sm = 0; sm < samples; sm++) {
                _measure(r, ep == 0 ? r.seg : r.seg - 1, phases[ph], ep == 0 ? "current" : "previous");
            }
        }
    }

    /// One measured payment from a snapshot, reverted afterwards; a sealing call is checked.
    function _measure(Run memory r, uint256 a, string memory phase, string memory endpoint) internal {
        uint256 snap = vm.snapshotState();
        uint256 eta = _nextEta(r);
        bool seals = r.m == r.c.K - 1;
        if (seals) vm.recordLogs();
        (uint256 gas, uint256 cdLen, uint256 cdGas, uint256 refund) = _redeem(r, eta, a, "");
        if (seals) _checkSeal(r, eta);
        _row(r, phase, endpoint, r.m, 0, [gas, cdLen, cdGas, refund, 0]);
        vm.revertToState(snap);
    }

    /// K random identifiers, sorted, over the whole domain or (bucketTag = 2t + 1) over bucket t only.
    function _fakeSegment(uint256 k, uint256 seed, uint256 bucketTag, uint256 b)
        internal
        pure
        returns (uint256[] memory z)
    {
        z = new uint256[](k);
        uint256 lb = Ref.log2(b);
        for (uint256 i = 0; i < k; i++) {
            uint256 x = uint256(keccak256(abi.encode("seg", seed, i)));
            z[i] = bucketTag == 0 ? x : ((bucketTag >> 1) << (256 - lb)) | (x >> lb);
        }
        for (uint256 i = 1; i < k; i++) {
            uint256 v = z[i];
            uint256 j = i;
            while (j > 0 && z[j - 1] > v) {
                z[j] = z[j - 1];
                j--;
            }
            z[j] = v;
        }
    }

    function _concat(bytes32 head, bytes[] memory parts) internal pure returns (bytes memory out) {
        uint256 n = 32;
        for (uint256 i = 0; i < parts.length; i++) {
            n += parts[i].length;
        }
        out = new bytes(n);
        assembly ("memory-safe") {
            mstore(add(out, 32), head)
        }
        uint256 o = 32;
        for (uint256 i = 0; i < parts.length; i++) {
            bytes memory p = parts[i];
            uint256 len = p.length;
            assembly ("memory-safe") {
                mcopy(add(add(out, 32), o), add(p, 32), len)
            }
            o += len;
        }
    }

    /// Moves a tags-layout vault to segment cNew and sets the head of segment e (cNew or cNew - 1);
    /// the buffers are untouched (cNew keeps the parity of the real segment).
    function _jump(Run memory r, uint256 cNew, uint256 e, bytes32 head) internal {
        require(r.c.lay == 0, "jump: tags only");
        uint256 acc = uint256(vm.load(address(r.v), bytes32(0)));
        acc = (acc & ~(uint256((1 << 48) - 1) << 152)) | (cNew << 152);
        vm.store(address(r.v), bytes32(0), bytes32(acc));
        vm.store(address(r.v), bytes32(1 + (e & 1)), head);
    }

    /// History replay: P = 0, 1, 10, 100 historical segments at occupancy K/2, current and previous
    /// endpoint, steady state. The P segments are reference-built (uniform identifiers, or all in one
    /// bucket); the vault's segment counter and the endpoint's head are moved to the fold's endpoint
    /// with storage writes (unmeasured).
    function runHistory(Cfg memory c, uint8 dist) internal {
        Run memory r = _start(c, 0, "history");
        r.file = string.concat(r.file, "_h", vm.toString(uint256(dist)), ".csv");
        if (vm.exists(r.file)) vm.removeFile(r.file);
        r.dist = dist;
        _deposit(r, "deposit-first");
        r.dist = 0;
        _nextSegment(r);
        _nextSegment(r);
        _fillTo(r, c.K / 2);
        r.dist = dist;
        uint256[4] memory ps = [uint256(0), 1, 10, 100];
        // One claimed identifier for every P (and, through the seeded sequence, every candidate).
        uint256 eta = uint256(keccak256(abi.encode("history eta", c.K)));
        for (uint256 ep = 0; ep < 2; ep++) {
            for (uint256 pi = 0; pi < 4; pi++) {
                _histCase(r, eta, ep, ps[pi], dist);
            }
        }
    }

    function _histCase(Run memory r, uint256 eta, uint256 ep, uint256 p, uint8 dist) internal {
        uint256 snap = vm.snapshotState();
        // the vault's current segment after the jump, and the claim's endpoint
        uint256 cNew = r.seg + 2 * ((p + 2) / 2);
        uint256 e = ep == 0 ? cNew : cNew - 1;
        uint256 a = e - p;
        bytes memory history;
        bytes32 x = keccak256("start head");
        if (p > 0) {
            bytes[] memory parts = new bytes[](p);
            for (uint256 q = 0; q < p; q++) {
                uint256[] memory z = _fakeSegment(r.c.K, q, dist == 0 ? 0 : (r.bucket << 1) | 1, r.c.B);
                x = Ref.step(r.d, a + q, x, Ref.root(r.c.commit, z));
                parts[q] = Ref.proof(r.c.commit, z, eta);
            }
            history = _concat(keccak256("start head"), parts);
        }
        _jump(r, cNew, e, x);
        (uint256 gas, uint256 cdLen, uint256 cdGas, uint256 refund) = _redeem(r, eta, a, history);
        _row(r, "steady", ep == 0 ? "current" : "previous", r.m, p, [gas, cdLen, cdGas, refund, history.length]);
        vm.revertToState(snap);
    }

    /// The sealing transaction in steady state (segment 2): the payment at occupancy K-2 (no seal)
    /// and the one at K-1 that seals, current endpoint, P = 0; uniform cells are means of 16.
    function runSeal(Cfg memory c, uint8 dist) internal {
        Run memory r = _start(c, dist, "seal");
        _deposit(r, "deposit-first");
        _nextSegment(r);
        _nextSegment(r);
        _fillTo(r, c.K - 2);
        uint256 samples = dist == 0 ? 16 : 1;
        for (uint256 sm = 0; sm < samples; sm++) {
            _measure(r, r.seg, "preseal", "current");
        }
        _pay(r);
        for (uint256 sm = 0; sm < samples; sm++) {
            _measure(r, r.seg, "seal", "current");
        }
    }
}
