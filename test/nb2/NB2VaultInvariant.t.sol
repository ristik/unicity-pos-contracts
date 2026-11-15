// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {INB2Vault, NB2Ref, NB2TestBase} from "./NB2TestBase.sol";

/// Drives the K = 4, B = 2 test build against an unbounded paid-set reference (section 16): every call's acceptance must
/// equal the reference's, built without the vault's code. Expected refusals are caught with low-level calls, so a handler
/// revert is a harness failure (fail_on_revert).
contract NB2Handler is Test {
    uint256 internal constant K = 4;
    uint256 internal constant B = 2;
    address internal constant RECIPIENT = address(0x00000000000000000000000000000000000BeeF0);
    bytes32 internal constant ASSET_UCT =
        0x87b0b8b600fcd942cc3383bac1dbb80fd69d54af700cf48faa4525451a7b1845;

    INB2Vault public immutable VAULT;
    bytes32 public immutable D;

    // the reference: the unbounded paid set, the sealed segments and heads, the current segment's arrivals
    mapping(bytes32 => bool) public paid;
    mapping(bytes32 => uint256) public paidStart; // the burn's signed index a of a paid identifier
    mapping(bytes32 => uint256) public payouts;
    bytes32[] public paidList;
    bytes32[][] internal segs;
    bytes32[] public heads;
    bytes32[] internal cur;
    uint256 public c;
    uint256 public deposited;
    uint256 public paidOut;
    uint256 public mismatches;
    uint256 internal ctr;

    constructor(INB2Vault vault, bytes32 d) {
        VAULT = vault;
        D = d;
        heads.push(NB2Ref.genesis(d, K));
    }

    function _verdict(bytes32 eta, uint256 a, uint256 amount) internal view returns (bytes memory) {
        return abi.encode(D, eta, uint64(a), ASSET_UCT, RECIPIENT, amount);
    }

    function _history(bytes32 eta, uint256 a, uint256 e)
        internal
        view
        returns (bool isPaid, bytes memory h)
    {
        if (a == e) return (false, "");
        h = abi.encodePacked(heads[a]);
        for (uint256 j = a; j < e; j++) {
            (bool p, bytes memory pr) = NB2Ref.proof(segs[j], eta);
            if (p) {
                // no gap exists: present a valid gap of another identifier instead
                (, pr) = NB2Ref.proof(segs[j], bytes32(uint256(segs[j][0]) + 1));
                isPaid = true;
            }
            h = bytes.concat(h, pr);
        }
    }

    function _redeem(bytes32 eta, uint256 a, bytes memory h, bytes memory ev)
        internal
        returns (bool ok)
    {
        (ok,) = address(VAULT).call(abi.encodeCall(INB2Vault.redeem, (ev, eta, uint64(a), h)));
    }

    function _record(bytes32 eta, uint256 a) internal {
        paid[eta] = true;
        paidStart[eta] = a;
        payouts[eta]++;
        paidList.push(eta);
        paidOut += 1;
        cur.push(eta);
        if (cur.length == K) {
            bytes32[] memory z = NB2Ref.sorted(cur);
            segs.push(z);
            heads.push(NB2Ref.step(D, c, heads[c], NB2Ref.root(z)));
            delete cur;
            c++;
        }
    }

    function _endpoint(uint256 a, uint256 sel) internal view returns (uint256 e) {
        e = c;
        if (sel % 2 == 1 && c > 0 && c - 1 >= a) e = c - 1;
    }

    // -------------------------------------------------------------------------------------------- actions

    function deposit(uint256 v) external {
        v = bound(v, 1, 1e6);
        vm.deal(address(this), v);
        VAULT.deposit{value: v}(
            bytes.concat(hex"d9987883014101582102", keccak256("k")), keccak256(abi.encode(ctr++))
        );
        deposited += v;
    }

    /// A fresh identifier with a start in [c - 3, c] and the current or previous endpoint.
    function payFresh(uint256 seed, uint256 back, uint256 sel) external {
        if (deposited - paidOut == 0) return;
        bytes32 eta = keccak256(abi.encode("fresh", seed, ctr++));
        if (sel % 5 == 0) eta = bytes32(uint256(eta) & ~(uint256(1) << 255)); // bucket 0 often
        uint256 a = c - bound(back, 0, c < 3 ? c : 3);
        uint256 e = _endpoint(a, sel);
        (, bytes memory h) = _history(eta, a, e);
        bool ok = _redeem(eta, a, h, _verdict(eta, a, 1));
        if (!ok) mismatches++; // the reference accepts every fresh identifier
        else _record(eta, a);
    }

    /// A paid identifier again, with its own signed start, at either endpoint: the reference refuses.
    function replay(uint256 idx, uint256 sel) external {
        if (paidList.length == 0) return;
        bytes32 eta = paidList[bound(idx, 0, paidList.length - 1)];
        uint256 a = paidStart[eta];
        uint256 e = _endpoint(a, sel);
        (, bytes memory h) = _history(eta, a, e);
        bool ok = _redeem(eta, a, h, _verdict(eta, a, 1));
        if (ok) {
            mismatches++;
            _record(eta, a);
        }
    }

    /// A forged claimed identifier with an honest history, and a verdict for a different (paid or fresh) identifier.
    function forged(uint256 seed, uint256 idx) external {
        if (deposited - paidOut == 0) return;
        bytes32 claimed = keccak256(abi.encode("forged", seed, ctr++));
        bytes32 real =
            paidList.length == 0 ? keccak256("x") : paidList[bound(idx, 0, paidList.length - 1)];
        (, bytes memory h) = _history(claimed, c, c);
        if (_redeem(claimed, c, h, _verdict(real, c, 1))) mismatches++;
    }

    /// A wrong unsigned start head: refused, and the honest history still pays.
    function wrongHead(uint256 seed) external {
        if (deposited - paidOut == 0 || c == 0) return;
        bytes32 eta = keccak256(abi.encode("head", seed, ctr++));
        (, bytes memory h) = _history(eta, c - 1, c);
        h[0] ^= 0x01;
        if (_redeem(eta, c - 1, h, _verdict(eta, c - 1, 1))) mismatches++;
        h[0] ^= 0x01;
        if (!_redeem(eta, c - 1, h, _verdict(eta, c - 1, 1))) mismatches++;
        else _record(eta, c - 1);
    }

    function paidCount() external view returns (uint256) {
        return paidList.length;
    }
}

contract NB2VaultInvariantTest is NB2TestBase {
    NB2Handler internal handler;
    World internal w0;

    function setUp() public {
        World memory w = deploy(4, 2, 1e30);
        handler = new NB2Handler(w.v, w.d);
        w0.v = w.v;
        w0.mock = w.mock;
        w0.d = w.d;
        targetContract(address(handler));
    }

    /// Bounded runs and depth with a fixed seed, so the CI run is reproducible and well inside the suite's time budget.
    /// forge-config: default.fuzz.seed = "0x4e4232"
    /// forge-config: default.invariant.runs = 48
    /// forge-config: default.invariant.depth = 64
    function invariant_matchesUnboundedReference() public view {
        assertEq(handler.mismatches(), 0, "acceptance differs from the paid-set reference");
        uint256 n = handler.paidCount();
        for (uint256 i = 0; i < n; i++) {
            assertEq(handler.payouts(handler.paidList(i)), 1, "an identifier paid twice");
        }
        (uint64 deposits, uint64 seg, uint16 pop, uint256 q, bytes32 head, bytes32 prev) =
            w0.v.state();
        deposits;
        assertEq(q, handler.deposited() - handler.paidOut(), "Q = deposits - payouts");
        assertGe(address(w0.v).balance, q, "balance covers Q");
        assertEq(seg, handler.c(), "segment");
        assertEq(pop, n - 4 * uint256(seg), "population");
        assertEq(head, handler.heads(seg), "head");
        assertEq(prev, seg == 0 ? bytes32(0) : handler.heads(seg - 1), "previous head");
    }

    /// Every run pays something: the reference comparison is not vacuous.
    function afterInvariant() public view {
        assertGt(handler.paidCount(), 0, "no payment in this run");
    }
}
