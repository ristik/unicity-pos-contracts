// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BenchBase, IV} from "./BenchBase.sol";
import {Ref} from "./Ref.sol";

/// Functional checks of every candidate at small K (immutables): sealing against the reference,
/// historical absence through real sealed segments, both endpoints, and the redeem refusals the
/// bake-off relies on. Not a vault test suite: NB2-04 (#1100) owns that.
contract CorrectnessTest is BenchBase {
    bytes4 internal constant ALREADY_PAID = 0xf4b76a0e;
    bytes4 internal constant BAD_GAP = 0xe7169745;
    bytes4 internal constant CHAIN = 0xa6226dc5;
    bytes4 internal constant FUTURE = 0x39a15193;
    bytes4 internal constant STALE = 0x683c7c78;
    bytes4 internal constant BAD_LEN = 0x37c8cb02;

    uint256[][] internal segs; // sealed segments, sorted

    function _cfg(uint8 layout, uint8 commit, uint256 k, uint256 b) internal pure returns (Cfg memory) {
        string[4] memory cn = ["gap", "mp", "radix", "raw"];
        string memory ln = layout == 0 ? "tags" : "sparse";
        string memory art = string.concat("V_", ln, "_", cn[commit], "_imm");
        return Cfg(art, k, b, layout, commit, true, ln, cn[commit], "imm");
    }

    function _sorted(uint256[] memory x) internal pure returns (uint256[] memory z) {
        z = new uint256[](x.length);
        for (uint256 i = 0; i < x.length; i++) {
            z[i] = x[i];
        }
        for (uint256 i = 1; i < z.length; i++) {
            for (uint256 j = i; j > 0 && z[j - 1] > z[j]; j--) {
                (z[j - 1], z[j]) = (z[j], z[j - 1]);
            }
        }
    }

    /// One payment (any start and history); a seal is checked against the reference and recorded.
    function _payOne(Run memory r, uint256 eta, uint256 a, bytes memory h) internal {
        bool seals = r.m == r.c.K - 1;
        if (seals) vm.recordLogs();
        r.v.redeem(_evidence(r, eta, a), bytes32(eta), uint64(a), h);
        if (seals) {
            _checkSeal(r, eta);
            uint256[] memory s = new uint256[](r.c.K);
            for (uint256 i = 0; i + 1 < r.c.K; i++) {
                s[i] = r.cur[i];
            }
            s[r.c.K - 1] = eta;
            segs.push(_sorted(s));
        }
        _mirror(r, eta);
    }

    function _payChecked(Run memory r, uint256 n) internal {
        for (uint256 q = 0; q < n; q++) {
            _payOne(r, _nextEta(r), r.seg, "");
        }
    }

    function _history(Run memory r, bytes32 start, uint256 a, uint256 e, uint256 eta)
        internal
        view
        returns (bytes memory h)
    {
        bytes[] memory parts = new bytes[](e - a);
        for (uint256 j = a; j < e; j++) {
            parts[j - a] = Ref.proof(r.c.commit, segs[j], eta);
        }
        return _concat(start, parts);
    }

    function _head(Run memory r, uint256 j) internal view returns (bytes32 x) {
        x = Ref.genesis(r.d, r.c.K);
        for (uint256 i = 0; i < j; i++) {
            x = Ref.step(r.d, i, x, Ref.root(r.c.commit, segs[i]));
        }
    }

    function _expect(Run memory r, uint256 eta, uint256 a, bytes memory h, bytes memory err) internal {
        bytes memory ev = _evidence(r, eta, a);
        vm.expectRevert(err);
        r.v.redeem(ev, bytes32(eta), uint64(a), h);
    }

    function _run(uint8 layout, uint8 commit, uint256 k, uint256 b, uint8 dist) internal {
        delete segs;
        Run memory r = _start(_cfg(layout, commit, k, b), dist, "check");
        r.v.deposit{value: 1e30}(_owner(), bytes32(0));
        (,,,, bytes32 h0,) = r.v.state();
        assertEq(h0, Ref.genesis(r.d, k), "genesis head");
        _payChecked(r, 3 * k + 1); // c = 3, m = 1
        assertEq(r.seg, 3);

        // Historical absence from a = 0 to the current endpoint e = c = 3.
        uint256 eta = _nextEta(r);
        _payOne(r, eta, 0, _history(r, Ref.genesis(r.d, k), 0, 3, eta));
        // ... and the same eta again: in the current buffer.
        _expect(r, eta, r.seg, "", abi.encodeWithSelector(ALREADY_PAID, eta));
        _expect(r, eta, 0, _history(r, Ref.genesis(r.d, k), 0, 3, eta), abi.encodeWithSelector(ALREADY_PAID, eta));

        // Previous endpoint e = c - 1 = 2 from a = 1, starting at H_1.
        uint256 eta2 = _nextEta(r);
        _payOne(r, eta2, 1, _history(r, _head(r, 1), 1, 2, eta2));
        // P = 0 at the previous endpoint scans both buffers (at K = 4 this payment seals).
        _payOne(r, _nextEta(r), 2, "");
        uint256 c = r.seg;

        // An identifier paid in sealed segment 0 cannot pass a gap proof of segment 0.
        uint256 old = segs[0][1];
        if (commit != Ref.RAW) {
            // A proof built for a nearby absent value does not cover old.
            bytes memory h = _history(r, Ref.genesis(r.d, k), 0, c, old + 1);
            _expect(r, old, 0, h, abi.encodeWithSelector(BAD_GAP, 0));
        } else {
            bytes[] memory parts = new bytes[](c);
            for (uint256 j = 0; j < c; j++) {
                parts[j] = abi.encodePacked(segs[j]);
            }
            _expect(r, old, 0, _concat(Ref.genesis(r.d, k), parts), abi.encodeWithSelector(BAD_GAP, 0));
        }
        // An identifier of the previous buffer (segment c - 1) is caught by the recent scan.
        _expect(r, segs[c - 1][0], c - 1, "", abi.encodeWithSelector(ALREADY_PAID, segs[c - 1][0]));

        uint256 eta4 = _nextEta(r);
        // Wrong start head: repairable ChainMismatch.
        _expect(r, eta4, 0, _history(r, keccak256("wrong"), 0, c, eta4), abi.encodeWithSelector(CHAIN));
        // A tampered sibling: ChainMismatch.
        bytes memory t = _history(r, Ref.genesis(r.d, k), 0, c, eta4);
        t[t.length - 1] = bytes1(uint8(t[t.length - 1]) ^ 1);
        _expect(r, eta4, 0, t, abi.encodeWithSelector(CHAIN));
        // Future index and stale endpoint.
        _expect(r, eta4, c + 1, "", abi.encodeWithSelector(FUTURE, uint64(c + 1), uint64(c)));
        _expect(
            r,
            eta4,
            0,
            _history(r, Ref.genesis(r.d, k), 0, 1, eta4),
            abi.encodeWithSelector(STALE, uint64(1), uint64(c))
        );
        // Truncated history.
        bytes memory h4 = _history(r, Ref.genesis(r.d, k), 0, c, eta4);
        bytes memory cut = new bytes(h4.length - 1);
        for (uint256 i = 0; i < cut.length; i++) {
            cut[i] = h4[i];
        }
        if (commit == Ref.GAP || commit == Ref.RAW) {
            _expect(r, eta4, 0, cut, abi.encodeWithSelector(BAD_LEN, cut.length));
        } else {
            bytes memory ev = _evidence(r, eta4, 0);
            vm.expectRevert();
            r.v.redeem(ev, bytes32(eta4), 0, cut);
        }
        // And the valid one still pays.
        _payOne(r, eta4, 0, h4);

        // Keep paying through two more seals, checked.
        _payChecked(r, 2 * k);
    }

    function test_tags_gap() public {
        _run(0, 0, 4, 2, 0);
        _run(0, 0, 8, 4, 1);
        _run(0, 0, 16, 8, 2);
        _run(0, 0, 32, 8, 3);
    }

    function test_tags_mp() public {
        _run(0, 1, 4, 2, 0);
        _run(0, 1, 8, 4, 1);
        _run(0, 1, 16, 8, 2);
    }

    function test_tags_radix() public {
        _run(0, 2, 4, 2, 0);
        _run(0, 2, 8, 4, 1);
        _run(0, 2, 16, 8, 2);
    }

    function test_tags_raw() public {
        _run(0, 3, 4, 2, 0);
        _run(0, 3, 8, 4, 1);
    }

    function test_sparse_gap() public {
        _run(1, 0, 4, 2, 0);
        _run(1, 0, 8, 4, 1);
        _run(1, 0, 64, 32, 0);
        _run(1, 0, 32, 8, 3);
    }

    function test_sparse_mp() public {
        _run(1, 1, 4, 2, 0);
        _run(1, 1, 8, 4, 2);
    }

    function test_sparse_radix() public {
        _run(1, 2, 4, 2, 0);
        _run(1, 2, 8, 4, 2);
    }

    function test_sparse_raw() public {
        _run(1, 3, 4, 2, 0);
    }
}
