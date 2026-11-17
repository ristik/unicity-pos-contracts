// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {FastJson} from "../FastJson.sol";
import {PoaComposer} from "../../../src/vr/poa/PoaComposer.sol";
import {Continuity} from "../../../src/p85/Continuity.sol";

/// @notice Runs the production composer on one flat vector input (fresh memory per call) and returns the flat result.
contract PoaComposerHarness {
    uint256 internal cur;

    function _next(uint256[] calldata w) internal returns (uint256 v) {
        v = w[cur++];
    }

    function run(uint256[] calldata w) external returns (uint256[] memory out, uint256 gasUsed) {
        cur = 0;
        PoaComposer.Input memory inp;
        uint256 n = _next(w);
        inp.o = new PoaComposer.Seat[](n);
        for (uint256 i = 0; i < n; ++i) {
            inp.o[i] = PoaComposer.Seat(
                uint64(_next(w)), bytes32(_next(w)), uint64(_next(w)), uint64(_next(w))
            );
        }
        n = _next(w);
        inp.forceRemoves = new PoaComposer.ForceRemove[](n);
        for (uint256 i = 0; i < n; ++i) {
            inp.forceRemoves[i] =
                PoaComposer.ForceRemove(uint64(_next(w)), uint64(_next(w)), uint64(_next(w)));
        }
        n = _next(w);
        inp.removing = new uint64[](n);
        for (uint256 i = 0; i < n; ++i) {
            inp.removing[i] = uint64(_next(w));
        }
        n = _next(w);
        inp.staged = new PoaComposer.Candidate[](n);
        for (uint256 i = 0; i < n; ++i) {
            inp.staged[i] = PoaComposer.Candidate(uint64(_next(w)), bytes32(_next(w)));
        }
        n = _next(w);
        inp.joiners = new PoaComposer.Candidate[](n);
        for (uint256 i = 0; i < n; ++i) {
            inp.joiners[i] = PoaComposer.Candidate(uint64(_next(w)), bytes32(_next(w)));
        }
        inp.progress = uint64(_next(w));
        inp.forceDeadline = uint64(_next(w));
        inp.nMin = uint32(_next(w));
        inp.nTarget = uint32(_next(w));
        inp.nMax = uint32(_next(w));
        inp.dueWork = uint32(_next(w));
        inp.params = Continuity.Params(uint64(_next(w)), uint64(_next(w)), uint64(_next(w)));
        require(cur == w.length, "input length");

        uint256 g = gasleft();
        (bool found, uint256 mask, PoaComposer.Pool memory pl) = PoaComposer.choose(inp);
        gasUsed = g - gasleft();

        uint256 np = pl.changes.length;
        uint256 nc = 0;
        for (uint256 i = 0; i < np; ++i) {
            if (mask & (1 << i) != 0) ++nc;
        }
        out = new uint256[](5 + 2 * np + 2 * nc);
        uint256 k = 0;
        out[k++] = found ? 1 : 0;
        out[k++] = pl.mandatory ? 1 : 0;
        out[k++] = pl.oldestFeasible ? 1 : 0;
        out[k++] = np;
        for (uint256 i = 0; i < np; ++i) {
            out[k++] = pl.changes[i].kind;
            out[k++] = pl.changes[i].id;
        }
        out[k++] = nc;
        for (uint256 i = 0; i < np; ++i) {
            if (mask & (1 << i) == 0) continue;
            out[k++] = pl.changes[i].kind;
            out[k++] = pl.changes[i].id;
        }
    }
}

/// @notice The composer against the exact-rational model (design 3.7.3; section 11 VT-03: n = 4, 5, 7 and 10, the swap at 4 and the
/// growth to 5, the empty trial outside the limits, the ForceRemove fixtures). `tools/poa_composer_vectors.py` is an independent reading
/// of the design text with Fraction arithmetic and a literal sort of the trials; every vector's pool, flags and chosen trial must match.
contract PoaComposerVectorsTest is Test, FastJson {
    string internal constant FILE = "/test/vr/poa/fixtures/poa-composer.json";

    function test_composerMatchesTheExactRationalModel() public {
        _jload(string.concat(vm.projectRoot(), FILE));
        assertEq(_js(".schema"), "unicity.vr.poa-composer/v1");
        string[] memory names = _jsarr(".vectors[*].name");
        PoaComposerHarness h = new PoaComposerHarness();
        uint256 found;
        uint256 maxGas;
        bool[4] memory sizes; // n = 4, 5, 7, 10 present
        for (uint256 i = 0; i < names.length; ++i) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            uint256[] memory input = _juarr(string.concat(p, ".input"));
            uint256[] memory want = _juarr(string.concat(p, ".expect"));
            (uint256[] memory got, uint256 g) = h.run(input);
            assertEq(got, want, names[i]);
            if (want[0] == 1) ++found;
            if (g > maxGas) maxGas = g;
            if (input[0] == 4) sizes[0] = true;
            if (input[0] == 5) sizes[1] = true;
            if (input[0] == 7) sizes[2] = true;
            if (input[0] == 10) sizes[3] = true;
        }
        assertEq(names.length, 431, "vector count");
        assertTrue(sizes[0] && sizes[1] && sizes[2] && sizes[3], "n = 4, 5, 7 and 10");
        emit log_named_uint("vectors", names.length);
        emit log_named_uint("with a candidate", found);
        emit log_named_uint("max composer gas", maxGas);
    }
}
