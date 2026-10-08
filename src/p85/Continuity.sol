// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the immutable V ceiling (at most 128 members per committee).
// forge-lint: disable-start(unsafe-typecast)

/// @title Continuity
/// @notice The binding-aware committee continuity rule of design v5 section 5: the membership budget M, the strict one-third turnover
/// boundary, the normalized weight distance D and the unchanged-binding weight overlap between two consecutive committees. The same
/// check judges O to J and J to K, each with its own predecessor and successor. This is the port of bft-core's `continuity` package
/// (`Check`); `test/p85/fixtures/continuity-vectors.json` is that package's output and `Continuity.t.sol` reproduces every case.
///
/// Committees are arrays strictly ascending by StakingID with positive weights. A member carries a `binding`: the hash of its
/// (rootNodeID, rootKey, evmNodeID, evmKey) tuple, equal exactly when the whole tuple is equal. The operator payee is deliberately not
/// part of it: a payee change alone is no signing-binding replacement. All arithmetic is exact integer arithmetic.
library Continuity {
    struct Member {
        uint64 id;
        bytes32 binding;
        uint64 weight;
    }

    /// @dev maxM bounds M = removed + added; maxDistNum/maxDistDen bound D = sum |w_i/W - v_i/V|.
    struct Params {
        uint64 maxM;
        uint64 distNum;
        uint64 distDen;
    }

    struct Measured {
        uint64 replaced; // r: shared identities with any changed binding field, counted once
        uint64 removed;
        uint64 added;
        uint64 m;
        uint256 unchangedOld; // weight the unchanged-binding identities carry in O
        uint256 unchangedNew; // and in S
        uint256 totalOld; // V
        uint256 totalNew; // W
        uint256 distanceNumerator; // sum |w*V - v*W|, i.e. D = numerator / (V*W)
    }

    uint8 internal constant FAIL_MEMBERSHIP = 1;
    uint8 internal constant FAIL_TURNOVER = 2;
    uint8 internal constant FAIL_DISTANCE = 4;
    uint8 internal constant FAIL_OVERLAP = 8;

    /// @dev A committee that cannot be judged: empty, not strictly ascending by identity (a duplicate included), a zero weight or a
    /// total that does not fit 64 bits. `successor` names the side.
    error InvalidCommittee(bool successor);
    error InvalidParams();

    function _total(Member[] memory c, bool successor) private pure returns (uint256 total) {
        if (c.length == 0) revert InvalidCommittee(successor);
        for (uint256 i = 0; i < c.length; ++i) {
            if (c[i].weight == 0 || (i > 0 && c[i].id <= c[i - 1].id)) {
                revert InvalidCommittee(successor);
            }
            total += c[i].weight;
        }
        if (total > type(uint64).max) revert InvalidCommittee(successor);
    }

    function _absDiff(uint256 a, uint256 b) private pure returns (uint256) {
        return a > b ? a - b : b - a;
    }

    /// @notice The transition quantities between the last committed committee `o` and the trial successor `s`.
    function measure(Member[] memory o, Member[] memory s)
        internal
        pure
        returns (Measured memory r)
    {
        r.totalOld = _total(o, false);
        r.totalNew = _total(s, true);
        uint256 onlyOld = 0;
        uint256 onlyNew = 0;
        uint256 i = 0;
        uint256 j = 0;
        // a merge walk over the two ascending lists
        while (i < o.length || j < s.length) {
            if (j == s.length || (i < o.length && o[i].id < s[j].id)) {
                ++onlyOld;
                r.distanceNumerator += _absDiff(0, uint256(o[i].weight) * r.totalNew);
                ++i;
            } else if (i == o.length || s[j].id < o[i].id) {
                ++onlyNew;
                r.distanceNumerator += _absDiff(uint256(s[j].weight) * r.totalOld, 0);
                ++j;
            } else {
                if (o[i].binding == s[j].binding) {
                    r.unchangedOld += o[i].weight;
                    r.unchangedNew += s[j].weight;
                } else {
                    ++r.replaced;
                }
                r.distanceNumerator += _absDiff(
                    uint256(s[j].weight) * r.totalOld, uint256(o[i].weight) * r.totalNew
                );
                ++i;
                ++j;
            }
        }
        r.removed = uint64(onlyOld) + r.replaced;
        r.added = uint64(onlyNew) + r.replaced;
        r.m = r.removed + r.added;
    }

    /// @notice Applies every predicate to the boundary o -> s. `failed` has a bit per failed predicate (FAIL_*), zero when the
    /// transition is allowed. `o` must be the last committed committee of that boundary, retiring or excluded members included.
    function check(Member[] memory o, Member[] memory s, Params memory p)
        internal
        pure
        returns (uint8 failed, Measured memory r)
    {
        if (p.distDen == 0) revert InvalidParams();
        r = measure(o, s);
        if (r.m > p.maxM) failed |= FAIL_MEMBERSHIP;
        uint256 minSize = o.length < s.length ? o.length : s.length;
        uint256 widest = r.removed > r.added ? r.removed : r.added;
        if (3 * widest >= minSize) failed |= FAIL_TURNOVER;
        // D <= num/den  <=>  numerator*den <= num*V*W
        if (r.distanceNumerator * p.distDen > uint256(p.distNum) * r.totalOld * r.totalNew) {
            failed |= FAIL_DISTANCE;
        }
        // strictly more than two thirds of both committees
        if (3 * r.unchangedOld <= 2 * r.totalOld || 3 * r.unchangedNew <= 2 * r.totalNew) {
            failed |= FAIL_OVERLAP;
        }
    }
}
