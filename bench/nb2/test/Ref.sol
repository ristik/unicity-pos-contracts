// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// Reference (wallet-side) builders for the four segment commitments and the archive chain of the
/// NB2-02 bake-off, written independently of the vault templates in plain Solidity.
library Ref {
    bytes32 internal constant ARCHIVE_GENESIS = 0x45076af3d8858f1d7a9bb6e037bb5ca4270d0b4fa90f9397eb7adb905590a339;
    bytes32 internal constant ARCHIVE_STEP = 0xc68efdc45f5c9a20bf6abfda6493e8e295d8e31495fd1e744cd4c35f74785dfa;

    uint8 internal constant GAP = 0;
    uint8 internal constant MP = 1;
    uint8 internal constant RADIX = 2;
    uint8 internal constant RAW = 3;

    function genesis(bytes32 d, uint256 k) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ARCHIVE_GENESIS, d, uint16(k)));
    }

    function step(bytes32 d, uint256 j, bytes32 h, bytes32 m) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ARCHIVE_STEP, d, uint64(j), h, m));
    }

    function node(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(1), l, r));
    }

    function log2(uint256 x) internal pure returns (uint256 r) {
        while ((uint256(1) << r) < x) r++;
    }

    /// All levels of a complete binary tree; levels[0] are the leaves.
    function levels(bytes32[] memory leaves) internal pure returns (bytes32[][] memory lv) {
        uint256 h = log2(leaves.length);
        lv = new bytes32[][](h + 1);
        lv[0] = leaves;
        for (uint256 j = 1; j <= h; j++) {
            uint256 w = leaves.length >> j;
            lv[j] = new bytes32[](w);
            for (uint256 i = 0; i < w; i++) {
                lv[j][i] = node(lv[j - 1][2 * i], lv[j - 1][2 * i + 1]);
            }
        }
    }

    function gapLeaves(uint256[] memory z) internal pure returns (bytes32[] memory l) {
        uint256 k = z.length;
        l = new bytes32[](k);
        for (uint256 i = 0; i < k; i++) {
            l[i] = keccak256(abi.encodePacked(uint8(0), z[i], z[(i + 1) % k]));
        }
    }

    function plainLeaves(uint256[] memory z) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](z.length);
        for (uint256 i = 0; i < z.length; i++) {
            l[i] = keccak256(abi.encodePacked(uint8(0), z[i]));
        }
    }

    function path(bytes32[][] memory lv, uint256 i) internal pure returns (bytes memory p) {
        for (uint256 j = 0; j + 1 < lv.length; j++) {
            p = bytes.concat(p, lv[j][(i >> j) ^ 1]);
        }
    }

    function root(uint8 commit, uint256[] memory z) internal pure returns (bytes32) {
        if (commit == GAP) {
            bytes32[][] memory lv = levels(gapLeaves(z));
            return lv[lv.length - 1][0];
        }
        if (commit == MP) {
            bytes32[][] memory lv = levels(plainLeaves(z));
            return lv[lv.length - 1][0];
        }
        if (commit == RADIX) return radixHash(z, 0, z.length - 1);
        return keccak256(abi.encodePacked(z));
    }

    /// The absence proof of eta in sorted segment z (eta must be absent).
    function proof(uint8 commit, uint256[] memory z, uint256 eta) internal pure returns (bytes memory) {
        uint256 k = z.length;
        for (uint256 i = 0; i < k; i++) {
            require(z[i] != eta, "Ref: eta present");
        }
        if (commit == GAP) {
            uint256 i = k - 1;
            if (eta > z[0] && eta < z[k - 1]) {
                for (i = 0; !(z[i] < eta && eta < z[i + 1]); i++) {}
            }
            return bytes.concat(bytes1(uint8(i)), bytes32(z[i]), bytes32(z[(i + 1) % k]), path(levels(gapLeaves(z)), i));
        }
        if (commit == MP) {
            bytes32[][] memory lv = levels(plainLeaves(z));
            if (eta < z[0]) return bytes.concat(bytes1(0xff), bytes32(z[0]), path(lv, 0));
            if (eta > z[k - 1]) return bytes.concat(bytes1(0xfe), bytes32(z[k - 1]), path(lv, k - 1));
            uint256 i = 0;
            while (!(z[i] < eta && eta < z[i + 1])) i++;
            uint256 t = 0;
            while ((i >> t) & 1 == 1) t++;
            bytes memory p = bytes.concat(bytes1(uint8(i)), bytes32(z[i]), bytes32(z[i + 1]));
            for (uint256 j = 0; j < t; j++) {
                p = bytes.concat(p, lv[j][(i >> j) ^ 1], lv[j][((i + 1) >> j) ^ 1]);
            }
            for (uint256 j = t + 1; j + 1 < lv.length; j++) {
                p = bytes.concat(p, lv[j][(i >> j) ^ 1]);
            }
            return p;
        }
        if (commit == RADIX) return radixProof(z, eta);
        return abi.encodePacked(z);
    }

    // ------------------------------------------------------------------ crit-bit tree, recursively
    function msb(uint256 x) internal pure returns (uint256 r) {
        while (x > 1) {
            x >>= 1;
            r++;
        }
    }

    function split(uint256[] memory z, uint256 lo, uint256 hi) internal pure returns (uint256 g, uint256 bit) {
        for (uint256 i = lo; i < hi; i++) {
            uint256 b = msb(z[i] ^ z[i + 1]);
            if (i == lo || b > bit) {
                bit = b;
                g = i;
            }
        }
    }

    function radixHash(uint256[] memory z, uint256 lo, uint256 hi) internal pure returns (bytes32) {
        if (lo == hi) return keccak256(abi.encodePacked(uint8(0), z[lo]));
        (uint256 g, uint256 bit) = split(z, lo, hi);
        return keccak256(abi.encodePacked(uint8(1), uint8(bit), radixHash(z, lo, g), radixHash(z, g + 1, hi)));
    }

    function radixProof(uint256[] memory z, uint256 eta) internal pure returns (bytes memory p) {
        uint256 lo = 0;
        uint256 hi = z.length - 1;
        uint256[] memory bits = new uint256[](z.length);
        bytes32[] memory sibs = new bytes32[](z.length);
        uint256 d = 0;
        while (lo < hi) {
            (uint256 g, uint256 bit) = split(z, lo, hi);
            bits[d] = bit;
            if ((eta >> bit) & 1 == 1) {
                sibs[d] = radixHash(z, lo, g);
                lo = g + 1;
            } else {
                sibs[d] = radixHash(z, g + 1, hi);
                hi = g;
            }
            d++;
        }
        p = bytes.concat(bytes1(uint8(d)), bytes32(z[lo]));
        for (uint256 j = d; j > 0; j--) {
            p = bytes.concat(p, bytes1(uint8(bits[j - 1])), sibs[j - 1]);
        }
    }
}
