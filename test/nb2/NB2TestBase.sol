// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test, Vm} from "forge-std/Test.sol";
import {NB2VaultBase} from "../../src/nb2/NB2VaultBase.sol";
import {NB2Config} from "../../src/nb2/NB2Config.sol";
import {NativeBridgeVaultV2} from "../../src/nb2/NativeBridgeVaultV2.sol";
import {NativeBridgeVaultV2Test} from "../../src/nb2/NativeBridgeVaultV2Test.sol";

/// The vault's external surface, as the spec's ABI (section 13).
interface INB2Vault {
    function deposit(bytes calldata firstOwner, bytes32 rho) external payable;
    function redeem(
        bytes calldata evidence,
        bytes32 claimedEta,
        uint64 claimedStart,
        bytes calldata history
    ) external;
    function domain() external view returns (bytes32);
    function config() external view returns (bytes memory);
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

/// A mock verifier (section 11.2): it returns or reverts with configured raw bytes, or, in echo mode, returns the evidence
/// itself (the evidence is then the 192-byte verdict). When `gammaHash` is set it refuses any Γ other than the expected one.
contract MockVerifierV2 {
    bool public reverts;
    bool public echo;
    bytes public data;
    bytes32 public gammaHash;

    function set(bool reverts_, bytes calldata data_) external {
        reverts = reverts_;
        echo = false;
        data = data_;
    }

    function setEcho() external {
        echo = true;
    }

    function expectGamma(bytes32 h) external {
        gammaHash = h;
    }

    function verifyReturn(bytes calldata gamma, bytes calldata evidence)
        external
        view
        returns (bytes32, bytes32, uint64, bytes32, address, uint256)
    {
        if (gammaHash != bytes32(0) && keccak256(gamma) != gammaHash) {
            revert("mock: unexpected gamma");
        }
        bytes memory out = data;
        if (echo) out = evidence;
        bool r = reverts && !echo;
        assembly ("memory-safe") {
            switch r
            case 0 { return(add(out, 32), mload(out)) }
            default { revert(add(out, 32), mload(out)) }
        }
    }
}

/// The NB2-02 bake-off's mock verifier (bench/nb2/src/MockVerifier.sol): stateless, the evidence is the verdict. The gas
/// suite etches it over the configurable mock so the figures compare with the bake-off's.
contract EchoVerifierV2 {
    function verifyReturn(bytes calldata, bytes calldata evidence)
        external
        pure
        returns (bytes32, bytes32, uint64, bytes32, address, uint256)
    {
        return abi.decode(evidence, (bytes32, bytes32, uint64, bytes32, address, uint256));
    }
}

/// A recipient that refuses value.
contract RevertingRecipient {
    receive() external payable {
        revert("no");
    }
}

/// A recipient that re-enters the vault from its receive hook, records the inner revert data and accepts the value.
contract ReenteringRecipient {
    INB2Vault internal immutable VAULT;
    bool internal immutable VIA_DEPOSIT;
    bytes public inner;

    constructor(INB2Vault vault, bool viaDeposit) {
        VAULT = vault;
        VIA_DEPOSIT = viaDeposit;
    }

    receive() external payable {
        if (VIA_DEPOSIT) {
            try VAULT.deposit{value: 1}("", bytes32(0)) {
                inner = "entered";
            } catch (bytes memory r) {
                inner = r;
            }
        } else {
            try VAULT.redeem("", bytes32(0), 0, "") {
                inner = "entered";
            } catch (bytes memory r) {
                inner = r;
            }
        }
    }
}

/// An independent plain-Solidity reference of the segment commitment (sections 10.1 to 10.3), written without the vault's
/// assembly: sorting, the circular-gap tree, gap proofs and archive steps.
library NB2Ref {
    bytes32 internal constant ARCHIVE_GENESIS = keccak256("UNICITY_NB2_ARCHIVE_GENESIS");
    bytes32 internal constant ARCHIVE_STEP = keccak256("UNICITY_NB2_ARCHIVE_STEP");

    function log2(uint256 x) internal pure returns (uint256 n) {
        while ((1 << n) < x) n++;
    }

    function bucket(bytes32 eta, uint256 b) internal pure returns (uint256) {
        return uint256(eta) >> (256 - log2(b));
    }

    function sorted(bytes32[] memory ids) internal pure returns (bytes32[] memory z) {
        z = new bytes32[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            z[i] = ids[i];
        }
        for (uint256 i = 1; i < z.length; i++) {
            bytes32 v = z[i];
            uint256 j = i;
            while (j > 0 && uint256(z[j - 1]) > uint256(v)) {
                z[j] = z[j - 1];
                j--;
            }
            z[j] = v;
        }
    }

    function leaves(bytes32[] memory z) internal pure returns (bytes32[] memory lv) {
        uint256 k = z.length;
        lv = new bytes32[](k);
        for (uint256 i = 0; i < k; i++) {
            lv[i] = keccak256(abi.encodePacked(bytes1(0x00), z[i], z[(i + 1) % k]));
        }
    }

    function root(bytes32[] memory z) internal pure returns (bytes32) {
        bytes32[] memory lv = leaves(z);
        for (uint256 w = lv.length / 2; w > 0; w /= 2) {
            for (uint256 i = 0; i < w; i++) {
                lv[i] = keccak256(abi.encodePacked(bytes1(0x01), lv[2 * i], lv[2 * i + 1]));
            }
        }
        return lv[0];
    }

    /// The gap proof of eta in the strictly sorted segment z, or paid = true when eta is one of its identifiers.
    function proof(bytes32[] memory z, bytes32 eta)
        internal
        pure
        returns (bool paid, bytes memory p)
    {
        uint256 k = z.length;
        uint256 e = uint256(eta);
        uint256 idx = k - 1;
        for (uint256 i = 0; i < k; i++) {
            if (z[i] == eta) return (true, "");
            if (i + 1 < k && uint256(z[i]) < e && e < uint256(z[i + 1])) idx = i;
        }
        p = abi.encodePacked(uint8(idx), z[idx], z[(idx + 1) % k]);
        bytes32[] memory lv = leaves(z);
        uint256 pos = idx;
        for (uint256 w = k; w > 1; w /= 2) {
            p = bytes.concat(p, lv[pos ^ 1]);
            for (uint256 i = 0; i < w / 2; i++) {
                lv[i] = keccak256(abi.encodePacked(bytes1(0x01), lv[2 * i], lv[2 * i + 1]));
            }
            pos /= 2;
        }
    }

    function genesis(bytes32 d, uint256 k) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ARCHIVE_GENESIS, d, uint16(k)));
    }

    function step(bytes32 d, uint256 j, bytes32 hj, bytes32 mj) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ARCHIVE_STEP, d, uint64(j), hj, mj));
    }
}

/// Γ construction for tests (section 4.1) and the deployment helpers shared by the NB2 vault suites.
contract NB2TestBase is Test {
    bytes32 internal constant ASSET_UCT =
        0x87b0b8b600fcd942cc3383bac1dbb80fd69d54af700cf48faa4525451a7b1845;
    bytes32 internal constant TOPIC_DEPOSITED =
        keccak256("Deposited(uint64,bytes32,uint256,bytes32,bytes)");
    bytes32 internal constant TOPIC_PAID = keccak256("Paid(bytes32,address,uint256)");
    bytes32 internal constant TOPIC_SEALED =
        keccak256("SegmentSealed(uint64,bytes32,bytes32,bytes)");
    address internal constant RECIPIENT = address(0x00000000000000000000000000000000000BeeF0);

    struct GammaFields {
        uint256 network;
        bytes32 rootGenesis;
        bytes32 executionGenesis;
        uint256 chainId;
        uint256 evmPartition;
        bytes evmShard;
        uint256 aggregatorPartition;
        address vault;
        bytes32 asset;
        bytes32 ty;
        bytes32 aid;
        bytes32 profileHash;
        address verifier;
        bytes32 verifierCodeHash;
        uint256 k;
        uint256 b;
        uint256 qmax;
    }

    /// A deployed vault with its mock verifier and the test's own mirror of what it has paid.
    struct World {
        INB2Vault v;
        MockVerifierV2 mock;
        bytes32 d;
        uint256 k;
        uint256 b;
        uint256 c; // mirror of the segment index
        bytes32[] cur; // identifiers paid into segment c, in arrival order
        bytes32[] prev; // identifiers of segment c - 1
        bytes32[][] segs; // sorted identifiers of every sealed segment
        bytes32[] heads; // H_0 .. H_c
        uint256 ctr;
    }

    // -------------------------------------------------------------------------------------------- CBOR
    function cHead(uint256 major, uint256 n) internal pure returns (bytes memory) {
        bytes1 m = bytes1(uint8(major << 5));
        if (n < 24) return abi.encodePacked(bytes1(uint8(major << 5) | uint8(n)));
        if (n < 1 << 8) return abi.encodePacked(m | 0x18, uint8(n));
        if (n < 1 << 16) return abi.encodePacked(m | 0x19, uint16(n));
        if (n < 1 << 32) return abi.encodePacked(m | 0x1a, uint32(n));
        return abi.encodePacked(m | 0x1b, uint64(n));
    }

    function cUint(uint256 n) internal pure returns (bytes memory) {
        return cHead(0, n);
    }

    function cBytes(bytes memory b) internal pure returns (bytes memory) {
        return bytes.concat(cHead(2, b.length), b);
    }

    function amountBytes(uint256 v) internal pure returns (bytes memory out) {
        uint256 n = 0;
        for (uint256 t = v; t != 0; t >>= 8) {
            n++;
        }
        out = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            out[n - 1 - i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    function encodeGamma(GammaFields memory f) internal pure returns (bytes memory) {
        bytes memory a = bytes.concat(
            cHead(4, 19),
            cBytes("UNICITY_NB2_CFG"),
            cUint(1),
            cUint(f.network),
            cBytes(abi.encodePacked(f.rootGenesis)),
            cBytes(abi.encodePacked(f.executionGenesis)),
            cUint(f.chainId),
            cUint(f.evmPartition),
            cBytes(f.evmShard),
            cUint(f.aggregatorPartition)
        );
        return bytes.concat(
            a,
            cBytes(abi.encodePacked(f.vault)),
            cBytes(abi.encodePacked(f.asset)),
            cBytes(abi.encodePacked(f.ty)),
            cBytes(abi.encodePacked(f.aid)),
            cBytes(abi.encodePacked(f.profileHash)),
            cBytes(abi.encodePacked(f.verifier)),
            cBytes(abi.encodePacked(f.verifierCodeHash)),
            cUint(f.k),
            cUint(f.b),
            cBytes(amountBytes(f.qmax))
        );
    }

    /// A valid Γ for (k, b) whose vault is `vault` and verifier `verifier` (section 4.2 derivations applied).
    function fields(address vault, address verifier, uint256 k, uint256 b, uint256 qmax)
        internal
        view
        returns (GammaFields memory f)
    {
        f.network = 3;
        f.rootGenesis = keccak256("root genesis");
        f.executionGenesis = keccak256("execution genesis");
        f.chainId = block.chainid;
        f.evmPartition = 8;
        f.evmShard = hex"80";
        f.aggregatorPartition = 3;
        f.vault = vault;
        f.asset = ASSET_UCT;
        bytes memory dstr =
            NB2Config.identityString(f.network, f.rootGenesis, f.executionGenesis, f.chainId);
        f.ty = sha256(bytes.concat("unicity-bridge:unicity-native-nb2:", dstr));
        f.aid = sha256(bytes.concat("unicity-bridge-coin:unicity-native-nb2:", dstr));
        f.profileHash = keccak256("profile");
        f.verifier = verifier;
        f.verifierCodeHash = verifier.codehash;
        f.k = k;
        f.b = b;
        f.qmax = qmax;
    }

    function isProduction(uint256 k, uint256 b) internal pure returns (bool) {
        return k == 64 && b == 16;
    }

    /// Deploys the build for (k, b) with a fresh mock verifier and qmax; the mock echoes the evidence as its verdict.
    function deploy(uint256 k, uint256 b, uint256 qmax) internal returns (World memory w) {
        w.mock = new MockVerifierV2();
        address addr = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        bytes memory gamma = encodeGamma(fields(addr, address(w.mock), k, b, qmax));
        if (isProduction(k, b)) w.v = INB2Vault(address(new NativeBridgeVaultV2(gamma)));
        else w.v = INB2Vault(address(new NativeBridgeVaultV2Test(gamma)));
        assertEq(address(w.v), addr, "predicted vault address");
        w.mock.setEcho();
        w.mock.expectGamma(keccak256(gamma));
        w.d = w.v.domain();
        assertEq(w.d, sha256(gamma), "D = H_U(gamma)");
        w.k = k;
        w.b = b;
        w.heads = new bytes32[](1);
        w.heads[0] = NB2Ref.genesis(w.d, k);
        w.segs = new bytes32[][](0);
        w.cur = new bytes32[](0);
        w.prev = new bytes32[](0);
    }

    function owner() internal pure returns (bytes memory) {
        return bytes.concat(hex"d9987883014101582102", keccak256("depositor key"));
    }

    function fund(World memory w, uint256 value) internal {
        vm.deal(address(this), address(this).balance + value);
        w.v.deposit{value: value}(owner(), keccak256(abi.encode("rho", value, w.ctr++)));
    }

    function verdict(World memory w, bytes32 eta, uint256 a, address to, uint256 amount)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(w.d, eta, uint64(a), ASSET_UCT, to, amount);
    }

    /// A fresh uniform identifier, or one in bucket `bkt` when bkt < B.
    function nextEta(World memory w, uint256 bkt) internal pure returns (bytes32) {
        w.ctr++;
        uint256 x = uint256(keccak256(abi.encode("eta", w.k, w.b, w.ctr)));
        if (bkt >= w.b) return bytes32(x);
        uint256 lb = NB2Ref.log2(w.b);
        return bytes32((bkt << (256 - lb)) | (x >> lb));
    }

    function push(bytes32[] memory a, bytes32 x) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](a.length + 1);
        for (uint256 i = 0; i < a.length; i++) {
            out[i] = a[i];
        }
        out[a.length] = x;
    }

    /// The honest history for eta from start a to endpoint e (section 12.3), built from the mirror; paid = true if eta is
    /// in one of the segments a .. e-1.
    function history(World memory w, bytes32 eta, uint256 a, uint256 e)
        internal
        pure
        returns (bool paid, bytes memory h)
    {
        if (a == e) return (false, "");
        h = abi.encodePacked(w.heads[a]);
        for (uint256 j = a; j < e; j++) {
            (bool p, bytes memory pr) = NB2Ref.proof(w.segs[j], eta);
            if (p) return (true, "");
            h = bytes.concat(h, pr);
        }
    }

    /// Records a successful payment of eta in the mirror, sealing it as the reference does.
    function mirrorPaid(World memory w, bytes32 eta) internal pure {
        w.cur = push(w.cur, eta);
        if (w.cur.length == w.k) {
            bytes32[] memory z = NB2Ref.sorted(w.cur);
            bytes32[][] memory s = new bytes32[][](w.segs.length + 1);
            for (uint256 i = 0; i < w.segs.length; i++) {
                s[i] = w.segs[i];
            }
            s[w.segs.length] = z;
            w.segs = s;
            w.heads = push(w.heads, NB2Ref.step(w.d, w.c, w.heads[w.c], NB2Ref.root(z)));
            w.prev = w.cur;
            w.cur = new bytes32[](0);
            w.c++;
        }
    }

    /// Pays eta at the current endpoint with start a (default: the current segment) to RECIPIENT, amount 1.
    function pay(World memory w, bytes32 eta) internal {
        (, bytes memory h) = history(w, eta, w.c, w.c);
        w.v.redeem(verdict(w, eta, w.c, RECIPIENT, 1), eta, uint64(w.c), h);
        mirrorPaid(w, eta);
    }

    function fill(World memory w, uint256 n, uint256 bkt) internal {
        for (uint256 i = 0; i < n; i++) {
            pay(w, nextEta(w, bkt));
        }
    }

    /// Asserts the vault's state() against the mirror.
    function checkState(World memory w) internal view {
        (, uint64 seg, uint16 pop,, bytes32 head, bytes32 prevHead) = w.v.state();
        assertEq(seg, w.c, "segment");
        assertEq(pop, w.cur.length, "population");
        assertEq(head, w.heads[w.c], "head");
        assertEq(prevHead, w.c == 0 ? bytes32(0) : w.heads[w.c - 1], "previous head");
    }

    function selectorOf(bytes memory r) internal pure returns (bytes4 s) {
        if (r.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            s := mload(add(r, 32))
        }
    }
}
