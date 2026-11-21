// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {
    NativeBridgeVault11,
    NativeBridgeVault11Ordinary
} from "../../../src/nb2/NativeBridgeVault11.sol";
import {EchoVerifierV2} from "../NB2TestBase.sol";
import {ProdHarness} from "./ProdHarness.sol";

/// @notice A/B of the ordinary hot path: an ordinary-only v1.1 vault (A) against the full vault with the cold route (B) under the
///         production verifier graph, at matched Γ, state, warmth and calldata. B's cold route is served by the fallback, so
///         the ordinary dispatch should be unchanged; the figures below are the measured delta.
contract NB2Vault11GasTest is ProdHarness {
    uint256 private constant K = 64;
    address private constant RECIPIENT = address(0x96f21e5603aff0A874383f28d66b2f68e6B51e2d);
    bytes32 private constant ASSET =
        0x87b0b8b600fcd942cc3383bac1dbb80fd69d54af700cf48faa4525451a7b1845;
    Graph private gr;

    function setUp() public override {
        super.setUp();
        gr = _production();
    }

    function _deploy(bool full) private {
        if (full) {
            deployCodeTo(
                "NativeBridgeVault11.sol:NativeBridgeVault11",
                abi.encode(
                    gr.gamma, address(gr.recovery), address(gr.recovery).codehash, gr.profile
                ),
                VAULT_ADDRESS
            );
        } else {
            deployCodeTo(
                "NativeBridgeVault11.sol:NativeBridgeVault11Ordinary",
                abi.encode(gr.gamma, gr.profile),
                VAULT_ADDRESS
            );
        }
        vm.etch(address(gr.ordinary), type(EchoVerifierV2).runtimeCode);
    }

    function _state(uint256 c, uint256 m) private {
        vm.store(
            VAULT_ADDRESS,
            bytes32(uint256(0)),
            bytes32((uint256(3) << 200) | (c << 152) | (m << 144) | 1000)
        );
        bytes32 head = keccak256("head");
        vm.store(VAULT_ADDRESS, bytes32(1 + (c & 1)), head);
        if (c != 0) vm.store(VAULT_ADDRESS, bytes32(1 + ((c - 1) & 1)), keccak256("prev"));
        uint256 tags;
        for (uint256 i; i < m; ++i) {
            bytes32 id = bytes32(keccak256(abi.encode("cur", i)));
            tags |= (uint256(id) >> 252) << (4 * i);
            vm.store(VAULT_ADDRESS, bytes32(16 + (c & 1) * K + i), id);
        }
        vm.store(VAULT_ADDRESS, bytes32(3 + (c & 1)), bytes32(tags));
        tags = 0;
        for (uint256 i; i < K && c != 0; ++i) {
            bytes32 id = bytes32(keccak256(abi.encode("old", i)));
            tags |= (uint256(id) >> 252) << (4 * i);
            vm.store(VAULT_ADDRESS, bytes32(16 + ((c & 1) ^ 1) * K + i), id);
        }
        if (c != 0) vm.store(VAULT_ADDRESS, bytes32(3 + ((c & 1) ^ 1)), bytes32(tags));
        vm.deal(VAULT_ADDRESS, 1000);
    }

    function _verdict(bytes32 eta, uint256 start) private view returns (bytes memory) {
        return abi.encode(sha256(gr.gamma), eta, uint64(start), ASSET, RECIPIENT, uint256(100));
    }

    /// @dev Gas used by the call and whether it succeeded.
    function _call(bytes memory data) private returns (uint256 used, bool ok) {
        uint256 before = gasleft();
        (ok,) = VAULT_ADDRESS.call(data);
        used = before - gasleft();
    }

    function _redeem(uint256 c, uint256 m, uint256 start, bytes32 eta)
        private
        view
        returns (bytes memory)
    {
        c;
        m;
        return abi.encodeWithSignature(
            "redeem(bytes,bytes32,uint64,bytes)",
            _verdict(eta, start),
            eta,
            uint64(start),
            bytes("")
        );
    }

    function _measure(
        string memory label,
        uint256 c,
        uint256 m,
        uint256 start,
        bool expectOk,
        bool preloaded
    ) private {
        bytes32 eta = keccak256(abi.encode("target", label));
        uint256 snap = vm.snapshotState();
        uint256[2] memory used;
        for (uint256 v; v < 2; ++v) {
            _deploy(v == 1);
            _state(c, m);
            if (preloaded) {
                // The target is already in the current buffer: AlreadyPaid after the scan.
                vm.store(VAULT_ADDRESS, bytes32(16 + (c & 1) * K + m), eta);
                vm.store(
                    VAULT_ADDRESS,
                    bytes32(3 + (c & 1)),
                    bytes32(
                        (uint256(vm.load(VAULT_ADDRESS, bytes32(3 + (c & 1))))
                                & ~(uint256(15) << (4 * m))) | ((uint256(eta) >> 252) << (4 * m))
                    )
                );
                vm.store(
                    VAULT_ADDRESS,
                    bytes32(uint256(0)),
                    bytes32(
                        uint256(vm.load(VAULT_ADDRESS, bytes32(uint256(0)))) + (uint256(1) << 144)
                    )
                );
            }
            bytes memory data = _redeem(c, m, start, eta);
            bool ok;
            (used[v], ok) = _call(data);
            assertEq(ok, expectOk, label);
            vm.revertToState(snap);
        }
        emit log_named_uint(string.concat(label, " A ordinary-only"), used[0]);
        emit log_named_uint(string.concat(label, " B full vault"), used[1]);
        emit log_named_int(string.concat(label, " delta"), int256(used[1]) - int256(used[0]));
        assertLe(used[1], used[0] + 100, string.concat(label, ": dispatch delta above 100"));
    }

    function testOrdinaryPathGasDelta() external {
        _measure("pay current buffer c=7 m=10", 7, 10, 7, true, false);
        _measure("pay previous+current c=8 m=30 e=c-1", 8, 30, 7, true, false);
        _measure("pay and seal c=7 m=63", 7, 63, 7, true, false);
        _measure("pay first slot c=0 m=0", 0, 0, 0, true, false);
        _measure("AlreadyPaid refusal c=7 m=10", 7, 10, 7, false, true);
    }

    function testDepositGasDelta() external {
        uint256 snap = vm.snapshotState();
        uint256[2] memory used;
        bytes memory owner =
            hex"d99878830141015821021111111111111111111111111111111111111111111111111111111111111111";
        for (uint256 v; v < 2; ++v) {
            _deploy(v == 1);
            vm.deal(address(this), 10);
            bytes memory data =
                abi.encodeWithSignature("deposit(bytes,bytes32)", owner, bytes32(uint256(5)));
            uint256 before = gasleft();
            (bool ok,) = VAULT_ADDRESS.call{value: 5}(data);
            used[v] = before - gasleft();
            assertTrue(ok);
            vm.revertToState(snap);
        }
        emit log_named_uint("deposit A ordinary-only", used[0]);
        emit log_named_uint("deposit B full vault", used[1]);
        assertLe(used[1], used[0] + 100);
    }

    function testUnknownSelectorIsBadPacketOnlyInTheFullVault() external {
        uint256 snap = vm.snapshotState();
        _deploy(true);
        (bool ok, bytes memory out) = VAULT_ADDRESS.call(hex"12345678");
        assertFalse(ok);
        assertEq(bytes4(out), bytes4(keccak256("BadPacket()")));
        vm.revertToState(snap);
        _deploy(false);
        (ok, out) = VAULT_ADDRESS.call(hex"12345678");
        assertFalse(ok);
        assertEq(out.length, 0);
    }
}
