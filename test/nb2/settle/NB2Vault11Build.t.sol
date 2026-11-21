// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {NativeBridgeVault11} from "../../../src/nb2/NativeBridgeVault11.sol";
import {ProdHarness} from "./ProdHarness.sol";

/// A recovery verifier that publishes whatever bindings it is given.
contract MockRecovery {
    bytes32 public DOMAIN;
    address public VAULT;
    address public ORDINARY;
    bytes32 public ORDINARY_HASH;
    address public RECEIPTS;
    bytes32 public RECEIPTS_HASH;
    bytes32 public PINS;
    bytes32 public GENERATION;

    constructor(
        bytes32 d,
        address v,
        address o,
        bytes32 oh,
        address r,
        bytes32 rh,
        bytes32 p,
        bytes32 g
    ) {
        (
            DOMAIN, VAULT, ORDINARY, ORDINARY_HASH, RECEIPTS, RECEIPTS_HASH, PINS, GENERATION
        ) = (d, v, o, oh, r, rh, p, g);
    }
}

/// @notice The production vault graph: generation checks, and refusal of foreign pin, helper and test configurations.
contract NB2Vault11BuildTest is ProdHarness {
    function _vault(bytes memory g, address recovery, bytes32 runtime, bytes32 profile) private {
        deployCodeTo(
            "NativeBridgeVault11.sol:NativeBridgeVault11",
            abi.encode(g, recovery, runtime, profile),
            VAULT_ADDRESS
        );
    }

    string private constant CTOR_FAILED =
        "StdCheats deployCodeTo(string,bytes,uint256,address): Failed to create runtime bytecode.";

    /// @dev `field` documents the expected BadConfig(field); deployCodeTo reports any constructor revert generically. Each
    ///      refusal is paired in the tests with an accepted deployment that differs only in the refused binding.
    function _refused(
        bytes memory g,
        address recovery,
        bytes32 runtime,
        bytes32 profile,
        uint256 field
    ) private {
        field;
        vm.expectRevert(bytes(CTOR_FAILED));
        this.attempt(g, recovery, runtime, profile);
    }

    function attempt(bytes memory g, address recovery, bytes32 runtime, bytes32 profile) external {
        _vault(g, recovery, runtime, profile);
    }

    function testProductionGraphConstructs() external {
        Graph memory gr = _production();
        _vault(gr.gamma, address(gr.recovery), address(gr.recovery).codehash, gr.profile);
        NativeBridgeVault11 v = NativeBridgeVault11(payable(VAULT_ADDRESS));
        assertEq(v.domain(), sha256(gr.gamma));
        assertEq(v.RECOVERY(), address(gr.recovery));
        assertEq(v.RECOVERY_RUNTIME(), address(gr.recovery).codehash);
        assertEq(v.RECOVERY_GENERATION(), gr.recovery.GENERATION());
        assertEq(v.RECOVERY_PINS(), gr.recovery.PINS());
        assertEq(address(v.RECEIPTS()), address(gr.recovery.RECEIPTS()));
        assertEq(keccak256(v.config()), keccak256(gr.gamma));
    }

    function testForeignPinsHelpersAndConfigurationsAreRefused() external {
        Graph memory gr = _production();
        address rec = address(gr.recovery);
        bytes32 runtime = rec.codehash;
        // The recovery's runtime hash is pinned.
        _refused(gr.gamma, rec, bytes32(uint256(runtime) ^ 1), gr.profile, 14);
        // The profile digest is pinned (and nonzero).
        _refused(gr.gamma, rec, runtime, bytes32(uint256(gr.profile) ^ 1), 13);
        _refused(gr.gamma, rec, runtime, bytes32(0), 13);
        // A recovery bound to another vault (its own Γ differs in the vault field), or to another domain.
        bytes memory other =
            _patch(gr.gamma, _vaultOffset(gr.gamma), abi.encodePacked(address(0xf300)));
        address foreign = address(_recovery(other, gr.ordinary));
        _refused(gr.gamma, foreign, foreign.codehash, gr.profile, 14);
        // A recovery publishing a foreign ordinary verifier, ordinary hash, receipt helper hash, zero pins or generation.
        bytes32 d = sha256(gr.gamma);
        address rcp = address(gr.recovery.RECEIPTS());
        bytes32 rch = gr.recovery.RECEIPTS_HASH();
        _mock(gr, d, VAULT_ADDRESS, address(0xbeef), gr.recovery.ORDINARY_HASH(), rcp, rch, 1, 1);
        _mock(gr, d, VAULT_ADDRESS, address(gr.ordinary), bytes32(uint256(1)), rcp, rch, 1, 1);
        _mock(
            gr,
            d,
            VAULT_ADDRESS,
            address(gr.ordinary),
            address(gr.ordinary).codehash,
            rcp,
            bytes32(uint256(7)),
            1,
            1
        );
        _mock(
            gr,
            d,
            VAULT_ADDRESS,
            address(gr.ordinary),
            address(gr.ordinary).codehash,
            address(0xdead),
            keccak256(""),
            1,
            1
        );
        _mock(
            gr,
            d,
            VAULT_ADDRESS,
            address(gr.ordinary),
            address(gr.ordinary).codehash,
            rcp,
            rch,
            0,
            1
        );
        _mock(
            gr,
            d,
            VAULT_ADDRESS,
            address(gr.ordinary),
            address(gr.ordinary).codehash,
            rcp,
            rch,
            1,
            0
        );
        // The mock with every binding right is accepted: the refusals above are the bindings, nothing else.
        MockRecovery good = new MockRecovery(
            d,
            VAULT_ADDRESS,
            address(gr.ordinary),
            address(gr.ordinary).codehash,
            rcp,
            rch,
            bytes32(uint256(1)),
            bytes32(uint256(1))
        );
        _vault(gr.gamma, address(good), address(good).codehash, gr.profile);
        // The ordinary verifier's runtime hash in Γ is checked against the live code.
        vm.etch(address(gr.ordinary), hex"00");
        _refused(gr.gamma, address(good), address(good).codehash, gr.profile, 15);
    }

    function testTestAndProductionBuildsAreDisjoint() external {
        Graph memory gr = _production();
        // The reference Γ has K = 64, B = 16: the test build refuses it, so a Γ is valid for exactly one build.
        vm.expectRevert(bytes(CTOR_FAILED));
        this.attemptTestBuild(
            gr.gamma, address(gr.recovery), address(gr.recovery).codehash, gr.profile
        );
    }

    function attemptTestBuild(bytes memory g, address recovery, bytes32 runtime, bytes32 profile)
        external
    {
        deployCodeTo(
            "NativeBridgeVault11.sol:NativeBridgeVault11Test",
            abi.encode(g, recovery, runtime, profile),
            VAULT_ADDRESS
        );
    }

    function testWrongChainOrVaultAddressIsRefused() external {
        Graph memory gr = _production();
        vm.chainId(1);
        _refused(gr.gamma, address(gr.recovery), address(gr.recovery).codehash, gr.profile, 5);
        vm.chainId(31337);
        vm.expectRevert(bytes(CTOR_FAILED));
        this.attemptAt(gr.gamma, address(gr.recovery), address(0xf222));
        // The same Γ at its own address on its own chain is accepted.
        _vault(gr.gamma, address(gr.recovery), address(gr.recovery).codehash, gr.profile);
    }

    function attemptAt(bytes memory g, address recovery, address where) external {
        deployCodeTo(
            "NativeBridgeVault11.sol:NativeBridgeVault11",
            abi.encode(
                g,
                recovery,
                recovery.codehash,
                sha256(vm.readFileBinary(string.concat(DIR, "semantic-profile.bin")))
            ),
            where
        );
    }

    function _mock(
        Graph memory gr,
        bytes32 d,
        address vaultAddr,
        address ordinary,
        bytes32 ordinaryHash,
        address receiptsAddr,
        bytes32 receiptsHash,
        uint256 pins,
        uint256 generation
    ) private {
        MockRecovery m = new MockRecovery(
            d,
            vaultAddr,
            ordinary,
            ordinaryHash,
            receiptsAddr,
            receiptsHash,
            bytes32(pins),
            bytes32(generation)
        );
        _refused(gr.gamma, address(m), address(m).codehash, gr.profile, 14);
    }

    function _vaultOffset(bytes memory g) private pure returns (uint256) {
        for (uint256 i; i + 21 <= g.length; ++i) {
            if (g[i] == 0x54 && g[i + 19] == 0xf2 && g[i + 20] == 0x00 && g[i + 1] == 0x00) {
                return i + 1;
            }
        }
        revert("vault field");
    }
}
