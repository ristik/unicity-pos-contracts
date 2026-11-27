// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {FlatBindings} from "../../../src/nb2/verifier/flat/FlatBindings.sol";
import {NativeBridgeVerifier11} from "../../../src/nb2/verifier/flat/NativeBridgeVerifier11.sol";
import {NativeBridgeRecovery11} from "../../../src/nb2/verifier/flat/NativeBridgeRecovery11.sol";
import {FlatHarness} from "../flat/FlatHarness.sol";

/// @dev The production verifier graph (NativeBridgeVerifier11 and NativeBridgeRecovery11 as deployed) bound to the reference Γ
///      with only the ordinary address and runtime hash fields rewritten, as in the T3 production-binding test.
abstract contract ProdHarness is FlatHarness {
    address internal constant VAULT_ADDRESS = address(0xf200);

    struct Graph {
        bytes gamma;
        NativeBridgeVerifier11 ordinary;
        NativeBridgeRecovery11 recovery;
        bytes32 profile;
    }

    function _descriptors() internal view returns (FlatBindings.ReleaseInputs memory) {
        return FlatBindings.ReleaseInputs(
            _descriptor("cert-batch-v2"),
            _descriptor("rsmt-member-v1"),
            _descriptor("seal-registry-layout"),
            _descriptor("cancun-b1"),
            _descriptor("build-index"),
            _descriptor("primitive-vectors")
        );
    }

    function _production() internal returns (Graph memory gr) {
        vm.etch(REGISTRY, hex"600200");
        gr.profile = sha256(vm.readFileBinary(string.concat(DIR, "semantic-profile.bin")));
        gr.ordinary = NativeBridgeVerifier11(
            deployCode(
                "NativeBridgeVerifier11.sol:NativeBridgeVerifier11",
                abi.encode(lineage, address(lineage).codehash, gr.profile, REGISTRY.codehash)
            )
        );
        gr.gamma = _patch(gamma, 252, abi.encodePacked(address(gr.ordinary)));
        gr.gamma = _patch(gr.gamma, 274, abi.encodePacked(address(gr.ordinary).codehash));
        gr.recovery = _recovery(gr.gamma, gr.ordinary);
    }

    function _recovery(bytes memory g, NativeBridgeVerifier11 ordinary)
        internal
        returns (NativeBridgeRecovery11)
    {
        FlatBindings.ReleaseInputs memory desc = _descriptors();
        bytes32 pins = FlatBindings.pins(
            desc,
            address(ordinary),
            address(ordinary).codehash,
            address(receipts),
            address(receipts).codehash,
            REGISTRY.codehash,
            address(lineage),
            address(lineage).codehash
        );
        return NativeBridgeRecovery11(
            payable(deployCode(
                    "NativeBridgeRecovery11.sol:NativeBridgeRecovery11",
                    abi.encode(g, ordinary, _gold("generation-salt.bin"), desc, pins)
                ))
        );
    }

    function _patch(bytes memory b, uint256 offset, bytes memory v)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(b);
        for (uint256 i; i < v.length; ++i) {
            out[offset + i] = v[i];
        }
    }
}
