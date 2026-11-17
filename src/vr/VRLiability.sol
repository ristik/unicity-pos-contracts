// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRC} from "./VRConstants.sol";

/// @title VRLiability
/// @notice The frozen generic liability-holder layout (design section 3.9.2, schema v1 section 2.6) that every liability holder writes in
/// its own storage at B = ERC-7201 `unicity.vr.liability.v1`, in the same function as every liability mutation. VR never writes it; the
/// generic Retirement verifier reads it at P.
library VRLiability {
    struct Facts {
        bool requested; // sticky
        uint32 liveExposures;
        uint32 lotReferences;
        uint64 maxLiabilityAnchor;
        bytes32 refDigest;
    }

    /// @custom:storage-location erc7201:unicity.vr.liability.v1
    struct LiabilityStorage {
        uint64 cursor; // B+0: the holder's root-record cursor
        mapping(uint64 => mapping(uint64 => Facts)) facts; // B+1: id => generation => facts
    }

    event RetirementRequested(uint64 indexed id, uint64 indexed generation);

    function load() internal pure returns (LiabilityStorage storage $) {
        bytes32 ns = VRC.LIABILITY_NAMESPACE;
        assembly ("memory-safe") {
            $.slot := ns
        }
    }
}
