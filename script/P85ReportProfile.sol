// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// @notice The two retirement report profiles of a reset genesis (#1297/#1298), in UC seconds, selected by P85_PROFILE.
///
///   production: W 7 d + 12 h reporting and inclusion margin = reportWindow 648,000; settlementMargin 43,200; timeFloor 691,200 (8 d).
///   testnet:    W 900 + 900 reporting and inclusion margin = reportWindow 1,800;   settlementMargin 1,800;  timeFloor 3,600.
///
/// Policy validation (FixedPolicy, GovernanceParams) refuses any snapshot with timeFloor < reportWindow + settlementMargin, at genesis
/// and on every governance update, so a mixed profile cannot be constructed.
library P85ReportProfile {
    error UnknownProfile(string name);

    function named(string memory name)
        internal
        pure
        returns (uint64 timeFloor, uint64 reportWindow, uint64 settlementMargin)
    {
        bytes32 h = keccak256(bytes(name));
        if (h == keccak256("production")) return (691_200, 648_000, 43_200);
        if (h != keccak256("testnet")) revert UnknownProfile(name);
        return (3_600, 1_800, 1_800);
    }
}
