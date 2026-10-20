// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {SealRegistryBase} from "../SealRegistryBase.sol";
import {SealRegistry} from "../../src/SealRegistry.sol";

/// @notice Drives the real SealRegistry at A_SR for a P85 test: installs its genesis, then runs one registry round per call (open,
/// the mandatory import of the given records at the given anchors, finalize) as the system caller. A separate contract because the
/// registry test base and the P85 test base declare the same names.
contract RegistryDriver is SealRegistryBase {
    OpenArgs internal _round;

    /// @dev The registry with its genesis, at the genesis UC time 0 of the P85 fixtures (the publication fixture's election thresholds
    /// count from the record source's UC time at initialization; the registry base's own fixture starts at 1,000).
    function install() external {
        maxEpochsFixture = MAX_EPOCHS; // the driver is etched, so its initializers never ran
        setUp();
        setWord("records.ucTime", bytes32(0));
    }

    function registry() external pure returns (address) {
        return A_SR;
    }

    function systemCaller() external pure returns (address) {
        return A_SYS;
    }

    function round(uint64 p, uint64 t, SealRegistry.ImportedRecord[] calldata es) external {
        _round = _round.n == 0 ? firstPayload() : _next(_round);
        (bool ok, bytes memory ret) = callAs(A_SYS, openCalldata(_round));
        require(ok, string(ret));
        SealRegistry reg = SealRegistry(A_SR);
        uint64 target = reg.recordCount() + uint64(es.length);
        bytes32 tip = es.length == 0
            ? bytes32(uintWord("records.targetTip"))
            : es[es.length - 1].record.recordID;
        (ok, ret) = callAs(
            A_SYS, abi.encodeCall(SealRegistry.importRootRecords, (_round.n, p, t, target, tip, es))
        );
        require(ok, "import refused");
        (ok, ret) = callAs(
            A_SYS, finalizeCalldata(_round.n, keccak256(abi.encode("p85-registry-round", _round.n)))
        );
        require(ok, "finalize refused");
    }

    function _next(OpenArgs memory a) internal pure returns (OpenArgs memory b) {
        b = a;
        b.n = a.n + 1;
        b.rootRound = a.rootRound + 1;
        b.timestamp = a.timestamp + 1;
    }
}
