// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {IRootRecords} from "../../src/p85/IP85.sol";
import {RootRecord, RecordKind} from "../../src/p85/P85Types.sol";

/// @notice Minimal local fixture for the authenticated root-record source.
/// To be replaced by PR1's authenticated SealRegistry fixtures: it carries no certificates, only
/// the interface PR2 consumes (sequential records with predecessors, progress and UC time).
contract MockRootRecords is IRootRecords {
    RootRecord[] internal _records;
    uint64 public progress;
    uint64 public ucTime;

    function recordCount() external view returns (uint64) {
        return uint64(_records.length);
    }

    function recordAt(uint64 index) external view returns (RootRecord memory) {
        return _records[index];
    }

    function setClock(uint64 p, uint64 t) external {
        require(p >= progress && t >= ucTime, "non-monotonic");
        progress = p;
        ucTime = t;
    }

    function push(RecordKind kind, bytes memory data) external returns (uint64 index) {
        index = uint64(_records.length);
        bytes32 predecessor = index == 0 ? bytes32(0) : _records[index - 1].recordID;
        bytes32 id = keccak256(abi.encode(index, predecessor, kind, progress, ucTime, data));
        _records.push(RootRecord(index, id, predecessor, kind, progress, ucTime, data));
    }

    /// @dev Append a record verbatim, for out-of-order and malformed-chain tests.
    function pushRaw(RootRecord memory r) external {
        _records.push(r);
    }

    function lastRecordID() external view returns (bytes32) {
        return _records.length == 0 ? bytes32(0) : _records[_records.length - 1].recordID;
    }
}
