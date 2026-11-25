// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {IRootRecords, ISealHistory, SealEpoch} from "../../src/p85/IP85.sol";
import {RootRecord, RecordKind} from "../../src/p85/P85Types.sol";

/// @notice Minimal local fixture for the authenticated root-record source.
/// To be replaced by PR1's authenticated SealRegistry fixtures: it carries no certificates, only
/// the interface PR2 consumes (sequential records with predecessors, progress and UC time).
contract MockRootRecords is IRootRecords, ISealHistory {
    RootRecord[] internal _records;
    uint64 public progress;
    uint64 public ucTime;
    /// @dev The installed B1 history (ISealHistory). While `strictEpochs` is false (the default, also for an etched copy) every epoch
    /// that was not installed explicitly reads as present, so a test that does not exercise the successor check sees it installed.
    bool public strictEpochs;
    mapping(uint64 => SealEpoch) internal _epochs;
    mapping(uint64 => bytes[]) internal _memberKeys;
    mapping(uint64 => uint64[]) internal _memberWeights;

    function setStrictEpochs(bool strict) external {
        strictEpochs = strict;
    }

    /// @dev Install (or overwrite) epoch e with its members; memberCount and totalWeight are derived.
    function installEpoch(
        uint64 e,
        uint64 start,
        bool hasEnd,
        uint64 end,
        uint64 scheme,
        bytes32 activationCommitID,
        bytes[] memory keys,
        uint64[] memory weights
    ) external {
        require(keys.length == weights.length, "members");
        delete _memberKeys[e];
        delete _memberWeights[e];
        uint64 total;
        for (uint256 i; i < keys.length; ++i) {
            _memberKeys[e].push(keys[i]);
            _memberWeights[e].push(weights[i]);
            total += weights[i];
        }
        _epochs[e] = SealEpoch(
            true, start, hasEnd, end, scheme, activationCommitID, uint64(keys.length), total
        );
    }

    function sealEpoch(uint64 e) external view returns (SealEpoch memory v) {
        v = _epochs[e];
        if (!v.present && !strictEpochs) v.present = true;
    }

    function sealMember(uint64 e, uint256 index)
        external
        view
        returns (bytes memory key, uint64 weight)
    {
        require(index < _memberKeys[e].length, "member out of range");
        return (_memberKeys[e][index], _memberWeights[e][index]);
    }

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
