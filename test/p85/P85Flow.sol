// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Base} from "./P85Base.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {MockRootRecords} from "./MockRootRecords.sol";
import {
    ReserveInput,
    RecordKind,
    AckData,
    RecoveryAckData,
    SessionClosedData,
    RetirementData
} from "../../src/p85/P85Types.sol";

/// @notice Canonical timelines shared by the lifecycle, maturity and evidence tests.
///
/// Genesis assignment G: root/EVM epoch 1, offset 0, first round 1. A handoff that orders H at
/// round 100 ends G at progress p(1,100) = 99 and starts J at offset 100, first round 101.
abstract contract P85Flow is P85Base {
    bytes32 internal constant RES_J = keccak256("result/J");
    bytes32 internal constant ASG_J = keccak256("assignment/J");
    bytes32 internal constant RES_J2 = keccak256("result/J2");
    bytes32 internal constant ASG_J2 = keccak256("assignment/J2");
    bytes32 internal constant ASG_K = keccak256("assignment/K");
    uint64 internal constant H_ROUND = 100;

    function allExcept(uint256 excluded) internal pure returns (uint256[] memory out) {
        out = new uint256[](N_GENESIS - 1);
        uint256 n;
        for (uint256 i; i < N_GENESIS; ++i) {
            if (i != excluded) out[n++] = i;
        }
    }

    function allMembers() internal pure returns (uint256[] memory out) {
        out = new uint256[](N_GENESIS);
        for (uint256 i; i < N_GENESIS; ++i) {
            out[i] = i;
        }
    }

    function ackData(bytes32 resultID, uint64 replacedH, uint64 offset, uint64 firstRound)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(AckData(resultID, replacedH, offset, firstRound));
    }

    /// @dev Reserve J over every genesis identity except `excluded`, acknowledge it in root order
    /// with H at round 100, and apply the records.
    function handoffExcluding(uint256 excluded) internal {
        reserve(RES_J, ASG_J, allExcept(excluded), 1);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
    }

    function closeGenesisAt(uint64 p, uint64 t) internal {
        clock(p, t);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"));
        applyAll();
    }

    function retireRecordAt(uint64 id, uint64 p, uint64 t) internal {
        (,,,, uint64 gen,,,,) = custody.positions(id);
        clock(p, t);
        pushRecord(
            RecordKind.Retirement,
            abi.encode(RetirementData(id, gen, custody.exposureChain(id, gen)))
        );
        applyAll();
    }

    function requestRetirement(uint256 i) internal {
        vm.prank(vm.addr(ownerPk(i)));
        custody.requestRetirement(gid(i));
    }

    /// @dev Identity `excluded` (genesis index) retires and is dropped by J; G closes at progress
    /// 150 / UC 1,200; its retirement record lands at progress 160 / UC 1,210.
    /// Then: round gate p > 2,160, UC-time gate t >= 4,810.
    function reachMaturable(uint256 excluded) internal {
        requestRetirement(excluded);
        handoffExcluding(excluded);
        closeGenesisAt(150, 1_200);
        retireRecordAt(gid(excluded), 160, 1_210);
    }

    function lotOf(uint64 id) internal view returns (uint256) {
        return lotsOf(id)[0];
    }

    function matureOne(uint256 lotID) internal {
        uint256[] memory ids = new uint256[](1);
        ids[0] = lotID;
        custody.mature(ids);
    }

    function creditOf(address who) internal view returns (uint256) {
        return custody.credit(who);
    }

    // Accessors so a separate handler contract can adopt this fixture's deployment.
    function custodyAddr() external view returns (StakeCustody) {
        return custody;
    }

    function electionAddr() external view returns (ElectionPolicy) {
        return election;
    }

    function evidenceAddr() external view returns (Evidence) {
        return evidence;
    }

    function rootsAddr() external view returns (MockRootRecords) {
        return roots;
    }

    function treasuryAddr() external view returns (address) {
        return treasury;
    }

    function reporterAddr() external view returns (address) {
        return reporter;
    }
}
