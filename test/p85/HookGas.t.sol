// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {
    RecordKind,
    RecoveryAckData,
    SessionClosedData,
    RetirementData
} from "../../src/p85/P85Types.sol";

/// @notice Gross gas of the mandatory records hook's custody call, `applyRootRecords(1)`, for each record kind on the largest committee
/// the shared harness builds (`N_GENESIS` identities). The figures feed the profile bound of the hook
/// (briefs/p85-pr1c-control-records.md section 6); production limits are larger (`vMax`), so the bound scales them, see the README.
/// The call is made as a plain external call with no pre-warmed storage beyond what the preceding setup left in the same transaction
/// context, which is how the system call meets it (a fresh transaction, cold storage); forge's cold/warm accounting makes these
/// figures a lower bound of a cold call, hence the factor the profile applies.
contract HookGasTest is P85Flow {
    uint256 internal gasSessionClosed;
    uint256 internal gasAck;
    uint256 internal gasRecovery;
    uint256 internal gasClosure;
    uint256 internal gasRetirement;

    function _measure() internal returns (uint256 used) {
        uint256 before = gasleft();
        custody.applyRootRecords(1);
        used = before - gasleft();
    }

    function test_measureEachKind() public {
        // SessionClosed
        reserve(RES_J, ASG_J, allMembers(), 1);
        pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(RES_J)));
        gasSessionClosed = _measure();

        // Ack
        reserve(RES_J2, ASG_J2, allExcept(0), 2);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J2, H_ROUND, 100, 101));
        gasAck = _measure();

        // Closure of the genesis assignment
        clock(150, 1_200);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "genesis"));
        gasClosure = _measure();

        // Retirement
        requestRetirement(0);
        (,,,, uint64 gen,,,,) = custody.positions(gid(0));
        clock(160, 1_210);
        pushRecord(
            RecordKind.Retirement,
            abi.encode(RetirementData(gid(0), gen, custody.exposureChain(gid(0), gen)))
        );
        gasRetirement = _measure();

        emit log_named_uint("SessionClosed", gasSessionClosed);
        emit log_named_uint("Ack", gasAck);
        emit log_named_uint("Closure", gasClosure);
        emit log_named_uint("Retirement", gasRetirement);
        // Regression ceilings on the measured figures (N_GENESIS = 4 identities); a profile reserves
        // `HookRecordGas` per record, chosen from these scaled to the deployment's committee size.
        assertLt(gasSessionClosed, 400_000);
        assertLt(gasAck, 300_000);
        assertLt(gasClosure, 700_000);
        assertLt(gasRetirement, 200_000);
    }

    function test_measureRecovery() public {
        requestRetirement(0);
        reserve(RES_J, ASG_J, allExcept(0), 1);
        clock(120, 1_000);
        pushRecord(
            RecordKind.RecoveryAck,
            abi.encode(RecoveryAckData(RES_J, ASG_K, 100, 101, 130, 130, 131, 3, 3))
        );
        gasRecovery = _measure();
        emit log_named_uint("RecoveryAck", gasRecovery);
        assertLt(gasRecovery, 2_000_000);
    }
}
