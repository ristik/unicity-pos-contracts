// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {
    ElectionParams,
    Delegation,
    DelegationRequest,
    ReserveInput,
    ReserveMember,
    RecordKind
} from "../../src/p85/P85Types.sol";

/// @notice The election's gas at the profile ceilings: 128 identities of 8 lots each, a committed committee of 32, and 96 outsiders that
/// outrank the lowest incumbent, so the greedy pass runs a continuity trial for every one of them.
contract ElectionGasTest is P85Flow {
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);
    // the scenario in force: V identities of L lots each, a committed committee of the first C
    uint256 internal V;
    uint256 internal L;
    uint256 internal C;

    function _electionParams() internal view override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: uint32(C == 0 ? 32 : C),
            nMax: 32,
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: 100_000,
            cadenceSeconds: 604_800
        });
    }

    function _admit(uint256 i) internal {
        uint64 id = gid(i);
        DelegationRequest memory r;
        r.id = id;
        r.generation = 1;
        r.binding = Delegation({
            rootNodeID: keccak256(abi.encode("root", i)),
            rootKey: compressed(rootPk(i)),
            evmNodeID: keccak256(abi.encode("evm", i)),
            evmKey: compressed(evmPk(i)),
            operatorPayee: vm.addr(payeePk(i))
        });
        r.expiry = 1_000_000_000;
        bytes32 digest = election.delegationDigest(r);
        election.admitDelegation(r, sign(ownerPk(i), digest), sign(evmPk(i), digest));
    }

    /// @dev Identities 5..V with L lots each: weight 10 for the first C (incumbents-to-be), 12 for the outsiders.
    function _populate() internal {
        vm.pauseGasMetering();
        for (uint256 i = N_GENESIS; i < V; ++i) {
            uint64 id = register(ownerPk(i), rootPk(i), vm.addr(wdPk(i)));
            assertEq(id, gid(i));
            uint256 perLot = (i < C ? 1_000 : 1_200) / L;
            for (uint256 k; k < L; ++k) {
                bondFor(id, perLot * UCT);
            }
            _admit(i);
        }
        vm.resumeGasMetering();
    }

    /// @dev Reserve and acknowledge a committee of the first C identities, in root order.
    function _commitFirstC() internal {
        ReserveInput memory in_;
        in_.resultID = RES_J;
        in_.assignmentID = ASG_J;
        in_.lineage = LINEAGE;
        in_.attempt = 1;
        in_.rootEpoch = 2;
        in_.evmEpoch = 2;
        in_.incumbentAssignmentID = custody.lastAckedAssignment();
        in_.members = new ReserveMember[](C);
        for (uint256 k; k < C; ++k) {
            uint64 id = gid(k);
            (,, bytes32 rootHash,,,,,,) = custody.positions(id);
            (bytes memory evm,) = _evmKeyOf(id);
            in_.members[k] = ReserveMember({
                id: id,
                weight: uint64(coverage(id) / (100 * UCT)),
                rootKeyHash: rootHash,
                evmKeyHash: keccak256(evm),
                operatorPayee: _payeeOf(id),
                lotIDs: lotsOf(id)
            });
        }
        vm.prank(address(election));
        custody.reserveCandidate(in_);
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
    }

    function _measureElection(uint256 v, uint256 l, uint256 c, uint256 ceiling) internal {
        (V, L, C) = (v, l, c);
        _deploy(_defaultPolicy()); // again, now that the profile names the committee size
        _populate();
        _commitFirstC();
        assertEq(election.liveCount(), V);
        clock(1_000_000, 10_000_000);

        vm.pauseGasMetering();
        vm.prank(SYS);
        vm.resumeGasMetering();
        uint256 before_ = gasleft();
        ElectionPolicy.Outcome out = election.elect(keccak256("origin"));
        uint256 used = before_ - gasleft();
        emit log_named_uint(
            string.concat(
                "elect gas V=", vm.toString(v), " L=", vm.toString(l), " C=", vm.toString(c)
            ),
            used
        );
        assertEq(uint8(out), uint8(ElectionPolicy.Outcome.Reserved));
        assertLt(used, ceiling);
    }

    function test_measureV128L8C32() public {
        _measureElection(128, 8, 32, 47_500_000);
    }

    function test_measureV64L8C16() public {
        _measureElection(64, 8, 16, 22_500_000);
    }

    function test_measureV32L4C10() public {
        _measureElection(32, 4, 10, 8_900_000);
    }

    function test_measureV16L2C8() public {
        _measureElection(16, 2, 8, 5_100_000);
    }
}
