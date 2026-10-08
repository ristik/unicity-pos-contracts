// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {
    ElectionParams,
    Limits,
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

    /// @dev The deployment is capped at exactly the measured profile (limits.vMax = V, limits.lMax = L, election nMax = C): the figure
    /// is the worst case of a chain deployed with those caps and of no other. Before a scenario is chosen, the profile ceilings.
    function _manifestLimits() internal view override returns (Limits memory) {
        return Limits({
            vMax: uint32(V == 0 ? 128 : V), lMax: uint32(L == 0 ? 8 : L), rMax: 4, maxBatch: 32
        });
    }

    function _electionParams() internal view override returns (ElectionParams memory) {
        return ElectionParams({
            nMin: 4,
            nTarget: uint32(C == 0 ? 32 : C),
            nMax: uint32(C == 0 ? 32 : C),
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
                rawWeight: uint64(coverage(id) / (100 * UCT)),
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
        uint256 used = _elect(v, l, c);
        assertLt(used, ceiling);
    }

    function _elect(uint256 v, uint256 l, uint256 c) internal returns (uint256 used) {
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
        used = before_ - gasleft();
        emit log_named_uint(
            string.concat(
                "elect gas V=", vm.toString(v), " L=", vm.toString(l), " C=", vm.toString(c)
            ),
            used
        );
        assertEq(uint8(out), uint8(ElectionPolicy.Outcome.Reserved));
    }

    /// @dev The genesis tool's measurement of the worst-case election for a chosen (V, L, C): V identities of L lots each, a committed
    /// committee of C, and every outsider outranking the weakest incumbent so the greedy pass tries all of them. Run through
    /// `script/measure-elect.sh V L C`, which prints one JSON line; the test refuses parameters outside the profile ceilings.
    function test_measureFromTheEnvironment() public {
        uint256 v = vm.envOr("P85_MEASURE_V", uint256(0));
        uint256 l = vm.envOr("P85_MEASURE_L", uint256(0));
        uint256 c = vm.envOr("P85_MEASURE_C", uint256(0));
        if (v == 0) return; // not a measurement run
        require(
            v >= 5 && v <= 128 && l >= 1 && l <= 8 && c >= 4 && c <= 32 && c <= v,
            "parameters outside the profile ceilings"
        );
        require(
            l == 1 || l == 2 || l == 4 || l == 8,
            "L must divide the 1,000 UCT principal into whole lots"
        );
        uint256 used = _elect(v, l, c);
        emit log_string(string.concat(
                "ELECT-MEASURE {\"v\":",
                vm.toString(v),
                ",\"l\":",
                vm.toString(l),
                ",\"c\":",
                vm.toString(c),
                ",\"gas\":",
                vm.toString(used),
                "}"
            ));
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

    /// @dev The measured worst case is the worst case only because the deployment cannot exceed it: at the devnet/testnet profile caps
    /// (V16, L2, C8) a seventeenth live identity and a third lot are refused, and the committee is bounded by nMax.
    function test_theDeployedCapsAreTheMeasuredProfile() public {
        (V, L, C) = (16, 2, 8);
        _deploy(_defaultPolicy());
        assertEq(election.vMax(), 16);
        _populate();
        assertEq(election.liveCount(), 16, "the index is full at V");

        uint64 extra = register(ownerPk(16), rootPk(16), vm.addr(wdPk(16)));
        // joining the live index is what the cap bounds: the seventeenth identity cannot become a candidate
        vm.expectRevert(ElectionPolicy.IndexFull.selector);
        this.bondExtra(extra);

        uint64 id = gid(0); // a genesis identity holds one lot
        bondFor(id, 100 * UCT); // the second of L = 2
        vm.expectRevert(StakeCustody.LotCapacity.selector);
        this.bondExtra(id);
    }

    function bondExtra(uint64 id) external {
        bondFor(id, 100 * UCT);
    }
}
