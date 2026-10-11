// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {MockRootRecords} from "./MockRootRecords.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {Quantize} from "../../src/p85/Quantize.sol";
import {
    ElectionParams,
    Limits,
    Delegation,
    DelegationRequest,
    ReserveInput,
    ReserveMember,
    RecordKind,
    RecoveryAckData
} from "../../src/p85/P85Types.sol";

/// @notice COLD gas of the records the mandatory hook applies and of the election, at the deployment's own caps (limits.vMax, limits.lMax, election
/// nMax), for the worst committee those caps admit: the committee has nMax members of lMax lots each. A scenario is chosen by the environment
/// (P85_GAS_KIND, P85_GAS_V/L/C) and built entirely in `setUp`, so the measured call is the first touch of every account and slot it reads, as
/// the system call meets them in a fresh transaction (a measurement inside the transaction that built the state is warm and a lower bound).
/// Run through `script/measure-hook-gas.sh`; without P85_GAS_KIND the test does nothing.
///   ack       Ack of a reserved J (activation, offsets, root-key rotation of every member)
///   stage     the closure of the Reserved J, staged (pending-J path)
///   closure   the closure of an Active J (every member's every lot)
///   recovery  the RecoveryAck of J whose closure is pending: activates J, derives K (an exposure per incumbent member) and applies the saved closure
///   elect     the election's hook step; elect-heavy: the same with the raw total above the weight cap (every trial quantized and measured)
contract HookGasColdTest is P85Flow {
    address internal constant SYS = address(0xff00000000000000000000000000000000000001);

    string internal kind;
    uint256 internal V;
    uint256 internal L;
    uint256 internal C;
    uint256 internal F = 1; // the heavy election scale: every identity bonds F times as much, so the raw total exceeds the weight cap

    function _env() internal view returns (string memory k, uint256 v, uint256 l, uint256 c) {
        k = vm.envOr("P85_GAS_KIND", string(""));
        v = vm.envOr("P85_GAS_V", uint256(16));
        l = vm.envOr("P85_GAS_L", uint256(2));
        c = vm.envOr("P85_GAS_C", uint256(8));
    }

    function _manifestLimits() internal view override returns (Limits memory) {
        (, uint256 v, uint256 l,) = _env();
        return Limits({vMax: uint32(v), lMax: uint32(l), rMax: 4, maxBatch: 32});
    }

    function _electionParams() internal view override returns (ElectionParams memory) {
        (,,, uint256 c) = _env();
        return ElectionParams({
            nMin: 4,
            nTarget: uint32(c),
            nMax: uint32(c),
            maxM: 4,
            distNum: 1,
            distDen: 4,
            cadenceRounds: 100_000,
            cadenceSeconds: 604_800
        });
    }

    function setUp() public override {
        (kind, V, L, C) = _env();
        if (bytes(kind).length == 0) return;
        if (keccak256(bytes(kind)) == keccak256("elect-heavy")) {
            F = L == 1
                ? (2 * Quantize.WEIGHT_CAP_B) / 10 + 1
                : (2 * Quantize.WEIGHT_CAP_B) / (10 * C) + 1;
        }
        super.setUp();
        _populate();
        bytes32 k = keccak256(bytes(kind));
        if (k == keccak256("ack")) {
            _reserve(RES_J, ASG_J, 0, 1);
            clock(120, 1_000);
            pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        } else if (k == keccak256("stage")) {
            _reserve(RES_J, ASG_J, 0, 1);
            clock(140, 1_100);
            pushRecord(RecordKind.Closure, closureData(ASG_J, 130, "j"));
        } else if (k == keccak256("closure")) {
            _reserve(RES_J, ASG_J, 0, 1);
            clock(120, 1_000);
            pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
            applyAll();
            clock(140, 1_100);
            pushRecord(RecordKind.Closure, closureData(ASG_J, 130, "j"));
        } else if (k == keccak256("recovery")) {
            // J1 is the incumbent K will be derived from; J2 is the reserved J whose closure is pending
            _reserve(RES_J, ASG_J, 0, 1);
            clock(120, 1_000);
            pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
            applyAll();
            _reserve(RES_J2, ASG_J2, C, 2);
            clock(140, 1_100);
            pushRecord(RecordKind.Closure, closureData(ASG_J2, 130, "j2"));
            applyAll();
            clock(150, 1_200);
            pushRecord(
                RecordKind.RecoveryAck,
                abi.encode(RecoveryAckData(RES_J2, ASG_K, 100, 101, 130, 130, 131, 3, 3))
            );
        } else if (k == keccak256("elect") || k == keccak256("elect-heavy")) {
            _reserve(RES_J, ASG_J, 0, 1);
            clock(120, 1_000);
            pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
            applyAll();
            clock(1_000_000, 10_000_000);
        } else {
            revert("unknown P85_GAS_KIND");
        }
    }

    function test_measureCold() public {
        if (bytes(kind).length == 0) return; // not a measurement run
        uint256 used;
        if (
            keccak256(bytes(kind)) == keccak256("elect")
                || keccak256(bytes(kind)) == keccak256("elect-heavy")
        ) {
            vm.prank(SYS);
            uint256 b = gasleft();
            election.elect(keccak256("origin"));
            used = b - gasleft();
        } else {
            uint256 b = gasleft();
            custody.applyRootRecords(1);
            used = b - gasleft();
        }
        emit log_string(string.concat(
                "HOOK-GAS {\"kind\":\"",
                kind,
                "\",\"v\":",
                vm.toString(V),
                ",\"l\":",
                vm.toString(L),
                ",\"c\":",
                vm.toString(C),
                ",\"cold_gas\":",
                vm.toString(used),
                "}"
            ));
    }

    // --- scenario builders (as in ElectionGasTest) ------------------------------------------------------------------------------------

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

    /// @dev V identities of L lots each (the four genesis identities get their further lots too), outsiders outranking the committee.
    function _populate() internal {
        vm.pauseGasMetering();
        for (uint256 i; i < N_GENESIS && i < V; ++i) {
            for (uint256 k = 1; k < L; ++k) {
                bondFor(gid(i), 1_000 * F * UCT / L);
            }
        }
        for (uint256 i = N_GENESIS; i < V; ++i) {
            uint64 id = register(ownerPk(i), rootPk(i), vm.addr(wdPk(i)));
            uint256 perLot = (i < C ? 1_000 : 1_200) * F / L;
            for (uint256 k; k < L; ++k) {
                bondFor(id, perLot * UCT);
            }
            _admit(i);
        }
        vm.resumeGasMetering();
    }

    /// @dev Reserve a committee of C members, identities `first`..`first + C - 1`, in a session of `attempt`.
    function _reserve(bytes32 result, bytes32 assignment, uint256 first, uint64 attempt) internal {
        vm.pauseGasMetering();
        ReserveInput memory in_;
        in_.resultID = result;
        in_.assignmentID = assignment;
        in_.lineage = LINEAGE;
        in_.attempt = attempt;
        in_.rootEpoch = 2;
        in_.evmEpoch = 2;
        in_.incumbentAssignmentID = custody.lastAckedAssignment();
        in_.members = new ReserveMember[](C);
        uint256[] memory raw = new uint256[](C);
        for (uint256 k; k < C; ++k) {
            raw[k] = coverage(gid(first + k)) / (100 * UCT);
        }
        uint256[] memory q = Quantize.quantize(raw);
        for (uint256 k; k < C; ++k) {
            uint64 id = gid(first + k);
            (,, bytes32 rootHash,,,,,,) = custody.positions(id);
            (bytes memory evm,) = _evmKeyOf(id);
            in_.members[k] = ReserveMember({
                id: id,
                weight: uint64(q[k]),
                rawWeight: uint64(raw[k]),
                rootKeyHash: rootHash,
                evmKeyHash: keccak256(evm),
                operatorPayee: _payeeOf(id),
                lotIDs: lotsOf(id)
            });
        }
        vm.prank(address(election));
        custody.reserveCandidate(in_);
        vm.resumeGasMetering();
    }
}
