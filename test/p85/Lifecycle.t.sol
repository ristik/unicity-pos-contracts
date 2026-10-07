// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {
    RecordKind,
    ReserveInput,
    ReserveMember,
    Delegation,
    DelegationRequest
} from "../../src/p85/P85Types.sol";

/// @notice The design's custody acceptance trace, with exact accounting after every call:
/// register, bond, reserve (primary), H and acknowledgement, replacement, retirement, maturity,
/// claim. Request-time exit, forced transfers and early claims cannot bypass the rules.
contract LifecycleTest is P85Flow {
    uint256 internal surplus;

    function _exact() internal view {
        assertEq(
            address(custody).balance,
            custody.totalFree() + custody.totalEncumbered() + custody.totalDraining()
                + custody.totalCredits() + surplus,
            "B = F + E + D + C + U"
        );
    }

    function test_registerBondElectReplaceRetireMatureClaim() public {
        _exact();
        // register and bond a new validator entity (identity 5)
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        _exact();
        uint256 lot = bondFor(id, 1_500 * UCT);
        _exact();
        assertEq(custody.totalFree(), 1_500 * UCT);

        // it joins a primary candidate (identity 5 alongside the genesis four): lots become encumbered
        // with weight 15. The EVM binding comes from the owner-authenticated admitDelegation.
        _bindEvm(id, 0x9301);
        reserveWithNewcomer(id);
        _exact();
        assertEq(lotv(lot).category, 2);
        assertEq(custody.totalFree(), 0);

        // J commits H at round 100 and is acknowledged; the genesis assignment is replaced
        clock(120, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, H_ROUND, 100, 101));
        applyAll();
        _exact();
        assertEq(custody.lastAckedAssignment(), ASG_J);

        // the owner requests retirement while the lot is still referenced: nothing is released
        vm.prank(vm.addr(0x9001));
        custody.requestRetirement(id);
        _exact();
        assertEq(lotv(lot).category, 2, "an active reference still encumbers the lot");
        uint256[] memory ids = new uint256[](1);
        ids[0] = lot;
        vm.expectRevert(StakeCustody.LotStillReferenced.selector);
        custody.mature(ids); // request-time exit is refused
        vm.prank(vm.addr(0x9201));
        vm.expectRevert(StakeCustody.InsufficientCredit.selector);
        custody.claim(1, vm.addr(0x9201)); // no credit exists yet

        // a replacement candidate J2 excludes the retiring identity and is acknowledged; G and J close
        reserve(RES_J2, ASG_J2, allMembers(), 2); // the four genesis identities; the newcomer is retiring
        clock(160, 1_300);
        pushRecord(RecordKind.Ack, ackData(RES_J2, 130, 300, 131));
        clock(170, 1_400);
        pushRecord(RecordKind.Closure, closureData(GENESIS_ASSIGNMENT, H_ROUND, "g"));
        pushRecord(RecordKind.Closure, closureData(ASG_J, 130, "j"));
        applyAll();
        _exact();
        assertEq(lotv(lot).refCount, 0);
        assertEq(lotv(lot).category, 3, "unreferenced and retiring: draining");
        assertEq(custody.totalDraining(), 1_500 * UCT);

        // before the retirement record the lot still cannot mature
        clock(9_000, 90_000);
        vm.expectRevert(StakeCustody.RetirementNotImported.selector);
        custody.mature(ids);
        retireRecordAt(id, 9_000, 90_000);
        // p_ret = 9,000: the round gate is p > 11,000
        vm.expectRevert(StakeCustody.RoundGateNotMet.selector);
        custody.mature(ids);
        clock(11_001, 90_000 + 3_600);
        custody.mature(ids);
        _exact();
        assertEq(creditOf(vm.addr(0x9201)), 1_500 * UCT);
        assertEq(custody.totalDraining(), 0);

        // a forced transfer is surplus, not claimable and not principal
        vm.deal(address(this), 1 ether);
        ForceSendLifecycle force = new ForceSendLifecycle{value: 1 ether}(payable(address(custody)));
        (bool ok,) = address(force).call("");
        assertTrue(ok);
        surplus += 1 ether;
        _exact();

        // the withdrawal authority claims to a recipient of its choosing; a second claim finds nothing
        address payable recipient = payable(makeAddr("recipient"));
        vm.prank(vm.addr(0x9201));
        custody.claim(1_500 * UCT, recipient);
        assertEq(recipient.balance, 1_500 * UCT);
        _exact();
        vm.prank(vm.addr(0x9201));
        vm.expectRevert(StakeCustody.InsufficientCredit.selector);
        custody.claim(1, recipient);

        // the genesis identities were never touched and stay encumbered by J2
        assertEq(custody.totalEncumbered(), N_GENESIS * GENESIS_BOND);
    }

    /// @dev Owner-authenticated admitDelegation for the newcomer (root key 0x9101, EVM key 0x9301).
    function _bindEvm(uint64 id, uint256 evmKeyPk) internal {
        DelegationRequest memory r;
        r.id = id;
        r.generation = 1;
        r.binding = Delegation(
            keccak256("root5"),
            compressed(0x9101),
            keccak256("evm5"),
            compressed(evmKeyPk),
            vm.addr(0x9401)
        );
        r.expiry = 1_000_000;
        bytes32 digest = election.delegationDigest(r);
        election.admitDelegation(r, sign(0x9001, digest), sign(evmKeyPk, digest));
    }

    /// @dev Primary candidate: the four genesis identities plus the newcomer (last, ascending id).
    function reserveWithNewcomer(uint64 id) internal {
        ReserveInput memory in_ = _reserveInput(RES_J, ASG_J, allMembers(), 1);
        ReserveMember[] memory genesisMembers = in_.members;
        in_.members = new ReserveMember[](genesisMembers.length + 1);
        for (uint256 i = 0; i < genesisMembers.length; ++i) {
            in_.members[i] = genesisMembers[i];
        }
        (Delegation memory d,,) = election.delegation(id, 1);
        (,, bytes32 rootHash,,,,,,) = custody.positions(id);
        in_.members[genesisMembers.length] = ReserveMember({
            id: id,
            weight: 15,
            rootKeyHash: rootHash,
            evmKeyHash: keccak256(d.evmKey),
            operatorPayee: d.operatorPayee,
            lotIDs: lotsOf(id)
        });
        vm.prank(address(election));
        custody.reserveCandidate(in_);
    }
}

contract ForceSendLifecycle {
    constructor(address payable target) payable {
        bytes memory runtime = abi.encodePacked(hex"73", target, hex"ff");
        assembly ("memory-safe") {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}
