// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";

/// @notice Claims are the only outflow. Credits are debited before the guarded transfer, a failing
/// recipient only reverts its own claim, and unsolicited value is surplus with no entitlement.
contract ClaimsTest is P85Flow {
    function _credit(address who) internal returns (uint256 amount) {
        // A settled offence credits the reporter 1 UCT (bounty) and the treasury 9 UCT.
        Evidence.VoteHeader memory h = Evidence.VoteHeader(NETWORK, 1, compressed(rootPk(0)), 1, 10);
        Evidence.SignedVote memory a = Evidence.SignedVote(
            keccak256("A"), sign(rootPk(0), evidence.voteDigest(h, keccak256("A")))
        );
        Evidence.SignedVote memory b = Evidence.SignedVote(
            keccak256("B"), sign(rootPk(0), evidence.voteDigest(h, keccak256("B")))
        );
        bytes32 expo_ = genesisExposure(0);
        vm.prank(who);
        bytes32 caseID = evidence.submitEvidence(h, a, b, expo_);
        uint256[] memory lots = new uint256[](1);
        lots[0] = lotOf(gid(0));
        evidence.settleEvidence(caseID, lots);
        return custody.credit(who);
    }

    function test_claimPaysOnlyTheCreditOwnerAndDebitsFirst() public {
        address payable payee = payable(makeAddr("payee"));
        assertEq(_credit(reporter), 1 * UCT);
        uint256 credits = custody.totalCredits();
        uint256 balance = address(custody).balance;
        vm.expectEmit(true, true, false, true, address(custody));
        emit StakeCustody.CreditClaimed(reporter, payee, 4e17);
        vm.prank(reporter);
        custody.claim(4e17, payee);
        assertEq(payee.balance, 4e17);
        assertEq(custody.credit(reporter), 6e17);
        assertEq(custody.totalCredits(), credits - 4e17);
        assertEq(address(custody).balance, balance - 4e17);
        assertConserved();
    }

    function test_claimRejectsZeroAmountZeroRecipientAndOverdraw() public {
        _credit(reporter);
        vm.startPrank(reporter);
        vm.expectRevert(StakeCustody.ZeroValue.selector);
        custody.claim(0, reporter);
        vm.expectRevert(StakeCustody.ZeroAddress.selector);
        custody.claim(1, address(0));
        vm.expectRevert(StakeCustody.InsufficientCredit.selector);
        custody.claim(1 * UCT + 1, reporter);
        vm.stopPrank();
    }

    function test_onlyTheCreditOwnerCanClaimIt() public {
        _credit(reporter);
        address thief = makeAddr("thief");
        vm.prank(thief);
        vm.expectRevert(StakeCustody.InsufficientCredit.selector);
        custody.claim(1, thief);
        // the treasury's credit is likewise only the treasury's
        vm.prank(reporter);
        vm.expectRevert(StakeCustody.InsufficientCredit.selector);
        custody.claim(9 * UCT, reporter);
    }

    function test_aRevertingRecipientOnlyFailsItsOwnClaim() public {
        _credit(reporter);
        RejectEther rejecter = new RejectEther();
        uint256 before_ = custody.credit(reporter);
        vm.prank(reporter);
        vm.expectRevert(StakeCustody.TransferFailed.selector);
        custody.claim(1 * UCT, address(rejecter));
        assertEq(custody.credit(reporter), before_, "a failed claim rolls back its debit");
        // another creditor is not trapped by the failure
        vm.prank(treasury);
        custody.claim(9 * UCT, treasury);
        assertEq(treasury.balance, 9 * UCT);
        assertConserved();
    }

    function test_aReentrantRecipientCannotClaimTwice() public {
        ReentrantClaimer attacker = new ReentrantClaimer(custody);
        _credit(address(attacker));
        assertEq(custody.credit(address(attacker)), 1 * UCT);
        attacker.claimAll();
        assertEq(address(attacker).balance, 1 * UCT, "paid exactly once");
        assertTrue(attacker.reenteredAndFailed());
        assertEq(custody.credit(address(attacker)), 0);
        assertConserved();
    }

    function test_forcedValueIsSurplusAndNeverClaimableOrReinterpreted() public {
        uint256 principalBefore =
            custody.totalFree() + custody.totalEncumbered() + custody.totalDraining();
        vm.deal(address(this), 5 ether);
        ForceSend force = new ForceSend{value: 5 ether}(payable(address(custody)));
        (bool sent,) = address(force).call("");
        assertTrue(sent);
        assertEq(address(custody).balance, N_GENESIS * GENESIS_BOND + 5 ether);
        assertEq(
            custody.totalFree() + custody.totalEncumbered() + custody.totalDraining(),
            principalBefore
        );
        assertEq(custody.totalCredits(), 0);
        // nobody holds a credit for it
        vm.prank(reporter);
        vm.expectRevert(StakeCustody.InsufficientCredit.selector);
        custody.claim(1, reporter);
        assertConserved();
    }

    function test_plainTransfersToCustodyAreRejected() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(custody).call{value: 1 ether}("");
        assertFalse(ok);
    }
}

contract RejectEther {
    receive() external payable {
        revert("no");
    }
}

/// @dev Forces value into a contract without calling it: the runtime pushes the target and
/// SELFDESTRUCTs (value moves even to a contract with no payable entry point).
contract ForceSend {
    constructor(address payable target) payable {
        bytes memory runtime = abi.encodePacked(hex"73", target, hex"ff");
        assembly ("memory-safe") {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}

contract ReentrantClaimer {
    StakeCustody internal immutable CUSTODY;
    bool public reenteredAndFailed;

    constructor(StakeCustody c) {
        CUSTODY = c;
    }

    function claimAll() external {
        CUSTODY.claim(CUSTODY.credit(address(this)), address(this));
    }

    receive() external payable {
        try CUSTODY.claim(1, address(this)) {}
        catch (bytes memory reason) {
            reenteredAndFailed =
                bytes4(reason) == bytes4(keccak256("ReentrancyGuardReentrantCall()"));
        }
    }
}
