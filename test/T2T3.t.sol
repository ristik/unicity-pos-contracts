// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {FeeCollector} from "../src/FeeCollector.sol";
import {WUCT} from "../src/WUCT.sol";

contract ForceEther {
    constructor(address payable recipient) payable {
        bytes memory runtime = abi.encodePacked(hex"73", recipient, hex"ff");
        assembly ("memory-safe") {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}

contract RejectEther {
    receive() external payable {
        revert("reject ether");
    }
}

contract WUCTReentrantReceiver {
    WUCT public immutable token;
    bool public nestedWithdrawBlocked;

    constructor(WUCT token_) {
        token = token_;
    }

    function wrapAndWithdraw(uint256 amount) external payable {
        token.deposit{value: msg.value}();
        token.withdraw(amount);
    }

    receive() external payable {
        try token.withdraw(1) {
            revert("nested withdrawal unexpectedly succeeded");
        } catch {
            nestedWithdrawBlocked = true;
        }
    }
}

contract TreasuryReentrantReceiver {
    FeeCollector public collector;
    bool public nestedWithdrawBlocked;

    function setCollector(FeeCollector collector_) external {
        require(address(collector) == address(0));
        collector = collector_;
    }

    function pull() external {
        collector.withdraw();
    }

    receive() external payable {
        try collector.withdraw() {
            revert("nested treasury withdrawal unexpectedly succeeded");
        } catch {
            nestedWithdrawBlocked = true;
        }
    }
}

contract T2T3Test is Test {
    address internal constant TREASURY = address(0xBEEF);
    address internal constant STRANGER = address(0xCAFE);

    WUCT internal token;

    function setUp() public {
        token = new WUCT();
    }

    receive() external payable {}

    function testDepositAndReceiveMintOneForOne() public {
        token.deposit{value: 7 ether}();
        assertEq(token.balanceOf(address(this)), 7 ether);

        (bool ok,) = address(token).call{value: 3 ether}("");
        assertTrue(ok);
        assertEq(token.balanceOf(address(this)), 10 ether);
        assertEq(token.totalSupply(), 10 ether);
        assertEq(address(token).balance, 10 ether);
    }

    function testWithdrawBurnsBeforeSendingAndPreservesBacking() public {
        token.deposit{value: 4 ether}();
        uint256 beforeBalance = address(this).balance;

        token.withdraw(1.5 ether);

        assertEq(token.balanceOf(address(this)), 2.5 ether);
        assertEq(token.totalSupply(), 2.5 ether);
        assertEq(address(token).balance, 2.5 ether);
        assertEq(address(this).balance, beforeBalance + 1.5 ether);
    }

    function testFuzz_WUCTBackingForEveryDepositAndWithdrawal(uint96 deposited, uint96 withdrawn)
        public
    {
        deposited = uint96(bound(deposited, 1, 1e24));
        withdrawn = uint96(bound(withdrawn, 0, deposited));
        token.deposit{value: deposited}();
        if (withdrawn != 0) token.withdraw(withdrawn);
        assertLe(token.totalSupply(), address(token).balance);
        assertEq(token.totalSupply(), uint256(deposited) - withdrawn);
    }

    function testWUCTRejectingReceiverRevertsBurnAndSendAtomically() public {
        RejectingDepositor depositor = new RejectingDepositor(token);
        vm.deal(address(depositor), 2 ether);
        depositor.deposit{value: 2 ether}();

        uint256 supplyBefore = token.totalSupply();
        uint256 wrappedBefore = token.balanceOf(address(depositor));
        vm.expectRevert(WUCT.NativeTransferFailed.selector);
        depositor.withdraw(1 ether);
        assertEq(token.totalSupply(), supplyBefore);
        assertEq(token.balanceOf(address(depositor)), wrappedBefore);
        assertEq(address(token).balance, supplyBefore);
    }

    function testWUCTReentrantReceiverCannotWithdrawTwice() public {
        WUCTReentrantReceiver receiver = new WUCTReentrantReceiver(token);
        vm.deal(address(this), 2 ether);
        receiver.wrapAndWithdraw{value: 2 ether}(2 ether);
        assertTrue(receiver.nestedWithdrawBlocked());
        assertEq(token.totalSupply(), 0);
        assertEq(address(token).balance, 0);
        assertEq(address(receiver).balance, 2 ether);
    }

    function testForcedNativeTransferOnlyAddsExcessBacking() public {
        token.deposit{value: 1 ether}();
        ForceEther force = new ForceEther{value: 2 ether}(payable(address(token)));
        (bool forced,) = address(force).call("");
        assertTrue(forced);
        assertEq(token.totalSupply(), 1 ether);
        assertEq(address(token).balance, 3 ether);
    }

    function testWUCTExposesNoPrivilegedMintOrPermit() public {
        (bool mintOk,) = address(token)
            .call(abi.encodeWithSignature("mint(address,uint256)", address(this), 1 ether));
        (bool permitOk,) = address(token)
            .call(
                abi.encodeWithSignature(
                    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                    address(this),
                    address(this),
                    1 ether,
                    block.timestamp,
                    27,
                    bytes32(0),
                    bytes32(0)
                )
            );
        assertFalse(mintOk);
        assertFalse(permitOk);
    }

    function testFuzz_FeeCollectorSplitsWithRemainderInRewardPot(
        uint96 amount,
        uint16 treasuryShareBps
    ) public {
        amount = uint96(bound(amount, 1, 1e24));
        treasuryShareBps = uint16(bound(treasuryShareBps, 0, 10_000));
        FeeCollector collector = new FeeCollector(payable(TREASURY), treasuryShareBps);
        vm.deal(address(this), amount);
        (bool ok,) = address(collector).call{value: amount}("");
        assertTrue(ok);

        vm.prank(STRANGER);
        collector.split();

        uint256 expectedTreasury = uint256(amount) * treasuryShareBps / 10_000;
        assertEq(collector.treasuryCredit(), expectedTreasury);
        assertEq(collector.rewardPot(), uint256(amount) - expectedTreasury);
        assertEq(collector.unallocatedBalance(), 0);
        assertEq(address(collector).balance, collector.treasuryCredit() + collector.rewardPot());
    }

    function testSplitIsPermissionlessAndRemainderStaysInRewardPot() public {
        FeeCollector collector = new FeeCollector(payable(TREASURY), 3333);
        vm.deal(address(this), 11);
        (bool ok,) = address(collector).call{value: 11}("");
        assertTrue(ok);

        vm.prank(STRANGER);
        collector.split();
        assertEq(collector.treasuryCredit(), 3);
        assertEq(collector.rewardPot(), 8);
        assertEq(collector.unallocatedBalance(), 0);

        collector.split();
        assertEq(collector.treasuryCredit(), 3, "a repeated split cannot credit the same wei twice");
        assertEq(collector.rewardPot(), 8);

        vm.deal(address(this), 16);
        ForceEther force = new ForceEther{value: 5}(payable(address(collector)));
        (bool forced,) = address(force).call("");
        assertTrue(forced);
        vm.prank(STRANGER);
        collector.split();
        assertEq(collector.treasuryCredit(), 4);
        assertEq(collector.rewardPot(), 12, "rounding remainder goes to the pot");
        assertEq(collector.unallocatedBalance(), 0);
    }

    function testTreasuryPullCannotExceedItsCredits() public {
        FeeCollector collector = new FeeCollector(payable(TREASURY), 6000);
        vm.deal(address(this), 10 ether);
        (bool ok,) = address(collector).call{value: 10 ether}("");
        assertTrue(ok);
        collector.split();
        assertEq(collector.treasuryCredit(), 6 ether);

        vm.prank(TREASURY);
        assertEq(collector.withdraw(), 6 ether);
        assertEq(collector.treasuryCredit(), 0);
        assertEq(collector.totalTreasuryPaid(), 6 ether);
        assertEq(collector.rewardPot(), 4 ether);
        vm.prank(TREASURY);
        assertEq(collector.withdraw(), 0);
        assertEq(collector.totalTreasuryPaid(), 6 ether);
        assertEq(address(collector).balance, collector.rewardPot());
    }

    function testFeeCollectorRejectsNonTreasuryWithdrawal() public {
        FeeCollector collector = new FeeCollector(payable(TREASURY), 5000);
        vm.deal(address(this), 4 ether);
        (bool ok,) = address(collector).call{value: 4 ether}("");
        assertTrue(ok);
        collector.split();
        vm.prank(STRANGER);
        vm.expectRevert(FeeCollector.TreasuryOnly.selector);
        collector.withdraw();
        assertEq(collector.treasuryCredit(), 2 ether);
    }

    function testRejectingTreasuryKeepsCreditAfterFailedWithdrawal() public {
        RejectEther rejectingTreasury = new RejectEther();
        FeeCollector collector = new FeeCollector(payable(address(rejectingTreasury)), 10000);
        vm.deal(address(this), 3 ether);
        (bool ok,) = address(collector).call{value: 3 ether}("");
        assertTrue(ok);
        collector.split();
        vm.prank(address(rejectingTreasury));
        vm.expectRevert(FeeCollector.NativeTransferFailed.selector);
        collector.withdraw();
        assertEq(collector.treasuryCredit(), 3 ether);
        assertEq(collector.totalTreasuryPaid(), 0);
        assertEq(address(collector).balance, 3 ether);
    }

    function testReentrantTreasuryCannotWithdrawTwice() public {
        TreasuryReentrantReceiver treasury = new TreasuryReentrantReceiver();
        FeeCollector collector = new FeeCollector(payable(address(treasury)), 10_000);
        treasury.setCollector(collector);
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(collector).call{value: 1 ether}("");
        assertTrue(ok);
        collector.split();
        treasury.pull();
        assertTrue(treasury.nestedWithdrawBlocked());
        assertEq(collector.treasuryCredit(), 0);
        assertEq(collector.totalTreasuryPaid(), 1 ether);
    }

    function testFeeCollectorConstructorBoundsRatioAndTreasury() public {
        vm.expectRevert(FeeCollector.InvalidTreasury.selector);
        new FeeCollector(payable(address(0)), 1);
        vm.expectRevert(FeeCollector.InvalidTreasuryShare.selector);
        new FeeCollector(payable(TREASURY), 10_001);
    }
}

contract RejectingDepositor {
    WUCT public immutable token;

    constructor(WUCT token_) {
        token = token_;
    }

    function deposit() external payable {
        token.deposit{value: msg.value}();
    }

    function withdraw(uint256 amount) external {
        token.withdraw(amount);
    }

    receive() external payable {
        revert("reject native coin");
    }
}
