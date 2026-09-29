// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Test} from "forge-std/Test.sol";
import {FeeCollector} from "../src/FeeCollector.sol";
import {WUCT} from "../src/WUCT.sol";

contract T2T3ForceEther {
    constructor(address payable recipient) payable {
        bytes memory runtime = abi.encodePacked(hex"73", recipient, hex"ff");
        assembly ("memory-safe") {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}

contract WUCTHandler is Test {
    WUCT public immutable token;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;

    constructor(WUCT token_) {
        token = token_;
    }

    function deposit(uint96 rawAmount) external {
        uint256 amount = bound(rawAmount, 1, 1e24);
        vm.deal(address(this), address(this).balance + amount);
        token.deposit{value: amount}();
        totalDeposited += amount;
    }

    function withdraw(uint96 rawAmount) external {
        uint256 held = token.balanceOf(address(this));
        if (held == 0) return;
        uint256 amount = bound(rawAmount, 1, held);
        token.withdraw(amount);
        totalWithdrawn += amount;
    }

    function forceBacking(uint96 rawAmount) external {
        uint256 amount = bound(rawAmount, 1, 1e24);
        vm.deal(address(this), address(this).balance + amount);
        T2T3ForceEther force = new T2T3ForceEther{value: amount}(payable(address(token)));
        (bool ok,) = address(force).call("");
        require(ok);
    }

    receive() external payable {}
}

contract FeeCollectorHandler is Test {
    FeeCollector public immutable collector;
    address payable public immutable treasury;
    uint256 public totalInflow;

    constructor(FeeCollector collector_, address payable treasury_) {
        collector = collector_;
        treasury = treasury_;
    }

    function contribute(uint96 rawAmount) external {
        uint256 amount = bound(rawAmount, 1, 1e24);
        vm.deal(address(this), address(this).balance + amount);
        (bool ok,) = address(collector).call{value: amount}("");
        require(ok);
        totalInflow += amount;
    }

    function forceTransfer(uint96 rawAmount) external {
        uint256 amount = bound(rawAmount, 1, 1e24);
        vm.deal(address(this), address(this).balance + amount);
        T2T3ForceEther force = new T2T3ForceEther{value: amount}(payable(address(collector)));
        (bool ok,) = address(force).call("");
        require(ok);
        totalInflow += amount;
    }

    function split() external {
        collector.split();
    }

    function withdrawTreasury() external {
        vm.prank(treasury);
        collector.withdraw();
    }
}

contract WUCTInvariantTest is StdInvariant, Test {
    WUCT internal token;
    WUCTHandler internal handler;

    function setUp() public {
        token = new WUCT();
        handler = new WUCTHandler(token);
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = WUCTHandler.deposit.selector;
        selectors[1] = WUCTHandler.withdraw.selector;
        selectors[2] = WUCTHandler.forceBacking.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_supplyNeverExceedsNativeBacking() public view {
        assertLe(token.totalSupply(), address(token).balance);
    }

    function invariant_supplyEqualsDepositsLessBurnedWithdrawals() public view {
        assertEq(token.totalSupply(), handler.totalDeposited() - handler.totalWithdrawn());
    }
}

contract FeeCollectorInvariantTest is StdInvariant, Test {
    address internal constant TREASURY = address(0xBEEF);
    FeeCollector internal collector;
    FeeCollectorHandler internal handler;

    function setUp() public {
        collector = new FeeCollector(payable(TREASURY), 6173);
        handler = new FeeCollectorHandler(collector, payable(TREASURY));
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = FeeCollectorHandler.contribute.selector;
        selectors[1] = FeeCollectorHandler.forceTransfer.selector;
        selectors[2] = FeeCollectorHandler.split.selector;
        selectors[3] = FeeCollectorHandler.withdrawTreasury.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_everyWeiIsLiabilityOrUnallocated() public view {
        uint256 accounted = collector.totalTreasuryPaid() + collector.treasuryCredit()
            + collector.rewardPot() + collector.unallocatedBalance();
        assertEq(
            address(collector).balance,
            collector.treasuryCredit() + collector.rewardPot() + collector.unallocatedBalance()
        );
        assertEq(handler.totalInflow(), accounted);
    }

    function invariant_payoutsNeverExceedTreasuryCredits() public view {
        assertLe(collector.totalTreasuryPaid(), collector.totalTreasuryCredits());
        assertEq(
            collector.treasuryCredit(),
            collector.totalTreasuryCredits() - collector.totalTreasuryPaid()
        );
    }

    function afterInvariant() public view {
        assertGt(handler.totalInflow(), 0, "the handler must exercise funded transitions");
    }
}
