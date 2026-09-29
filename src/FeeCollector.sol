// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: see bft-core #1.
pragma solidity 0.8.37;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title FeeCollector
/// @notice A coinbase/fee-beneficiary sink that permissionlessly splits unallocated native balance
/// into a treasury pull credit and a retained reward pot. It performs no per-assignment accounting.
contract FeeCollector is ReentrancyGuard {
    uint256 public constant BPS = 10_000;

    error InvalidTreasury();
    error InvalidTreasuryShare();
    error TreasuryOnly();
    error NativeTransferFailed();

    event Split(uint256 unallocated, uint256 treasuryCredit, uint256 rewardPot);
    event TreasuryWithdrawn(address indexed treasury, uint256 amount);

    address payable public immutable treasury;
    uint16 public immutable treasuryShareBps;

    uint256 public treasuryCredit;
    uint256 public rewardPot;
    uint256 public totalTreasuryCredits;
    uint256 public totalTreasuryPaid;

    constructor(address payable treasury_, uint16 treasuryShareBps_) {
        if (treasury_ == address(0)) revert InvalidTreasury();
        if (treasuryShareBps_ > BPS) revert InvalidTreasuryShare();
        treasury = treasury_;
        treasuryShareBps = treasuryShareBps_;
    }

    receive() external payable {}

    /// @notice Classify all balance not already committed to treasury/reward liabilities.
    /// @dev Rounding dust is assigned to the reward pot, so every wei is accounted for exactly.
    function split() external {
        uint256 unallocated = unallocatedBalance();
        uint256 treasuryAmount = Math.mulDiv(unallocated, treasuryShareBps, BPS);
        uint256 rewardAmount = unallocated - treasuryAmount;

        treasuryCredit += treasuryAmount;
        totalTreasuryCredits += treasuryAmount;
        rewardPot += rewardAmount;

        emit Split(unallocated, treasuryAmount, rewardAmount);
    }

    /// @notice Let the immutable treasury pull only its credited amount.
    function withdraw() external nonReentrant returns (uint256 amount) {
        if (msg.sender != treasury) revert TreasuryOnly();
        amount = treasuryCredit;
        treasuryCredit = 0;
        totalTreasuryPaid += amount;

        (bool ok,) = treasury.call{value: amount}("");
        if (!ok) revert NativeTransferFailed();
        emit TreasuryWithdrawn(treasury, amount);
    }

    /// @notice Balance above outstanding liabilities, including donations and forced transfers.
    function unallocatedBalance() public view returns (uint256) {
        return address(this).balance - treasuryCredit - rewardPot;
    }
}
