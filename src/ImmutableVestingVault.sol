// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: see bft-core #1.
pragma solidity 0.8.37;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Immutable Vesting Vault
/// @notice A fixed-principal native-coin allocation with a linear timestamp schedule.
/// @dev Donations do not change principal or vesting. Only the original principal is releasable.
contract ImmutableVestingVault is ReentrancyGuard {
    error InvalidRecipient();
    error InvalidSchedule();
    error NativeTransferFailed();

    event Released(address indexed recipient, uint256 amount);
    event Received(address indexed sender, uint256 amount);

    address payable public immutable recipient;
    uint256 public immutable principal;
    uint64 public immutable start;
    uint64 public immutable cliff;
    uint64 public immutable duration;
    uint256 public released;

    constructor(
        address payable recipient_,
        uint256 principal_,
        uint64 start_,
        uint64 cliff_,
        uint64 duration_
    ) {
        if (recipient_ == address(0)) revert InvalidRecipient();
        if (duration_ == 0 || cliff_ > duration_ || start_ > type(uint64).max - duration_) {
            revert InvalidSchedule();
        }
        recipient = recipient_;
        principal = principal_;
        start = start_;
        cliff = cliff_;
        duration = duration_;
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    /// @notice The principal vested and still available for pull release at the current timestamp.
    function releasable() public view returns (uint256) {
        return vestedAmount(block.timestamp) - released;
    }

    /// @notice The linear schedule's vested amount at timestamp `timestamp`.
    function vestedAmount(uint256 timestamp) public view returns (uint256) {
        uint256 cliffTime = uint256(start) + cliff;
        if (timestamp < cliffTime) return 0;
        uint256 end = uint256(start) + duration;
        if (timestamp >= end) return principal;
        return Math.mulDiv(principal, timestamp - start, duration);
    }

    /// @notice Amount above the unpaid fixed principal. It is never added to vesting entitlement.
    function surplusBalance() public view returns (uint256) {
        uint256 unpaidPrincipal = principal - released;
        uint256 balance = address(this).balance;
        return balance > unpaidPrincipal ? balance - unpaidPrincipal : 0;
    }

    /// @notice Pull all currently vested but unreleased principal to the immutable recipient.
    function release() external nonReentrant returns (uint256 amount) {
        amount = releasable();
        if (amount == 0) return 0;

        released += amount;
        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert NativeTransferFailed();
        emit Released(recipient, amount);
    }
}
