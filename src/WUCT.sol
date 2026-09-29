// SPDX-License-Identifier: UNLICENSED
// License not yet chosen: see bft-core #1.
pragma solidity 0.8.37;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Wrapped Unicity Coin
/// @notice A native-coin wrapper. Each WUCT is minted only against a deposit and is burned before
/// native coin is sent back to its holder. There is no privileged mint or reserve withdrawal.
contract WUCT is ERC20, ReentrancyGuard {
    error NativeTransferFailed();

    event Deposit(address indexed account, uint256 amount);
    event Withdrawal(address indexed account, uint256 amount);

    constructor() ERC20("Wrapped Unicity Coin", "WUCT") {}

    receive() external payable nonReentrant {
        _deposit();
    }

    /// @notice Deposit native coin and mint the same amount of WUCT.
    function deposit() external payable nonReentrant {
        _deposit();
    }

    /// @notice Burn WUCT before returning its native backing to the caller.
    function withdraw(uint256 amount) external nonReentrant {
        _burn(msg.sender, amount);
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert NativeTransferFailed();
        emit Withdrawal(msg.sender, amount);
    }

    function _deposit() private {
        _mint(msg.sender, msg.value);
        emit Deposit(msg.sender, msg.value);
    }
}
