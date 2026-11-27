// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @dev Deposit-only emitter for an isolated execution lane.
// forge-lint: disable-next-line(locked-ether)
contract LaneDeposit11 {
    uint64 private _nonce;
    event Deposited(
        uint64 indexed nonce, bytes32 domain, uint256 amount, bytes32 rho, bytes firstOwner
    );

    function deposit(bytes calldata firstOwner, bytes32 rho, bytes32 domain) external payable {
        require(msg.value != 0 && firstOwner.length == 42);
        emit Deposited(++_nonce, domain, msg.value, rho, firstOwner);
    }
}
