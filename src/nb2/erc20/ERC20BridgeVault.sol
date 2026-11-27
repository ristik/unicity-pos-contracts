// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ERC20Context, IERC20ActivationContext} from "./ERC20Context.sol";
import {ERC20VaultRecovered} from "./generated/ERC20VaultRecovered.sol";

abstract contract ERC20VaultActivation is ERC20VaultRecovered {
    constructor(ERC20Context.Vault memory ctx)
        ERC20VaultRecovered(ctx.gamma, ctx.recovery, ctx.recoveryHash, ctx.profile)
    {}
}

/// @notice Immutable single-token escrow with both NB2 return routes.
contract ERC20BridgeVault is ERC20VaultActivation {
    uint256 public constant BALANCE_GAS = 30_000;
    uint256 public constant TRANSFER_GAS = 150_000;

    error BadCredit();
    error ExcessDebit();
    error InsufficientBacking();
    error TokenCallFailed();

    event ERC20Deposited(
        uint64 indexed nonce,
        address indexed token,
        bytes32 domain,
        uint256 credit,
        bytes32 rho,
        bytes firstOwner
    );

    constructor() ERC20VaultActivation(IERC20ActivationContext(msg.sender).vaultContext()) {}

    /// @notice Locks the certified net credit. The caller authorizes at most requested base units.
    function depositERC20(
        uint256 requested,
        uint256 minCredit,
        bytes calldata firstOwner,
        bytes32 rho
    ) external {
        _enter();
        if (minCredit == 0 || minCredit > requested) revert BadCredit();
        _checkOwner(firstOwner);

        uint256 acc = _loadA();
        uint256 n = acc >> N_SHIFT;
        if (n >= N_MAX) revert DepositCounterExhausted();
        uint256 q = acc & Q_MASK;
        uint256 room = QMAX - q;
        if (minCredit > room) revert LiabilityCap(q, minCredit, QMAX);

        uint256 credit = _lock(requested, minCredit, q);
        if (credit > room) revert LiabilityCap(q, credit, QMAX);
        n += 1;
        uint256 next = (n << N_SHIFT) | (acc & (N_MAX << M_SHIFT)) | (q + credit);
        assembly ("memory-safe") {
            sstore(SLOT_A, next)
        }
        // Checked against the packed 56-bit limit above.
        // forge-lint: disable-next-line(unsafe-typecast)
        emit ERC20Deposited(uint64(n), TOKEN, D, credit, rho, firstOwner);
        _exit();
    }

    function _lock(uint256 requested, uint256 minCredit, uint256 q)
        private
        returns (uint256 credit)
    {
        uint256 beforeVault = _balance(address(this));
        if (beforeVault < q) revert InsufficientBacking();
        uint256 beforeSender = _balance(msg.sender);
        _transfer(abi.encodeWithSelector(0x23b872dd, msg.sender, address(this), requested));
        uint256 afterVault = _balance(address(this));
        uint256 afterSender = _balance(msg.sender);

        if (afterSender > beforeSender || beforeSender - afterSender > requested) {
            revert ExcessDebit();
        }
        if (afterVault < beforeVault) revert BadCredit();
        credit = afterVault - beforeVault;
        if (credit < minCredit || credit > requested) revert BadCredit();
    }

    function _pay(address recipient, uint256 amount) internal override {
        // The shared settlement core has debited Q. A failure reverts that debit and any seal.
        uint256 previousLiability = (_loadA() & Q_MASK) + amount;
        uint256 beforeVault = _balance(address(this));
        if (beforeVault < previousLiability) revert InsufficientBacking();
        uint256 beforeRecipient = _balance(recipient);
        _transfer(abi.encodeWithSelector(0xa9059cbb, recipient, amount));
        uint256 afterVault = _balance(address(this));
        uint256 afterRecipient = _balance(recipient);
        if (
            afterVault != beforeVault - amount || afterRecipient < beforeRecipient
                || afterRecipient - beforeRecipient != amount
        ) revert PayoutFailed();
    }

    function _balance(address account) private view returns (uint256 value) {
        address token = TOKEN;
        bool ok;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, shl(224, 0x70a08231))
            mstore(add(p, 4), account)
            ok := staticcall(BALANCE_GAS, token, p, 36, p, 32)
            ok := and(ok, eq(returndatasize(), 32))
            value := mload(p)
        }
        if (!ok) revert TokenCallFailed();
    }

    function _transfer(bytes memory input) private {
        address token = TOKEN;
        bool ok;
        assembly ("memory-safe") {
            let p := mload(0x40)
            ok := call(TRANSFER_GAS, token, 0, add(input, 32), mload(input), p, 32)
            switch returndatasize()
            case 0 { ok := and(ok, gt(extcodesize(token), 0)) }
            case 32 { ok := and(ok, eq(mload(p), 1)) }
            default { ok := 0 }
        }
        if (!ok) revert TokenCallFailed();
    }
}
