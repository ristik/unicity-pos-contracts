// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// One namespace of named errors for the B4 vault, the composing verifier and their libraries.
// Tests assert exact selectors; a revert from the verifier bubbles through the vault unchanged.

// Encoding and framing.
error CborMalformed();
error CfgMalformed();
error PolicyMalformed();
error EnvelopeFraming();
error BudgetExceeded();
error KernelBadOutput();
/// @dev The native composition (0x0105) refused the redemption; `status` is bft-core `ComposeStatus`.
error BridgeRejected(uint256 status);

// Configuration.
error ChainIdMismatch(uint256 expected, uint256 actual);
error WrongVerifier(address expected, address actual);
error ZeroConfig();
error BadEvmShard();
error PolicyPartitionIsEvm();
error VerifierCodeHashMismatch(bytes32 expected, bytes32 actual);

// Policy carrier.
error PolicyHashMismatch(bytes32 expected, bytes32 actual);
error PolicyAnchorCount(uint256 count);
error PolicyAnchorDuplicate(uint256 anchor);
error PolicyAnchorUnused(uint256 anchor);
error PolicyTupleMismatch();
error PolicyLeafCount(uint256 expected, uint256 actual);
error PolicyLeafIndex(uint256 leaf, uint256 anchorIndex);

// Kernel and B1.
error KernelRejected();
error KernelResultShape();
error PrecompileFailed(address target);
error PrecompileBadReturn(address target);
error UCRejected();
error UCScanRejected();
error PathBitmapMismatch(uint256 leaf);
error IRBadOpening();
error IRMalformed();
error IRStateMismatch(bytes32 expected, bytes32 actual);
error IRTimeAfterAnchor(uint256 leaf, uint256 referenceTime, uint256 timestamp);
error LeafNotIncluded(uint256 leaf);

// Vault.
error Reentrancy();
error ZeroAmount();
error BadRecipient();
error NonceExhausted();
error LockDigestZero();
error KernelCfgMismatch(bytes32 expected, bytes32 actual);
error KernelNonceMismatch(uint256 expected, uint256 actual);
error KernelAmountMismatch(uint256 expected, uint256 actual);
error UnknownLock(uint256 nonce);
error LockDigestMismatch(uint256 nonce);
/// @dev The lock is complete: every unit locked has been redeemed (the mint view of a finished lock).
error AlreadyRedeemed(uint256 nonce);
/// @dev This part of this lock was already paid (whatever burn or witnesses it is presented with).
error PartAlreadyRedeemed(uint256 nonce, bytes32 partId);
/// @dev The part's amount exceeds what the lock has left.
error PartExceedsRemaining(uint256 nonce, uint256 remaining, uint256 amount);
/// @dev The result's root amount is not the amount stored at lock time.
error KernelRootAmountMismatch(uint256 expected, uint256 actual);
error ZeroNullifier();
error InsufficientCredit(uint256 have, uint256 want);
error PayoutFailed();
