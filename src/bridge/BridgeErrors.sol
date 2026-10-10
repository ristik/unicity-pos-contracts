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
error AlreadyRedeemed(uint256 nonce);
error ZeroNullifier();
error CreditExceedsLocked(uint256 credited, uint256 amount, uint256 locked);
error InsufficientCredit(uint256 have, uint256 want);
error PayoutFailed();
