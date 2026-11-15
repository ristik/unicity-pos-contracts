// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// The linter's boolean-cst and uninitialized-local flag every `return (false, ...)` and zero-initialised accumulator; the
// precompile calls in loops are bounded by the input; typecasts are range-checked before narrowing; CBOR encodings are
// self-delimiting, so packed concatenation does not collide.
// forge-lint: disable-start(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)

/// @notice The section 14 rules the token verifier raises (docs/design/native-bridge-v2.md). The verifier reverts with
///         `<Rule>()`, so each constant is the 4-byte selector of that custom error.
library Nb2Rules {
    bytes4 internal constant TRUNCATED = bytes4(keccak256("Truncated()"));
    bytes4 internal constant TRAILING = bytes4(keccak256("Trailing()"));
    bytes4 internal constant NON_CANONICAL = bytes4(keccak256("NonCanonical()"));
    bytes4 internal constant SHAPE = bytes4(keccak256("Shape()"));
    bytes4 internal constant TAG = bytes4(keccak256("Tag()"));
    bytes4 internal constant VERSION = bytes4(keccak256("Version()"));
    bytes4 internal constant LENGTH = bytes4(keccak256("Length()"));
    bytes4 internal constant INT_RANGE = bytes4(keccak256("IntRange()"));
    bytes4 internal constant INPUT_TOO_LARGE = bytes4(keccak256("InputTooLarge()"));
    bytes4 internal constant CONFIG_SHAPE = bytes4(keccak256("ConfigShape()"));
    bytes4 internal constant EVIDENCE_SHAPE = bytes4(keccak256("EvidenceShape()"));
    bytes4 internal constant MINT_DOMAIN = bytes4(keccak256("MintDomain()"));
    bytes4 internal constant DEPOSIT_UC = bytes4(keccak256("DepositUC()"));
    bytes4 internal constant DEPOSIT_HEADER = bytes4(keccak256("DepositHeader()"));
    bytes4 internal constant RECEIPT_PATH = bytes4(keccak256("ReceiptPath()"));
    bytes4 internal constant RECEIPT_TYPE = bytes4(keccak256("ReceiptType()"));
    bytes4 internal constant RECEIPT_STATUS = bytes4(keccak256("ReceiptStatus()"));
    bytes4 internal constant LOG_INDEX = bytes4(keccak256("LogIndex()"));
    bytes4 internal constant LOG_EMITTER = bytes4(keccak256("LogEmitter()"));
    bytes4 internal constant LOG_TOPICS = bytes4(keccak256("LogTopics()"));
    bytes4 internal constant LOG_DATA = bytes4(keccak256("LogData()"));
    bytes4 internal constant SECRET_OPENING = bytes4(keccak256("SecretOpening()"));
    bytes4 internal constant MINT_SALT = bytes4(keccak256("MintSalt()"));
    bytes4 internal constant MINT_TYPE = bytes4(keccak256("MintType()"));
    bytes4 internal constant MINT_OWNER = bytes4(keccak256("MintOwner()"));
    bytes4 internal constant MINT_DATA = bytes4(keccak256("MintData()"));
    bytes4 internal constant MINT_REASON = bytes4(keccak256("MintReason()"));
    bytes4 internal constant NOT_BURN = bytes4(keccak256("NotBurn()"));
    bytes4 internal constant BURN_NOT_FINAL = bytes4(keccak256("BurnNotFinal()"));
    bytes4 internal constant BURN_REASON = bytes4(keccak256("BurnReason()"));
    bytes4 internal constant RETURN_DATA = bytes4(keccak256("ReturnData()"));
    bytes4 internal constant RETURN_DOMAIN = bytes4(keccak256("ReturnDomain()"));
    bytes4 internal constant RETURN_ASSET = bytes4(keccak256("ReturnAsset()"));
    bytes4 internal constant RETURN_AMOUNT = bytes4(keccak256("ReturnAmount()"));
    bytes4 internal constant RETURN_RECIPIENT = bytes4(keccak256("ReturnRecipient()"));
    bytes4 internal constant RETURN_INDEX = bytes4(keccak256("ReturnIndex()"));
    bytes4 internal constant PREDICATE = bytes4(keccak256("Predicate()"));
    bytes4 internal constant MINT_SHAPE = bytes4(keccak256("MintShape()"));
    bytes4 internal constant TRANSFER_DATA = bytes4(keccak256("TransferData()"));
    bytes4 internal constant CDMISMATCH = bytes4(keccak256("CDMismatch()"));
    bytes4 internal constant UNLOCK_LENGTH = bytes4(keccak256("UnlockLength()"));
    bytes4 internal constant UNLOCK_SCALARS = bytes4(keccak256("UnlockScalars()"));
    bytes4 internal constant UNLOCK_RECOVERY = bytes4(keccak256("UnlockRecovery()"));
    bytes4 internal constant UNLOCK_KEY = bytes4(keccak256("UnlockKey()"));
    bytes4 internal constant REPEATED_SID = bytes4(keccak256("RepeatedSID()"));
    bytes4 internal constant NO_TRANSFERS = bytes4(keccak256("NoTransfers()"));
    bytes4 internal constant DEADLINE_MISMATCH = bytes4(keccak256("DeadlineMismatch()"));
    bytes4 internal constant DEADLINE_EXPIRED = bytes4(keccak256("DeadlineExpired()"));
    bytes4 internal constant INCLUSION_PROOF = bytes4(keccak256("InclusionProof()"));
    bytes4 internal constant REFERENCE_TIME = bytes4(keccak256("ReferenceTime()"));
    bytes4 internal constant SEAL_NETWORK = bytes4(keccak256("SealNetwork()"));
    bytes4 internal constant SEAL_EPOCH = bytes4(keccak256("SealEpoch()"));
    bytes4 internal constant NO_ENTRY_FOR_EPOCH = bytes4(keccak256("NoEntryForEpoch()"));
    bytes4 internal constant CERT_STRUCTURE = bytes4(keccak256("CertStructure()"));
    bytes4 internal constant SEAL_ROOT = bytes4(keccak256("SealRoot()"));
    bytes4 internal constant QUORUM_NOT_MET = bytes4(keccak256("QuorumNotMet()"));
    bytes4 internal constant UNSUPPORTED_CERTIFICATE_ENCODING =
        bytes4(keccak256("UnsupportedCertificateEncoding()"));
    bytes4 internal constant SPLIT_JUSTIF = bytes4(keccak256("SplitJustif()"));
    bytes4 internal constant SPLIT_PROOF_COUNT = bytes4(keccak256("SplitProofCount()"));
    bytes4 internal constant SPLIT_PROOF_SHAPE = bytes4(keccak256("SplitProofShape()"));
    bytes4 internal constant SPLIT_MANIFEST = bytes4(keccak256("SplitManifest()"));
    bytes4 internal constant SPLIT_BURN = bytes4(keccak256("SplitBurn()"));
    bytes4 internal constant SPLIT_PROOF = bytes4(keccak256("SplitProof()"));
    bytes4 internal constant SPLIT_SUM = bytes4(keccak256("SplitSum()"));
}
// forge-lint: disable-end(boolean-cst,uninitialized-local,calls-loop,unsafe-typecast,incorrect-shift,encode-packed-collision)
