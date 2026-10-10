#!/usr/bin/env python3
"""Disable each bridge guard once and confirm a named test fails.

Usage: script/bridge-guards.py [--jobs N] [--only ID[,ID...]]

For every entry in GUARDS the script copies the repository into a private scratch directory, replaces
`old` (its `occ`-th occurrence in `file`) with `new`, runs `forge test` restricted to the tests that
must notice, and requires at least one of those named tests to FAIL. A guard whose removal leaves every
named test green is reported SURVIVED and the script exits non-zero. Sources are never modified in
place. Compile errors, timeouts and zero-test runs are reported separately and are not kills.

The mutation is "disable the guard" (condition replaced by `false`, statement removed) unless the entry
says otherwise.
"""
import argparse
import concurrent.futures as cf
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FOUNDRY = os.path.expanduser("~/.foundry/bin")

V = "src/bridge/BridgeVault.sol"
T = "src/bridge/TokenVerifier.sol"
P = "src/bridge/BridgeProfile.sol"
C = "src/bridge/Cbor.sol"
B = "src/bridge/B1Calls.sol"
BB = "src/bridge/BridgeBounds.sol"
U = "src/bridge/UcScan.sol"
I = "src/bridge/InputRecord.sol"

VT = "test/bridge/BridgeVault.t.sol"
VI = "test/bridge/BridgeVaultIntegration.t.sol"
TT = "test/bridge/TokenVerifier.t.sol"
BT = "test/bridge/B1Calls.t.sol"
IT = "test/bridge/InputRecord.t.sol"
UT = "test/bridge/UcScan.t.sol"


def g(id, file, old, new, tests, path, occ=1):
    return dict(id=id, file=file, old=old, new=new, tests=tests, path=path, occ=occ)


CFG = "if (r.cfg != CFG) revert KernelCfgMismatch(CFG, r.cfg);"
UNK = "if (nonce == 0 || nonce > lastNonce) revert UnknownLock(nonce);"
DIG = "if (lockDigest[nonce] != r.lockDigest) revert LockDigestMismatch(nonce);"
SPENT = "if (spentNullifier[nonce] != bytes32(0)) revert AlreadyRedeemed(nonce);"

GUARDS = [
    # ---- vault: construction ------------------------------------------------------------------
    g("V-ctor-rootGenesis", V, "d.rootGenesis == 0 ||", "false ||", "test_constructor_rootGenesisZero", VT),
    g("V-ctor-execGenesis", V, "|| d.executionGenesis == 0", "|| false", "test_constructor_executionGenesisZero", VT),
    g("V-ctor-semantic", V, "|| d.semanticProfileHash == 0", "|| false", "test_constructor_semanticProfileZero", VT),
    g("V-ctor-b1Profile", V, "|| d.b1ProfileHash == 0", "|| false", "test_constructor_b1ProfileZero", VT),
    g("V-ctor-shardEmpty", V, "d.evmShard.length == 0 ||", "false ||", "test_constructor_evmShardEmpty", VT),
    g("V-ctor-shardLong", V, "|| d.evmShard.length > BridgeProfile.MAX_SHARD_BYTES", "|| false", "test_constructor_evmShardTooLong", VT),
    g("V-ctor-codeHashZero", V, "codeHash == 0 ||", "false ||", "test_constructor_verifierMissing", VT),
    g("V-ctor-codeHashEmpty", V, "|| codeHash == keccak256(\"\")", "|| false", "test_constructor_verifierWithoutCode", VT),
    g("V-ctor-codeHashPin", V, "|| codeHash != d.tokenVerifierCodeHash", "|| false", "test_constructor_verifierCodeHashPin", VT),
    g("V-ctor-policyPartition", V, "if (p.partition == d.evmPartition) revert PolicyPartitionIsEvm();", "if (false) revert PolicyPartitionIsEvm();", "test_constructor_policyPartitionIsEvmPartition", VT),
    g("V-ctor-policyDecode", V, "Policy memory p = BridgeProfile.decodePolicy(d.policyBody);", "Policy memory p = Policy({partition: 11, depth: 0, shardConfHashes: new bytes32[](1)});", "test_constructor_policyMalformed", VT),
    g("V-ctor-identity", V, "deriveType(d.network, d.rootGenesis, d.executionGenesis, chainId)", "deriveType(d.network, d.executionGenesis, d.executionGenesis, chainId)", "test_constructor_configuration|test_constructor_identifiersMatchTheOracleFamily", VT),
    g("V-ctor-identityChain", V, "deriveAsset(d.network, d.rootGenesis, d.executionGenesis, chainId)", "deriveAsset(d.network, d.rootGenesis, d.executionGenesis, 1)", "test_constructor_everyIdentityComponentChangesBothIdentifiers|test_constructor_identifiersMatchTheOracleFamily", VT),
    # ---- vault: lock --------------------------------------------------------------------------
    g("V-lock-zeroValue", V, "if (amount == 0) revert ZeroAmount();", "", "test_lock_zeroValue", VT),
    g("V-lock-nonceExhausted", V, "if (last >= type(uint64).max) revert NonceExhausted();", "", "test_lock_nonceExhaustedAtU64Max", VT),
    g("V-lock-cfg", V, CFG, "", "test_lock_kernelCfgMismatch", VT, 1),
    g("V-lock-nonce", V, "if (r.nonce != nonce) revert KernelNonceMismatch(nonce, r.nonce);", "", "test_lock_kernelNonceMismatch", VT),
    g("V-lock-amount", V, "if (r.amount != amount) revert KernelAmountMismatch(amount, r.amount);", "", "test_lock_kernelAmountMismatch", VT),
    g("V-lock-zeroDigest", V, "if (r.lockDigest == bytes32(0)) revert LockDigestZero();", "", "test_lock_zeroDigestRejected", VT),
    g("V-lock-lastNonce", V, "lastNonce = nonce;", "", "test_lock_recordsDigestAndEmitsTheCompleteRecord|test_lock_nonceIncrementsOnlyOnSuccess", VT),
    g("V-lock-locked", V, "locked += amount;", "", "test_lock_recordsDigestAndEmitsTheCompleteRecord", VT),
    g("V-lock-digestStore", V, "lockDigest[nonce] = r.lockDigest;", "", "test_lock_recordsDigestAndEmitsTheCompleteRecord", VT),
    # ---- vault: verifyMint --------------------------------------------------------------------
    g("V-mint-cfg", V, CFG, "", "test_verifyMint_cfgMismatch", VT, 2),
    g("V-mint-unknown", V, UNK, "", "test_verifyMint_unknownLock", VT, 1),
    g("V-mint-digest", V, DIG, "", "test_verifyMint_digestMismatch", VT, 1),
    g("V-mint-spent", V, SPENT, "", "test_verifyMint_alreadyRedeemed", VT, 1),
    # ---- vault: redeem ------------------------------------------------------------------------
    g("V-redeem-cfg", V, CFG, "", "test_redeem_cfgMismatch", VT, 3),
    g("V-redeem-unknown", V, UNK, "", "test_redeem_unknownNonce", VT, 2),
    g("V-redeem-digest", V, DIG, "", "test_redeem_digestMismatch|test_redeem_digestOfAnotherNonce", VT, 2),
    g("V-redeem-spent", V, SPENT, "", "test_redeem_sameProofTwice|test_redeem_conflictingBurnWithDifferentNullifierSameNonce", VT, 2),
    g("V-redeem-zeroNullifier", V, "if (r.nullifier == bytes32(0)) revert ZeroNullifier();", "", "test_redeem_zeroNullifier", VT),
    g("V-redeem-recipientZero", V, "r.releaseTo == address(0) ||", "false ||", "test_redeem_badRecipients", VT),
    g("V-redeem-recipientVault", V, "|| r.releaseTo == address(this)", "|| false", "test_redeem_badRecipients", VT),
    g("V-redeem-creditBound", V, "if (d + amount > locked) revert CreditExceedsLocked(d, amount, locked);", "", "test_redeem_creditNeverExceedsLockedPerLock|test_redeem_creditNeverExceedsLockedCumulatively", VT),
    g("V-redeem-spentStore", V, "spentNullifier[nonce] = r.nullifier;", "", "test_redeem_sameProofTwice|test_redeem_creditsTheBurnRecipientNotTheSubmitter", VT),
    g("V-redeem-creditedStore", V, "credited = d + amount;", "", "test_redeem_creditsTheBurnRecipientNotTheSubmitter", VT),
    g("V-redeem-claimableStore", V, "claimable[r.releaseTo] += amount;", "", "test_redeem_creditsTheBurnRecipientNotTheSubmitter", VT),
    g("V-redeem-submitterGetsCredit", V, "claimable[r.releaseTo] += amount;", "claimable[msg.sender] += amount;", "test_redeem_creditsTheBurnRecipientNotTheSubmitter", VT),
    # ---- vault: claim -------------------------------------------------------------------------
    g("V-claim-zero", V, "if (amount == 0) revert ZeroAmount();", "", "test_claim_zeroAndBadDestination", VT, 2),
    g("V-claim-toZero", V, "if (to == address(0) ||", "if (false ||", "test_claim_zeroAndBadDestination", VT),
    g("V-claim-toVault", V, "|| to == address(this)) revert BadRecipient();", "|| false) revert BadRecipient();", "test_claim_zeroAndBadDestination", VT),
    g("V-claim-insufficient", V, "if (have < amount) revert InsufficientCredit(have, amount);", "", "test_claim_onlyTheCreditedRecipientCanRedirect", VT),
    g("V-claim-debit", V, "claimable[msg.sender] = have - amount;", "", "test_claim_paysAndAccounts|test_claim_reentrantPayeeIsBlockedOnEveryEntryPoint", VT),
    g("V-claim-paid", V, "paid += amount;", "", "test_claim_paysAndAccounts|test_claim_reentrantPayeeIsBlockedOnEveryEntryPoint", VT),
    g("V-claim-payoutFailed", V, "if (!ok) revert PayoutFailed();", "if (false) revert PayoutFailed(); ok;", "test_claim_revertingPayeeRestoresEverything|test_claim_reentrantPayeeThatPropagatesFailsTheClaim", VT),
    # ---- vault: shared guard ------------------------------------------------------------------
    g("V-guard-check", V, "if (entered != 0) revert Reentrancy();", "", "test_guard_lockRedeemClaimRefuseWhileEntered|test_claim_reentrantPayeeIsBlockedOnEveryEntryPoint", VT),
    g("V-guard-set", V, "entered = 1;", "", "test_claim_reentrantPayeeIsBlockedOnEveryEntryPoint", VT),
    g("V-guard-release", V, "entered = 0;", "", "test_guard_releasedAfterEveryCall", VT),
    # ---- verifier: configuration and environment ---------------------------------------------
    g("T-cfg-verifier", T, "if (c.tokenVerifier != address(this)) revert WrongVerifier(c.tokenVerifier, address(this));", "", "test_cfg_wrongVerifierAddress", TT),
    g("T-cfg-chainId", T, "if (c.chainId != block.chainid) revert ChainIdMismatch(c.chainId, block.chainid);", "", "test_cfg_chainIdMismatch", TT),
    g("T-prepare-p0Cap", T, "if (p0.length > BridgeBounds.MAX_SEMANTIC_BYTES) revert BudgetExceeded();", "", "test_prepare_p0OverCapIsBudget", TT),
    g("T-history-cap", T, "if (history.length > BridgeBounds.MAX_SEMANTIC_BYTES) revert BudgetExceeded();", "", "test_envelope_historyOverCapIsBudget", TT),
    # ---- verifier: envelope -------------------------------------------------------------------
    g("T-env-cap", T, "if (proof.length > BridgeBounds.MAX_ENVELOPE_BYTES) revert BudgetExceeded();", "", "test_envelope_oversizeIsBudget", TT),
    g("T-frame-size", T, "if (n < 128 || n % 32 != 0) revert EnvelopeFraming();", "", "test_envelope_unalignedLengthRejected|test_envelope_tooShortRejected", TT),
    g("T-frame-head", T, "if (_word(b, 0) != 128) revert EnvelopeFraming();", "", "test_envelope_everyTupleOffsetWordMustBeCanonical", TT),
    g("T-frame-off1", T, "if (_word(b, 32) != pos) revert EnvelopeFraming();", "", "test_envelope_noncanonicalOffsetRejected|test_envelope_aliasedOffsetRejected", TT),
    g("T-frame-off2", T, "if (_word(b, 64) != pos) revert EnvelopeFraming();", "", "test_envelope_noncanonicalOffsetRejected|test_envelope_aliasedOffsetRejected", TT),
    g("T-frame-off3", T, "if (_word(b, 96) != pos) revert EnvelopeFraming();", "", "test_envelope_noncanonicalOffsetRejected|test_envelope_aliasedOffsetRejected", TT),
    g("T-frame-end", T, "if (pos != n) revert EnvelopeFraming();", "", "test_envelope_trailingWordRejected", TT),
    g("T-frame-padding", T, "if (uint256(bytes32(b[end - 32:end])) & ((uint256(1) << (8 * (32 - tail))) - 1) != 0) {", "if (false) {", "test_envelope_dirtyPaddingOfEveryBytesFieldIsFraming", TT),
    g("T-frame-anchorOffset", T, "if (_word(b, base + 32 * i) != pos - base) revert EnvelopeFraming();", "", "test_envelope_anAnchorOffsetOutOfPlaceIsFraming", TT, 1),
    g("T-frame-leafOffset", T, "if (_word(b, base + 32 * i) != pos - base) revert EnvelopeFraming();", "", "test_envelope_aLeafProofOffsetOutOfPlaceIsFraming", TT, 2),
    g("T-frame-shardOffset", T, "|| _word(b, t + 32) != 224) revert EnvelopeFraming();", ") revert EnvelopeFraming();", "test_envelope_everyTupleOffsetWordMustBeCanonical", TT),
    g("T-frame-ucOffset", T, "if (_word(b, t + 160) != pos - t) revert EnvelopeFraming();", "", "test_envelope_everyTupleOffsetWordMustBeCanonical", TT),
    g("T-frame-irOffset", T, "if (_word(b, t + 192) != pos - t) revert EnvelopeFraming();", "", "test_envelope_everyTupleOffsetWordMustBeCanonical", TT),
    g("T-frame-siblingsOffset", T, "|| _word(b, t + 64) != 96) revert EnvelopeFraming();", ") revert EnvelopeFraming();", "test_envelope_everyTupleOffsetWordMustBeCanonical", TT),
    g("T-env-anchorsCount", T, "if (na > n) revert EnvelopeFraming();", "", "test_envelope_countLargerThanTheDataIsFramingNotBudget", TT),
    g("T-env-anchorsCap", T, "if (na > BridgeBounds.MAX_ANCHORS) revert BudgetExceeded();", "", "test_envelope_tooManyAnchorsIsBudget", TT),
    g("T-env-leavesCount", T, "if (nl > n) revert EnvelopeFraming();", "", "test_envelope_countLargerThanTheDataIsFramingNotBudget", TT),
    g("T-env-leavesCap", T, "if (nl > BridgeBounds.MAX_LEAVES) revert BudgetExceeded();", "", "test_envelope_tooManyLeafProofsIsBudget", TT),
    g("T-env-siblings", T, "if (_word(b, t + sRel) > BridgeBounds.MAX_RSMT_SIBLINGS) revert BudgetExceeded();", "", "test_envelope_cumulativePathStepsIsBudget|test_envelope_cumulativeAcrossPaths", TT),
    g("T-env-ucCap", T, "if (_word(b, t + _word(b, t + 160)) > BridgeBounds.MAX_ANCHOR_UC_BYTES) {", "if (false) {", "test_b1_ucOverCapIsBudget", TT),
    g("T-env-wordRange", T, "if (off + 32 > b.length) revert EnvelopeFraming();", "", "test_envelope_tooShortRejected|test_envelope_offsetAtTheEndIsFraming", TT),
    g("T-env-wordU64", T, "if (v > type(uint64).max) revert EnvelopeFraming();", "", "test_envelope_hugeWordIsFraming", TT),
    # ---- verifier: policy ---------------------------------------------------------------------
    g("T-pol-cap", T, "if (body.length > BridgeProfile.MAX_POLICY_BYTES) revert BudgetExceeded();", "", "test_policy_oversizeBody", TT),
    g("T-pol-hash", T, "if (h != c.aggregatorPolicyHash) revert PolicyHashMismatch(c.aggregatorPolicyHash, h);", "", "test_policy_hashMismatch|test_policy_missingBody", TT),
    g("T-pol-evm", T, "if (p.partition == c.evmPartition) revert PolicyPartitionIsEvm();", "", "test_policy_partitionEqualToEvmPartition", TT),
    g("T-pol-anchorCount", T, "if (anchorCount == 0) revert PolicyAnchorCount(anchorCount);", "", "test_policy_anchorCountZero", TT),
    g("T-pol-tupleFound", T, "if (!found || a.partition", "if (false || a.partition", "test_policy_shardOfAnotherTopologyEvenWithARowsConfiguration", TT),
    g("T-pol-tuplePartition", T, "|| a.partition != pol.partition", "|| false", "test_policy_unrelatedRootCertifiedPartition", TT),
    g("T-pol-tupleConf", T, "|| a.shardConfHash != pol.shardConfHashes[row]", "|| false", "test_policy_changedConfiguration|test_policy_changedConfigurationOfTheSecondAnchor", TT),
    g("T-pol-tupleShardLen", T, "a.shard.length == 1 &&", "true &&", "test_policy_emptyShardBytes|test_policy_longerShard", TT),
    g("T-pol-tupleShardByte", T, "a.shard[0] == BridgeProfile.shardId(pol.depth, k)", "true", "test_policy_shardOfAnotherTopology|test_policy_shardOfAnotherTopologyEvenWithARowsConfiguration", TT),
    g("T-pol-leafCount", T, "if (paths.length != nl) revert PolicyLeafCount(nl, paths.length);", "", "test_policy_leafCountMismatch|test_policy_extraLeafProof|test_policy_mintNeedsExactlyOnePath", TT),
    g("T-pol-moreAnchorsThanLeaves", T, "if (anchors.length > nl) revert PolicyAnchorCount(anchors.length);", "", "test_policy_moreAnchorsThanLeaves", TT),
    g("T-pol-duplicate", T, "if (ucHash[k] == ucHash[j]) revert PolicyAnchorDuplicate(j);", "", "test_policy_identicalUcBytesAreOneAnchorNeverTwo", TT),
    g("T-pol-leafRange", T, "idx >= na ||", "false ||", "test_policy_leafIndexOutOfRange", TT),
    g("T-pol-leafOrder", T, "|| idx > next", "|| false", "test_policy_anchorsNotInFirstUseOrder", TT),
    g("T-pol-leafShard", T, "|| rowOf[idx] != want", "|| false", "test_policy_leafNamesAnAnchorOfAnotherShard", TT),
    g("T-pol-leafRowFromSid", T, "uint256(uint8(r.leaves[i].sid[0]) >> 7)", "uint256(0)", "test_verifyReturn_golden_everyLeafOnceInOrder|test_policy_leafNamesAnAnchorOfAnotherShard", TT),
    g("T-pol-nextUse", T, "if (idx == next) ++next;", "", "test_verifyReturn_golden_everyLeafOnceInOrder", TT),
    g("T-pol-unused", T, "if (next != na) revert PolicyAnchorUnused(next);", "", "test_policy_unusedAnchorIsRefused", TT),
    # ---- verifier: gas gate -------------------------------------------------------------------
    g("T-gate-bitmap", T, "if (pop != paths[i].siblings.length) revert PathBitmapMismatch(i);", "", "test_gate_bitmapPopcountMustEqualTheSiblingCount", TT),
    g("T-gate-ucGas", T, "plan.ucGas[j] = BridgeBounds.ucGas(a.shard.length, a.uc.length, sigs, steps);", "plan.ucGas[j] = 0;", "test_gas_everyNativeCallIsForwardedExactlyItsCharge", TT),
    g("T-gate-leafGas", T, "plan.leafGas[i] = BridgeBounds.rsmtGas(pop);", "plan.leafGas[i] = 0;", "test_gas_everyNativeCallIsForwardedExactlyItsCharge", TT),
    g("T-gate-kernelGas", T, "BridgeBounds.KERNEL_MAX_LEAVES\n            )\n        );", "BridgeBounds.MAX_LEAVES\n            )\n        );", "test_gas_everyNativeCallIsForwardedExactlyItsCharge", TT),
    g("BB-ucBase", BB, "UC_BASE = 1_243_700;", "UC_BASE = 1_243_699;", "test_gate_everyGoldenComponentEqualsTheOracleGate|test_gate_worstAdmittedBundleFitsTheBudget", TT),
    g("BB-rsmtPerSibling", BB, "+ PER_STEP * (1 + siblings);", "+ PER_STEP * siblings;", "test_gate_everyGoldenComponentEqualsTheOracleGate|test_gate_worstAdmittedBundleFitsTheBudget", TT),
    g("BB-b2PerLeaf", BB, "B2_PER_LEAF = 14_000;", "B2_PER_LEAF = 13_999;", "test_gate_everyGoldenComponentEqualsTheOracleGate", TT),
    g("BB-intrinsic", BB, "return INTRINSIC_BASE + PER_BYTE * envelopeBytes;", "return INTRINSIC_BASE + PER_BYTE * envelopeBytes + 1;", "test_gate_everyGoldenComponentEqualsTheOracleGate", TT),
    # ---- UC scan ------------------------------------------------------------------------------
    g("U-depth", U, "if (n != depth) revert UCScanRejected();", "", "test_wrongDepthIsRefused", UT),
    g("U-steps", U, "if (n > BridgeBounds.MAX_UNICITY_STEPS) revert BudgetExceeded();", "", "test_craftedBoundsAreExactlyTheirCaps", UT),
    g("U-sigs", U, "if (sigs > BridgeBounds.MAX_SIGNATURES) revert BudgetExceeded();", "", "test_signatureCountOverTheCapIsBudget", UT),
    g("U-tag", U, "if (major != MAJOR_TAG || arg != tag) revert UCScanRejected();", "", "test_gate_ucWithAnotherTagIsRefusedBeforeAnyNativeCall", TT),
    g("U-arity", U, "if (major != MAJOR_ARRAY || arg != n) revert UCScanRejected();", "", "test_aShorterOrLongerArrayIsRefused", UT),
    g("U-shardLen", U, "|| len != shard.length", "|| false", "test_claimShardOfAnotherLengthIsRefused", UT),
    g("U-shardBytes", U, "if (b[p + i] != shard[i]) revert UCScanRejected();", "", "test_certificateOfAnotherShardIsRefused", UT),
    g("U-nullCount", U, "if (pos < b.length && uint8(b[pos]) == NULL) return (0, pos + 1);", "", "test_nullStepsAndNullSignaturesCountAsZero", UT),
    # ---- verifier: kernel output --------------------------------------------------------------
    g("T-ker-marker", T, "if (_mw(out, 0) != uint256(KERNEL_MARKER)) revert KernelBadOutput();", "", "test_kernel_wrongMarker", TT),
    g("T-ker-validBool", T, "if (valid > 1 ||", "if (false ||", "test_kernel_validWordNotBool", TT),
    g("T-ker-resultOffset", T, "|| _mw(out, 64) != 0x60", "|| false", "test_kernel_resultOffsetNotCanonical", TT),
    g("T-ker-leavesOffset", T, "|| _mw(out, 384) != 0x140", "|| false", "test_kernel_leavesOffsetNotCanonical", TT),
    g("T-ker-leafCap", T, "if (k > BridgeBounds.KERNEL_MAX_LEAVES ||", "if (false ||", "test_kernel_hugeLeafCountDoesNotOverflow|test_kernel_leafCountOverCap", TT),
    g("T-ker-profileLeafCap", T, "if (k > BridgeBounds.MAX_LEAVES) revert BudgetExceeded();", "", "test_kernel_aValidResultOverTheProfileLeafBoundIsBudgetExceeded", TT),
    g("T-ker-exactLength", T, "|| len != KERNEL_FIXED_BYTES + KERNEL_LEAF_BYTES * k) {", "|| false) {", "test_kernel_leafCountDisagreesWithLength|test_kernel_extraTrailingWord|test_kernel_shortOutput|test_kernel_everyTruncationIsBadOutput|test_kernel_oldStrideOutputIsRefused|test_kernel_aPartialLeafIsRefused", TT),
    g("T-ker-stride", T, "KERNEL_LEAF_BYTES = 128;", "KERNEL_LEAF_BYTES = 64;", "test_kernel_strideIsFourWordsPerLeaf|test_verifyReturn_golden_everyLeafOnceInOrder|test_kernel_theMaximumProfileOutputIsAccepted", TT),
    g("T-ker-timeHigh", T, "if (t > type(uint64).max) revert KernelBadOutput();", "", "test_kernel_referenceTimeWordNeedsZeroHighBits", TT),
    g("T-ker-timeWord", T, "referenceTime: uint64(t),", "referenceTime: 0,", "test_kernel_referenceTimeIsReadFromTheThirdWordAndValueFromTheFourth|test_ir_timeOneBelowTheLatestLeafIsRejected", TT),
    g("T-ker-valueWord", T, "leafValue: bytes32(_mw(out, o + 96))", "leafValue: bytes32(_mw(out, o + 32))", "test_kernel_referenceTimeIsReadFromTheThirdWordAndValueFromTheFourth|test_verifyReturn_golden_everyLeafOnceInOrder", TT),
    g("T-ker-releaseToBits", T, "if (releaseTo > type(uint160).max) revert KernelBadOutput();", "", "test_kernel_releaseToHighBitsDirty", TT),
    g("T-ker-validZero", T, "if (valid == 0) revert KernelRejected();", "", "test_kernel_invalidIsRejectedNotBad", TT),
    # ---- verifier: result shape ---------------------------------------------------------------
    g("T-shape-cfg", T, "if (r.cfg != ch) revert KernelCfgMismatch(ch, r.cfg);", "", "test_kernel_cfgHashMismatch|test_prepare_cfgMismatchInResult", TT),
    g("T-shape-nonceZero", T, "r.nonce == 0 ||", "false ||", "test_shape_nonceZero", TT),
    g("T-shape-nonceU64", T, "|| r.nonce > type(uint64).max", "|| false", "test_shape_nonceAboveU64", TT),
    g("T-shape-amountZero", T, "|| r.amount == 0", "|| false", "test_shape_amountZero", TT),
    g("T-shape-digestZero", T, "|| r.lockDigest == bytes32(0)", "|| false", "test_shape_lockDigestZero", TT),
    g("T-shape-prepareLeaves", T, "if (n != 0 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "test_shape_prepareWithLeavesOrRelease", TT),
    g("T-shape-prepareRelease", T, "if (n != 0 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (n != 0 || r.nullifier != bytes32(0)) {", "test_shape_prepareWithLeavesOrRelease", TT),
    g("T-shape-mintLeaves", T, "if (n != 1 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "test_shape_mintWithTwoLeaves", TT),
    g("T-shape-mintRelease", T, "if (n != 1 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (n != 1 || r.nullifier != bytes32(0)) {", "test_shape_mintWithReleaseFields", TT),
    g("T-shape-mintNullifier", T, "if (n != 1 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (n != 1 || r.releaseTo != address(0)) {", "test_shape_mintWithReleaseFields", TT),
    g("T-shape-returnMin", T, "n < 2 ||", "false ||", "test_shape_returnNeedsMintAndBurnAtLeast", TT),
    g("T-shape-returnZero", T, "|| r.releaseTo == address(0) ||", "|| false ||", "test_shape_returnReleaseToZero", TT),
    g("T-shape-returnVault", T, "|| r.releaseTo == c.vault", "|| false", "test_shape_returnReleaseToVault", TT),
    g("T-shape-returnNullifier", T, "|| r.nullifier == bytes32(0)\n            ) revert KernelResultShape();", "\n            ) revert KernelResultShape();", "test_shape_returnNullifierZero", TT),
    # ---- verifier: B1 outcomes ----------------------------------------------------------------
    g("T-b1-ucFalse", T, "if (!B1Calls.verdict(B1Calls.UC_VERIFIER, B1Calls.ucRequest(a), plan.ucGas[j])) {", "B1Calls.verdict(B1Calls.UC_VERIFIER, B1Calls.ucRequest(a), plan.ucGas[j]);\n            if (false) {", "test_b1_ucFalse|test_b1_ucFalseDoesNotReachRsmt", TT),
    g("T-b1-leafFalse", T, "if (!B1Calls.verdict(B1Calls.RSMT_VERIFIER, req, plan.leafGas[i])) {", "B1Calls.verdict(B1Calls.RSMT_VERIFIER, req, plan.leafGas[i]);\n            if (false) {", "test_b1_rsmtFalseNamesTheLeaf", TT),
    # ---- verifier: InputRecord opening and the time comparison ---------------------------------
    g("T-ir-time", T, "if (r.leaves[i].referenceTime > anchorTime) {", "if (false) {", "test_ir_timeOneBelowTheLatestLeafIsRejected|test_ir_theFirstViolatingLeafIsNamed|test_ir_aStaleOpeningIsRefusedByTimeNotAcceptedByAge", TT),
    g("T-ir-timeBoundary", T, "r.leaves[i].referenceTime > anchorTime", "r.leaves[i].referenceTime >= anchorTime", "test_ir_timeEqualToTheLatestLeafIsAccepted|test_ir_u64Extremes", TT),
    g("T-ir-open", T, "times[j] = InputRecord.open(a.inputRecord, a.expectedIRHash, a.expectedStateRoot);", "times[j] = type(uint64).max;", "test_ir_aTimestampLieWithTheSameHashIsBadOpening|test_ir_aHashThatIsNotTheOpeningsIsBadOpening|test_ir_theOpenedStateMustBeTheExpectedStateRoot|test_ir_missingOpeningIsMalformed", TT),
    g("T-ir-ownAnchor", T, "uint64 anchorTime = times[plan.leafAnchor[i]];", "uint64 anchorTime = times[0];", "test_ir_eachLeafIsBoundedByItsOwnAnchorsTime", TT),
    g("T-leaf-ownRoot", T, "anchors[plan.leafAnchor[i]].expectedStateRoot,", "anchors[0].expectedStateRoot,", "test_verifyReturn_golden_everyLeafOnceInOrder", TT),
    g("T-ir-budget", T, "if (_word(b, t + _word(b, t + 192)) > InputRecord.MAX_BYTES) revert BudgetExceeded();", "", "test_ir_boundIsReadBeforeAnythingIsAllocated", TT),
    g("T-ir-budgetLoop", T, "for (uint256 i = 0; i < na; ++i) {\n            uint256 t = offAnchors", "for (uint256 i = 0; i < 0; ++i) {\n            uint256 t = offAnchors", "test_ir_boundIsReadBeforeAnythingIsAllocated", TT),
    g("T-ir-order", T, "if (!B1Calls.verdict(B1Calls.UC_VERIFIER, B1Calls.ucRequest(a), plan.ucGas[j])) {", "InputRecord.open(a.inputRecord, a.expectedIRHash, a.expectedStateRoot);\n            if (!B1Calls.verdict(B1Calls.UC_VERIFIER, B1Calls.ucRequest(a), plan.ucGas[j])) {", "test_ir_isNotTrustedBeforeTheUcVerdict", TT),
    g("T-member-value", T, "abi.encodePacked(r.leaves[i].leafValue),", "abi.encodePacked(r.leaves[i].txHash),", "test_member_theValueIsTheRawLeafValueNotTheTxHash|test_verifyReturn_golden_everyLeafOnceInOrder", TT),
    g("BB-max-semantic", BB, "MAX_SEMANTIC_BYTES = 16 * 1024;", "MAX_SEMANTIC_BYTES = 8 * 1024;", "test_envelope_historyAtTheSemanticCapReachesTheKernel", TT),
    # ---- InputRecord opening ------------------------------------------------------------------
    g("I-hash", I, "if (sha256(ir) != expectedIRHash) revert IRBadOpening();", "", "test_hashMismatchIsBadOpening|test_hashIsCheckedBeforeShape", IT),
    g("I-state", I, "if (state != expectedStateRoot) revert IRStateMismatch(expectedStateRoot, state);", "", "test_stateMismatchNamesBothRoots|test_noFieldOrderIsInterchangeable", IT),
    g("I-tag", I, "if (v != TAG) revert IRMalformed();", "", "test_tagAndArity", IT),
    g("I-arity", I, "if (v != ARITY) revert IRMalformed();", "", "test_tagAndArity", IT),
    g("I-version", I, "if (v != VERSION) revert IRMalformed();", "", "test_version", IT),
    g("I-end", I, "if (pos != b.length) revert IRMalformed();", "", "test_trailingBytes", IT),
    g("I-summaryMax", I, "if (v > MAX_SUMMARY_BYTES) revert IRMalformed();", "", "test_summaryBounds", IT),
    g("I-shortest", I, "if (arg < floor) revert IRMalformed();", "", "test_integerFieldsAreShortestUnsigned|test_version|test_summaryBounds", IT),
    g("I-headMajor", I, "if (first >> 5 != major) revert IRMalformed();", "", "test_integerFieldsAreShortestUnsigned|test_summaryIsNullOrBytes", IT),
    g("I-headReserved", I, "if (ai > 27) revert IRMalformed();", "", "test_integerFieldsAreShortestUnsigned", IT),
    g("I-headWidth", I, "if (next + width > b.length) revert IRMalformed();", "", "test_integerFieldsAreShortestUnsigned|test_everyTruncationIsRefused", IT),
    g("I-headEnd", I, "if (pos >= b.length) revert IRMalformed();", "", "test_everyTruncationIsRefused", IT, 1),
    g("I-summaryEndOfInput", I, "if (pos >= b.length) revert IRMalformed();", "", "test_everyTruncationIsRefused", IT, 2),
    g("I-hashOrNullEnd", I, "if (pos >= b.length) revert IRMalformed();", "", "test_everyTruncationIsRefused", IT, 3),
    g("I-hashLength", I, "|| uint8(b[pos + 1]) != 32) {", "|| false) {", "test_hashFieldsAreExactlyThirtyTwoBytesOrNull|test_declaredHashLengthIsChecked", IT),
    g("I-hashMajor", I, "|| uint8(b[pos]) != 0x58", "|| false", "test_hashFieldsAreExactlyThirtyTwoBytesOrNull", IT),
    g("I-hashEnd", I, "if (pos + 34 > b.length ||", "if (false ||", "test_everyTruncationIsRefused", IT),
    # ---- B1 wrappers --------------------------------------------------------------------------
    g("B-call-gasCap", B, "ok := staticcall(gasCap, target,", "ok := staticcall(gas(), target,", "test_gas_everyNativeCallIsForwardedExactlyItsCharge", TT),
    g("B-call-failed", B, "if (!ok) revert PrecompileFailed(target);", "", "test_b1_ucMalformedHaltIsFailureNotFalse|test_kernel_revertIsPrecompileFailed|test_b1_rsmtHaltIsFailureNotFalse", TT),
    g("B-call-bound", B, "if (size > maxReturn) revert PrecompileBadReturn(target);", "", "test_kernel_oversizeReturndataIsBoundedBeforeCopy", TT),
    g("B-verdict-length", B, "if (out.length != 64) revert PrecompileBadReturn(target);", "", "test_b1_ucBadReturnShapes|test_b1_inactiveUcAddressIsBadReturn|test_b1_rsmtBadReturnShapes", TT),
    g("B-verdict-version", B, "if (version != 1 ||", "if (false ||", "test_b1_ucBadReturnShapes|test_b1_rsmtBadReturnShapes", TT),
    g("B-verdict-flag", B, "|| flag > 1) revert PrecompileBadReturn(target);", "|| false) revert PrecompileBadReturn(target);", "test_b1_ucBadReturnShapes", TT),
    g("B-uc-shardCap", B, "a.shard.length > MAX_SHARD_BYTES ||", "false ||", "test_ucRequest_capsAreEnforced", BT),
    g("B-uc-ucCap", B, "|| a.uc.length > MAX_UC_BYTES", "|| false", "test_ucRequest_capsAreEnforced", BT),
    g("B-member-valueCap", B, "if (value.length > MAX_RSMT_VALUE_BYTES) revert BudgetExceeded();", "", "test_memberRequest_valueCap", BT),
    # ---- identity family (unicity-native) -----------------------------------------------------
    g("P-id-typePrefix", P, "bytes(TYPE_PREFIX), identityD", "bytes(ASSET_PREFIX), identityD", "test_golden_typeAndAssetDerivations|test_golden_identityFamilyVectors", TT),
    g("P-id-assetPrefix", P, "bytes(ASSET_PREFIX), identityD", "bytes(TYPE_PREFIX), identityD", "test_golden_typeAndAssetDerivations|test_golden_identityFamilyVectors", TT),
    g("P-id-network", P, "bytes(Strings.toString(network)),", "bytes(Strings.toString(0)),", "test_golden_identityFamilyVectors", TT),
    g("P-id-root", P, "_hex32(rootGenesis),", "_hex32(executionGenesis),", "test_golden_identityFamilyVectors|test_golden_typeAndAssetDerivations", TT),
    g("P-id-exec", P, "_hex32(executionGenesis),\n            \":\",\n            bytes(Strings", "_hex32(rootGenesis),\n            \":\",\n            bytes(Strings", "test_golden_identityFamilyVectors|test_golden_typeAndAssetDerivations", TT),
    g("P-id-chain", P, "bytes(Strings.toString(chainId)),", "bytes(Strings.toString(1)),", "test_golden_identityFamilyVectors", TT),
    g("P-id-zeroAddress", P, '"0000000000000000000000000000000000000000"', '"000000000000000000000000000000000000000"', "test_golden_identityFamilyVectors|test_golden_typeAndAssetDerivations", TT),
    g("P-id-hexCase", P, 'bytes16 digits = "0123456789abcdef";', 'bytes16 digits = "0123456789ABCDEF";', "test_golden_identityFamilyVectors|test_golden_typeAndAssetDerivations", TT),
    g("P-id-hexNibble", P, "out[2 * i + 1] = digits[b & 0x0f];", "out[2 * i + 1] = digits[b >> 4];", "test_golden_identityFamilyVectors|test_golden_typeAndAssetDerivations", TT),
    # ---- profile codecs -----------------------------------------------------------------------
    g("T-cfg-cap", T, "if (cfgBytes.length > BridgeProfile.MAX_CFG_BYTES) revert BudgetExceeded();", "", "test_cfg_oversizeIsBudget", TT),
    g("P-cfg-reencode", P, "if (keccak256(encodeCfg(c)) != keccak256(b)) revert CfgMalformed();", "", "test_cfg_malformedVariants", TT),
    g("P-pol-reencode", P, "if (keccak256(encodePolicy(p)) != keccak256(b)) revert PolicyMalformed();", "", "test_policy_trailingByteWithMatchingHash|test_policy_nonShortestPartitionWithMatchingHash|test_policy_wrongDomainWithMatchingHash", TT),
    g("P-pol-partitionZero", P, "if (v == 0) revert PolicyMalformed();", "", "test_policy_partitionZero", TT),
    g("P-pol-rows", P, "if (major != Cbor.ARRAY || n != rows) revert PolicyMalformed();", "", "test_policy_rowCountDoesNotMatchDepth", TT),
    g("P-pol-maxDepth", P, "uint8 internal constant MAX_DEPTH = 1;", "uint8 internal constant MAX_DEPTH = 2;", "test_policy_depthTwo", TT),
    # ---- CBOR reader --------------------------------------------------------------------------
    g("C-head-end", C, "if (pos >= b.length) revert CborMalformed();", "", "test_cfg_everyPrefixIsRefusedWithANamedError", TT),
    g("C-head-reserved", C, "if (ai > 27) revert CborMalformed();", "", "test_cfg_reservedAdditionalInformationIsCborMalformed", TT),
    g("C-head-width", C, "if (next + width > b.length) revert CborMalformed();", "", "test_cfg_everyPrefixIsRefusedWithANamedError", TT),
    g("C-bytes-major", C, "if (major != BYTES ||", "if (false ||", "test_cfg_wrongMajorTypesAndWidths", TT),
    g("C-bytes-min", C, "|| len < min", "|| false", "test_cfg_wrongMajorTypesAndWidths|test_cfg_decodeRejectsEmptyAndOversizeShard", TT),
    g("C-bytes-max", C, "|| len > max", "|| false", "test_cfg_wrongMajorTypesAndWidths|test_cfg_decodeRejectsEmptyAndOversizeShard", TT),
    g("C-bytes-end", C, "|| p + len > b.length) revert CborMalformed();", "|| false) revert CborMalformed();", "test_cfg_everyPrefixIsRefusedWithANamedError", TT),
    g("C-uint-major", C, "if (major != UINT ||", "if (false ||", "test_cfg_wrongMajorTypesAndWidths", TT),
    g("C-uint-max", C, "|| v > max) revert CborMalformed();", "|| false) revert CborMalformed();", "test_cfg_wrongMajorTypesAndWidths", TT),
]


def build_template(scratch):
    """One warm copy of the bridge sources and tests; every guard starts from a clone of it."""
    t = os.path.join(scratch, "template")
    os.makedirs(t)
    shutil.copytree(os.path.join(ROOT, "src", "bridge"), os.path.join(t, "src", "bridge"))
    shutil.copytree(os.path.join(ROOT, "test", "bridge"), os.path.join(t, "test", "bridge"))
    os.makedirs(os.path.join(t, "script"))
    for f in ("BridgeGenesisBinding.sol", "BridgeDeploy.s.sol"):  # imported by test/bridge/GenesisBinding.t.sol
        shutil.copy(os.path.join(ROOT, "script", f), os.path.join(t, "script", f))
    shutil.copy(os.path.join(ROOT, "src", "B1Layout.sol"), os.path.join(t, "src", "B1Layout.sol"))  # imported by script/BridgeGenesisBinding.sol
    shutil.copy(os.path.join(ROOT, "foundry.toml"), t)
    os.makedirs(os.path.join(t, "lib"))
    for lib in ("forge-std", "openzeppelin-contracts"):
        os.symlink(os.path.join(ROOT, "lib", lib), os.path.join(t, "lib", lib))
    env = dict(os.environ, PATH=FOUNDRY + ":" + os.environ["PATH"])
    r = subprocess.run(["forge", "build"], cwd=t, env=env, capture_output=True, text=True, timeout=3000)
    if r.returncode != 0:
        sys.exit("template build failed:\n" + (r.stdout + r.stderr)[-2000:])
    return t


def run(guard, template, scratch):
    """Returns (id, status, detail). status: KILLED | SURVIVED | ERROR."""
    work = tempfile.mkdtemp(prefix="guard-", dir=scratch)
    try:
        shutil.rmtree(work)
        clone = ["cp", "-Rc", template, work] if sys.platform == "darwin" else ["cp", "-R", template, work]
        subprocess.run(clone, check=True)
        path = os.path.join(work, guard["file"])
        text = open(path).read()
        idx = -1
        for _ in range(guard["occ"]):
            idx = text.find(guard["old"], idx + 1)
            if idx < 0:
                return guard["id"], "ERROR", "pattern not found (occurrence %d)" % guard["occ"]
        open(path, "w").write(text[:idx] + guard["new"] + text[idx + len(guard["old"]):])
        env = dict(os.environ, PATH=FOUNDRY + ":" + os.environ["PATH"], FOUNDRY_FUZZ_RUNS="64", FOUNDRY_DENY="never")
        cmd = ["forge", "test", "--match-path", guard["path"], "--match-test", "^(" + guard["tests"] + ")"]
        res = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=1500)
        out = res.stdout + res.stderr
        failed = re.findall(r"^\[FAIL.*\]\s+(\w+)\(", out, re.M)
        if "Compiler run failed" in out and not failed:
            return guard["id"], "ERROR", "compile error: " + " ".join(out.split("Compiler run failed")[-1].split())[:200]
        if "No tests match" in out:
            return guard["id"], "ERROR", "no tests matched"
        names = set(guard["tests"].split("|"))
        hit = sorted(set(f for f in failed if any(f == n or f.startswith(n) for n in names)))
        if hit:
            return guard["id"], "KILLED", ",".join(hit)
        return guard["id"], "SURVIVED", "named tests stayed green: " + guard["tests"]
    except subprocess.TimeoutExpired:
        return guard["id"], "ERROR", "timeout"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    sel = [g_ for g_ in GUARDS if not args.only or g_["id"] in args.only.split(",")]
    scratch = tempfile.mkdtemp(prefix="bridge-guards-")
    results = []
    try:
        template = build_template(scratch)
        with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = [ex.submit(run, g_, template, scratch) for g_ in sel]
            for f in cf.as_completed(futs):
                r = f.result()
                results.append(r)
                print("%-10s %-30s %s" % (r[1], r[0], r[2]), flush=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    killed = sum(1 for r in results if r[1] == "KILLED")
    print("\n%d guards: %d killed, %d survived, %d error" % (
        len(results), killed, sum(1 for r in results if r[1] == "SURVIVED"), sum(1 for r in results if r[1] == "ERROR")))
    return 0 if killed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
