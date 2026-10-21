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
CG = "src/bridge/CertGroups.sol"
I = "src/bridge/InputRecord.sol"

VT = "test/bridge/BridgeVault.t.sol"
VI = "test/bridge/BridgeVaultIntegration.t.sol"
TT = "test/bridge/TokenVerifier.t.sol"
BT = "test/bridge/B1Calls.t.sol"
IT = "test/bridge/InputRecord.t.sol"
CGT = "test/bridge/CertGroups.t.sol"


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
    g("V-redeem-creditBound", V, "if (d + amount > locked) revert CreditExceedsLocked(d, amount, locked);", "", "test_redeem_creditNeverExceedsLockedGlobally|test_redeem_creditNeverExceedsLockedCumulatively", VT),
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
    # ---- verifier: envelope -------------------------------------------------------------------
    # ---- verifier: policy ---------------------------------------------------------------------
    # ---- verifier: gas gate -------------------------------------------------------------------
    # ---- UC scan ------------------------------------------------------------------------------
    # ---- verifier: kernel output --------------------------------------------------------------
    g("T-ker-validBool", T, "if (valid > 1 ||", "if (false ||", "test_prepare_everyNoncanonicalKernelOutputIsBad", TT),
    g("T-ker-resultOffset", T, "|| _mw(out, 64) != 0x60", "|| false", "test_prepare_everyNoncanonicalKernelOutputIsBad", TT),
    g("T-ker-leavesOffset", T, "|| _mw(out, 384) != 0x140", "|| false", "test_prepare_everyNoncanonicalKernelOutputIsBad", TT),
    g("T-ker-releaseToBits", T, "if (releaseTo > type(uint160).max) revert KernelBadOutput();", "", "test_prepare_everyNoncanonicalKernelOutputIsBad", TT),
    g("T-ker-validZero", T, "if (valid == 0) revert KernelRejected();", "", "test_prepare_anInvalidResultIsKernelRejected", TT),
    # ---- verifier: result shape ---------------------------------------------------------------
    g("T-shape-cfg", T, "if (r.cfg != ch) revert KernelCfgMismatch(ch, r.cfg);", "", "test_kernel_cfgHashMismatch|test_prepare_cfgMismatchInResult", TT),
    g("T-shape-nonceZero", T, "r.nonce == 0 ||", "false ||", "test_shape_nonceZero", TT),
    g("T-shape-nonceU64", T, "|| r.nonce > type(uint64).max", "|| false", "test_shape_nonceAboveU64", TT),
    g("T-shape-amountZero", T, "|| r.amount == 0", "|| false", "test_shape_amountZero", TT),
    g("T-shape-digestZero", T, "|| r.lockDigest == bytes32(0)", "|| false", "test_shape_lockDigestZero", TT),
    g("T-ker-prepareNoLeaves", T, "|| _mw(out, 416) != 0", "", "test_prepare_everyNoncanonicalKernelOutputIsBad", TT),
    g("T-shape-prepareRelease", T, "if (r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (r.nullifier != bytes32(0)) {", "test_shape_prepareWithLeavesOrRelease", TT),
    g("T-shape-mintLeaves", T, "if (n != 1 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "test_shape_mintWithTwoLeaves", TT),
    g("T-shape-mintRelease", T, "if (n != 1 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (n != 1 || r.nullifier != bytes32(0)) {", "test_shape_mintWithReleaseFields", TT),
    g("T-shape-mintNullifier", T, "if (n != 1 || r.releaseTo != address(0) || r.nullifier != bytes32(0)) {", "if (n != 1 || r.releaseTo != address(0)) {", "test_shape_mintWithReleaseFields", TT),
    g("T-shape-returnMin", T, "n < 2 ||", "false ||", "test_shape_returnNeedsMintAndBurnAtLeast", TT),
    g("T-shape-returnZero", T, "|| r.releaseTo == address(0) ||", "|| false ||", "test_shape_returnReleaseToZero", TT),
    g("T-shape-returnVault", T, "|| r.releaseTo == c.vault", "|| false", "test_shape_returnReleaseToVault", TT),
    g("T-shape-returnNullifier", T, "|| r.nullifier == bytes32(0)\n            ) revert KernelResultShape();", "\n            ) revert KernelResultShape();", "test_shape_returnNullifierZero", TT),
    # ---- verifier: B1 outcomes ----------------------------------------------------------------
    # ---- verifier: InputRecord opening and the time comparison ---------------------------------
    # ---- InputRecord opening ------------------------------------------------------------------
    # ---- B1 wrappers --------------------------------------------------------------------------
    g("B-call-gasCap", B, "ok := staticcall(gasCap, target,", "ok := staticcall(gas(), target,", "test_prepare_theKernelIsForwardedExactlyItsCharge", TT),
    g("B-call-failed", B, "if (!ok) revert PrecompileFailed(target);", "", "test_prepare_aKernelHaltIsPrecompileFailed|test_compose_aHaltIsPrecompileFailed", TT),
    g("B-call-bound", B, "if (size > maxReturn) revert PrecompileBadReturn(target);", "", "test_shape_prepareWithLeavesOrRelease", TT),
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
    g("P-pol-partitionZero", P, "if (v == 0) revert PolicyMalformed();", "", "test_policy_decodeIsStrict", TT),
    # ---- CBOR reader --------------------------------------------------------------------------
    g("C-head-end", C, "if (pos >= b.length) revert CborMalformed();", "", "test_cfg_everyPrefixIsRefusedWithANamedError", TT),
    g("C-head-reserved", C, "if (ai > 27) revert CborMalformed();", "", "test_cfg_reservedAdditionalInformationIsCborMalformed", TT),
    g("C-head-width", C, "if (next + width > b.length) revert CborMalformed();", "", "test_cfg_everyPrefixIsRefusedWithANamedError", TT),
    g("C-bytes-major", C, "if (major != BYTES ||", "if (false ||", "test_cfg_wrongMajorTypesAndWidths", TT),
    g("C-bytes-min", C, "|| len < min", "|| false", "test_cfg_wrongMajorTypesAndWidths|test_cfg_decodeRejectsEmptyAndOversizeShard", TT),
    g("C-bytes-max", C, "|| len > max", "|| false", "test_cfg_wrongMajorTypesAndWidths|test_cfg_decodeRejectsEmptyAndOversizeShard", TT),
    g("C-bytes-end", C, "|| p + len > b.length) revert CborMalformed();", "|| false) revert CborMalformed();", "test_readBytes_aDeclaredLengthPastTheInputIsMalformed", "test/bridge/Cbor.t.sol"),
    g("C-uint-major", C, "if (major != UINT ||", "if (false ||", "test_cfg_wrongMajorTypesAndWidths", TT),
    g("C-uint-max", C, "|| v > max) revert CborMalformed();", "|| false) revert CborMalformed();", "test_cfg_wrongMajorTypesAndWidths", TT),
    # ---- any-age: policy, coverage, preflight, gate, batch call -----------------------------------
    g("V-ctor-policyDecode", V, "Policy memory p = BridgeProfile.decodePolicy(d.policyBody);", "Policy memory p = Policy({partition: 11});", "test_constructor_policyMalformed", VT),
    g("P-pol-reencode", P, "if (keccak256(encodePolicy(p)) != keccak256(b)) revert PolicyMalformed();", "if (encodePolicy(p).length != b.length) revert PolicyMalformed();", "test_policy_decodeIsStrict", TT),
    # ---- the Solidity scan and grouping (CertGroups) ---------------------------------------------
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
