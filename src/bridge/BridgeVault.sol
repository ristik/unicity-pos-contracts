// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BridgeProfile} from "./BridgeProfile.sol";
import {TokenVerifier} from "./TokenVerifier.sol";
import {Cfg, Deployment, KernelResult, Policy} from "./BridgeTypes.sol";
import {
    AlreadyRedeemed,
    BadEvmShard,
    BadRecipient,
    InsufficientCredit,
    KernelAmountMismatch,
    KernelCfgMismatch,
    KernelNonceMismatch,
    KernelRootAmountMismatch,
    LockDigestMismatch,
    LockDigestZero,
    NonceExhausted,
    PartAlreadyRedeemed,
    PartExceedsRemaining,
    PayoutFailed,
    PolicyPartitionIsEvm,
    Reentrancy,
    UnknownLock,
    VerifierCodeHashMismatch,
    ZeroAmount,
    ZeroConfig,
    ZeroNullifier
} from "./BridgeErrors.sol";

/// @notice Non-upgradeable native-UCT vault of the native bridge profile (design `bridge-b2b4-design-v2.md`, "Vault state,
///         nullifiers and claims"; protocol 6 split lineage, bft-core docs/design/bridge-split-lineage-spec.md).
///
///         One lock per token minted at lock time, redeemable in WHOLE PARTS: the token may be split any number of times off
///         chain and each part burned for its own amount. `lock` records a permanent digest and the locked amount and raises L;
///         `redeem` verifies one burn through the immutable `TokenVerifier`, pays out of the lock's remaining amount once per
///         part and credits the burn's recipient (D); `claim` is the only native transfer (P). No owner, no setter, no
///         delegatecall, no refund, no fee, no upgrade path, no way to move a donation.
///
///         Storage is exactly slots 0..9 below, as full 32-byte words (slot 5, the lock digest, is where the lock-proof readers
///         expect it). No base contract adds storage ahead of them; configuration lives in immutables and a code-only data
///         contract. The accounting holds after every successful call: `0 <= P <= D <= L`, for every lock `0 <= redeemed[n] <=
///         lockedAmount[n]`, `sum_n redeemed[n] = D`, `sum_n lockedAmount[n] = L`, `claimable` sums to `D - P`,
///         `balance = L - P + X`, `X >= 0`.
contract BridgeVault {
    // ---- storage layout (do not reorder, insert or resize) -------------------------------------
    /// @dev slot 0: last allocated lock nonce; runtime bound u64.
    uint256 public lastNonce;
    /// @dev slot 1: cumulative L, the sum of every lock amount.
    uint256 public locked;
    /// @dev slot 2: cumulative D, the sum of every redeemed part amount.
    uint256 public credited;
    /// @dev slot 3: cumulative P, the sum of every paid claim.
    uint256 public paid;
    /// @dev slot 4: shared reentrancy guard (0/1) for lock, redeem and claim.
    uint256 private entered;
    /// @dev slot 5: permanent lock digest by nonce; never deleted or overwritten.
    mapping(uint256 => bytes32) public lockDigest;
    /// @dev slot 6: per lock, the sum of the part amounts redeemed so far (`<= lockedAmount`).
    mapping(uint256 => uint256) public redeemedAmount;
    /// @dev slot 7: pull credit by recipient.
    mapping(address => uint256) public claimable;
    /// @dev slot 8: the amount locked under each nonce, fixed at lock time.
    mapping(uint256 => uint256) public lockedAmount;
    /// @dev slot 9: zero until a part of a lock is redeemed, then that part's burn nullifier, once. The key is the part's token
    ///      ID from the verified result, so the same part cannot be paid twice whatever burn or witnesses are presented.
    mapping(uint256 => mapping(bytes32 => bytes32)) public spentPart;
    // --------------------------------------------------------------------------------------------

    /// @notice `cfg = H(Cfg)`, the immutable configuration hash every kernel result must carry.
    bytes32 public immutable CFG;
    /// @notice The only verifier this vault consults; its address and code hash are pinned in Cfg.
    TokenVerifier public immutable VERIFIER;
    /// @notice Code-only contract holding the exact Cfg bytes (runtime code is a STOP byte followed by Cfg).
    address private immutable CFG_DATA;
    /// @notice Cfg type and asset identifiers, derived at construction.
    bytes32 public immutable TYPE_ID;
    bytes32 public immutable ASSET_ID;

    event Configured(bytes32 indexed cfg, bytes cfgBytes);
    /// @dev The complete lock record K = [zeroAddress, ty, aid, amount, id, rcpt] and everything an
    ///      SDK needs to build the mint M: depositor, salt and the first predicate P0.
    event Locked(
        uint256 indexed nonce,
        address indexed depositor,
        bytes32 digest,
        address zeroAddress,
        bytes32 ty,
        bytes32 aid,
        uint256 amount,
        bytes32 tokenId,
        bytes32 salt,
        bytes32 rcpt,
        bytes p0
    );
    /// @dev One part of lock `nonce` was redeemed: `partId` is its token ID, `nullifier` its burn's, `amount` its whole amount and
    ///      `remaining` what the lock has left after it (zero completes the lock).
    event RedemptionCredited(
        uint256 indexed nonce,
        bytes32 indexed partId,
        address indexed recipient,
        bytes32 nullifier,
        uint256 amount,
        uint256 remaining
    );
    event Claimed(address indexed recipient, address indexed to, uint256 amount);
    event Received(address indexed from, uint256 amount);

    modifier nonReentrant() {
        if (entered != 0) revert Reentrancy();
        entered = 1;
        _;
        entered = 0;
    }

    constructor(Deployment memory d) {
        if (
            d.rootGenesis == 0 || d.executionGenesis == 0 || d.semanticProfileHash == 0
                || d.b1ProfileHash == 0
        ) revert ZeroConfig();
        if (d.evmShard.length == 0 || d.evmShard.length > BridgeProfile.MAX_SHARD_BYTES) {
            revert BadEvmShard();
        }
        bytes32 codeHash = d.tokenVerifier.codehash;
        if (codeHash == 0 || codeHash == keccak256("") || codeHash != d.tokenVerifierCodeHash) {
            revert VerifierCodeHashMismatch(d.tokenVerifierCodeHash, codeHash);
        }
        // The policy body is opened here once: canonical, hash taken from the exact bytes, and its
        // aggregator partition distinct from the EVM backing partition.
        Policy memory p = BridgeProfile.decodePolicy(d.policyBody);
        if (p.partition == d.evmPartition) revert PolicyPartitionIsEvm();

        // Chain IDs are u64 on every Ethereum execution client (reth included), so the narrowing is exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 chainId = uint64(block.chainid);
        Cfg memory c = Cfg({
            network: d.network,
            rootGenesis: d.rootGenesis,
            chainId: chainId,
            executionGenesis: d.executionGenesis,
            evmPartition: d.evmPartition,
            evmShard: d.evmShard,
            vault: address(this),
            zeroAddress: address(0),
            ty: BridgeProfile.deriveType(d.network, d.rootGenesis, d.executionGenesis, chainId),
            aid: BridgeProfile.deriveAsset(d.network, d.rootGenesis, d.executionGenesis, chainId),
            semanticProfileHash: d.semanticProfileHash,
            tokenVerifier: d.tokenVerifier,
            tokenVerifierCodeHash: d.tokenVerifierCodeHash,
            b1ProfileHash: d.b1ProfileHash,
            aggregatorPolicyHash: sha256(d.policyBody)
        });
        bytes memory raw = BridgeProfile.encodeCfg(c);
        bytes32 h = BridgeProfile.cfgHash(raw);
        CFG = h;
        VERIFIER = TokenVerifier(d.tokenVerifier);
        TYPE_ID = c.ty;
        ASSET_ID = c.aid;
        CFG_DATA = address(new CfgData(raw));
        emit Configured(h, raw);
    }

    // ---------------------------------------------------------------------------------------------
    // Lock
    // ---------------------------------------------------------------------------------------------

    /// @notice Locks `msg.value` as one whole token whose first owner is the signature predicate `p0`.
    ///         The nonce is allocated here and only on success; there is no refund or timeout path.
    function lock(bytes calldata p0) external payable nonReentrant returns (uint256 nonce) {
        uint256 amount = msg.value;
        if (amount == 0) revert ZeroAmount();
        uint256 last = lastNonce;
        if (last >= type(uint64).max) revert NonceExhausted();
        nonce = last + 1;

        KernelResult memory r = VERIFIER.prepareLock(cfgBytes(), nonce, amount, p0);
        if (r.cfg != CFG) revert KernelCfgMismatch(CFG, r.cfg);
        if (r.nonce != nonce) revert KernelNonceMismatch(nonce, r.nonce);
        if (r.amount != amount) revert KernelAmountMismatch(amount, r.amount);
        if (r.lockDigest == bytes32(0)) revert LockDigestZero();

        lastNonce = nonce;
        locked += amount;
        lockedAmount[nonce] = amount;
        lockDigest[nonce] = r.lockDigest;
        emit Locked(
            nonce,
            msg.sender,
            r.lockDigest,
            address(0),
            TYPE_ID,
            ASSET_ID,
            amount,
            r.tokenId,
            r.salt,
            r.firstPredicateHash,
            p0
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Mint view
    // ---------------------------------------------------------------------------------------------

    /// @notice Verifies that `proof` proves a mint of an existing lock of this vault that is not complete (some of it is still
    ///         unredeemed). It creates no state; the token exists off EVM. Returns the lock nonce.
    function verifyMint(bytes calldata proof) external view returns (uint256 nonce) {
        KernelResult memory r = VERIFIER.verifyMint(cfgBytes(), proof);
        if (r.cfg != CFG) revert KernelCfgMismatch(CFG, r.cfg);
        nonce = r.nonce;
        if (nonce == 0 || nonce > lastNonce) revert UnknownLock(nonce);
        if (lockDigest[nonce] != r.lockDigest) revert LockDigestMismatch(nonce);
        if (redeemedAmount[nonce] == lockedAmount[nonce]) revert AlreadyRedeemed(nonce);
    }

    // ---------------------------------------------------------------------------------------------
    // Redeem
    // ---------------------------------------------------------------------------------------------

    /// @notice Redeems one burn of one part of a lock. Anyone may submit; every release field comes from the certified burn, never
    ///         from `msg.sender`. Credits the recipient and pays nothing: payment is `claim`. The part is redeemed whole, once,
    ///         for its own amount, out of what the lock has left; siblings redeem independently until the lock is complete.
    /// @dev The lock's identity is the root's (`r.lockDigest` against the stored digest, `r.amount` against the stored amount);
    ///      the part comes from the verified lineage. Conservation is enforced per lock (`redeemed + partAmount <= lockedAmount`)
    ///      (hence `credited <= locked`). Returns the lock nonce and the part's token ID.
    function redeem(bytes calldata proof)
        external
        nonReentrant
        returns (uint256 nonce, bytes32 partId)
    {
        KernelResult memory r = VERIFIER.verifyReturn(cfgBytes(), proof);
        if (r.cfg != CFG) revert KernelCfgMismatch(CFG, r.cfg);
        nonce = r.nonce;
        if (nonce == 0 || nonce > lastNonce) revert UnknownLock(nonce);
        if (lockDigest[nonce] != r.lockDigest) revert LockDigestMismatch(nonce);
        uint256 total = lockedAmount[nonce];
        if (r.amount != total) revert KernelRootAmountMismatch(total, r.amount);
        if (r.nullifier == bytes32(0)) revert ZeroNullifier();
        if (r.releaseTo == address(0) || r.releaseTo == address(this)) revert BadRecipient();
        partId = r.partTokenId;
        uint256 amount = r.partAmount;
        if (partId == bytes32(0) || amount == 0) revert ZeroAmount();
        if (spentPart[nonce][partId] != bytes32(0)) revert PartAlreadyRedeemed(nonce, partId);

        uint256 done = redeemedAmount[nonce];
        uint256 left = total - done;
        if (amount > left) revert PartExceedsRemaining(nonce, left, amount);

        // `credited <= locked` needs no check of its own: the sum of the per-lock amounts is `locked` and each lock stays within
        // its own.
        spentPart[nonce][partId] = r.nullifier;
        redeemedAmount[nonce] = done + amount;
        credited += amount;
        claimable[r.releaseTo] += amount;
        emit RedemptionCredited(nonce, partId, r.releaseTo, r.nullifier, amount, left - amount);
    }

    // ---------------------------------------------------------------------------------------------
    // Claim
    // ---------------------------------------------------------------------------------------------

    /// @notice Pays `amount` of the caller's credit to `to`. Checks and effects precede the value
    ///         call; a failed payout reverts credit and P together. Only the credited recipient can
    ///         redirect payment.
    function claim(uint256 amount, address to) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (to == address(0) || to == address(this)) revert BadRecipient();
        uint256 have = claimable[msg.sender];
        if (have < amount) revert InsufficientCredit(have, amount);
        claimable[msg.sender] = have - amount;
        paid += amount;
        // The payee is the credited recipient's own choice; credit and P are already updated.
        // forge-lint: disable-next-line(arbitrary-send-eth)
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert PayoutFailed();
        emit Claimed(msg.sender, to, amount);
    }

    /// @notice Donations are accepted without changing L, D or P. Forced transfers (selfdestruct,
    ///         coinbase) can also arrive; both raise only `unexpectedValue`.
    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    // ---------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------

    /// @notice Exact Cfg bytes the verifier is called with.
    function cfgBytes() public view returns (bytes memory out) {
        address data = CFG_DATA;
        uint256 size;
        assembly ("memory-safe") {
            size := extcodesize(data)
        }
        out = new bytes(size - 1);
        assembly ("memory-safe") {
            extcodecopy(data, add(out, 32), 1, sub(size, 1))
        }
    }

    /// @notice What lock `nonce` has left to redeem: `lockedAmount - redeemedAmount`.
    function remaining(uint256 nonce) external view returns (uint256) {
        return lockedAmount[nonce] - redeemedAmount[nonce];
    }

    /// @notice Whether lock `nonce` exists and every unit of it has been redeemed.
    function lockComplete(uint256 nonce) external view returns (bool) {
        uint256 total = lockedAmount[nonce];
        return total != 0 && redeemedAmount[nonce] == total;
    }

    /// @notice O = L - D, the backing of locks not yet redeemed.
    function outstanding() external view returns (uint256) {
        return locked - credited;
    }

    /// @notice C = D - P, which equals the sum of every `claimable` balance.
    function pendingClaims() external view returns (uint256) {
        return credited - paid;
    }

    /// @notice X = balance - (L - P): donations and forced transfers. Derived, never a counter.
    function unexpectedValue() external view returns (uint256) {
        return address(this).balance - (locked - paid);
    }
}

/// @notice Code-only data contract: its runtime code is a STOP byte followed by `data`. It has no
///         functions and no storage; the vault reads it with EXTCODECOPY.
contract CfgData {
    constructor(bytes memory data) {
        bytes memory code = bytes.concat(hex"00", data);
        assembly ("memory-safe") {
            return(add(code, 32), mload(code))
        }
    }
}
