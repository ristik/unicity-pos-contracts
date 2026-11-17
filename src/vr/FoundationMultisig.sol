// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {VRC} from "./VRConstants.sol";
import {IVRRecordSource} from "./VRTypes.sol";

/// @title FoundationMultisig
/// @notice The Foundation's 3-of-5 governor (design section 3.5.5): VR's `governor` and the PoS prototype's
/// `GovernanceParams.AUTHORITY`. Clean-room and minimal: a proposal is one call (target, calldata) under an EIP-712 typed digest with
/// the multisig's sequential nonce; any three of the five signers sign it off-chain and anyone submits the signatures. A signer-set
/// change is a delayed self-call: an approved `proposeSigners` stages the new set, which anyone may apply after both governance delays
/// (DELAY_ROUNDS progress units and DELAY_SECONDS UC seconds of the SealRegistry clock, as VR's own changes), and an approved
/// `cancelSigners` withdraws it before then. No value transfer, no delegatecall, no upgrade path.
contract FoundationMultisig {
    error NotSelf();
    error BadSigners();
    error BadSignatures();
    error CallFailed();
    error NoPendingSigners();
    error DelayNotElapsed();
    error SignersPending();

    event Executed(uint64 indexed nonce, address indexed target, bytes32 dataHash);
    event SignersProposed(address[5] signers, uint64 notBeforeProgress, uint64 notBeforeTime);
    event SignersCancelled();
    event SignersChanged(address[5] signers);

    uint256 public constant THRESHOLD = 3;
    uint256 public constant SIGNER_COUNT = 5;
    uint256 internal constant HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant CALL_TYPEHASH =
        keccak256("Call(address target,bytes data,uint64 nonce)");
    bytes32 internal constant NAME_HASH = keccak256("UnicityFoundationMultisig");
    bytes32 internal constant VERSION_HASH = keccak256("1");

    address[5] internal _signers; // strictly ascending
    uint64 public nonce;
    address[5] internal _nextSigners;
    bool public signersPending;
    uint64 public nextNotBeforeProgress;
    uint64 public nextNotBeforeTime;

    constructor(address[5] memory signers_) {
        _checkSigners(signers_);
        _signers = signers_;
        emit SignersChanged(signers_);
    }

    function signers() external view returns (address[5] memory) {
        return _signers;
    }

    function nextSigners() external view returns (address[5] memory) {
        return _nextSigners;
    }

    function isSigner(address a) public view returns (bool) {
        for (uint256 i = 0; i < SIGNER_COUNT; ++i) {
            if (_signers[i] == a) return true;
        }
        return false;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    /// @notice The EIP-712 digest the signers sign for a call at `nonce_`.
    function callDigest(address target, bytes calldata data, uint64 nonce_)
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(CALL_TYPEHASH, target, keccak256(data), nonce_));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice Executes one call approved by at least three distinct signers. `sigs` are 65-byte low-s signatures (v 27 or 28) over
    /// `callDigest(target, data, nonce)`, ordered by strictly ascending signer address. The nonce is consumed only if the call succeeds;
    /// a reverting call reverts the whole execution, so a proposal can never half-apply.
    function execute(address target, bytes calldata data, bytes[] calldata sigs) external {
        if (target == address(0)) revert CallFailed();
        uint64 n = nonce;
        bytes32 digest = callDigest(target, data, n);
        if (sigs.length < THRESHOLD) revert BadSignatures();
        address last = address(0);
        for (uint256 i = 0; i < sigs.length; ++i) {
            address s = _recover(digest, sigs[i]);
            if (s == address(0) || s <= last || !isSigner(s)) revert BadSignatures();
            last = s;
        }
        nonce = n + 1;
        (bool ok,) = target.call(data);
        if (!ok) revert CallFailed();
        emit Executed(n, target, keccak256(data));
    }

    /// @notice Self-call only (an approved proposal): stages a new signer set, applicable after both governance delays.
    function proposeSigners(address[5] calldata next) external {
        if (msg.sender != address(this)) revert NotSelf();
        if (signersPending) revert SignersPending();
        _checkSigners(next);
        IVRRecordSource seal = IVRRecordSource(VRC.SEAL_REGISTRY);
        _nextSigners = next;
        signersPending = true;
        nextNotBeforeProgress = seal.progress() + VRC.DELAY_ROUNDS;
        nextNotBeforeTime = seal.ucTime() + VRC.DELAY_SECONDS;
        emit SignersProposed(next, nextNotBeforeProgress, nextNotBeforeTime);
    }

    /// @notice Self-call only: withdraws a staged signer set before it is applied.
    function cancelSigners() external {
        if (msg.sender != address(this)) revert NotSelf();
        if (!signersPending) revert NoPendingSigners();
        delete _nextSigners;
        signersPending = false;
        emit SignersCancelled();
    }

    /// @notice Anyone, after both delays: applies the staged signer set.
    function applySigners() external {
        if (!signersPending) revert NoPendingSigners();
        IVRRecordSource seal = IVRRecordSource(VRC.SEAL_REGISTRY);
        if (seal.progress() < nextNotBeforeProgress || seal.ucTime() < nextNotBeforeTime) {
            revert DelayNotElapsed();
        }
        _signers = _nextSigners;
        delete _nextSigners;
        signersPending = false;
        emit SignersChanged(_signers);
    }

    function _checkSigners(address[5] memory s) internal pure {
        for (uint256 i = 0; i < SIGNER_COUNT; ++i) {
            if (s[i] == address(0) || (i > 0 && s[i] <= s[i - 1])) revert BadSigners();
        }
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > HALF_N || (v != 27 && v != 28)) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
