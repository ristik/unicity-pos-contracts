// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Manifest, GenesisIdentity, Delegation, DelegationRequest} from "./P85Types.sol";
import {IRootRecords, IStakeCustody} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";

/// @title ElectionPolicy (PR2 surface)
/// @notice The part of ElectionPolicy that PR2 freezes for PR3 (design v5 section 2): the bounded
/// live index, the owner-authenticated `admitDelegation` mutator with its staged
/// (binding, operatorPayee) storage and replay nonces keyed by (StakingID, generation).
/// Election, primary proof slots, candidate and K bodies and the attempt cursor are PR3.
///
/// `admitDelegation` is the sole post-genesis operator-payee nomination path. The signed payload is
/// (network, chain, ElectionPolicyAddress, admitDelegation, StakingID, generation, rootNodeID,
/// rootVerificationKey, evmNodeID, evmVerificationKey, operatorPayee, roleNonce, delegationNonce,
/// expiry); both the owner and the EVM key sign that exact digest.
contract ElectionPolicy {
    bytes32 internal constant DELEGATION_DOMAIN = keccak256("unicity.p85.admitDelegation");
    bytes32 internal constant BINDING_DOMAIN = keccak256("unicity.p85.delegation-binding");

    error NotFactory();
    error AlreadyInitialized();
    error NotInitialized();
    error ManifestMismatch();
    error NotCustody();
    error UnknownIdentity();
    error StaleGeneration();
    error RoleNonceMismatch();
    error DelegationNonceMismatch();
    error DelegationExpired();
    error ZeroPayee();
    error BadRootKey();
    error WrongRootKey();
    error BadOwnerAuthorization();
    error BadEvmPossession();
    error IndexFull();

    event Initialized(bytes32 manifestHash);
    event DelegationAdmitted(
        uint64 indexed id, bytes32 bindingHash, address operatorPayee, uint64 nonce
    );
    event LiveIndexChanged(uint64 indexed id, bool included);

    struct Staged {
        Delegation binding;
        bytes32 bindingHash;
        uint64 nextNonce;
    }

    address public immutable FACTORY;
    bool public initialized;
    bytes32 public manifestHash;
    bytes32 public network;
    IStakeCustody public custody;
    IRootRecords public roots;
    uint32 public vMax;

    mapping(uint64 => mapping(uint64 => Staged)) internal _staged;
    uint64[] internal _index;
    mapping(uint64 => uint32) internal _indexPosition; // 1-based; zero means absent

    constructor() {
        FACTORY = msg.sender;
    }

    /// @notice Seeds the genesis live index and staged bindings from the manifest. Custody has
    /// already assigned StakingIDs 1..n in manifest order.
    function initialize(bytes32 manifestHash_, Manifest calldata m) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (initialized) revert AlreadyInitialized();
        if (m.election != address(this)) {
            revert ManifestMismatch();
        }
        initialized = true;
        manifestHash = manifestHash_;
        network = m.network;
        // forge-lint: disable-next-line(missing-events-access-control)
        custody = IStakeCustody(m.custody);
        roots = IRootRecords(m.roots);
        vMax = m.limits.vMax;
        for (uint256 i = 0; i < m.identities.length; ++i) {
            GenesisIdentity calldata g = m.identities[i];
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 id = uint64(i + 1); // identities are bounded by vMax (a uint32)
            Staged storage s = _staged[id][1];
            s.binding = Delegation(g.rootNodeID, g.rootKey, g.evmNodeID, g.evmKey, g.operatorPayee);
            s.bindingHash = _bindingHash(id, 1, s.binding);
            _addIndex(id);
        }
        emit Initialized(manifestHash_);
    }

    modifier whenInitialized() {
        _requireInitialized();
        _;
    }

    function _requireInitialized() private view {
        if (!initialized) revert NotInitialized();
    }

    /// @notice The digest both the owner and the EVM key sign.
    function delegationDigest(DelegationRequest calldata r) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DELEGATION_DOMAIN,
                network,
                block.chainid,
                address(this),
                r.id,
                r.generation,
                r.binding.rootNodeID,
                keccak256(r.binding.rootKey),
                r.binding.evmNodeID,
                keccak256(r.binding.evmKey),
                r.binding.operatorPayee,
                r.roleNonce,
                r.delegationNonce,
                r.expiry
            )
        );
    }

    /// @notice Stage a future EVM binding and operator payee for (id, generation). Anyone may relay;
    /// authority is the owner's signature plus EVM-key possession over the exact payload. The
    /// delegation nonce is consumed atomically. Frozen election records, exact K and existing
    /// credits are untouched: a nomination affects only later election snapshots.
    function admitDelegation(
        DelegationRequest calldata r,
        bytes calldata ownerSignature,
        bytes calldata evmPossession
    ) external whenInitialized {
        // forge-lint: disable-start(unused-return)
        (
            address owner,,
            bytes32 activeRootKey,
            bytes32 stagedRootKey,
            uint64 generation,
            uint64 roleNonce,,,
        ) = custody.positions(r.id);
        // forge-lint: disable-end(unused-return)
        if (owner == address(0)) revert UnknownIdentity();
        if (generation != r.generation) revert StaleGeneration();
        if (roleNonce != r.roleNonce) revert RoleNonceMismatch();
        Staged storage s = _staged[r.id][r.generation];
        if (s.nextNonce != r.delegationNonce) revert DelegationNonceMismatch();
        if (r.expiry < roots.ucTime()) revert DelegationExpired();
        if (r.binding.operatorPayee == address(0)) revert ZeroPayee();
        if (r.binding.rootKey.length != KeyLib.KEY_LENGTH) revert BadRootKey();
        bytes32 rootHash = keccak256(r.binding.rootKey);
        if (rootHash != activeRootKey && (stagedRootKey == 0 || rootHash != stagedRootKey)) {
            revert WrongRootKey();
        }
        bytes32 digest = delegationDigest(r);
        address signer = KeyLib.recover(digest, ownerSignature);
        if (signer == address(0) || signer != owner) revert BadOwnerAuthorization();
        if (!KeyLib.verify(r.binding.evmKey, digest, evmPossession)) revert BadEvmPossession();
        custody.registerEvmKey(r.id, keccak256(r.binding.evmKey));

        s.binding = r.binding;
        s.bindingHash = _bindingHash(r.id, r.generation, r.binding);
        s.nextNonce = r.delegationNonce + 1;
        emit DelegationAdmitted(r.id, s.bindingHash, r.binding.operatorPayee, r.delegationNonce);
    }

    /// @notice Custody-only: reconcile the bounded live index with custody's open-lot state.
    function syncLiveIndex(uint64 id) external whenInitialized {
        if (msg.sender != address(custody)) revert NotCustody();
        // forge-lint: disable-start(unused-return)
        (,,,,,, uint32 openLots,,) = custody.positions(id);
        // forge-lint: disable-end(unused-return)
        bool included = openLots != 0;
        bool present = _indexPosition[id] != 0;
        if (included && !present) {
            _addIndex(id);
            emit LiveIndexChanged(id, true);
        } else if (!included && present) {
            uint32 slot = _indexPosition[id] - 1;
            uint64 last = _index[_index.length - 1];
            _index[slot] = last;
            _indexPosition[last] = slot + 1;
            _index.pop();
            delete _indexPosition[id];
            emit LiveIndexChanged(id, false);
        }
    }

    function _addIndex(uint64 id) private {
        if (_index.length >= vMax) revert IndexFull();
        _index.push(id);
        // forge-lint: disable-next-line(unsafe-typecast)
        _indexPosition[id] = uint32(_index.length); // bounded by vMax, a uint32
    }

    function _bindingHash(uint64 id, uint64 generation, Delegation memory d)
        private
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                BINDING_DOMAIN,
                id,
                generation,
                d.rootNodeID,
                keccak256(d.rootKey),
                d.evmNodeID,
                keccak256(d.evmKey),
                d.operatorPayee
            )
        );
    }

    function delegation(uint64 id, uint64 generation)
        external
        view
        returns (Delegation memory binding, bytes32 bindingHash, uint64 nextNonce)
    {
        Staged storage s = _staged[id][generation];
        return (s.binding, s.bindingHash, s.nextNonce);
    }

    function liveCount() external view returns (uint32) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(_index.length); // bounded by vMax, a uint32
    }

    function isIndexed(uint64 id) external view returns (bool) {
        return _indexPosition[id] != 0;
    }

    function liveIndexAt(uint32 i) external view returns (uint64) {
        return _index[i];
    }
}
