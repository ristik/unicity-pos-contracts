// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ERC20Config} from "./ERC20Config.sol";
import {ERC20Context, IERC20ActivationContext} from "./ERC20Context.sol";
import {ERC20BridgeVerifier} from "./generated/ERC20BridgeVerifier.sol";
import {FlatBindings} from "../verifier/flat/FlatBindings.sol";

/// @notice One permissionless ERC20 vault per token and factory generation.
contract ERC20BridgeFactory is IERC20ActivationContext {
    uint256 private constant INITCODE_LIMIT = 49_152;
    address private transient _activating;
    address private transient _vault;
    address private transient _recovery;
    bytes32 private transient _recoveryHash;

    bytes32 public immutable VAULT_INITCODE_HASH;
    bytes32 public immutable RECOVERY_INITCODE_HASH;
    uint64 private immutable CHAIN_ID;
    bytes32 private immutable EXECUTION_GENESIS;
    bytes32 public immutable GENERATION;
    bytes32 public immutable PINS;
    bytes32 private immutable PROFILE;
    ERC20BridgeVerifier private immutable ORDINARY;
    bytes32 private immutable ORDINARY_HASH;

    bytes private _prefix;
    bytes private _suffix;
    FlatBindings.ReleaseInputs private _release;

    error BadRelease();
    error BadToken();
    error BadTemplate();
    error ActivationInProgress();
    error InvalidActivation();
    error ConstructorOnly();

    event ERC20Activated(
        address indexed token,
        address indexed vault,
        address indexed recovery,
        bytes32 domain,
        bytes32 vaultRuntimeHash,
        bytes32 recoveryRuntimeHash
    );

    struct Release {
        ERC20BridgeVerifier ordinary;
        bytes32 ordinaryHash;
        bytes32 profile;
        bytes32 generation;
        bytes32 vaultTemplate;
        bytes32 recoveryTemplate;
        FlatBindings.ReleaseInputs inputs;
    }

    constructor(ERC20Config.Chain memory chain, Release memory release) {
        if (
            block.chainid == 0 || block.chainid > type(uint64).max || release.generation == 0
                || release.vaultTemplate == 0 || release.recoveryTemplate == 0
                || release.ordinaryHash == 0 || address(release.ordinary).code.length == 0
                || address(release.ordinary).codehash != release.ordinaryHash
                || release.profile == 0 || release.profile != release.ordinary.PROFILE_HASH()
        ) revert BadRelease();
        // Bounded above.
        // forge-lint: disable-next-line(unsafe-typecast)
        CHAIN_ID = uint64(block.chainid);
        EXECUTION_GENESIS = chain.executionGenesis;
        GENERATION = release.generation;
        PROFILE = release.profile;
        ORDINARY = release.ordinary;
        ORDINARY_HASH = release.ordinaryHash;
        VAULT_INITCODE_HASH = release.vaultTemplate;
        RECOVERY_INITCODE_HASH = release.recoveryTemplate;
        _release = release.inputs;
        PINS = FlatBindings.pins(
            release.inputs,
            address(ORDINARY),
            ORDINARY_HASH,
            address(ORDINARY.RECEIPTS()),
            ORDINARY.RECEIPTS_HASH(),
            ORDINARY.REGISTRY_HASH(),
            address(ORDINARY.LINEAGE()),
            ORDINARY.LINEAGE_HASH()
        );
        _prefix = ERC20Config.prefix(chain, CHAIN_ID);
        _suffix = ERC20Config.suffix(PROFILE, address(ORDINARY), ORDINARY_HASH, chain.qmax);
        // Validate the canonical configuration and chain/graph settings before publishing the factory.
        ORDINARY.readConfig(config(address(1)));
    }

    function predict(address token) public view returns (address vault, address recovery) {
        vault = _predict(_vaultSalt(token), VAULT_INITCODE_HASH);
        recovery = _predict(_recoverySalt(token), RECOVERY_INITCODE_HASH);
    }

    function config(address token) public view returns (bytes memory) {
        (address vault,) = predict(token);
        (bytes32 asset, bytes32 coin, bytes32 tokenType) =
            ERC20Config.identities(CHAIN_ID, token, EXECUTION_GENESIS);
        return abi.encodePacked(
            _prefix,
            hex"54",
            vault,
            hex"5820",
            asset,
            hex"5820",
            tokenType,
            hex"5820",
            coin,
            _suffix,
            hex"54",
            token,
            hex"5820",
            GENERATION,
            hex"5820",
            PINS
        );
    }

    function activate(address token, bytes calldata vaultInitcode, bytes calldata recoveryInitcode)
        external
        returns (address vault, address recovery, bytes32 domain)
    {
        if (_activating != address(0)) revert ActivationInProgress();
        if (block.chainid != CHAIN_ID || token.code.length == 0) revert BadToken();
        (vault, recovery) = predict(token);
        domain = sha256(config(token));
        if (vault.code.length != 0) {
            // The only creation path installs both release templates atomically.
            if (recovery.code.length == 0) revert InvalidActivation();
            return (vault, recovery, domain);
        }
        if (
            recovery.code.length != 0 || vaultInitcode.length > INITCODE_LIMIT
                || recoveryInitcode.length > INITCODE_LIMIT
                || keccak256(vaultInitcode) != VAULT_INITCODE_HASH
                || keccak256(recoveryInitcode) != RECOVERY_INITCODE_HASH
        ) revert BadTemplate();

        _activating = token;
        _vault = vault;
        _recovery = recovery;
        if (_create(recoveryInitcode, _recoverySalt(token)) != recovery) {
            revert InvalidActivation();
        }
        _recoveryHash = recovery.codehash;
        if (_create(vaultInitcode, _vaultSalt(token)) != vault) revert InvalidActivation();
        // The vault constructor checks the recovery runtime and all Γ bindings.
        emit ERC20Activated(token, vault, recovery, domain, vault.codehash, _recoveryHash);
        _activating = address(0);
        _vault = address(0);
        _recovery = address(0);
        _recoveryHash = 0;
    }

    function recoveryContext() external view returns (ERC20Context.Recovery memory) {
        if (_activating == address(0) || msg.sender != _recovery) revert ConstructorOnly();
        return
            ERC20Context.Recovery(
                config(_activating), address(ORDINARY), GENERATION, _release, PINS
            );
    }

    function vaultContext() external view returns (ERC20Context.Vault memory) {
        if (_activating == address(0) || msg.sender != _vault || _recoveryHash == 0) {
            revert ConstructorOnly();
        }
        return ERC20Context.Vault(config(_activating), _recovery, _recoveryHash, PROFILE);
    }

    function _predict(bytes32 salt, bytes32 hash) private view returns (address) {
        // CREATE2 uses the low 20 bytes of the digest.
        // forge-lint: disable-next-line(unsafe-typecast)
        return
            address(
                uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(this), salt, hash))))
            );
    }

    function _vaultSalt(address token) private pure returns (bytes32) {
        return bytes32(uint256(uint160(token)));
    }

    function _recoverySalt(address token) private pure returns (bytes32) {
        return keccak256(abi.encode(token));
    }

    function _create(bytes memory initcode, bytes32 salt) private returns (address deployed) {
        assembly ("memory-safe") {
            deployed := create2(0, add(initcode, 32), mload(initcode), salt)
        }
    }
}
