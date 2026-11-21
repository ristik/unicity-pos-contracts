// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// Loop indices start at zero. Each signed source requires a call to the pinned helper.
// forge-lint: disable-start(uninitialized-local,calls-loop)

import {FlatBindings} from "./FlatBindings.sol";
import {FlatLineage} from "./FlatLineage.sol";
import {FlatReceipts} from "./FlatReceipts.sol";
import {FlatNative} from "./FlatNative.sol";
import {
    FlatConfig,
    FlatPart,
    FlatClaim,
    FlatVerdict,
    FlatWire as W,
    BadBinding,
    BadStep
} from "./FlatTypes.sol";

abstract contract FlatOrdinary {
    FlatLineage public immutable LINEAGE;
    bytes32 public immutable LINEAGE_HASH;

    struct Map {
        // Alternating key and value words. Zero keys have their own slot.
        bytes32[] slots;
        uint256 count;
        bool hasZero;
        bytes32 zeroValue;
    }

    constructor(FlatLineage lineage, bytes32 lineageHash) {
        if (lineageHash == 0 || address(lineage).codehash != lineageHash) revert BadBinding();
        LINEAGE = lineage;
        LINEAGE_HASH = lineageHash;
    }

    struct Execution {
        FlatConfig cfg;
        FlatPart part;
        FlatVerdict verdict;
        Map sids;
        Map claims;
        FlatNative.Batch batch;
    }

    function verifyReturn(bytes calldata gamma, bytes calldata evidence)
        external
        view
        returns (FlatVerdict memory)
    {
        Execution memory x;
        x.cfg = _config(gamma);
        x.sids.slots = new bytes32[](32);
        x.claims.slots = new bytes32[](32);
        x.batch = FlatNative.batch();
        uint64 levels = W.prelude(evidence);
        uint256 pos = 14;
        for (uint64 remaining = levels; remaining != 0; --remaining) {
            uint256 transfers;
            (pos, transfers) = _level(x, evidence, pos, remaining == levels);
            while (transfers != 0) {
                uint8 ending = --transfers != 0 ? 0 : remaining == 1 ? 2 : 1;
                pos = _transfer(x, evidence, pos, ending);
            }
        }
        if (pos != evidence.length) revert BadStep();
        FlatNative.flush(x.batch);
        return x.verdict;
    }

    function _level(Execution memory x, bytes calldata evidence, uint256 pos, bool root)
        private
        view
        returns (uint256 next, uint256 count)
    {
        _reserve(x.sids, 1);
        _reserve(x.claims, root ? 2 : 1);
        uint256 scratch = W.freeMemory();
        uint8 phase = root ? 1 : 2;
        (bytes calldata alloc, uint256 p) = W.stepBlob(evidence, pos, W.allocationCap(phase));
        (bytes calldata mint, uint256 q) = W.stepBlob(evidence, p, W.mintCap(phase));
        (bytes calldata proof, uint256 r) = W.stepBlob(evidence, q, W.MAX_MINT_PROOF);
        if (evidence.length - r < 8) revert BadStep();
        count = W.number(evidence, r, 8);
        if (count == 0) revert BadStep();
        next = r + 8;
        (FlatPart memory part, bytes32 sid, FlatClaim memory claim, FlatClaim memory deposit) =
            LINEAGE.mint(x.cfg, x.part, root, alloc, mint, proof);
        if (!_add(x.sids, sid, 0)) revert BadStep();
        if (root && _add(x.claims, deposit.key, deposit.value)) {
            FlatNative.append(x.batch, deposit);
        }
        if (_add(x.claims, claim.key, claim.value)) FlatNative.append(x.batch, claim);
        W.copyPart(x.part, part);
        W.releaseMemory(scratch);
    }

    function _transfer(Execution memory x, bytes calldata evidence, uint256 pos, uint8 ending)
        private
        view
        returns (uint256 next)
    {
        _reserve(x.sids, 1);
        _reserve(x.claims, 1);
        uint256 scratch = W.freeMemory();
        bytes calldata pair;
        (pair, next) = W.stepBlob(evidence, pos, W.MAX_PAIR);
        (FlatPart memory part, bytes32 sid, FlatClaim memory claim, FlatVerdict memory verdict) =
            LINEAGE.transfer(x.cfg, x.part, ending, pair);
        if (!_add(x.sids, sid, 0)) revert BadStep();
        if (_add(x.claims, claim.key, claim.value)) FlatNative.append(x.batch, claim);
        W.copyPart(x.part, part);
        // Keep the terminal verdict until the B1 batch has been verified.
        if (ending == 2) x.verdict = verdict;
        else W.releaseMemory(scratch);
    }

    /// @dev Shared Γ validation: the decoded configuration, this chain and the lineage helper.
    /// The deployment-specific identity (ordinary address and hash, profile, registry) is `_bind`.
    function _config(bytes calldata gamma) internal view returns (FlatConfig memory) {
        FlatBindings.ConfigBinding memory binding = FlatBindings.decode(gamma);
        if (binding.chainId != block.chainid || address(LINEAGE).codehash != LINEAGE_HASH) {
            revert BadBinding();
        }
        _bind(binding);
        return binding.cfg;
    }

    function _bind(FlatBindings.ConfigBinding memory binding) internal view virtual;

    function _add(Map memory map, bytes32 key, bytes32 value) private pure returns (bool) {
        if (key == 0) {
            if (map.hasZero) {
                if (map.zeroValue != value) revert BadStep();
                return false;
            }
            map.hasZero = true;
            map.zeroValue = value;
        } else {
            uint256 slot = _find(map.slots, key);
            if (map.slots[slot] != 0) {
                if (map.slots[slot + 1] != value) revert BadStep();
                return false;
            }
            map.slots[slot] = key;
            map.slots[slot + 1] = value;
        }
        ++map.count;
        return true;
    }

    function _reserve(Map memory map, uint256 incoming) private pure {
        bytes32[] memory slots = map.slots;
        if ((map.count + incoming) * 4 <= slots.length) return;
        bytes32[] memory expanded = new bytes32[](slots.length * 2);
        for (uint256 i; i < slots.length; i += 2) {
            bytes32 key = slots[i];
            if (key == 0) continue;
            uint256 j = _find(expanded, key);
            expanded[j] = key;
            expanded[j + 1] = slots[i + 1];
        }
        map.slots = expanded;
    }

    function _find(bytes32[] memory slots, bytes32 key) private pure returns (uint256 i) {
        uint256 mask = slots.length - 2;
        i = uint256(key) & mask;
        while (slots[i] != 0 && slots[i] != key) i = (i + 2) & mask;
    }
}

/// @notice Version 11 ordinary native bridge return verifier.
contract NativeBridgeVerifier11 is FlatOrdinary {
    bytes32 public immutable PROFILE_HASH;
    bytes32 public immutable REGISTRY_HASH;
    FlatReceipts public immutable RECEIPTS;
    bytes32 public immutable RECEIPTS_HASH;

    constructor(FlatLineage lineage, bytes32 lineageHash, bytes32 profileHash, bytes32 registryHash)
        FlatOrdinary(lineage, lineageHash)
    {
        if (
            profileHash == 0 || registryHash == 0 || FlatNative.REGISTRY.codehash != registryHash
                || FlatNative.REGISTRY.code.length == 0
        ) revert BadBinding();
        PROFILE_HASH = profileHash;
        REGISTRY_HASH = registryHash;
        RECEIPTS = lineage.RECEIPTS();
        RECEIPTS_HASH = lineage.RECEIPTS_HASH();
        if (address(RECEIPTS).codehash != RECEIPTS_HASH || address(RECEIPTS).code.length == 0) {
            revert BadBinding();
        }
    }

    function readConfig(bytes calldata gamma) external view returns (FlatConfig memory) {
        return _config(gamma);
    }

    function readChainId(bytes calldata gamma) external view returns (uint64) {
        _config(gamma);
        return FlatBindings.decode(gamma).chainId;
    }

    function _bind(FlatBindings.ConfigBinding memory binding) internal view override {
        if (
            binding.ordinary != address(this) || binding.ordinaryHash != address(this).codehash
                || binding.profileHash != PROFILE_HASH
                || FlatNative.REGISTRY.codehash != REGISTRY_HASH
        ) revert BadBinding();
    }
}
