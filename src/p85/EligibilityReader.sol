// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the V ceiling (at most 128 identities) and L ceiling (at most 8 lots per generation).
// forge-lint: disable-start(calls-loop)

import {Position} from "./P85Types.sol";
import {Continuity} from "./Continuity.sol";
import {IStakeCustody, IEvidence} from "./IP85.sol";

/// @title EligibilityReader
/// @notice The stateless custody/evidence reading half of the election snapshot, split from ElectionPolicy to keep that contract under the
/// size limit. It holds no state and no authority: it answers views over custody and evidence, and ElectionPolicy supplies from its own
/// storage the delegated bindings these views cannot see. Its two sources are immutable and pinned by the manifest (ElectionPolicy
/// refuses a reader wired to other modules).
contract EligibilityReader {
    error CustodyRead();

    IStakeCustody public immutable CUSTODY;
    IEvidence public immutable EVIDENCE;

    /// @dev An identity that may still be a primary candidate by position: it exists, has no retirement request and is not excluded.
    struct Pos {
        uint64 id;
        uint64 generation;
        bytes32 rootKeyHash;
        bytes32 stagedRootKeyHash;
    }

    /// @dev A delegation ElectionPolicy accepted for the identity's open generation: the EVM key whose registration custody must confirm.
    struct Delegated {
        uint64 id;
        uint64 generation;
        bytes32 rootKeyHash;
        bytes32 evmKeyHash;
        bytes32 bindingHash;
    }

    /// @dev A fully eligible identity: assigned weight and the unreleased lots of its open generation, ascending.
    struct Weighted {
        uint64 id;
        uint64 weight;
        bytes32 binding; // the signing binding the continuity rule compares
        uint256[] lots;
    }

    bytes32 internal constant SIGNING_DOMAIN = keccak256("unicity.p85.signing-binding");
    bytes32 internal constant CONTRACTS_DOMAIN = keccak256("unicity.p85.contracts");

    constructor(address custody, address evidence) {
        CUSTODY = IStakeCustody(custody);
        EVIDENCE = IEvidence(evidence);
    }

    /// @notice The given identities that pass the position checks, ascending by identity.
    function positions(uint64[] memory ids) external view returns (Pos[] memory out) {
        uint256 n = ids.length;
        for (uint256 i = 1; i < n; ++i) {
            uint64 id = ids[i];
            uint256 j = i;
            while (j > 0 && ids[j - 1] > id) {
                ids[j] = ids[j - 1];
                --j;
            }
            ids[j] = id;
        }
        Pos[] memory tmp = new Pos[](n);
        uint256 count = 0;
        for (uint256 i = 0; i < n; ++i) {
            (bool read, bytes memory ret) =
                address(CUSTODY).staticcall(abi.encodeCall(IStakeCustody.positions, (ids[i])));
            if (!read) revert CustodyRead();
            Position memory pos = abi.decode(ret, (Position));
            if (pos.owner == address(0) || pos.retirementRequested || EVIDENCE.excluded(ids[i])) {
                continue;
            }
            tmp[count++] = Pos(ids[i], pos.generation, pos.rootKeyHash, pos.stagedRootKeyHash);
        }
        out = new Pos[](count);
        for (uint256 i = 0; i < count; ++i) {
            out[i] = tmp[i];
        }
    }

    /// @notice Of the delegated identities (ascending), those whose EVM key custody registered to them and whose open-generation
    /// principal is at least B_min with a positive assigned weight, and the snapshot digest folded over them from `seed`.
    function weights(Delegated[] memory d, bytes32 seed)
        external
        view
        returns (Weighted[] memory out, bytes32 digest)
    {
        uint128 unit = CUSTODY.bondUnit();
        uint128 floor_ = CUSTODY.minBond();
        Weighted[] memory tmp = new Weighted[](d.length);
        uint256 count = 0;
        for (uint256 i = 0; i < d.length; ++i) {
            (uint64 keyID, uint8 role) = CUSTODY.keyOwner(d[i].evmKeyHash);
            if (keyID != d[i].id || role != 2) continue;
            (uint256[] memory lots, uint256 principal) = _openLots(d[i].id, d[i].generation);
            if (principal < floor_) continue;
            uint256 w = principal / unit;
            if (w == 0 || w > type(uint64).max) continue;
            bytes32 binding =
                keccak256(abi.encode(SIGNING_DOMAIN, d[i].rootKeyHash, d[i].evmKeyHash));
            digest = keccak256(
                abi.encode(
                    digest == bytes32(0) ? seed : digest,
                    d[i].id,
                    d[i].generation,
                    d[i].bindingHash,
                    w,
                    keccak256(abi.encodePacked(lots))
                )
            );
            // forge-lint: disable-next-line(unsafe-typecast)
            tmp[count++] = Weighted(d[i].id, uint64(w), binding, lots); // checked above
        }
        if (count == 0) digest = seed;
        out = new Weighted[](count);
        for (uint256 i = 0; i < count; ++i) {
            out[i] = tmp[i];
        }
    }

    /// @notice The last committed committee: the exposures of an assignment (ascending by StakingID) as continuity members.
    function committed(bytes32 assignmentID) external view returns (Continuity.Member[] memory o) {
        bytes32[] memory ids = CUSTODY.assignmentExposures(assignmentID);
        o = new Continuity.Member[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            (bool ok, bytes memory ret) =
                address(CUSTODY).staticcall(abi.encodeCall(IStakeCustody.exposures, (ids[i])));
            if (!ok) revert CustodyRead();
            // (assignmentID, id, generation, rootKeyHash, evmKeyHash, weight, ...)
            (, uint64 id,, bytes32 rootKeyHash, bytes32 evmKeyHash, uint64 weight) =
                abi.decode(ret, (bytes32, uint64, uint64, bytes32, bytes32, uint64));
            o[i] = Continuity.Member(
                id, keccak256(abi.encode(SIGNING_DOMAIN, rootKeyHash, evmKeyHash)), weight
            );
        }
    }

    /// @notice custody's assignment head: its lineage and epochs.
    function head(bytes32 assignmentID)
        external
        view
        returns (bytes32 lineage, uint64 rootEpoch, uint64 evmEpoch)
    {
        (, lineage, rootEpoch, evmEpoch,,,,,,,,,,,,) = _assignment(assignmentID);
    }

    /// @notice custody's assignment state and the digests it committed over its exposures and keys.
    function digests(bytes32 assignmentID)
        external
        view
        returns (uint8 state, bytes32 exposureDigest, bytes32 keyDigest)
    {
        (state,,,,,,,,,,,,, exposureDigest, keyDigest,) = _assignment(assignmentID);
    }

    function _assignment(bytes32 assignmentID)
        private
        view
        returns (
            uint8,
            bytes32,
            uint64,
            uint64,
            uint64,
            uint64,
            bool,
            bool,
            uint64,
            bool,
            uint64,
            uint64,
            bytes32,
            bytes32,
            bytes32,
            uint32
        )
    {
        (bool ok, bytes memory ret) = address(CUSTODY)
            .staticcall(abi.encodeCall(IStakeCustody.assignments, (assignmentID)));
        if (!ok) revert CustodyRead();
        return abi.decode(
            ret,
            (
                uint8,
                bytes32,
                uint64,
                uint64,
                uint64,
                uint64,
                bool,
                bool,
                uint64,
                bool,
                uint64,
                uint64,
                bytes32,
                bytes32,
                bytes32,
                uint32
            )
        );
    }

    /// @notice The EVM key hash of an exposure.
    function evmKeyHashOf(bytes32 exposureID) external view returns (bytes32 evmKeyHash) {
        (bool ok, bytes memory ret) =
            address(CUSTODY).staticcall(abi.encodeCall(IStakeCustody.exposures, (exposureID)));
        if (!ok) revert CustodyRead();
        (,,,, evmKeyHash) = abi.decode(ret, (bytes32, uint64, uint64, bytes32, bytes32));
    }

    /// @notice The state of a custody session.
    function sessionState(bytes32 resultID) external view returns (uint8 state) {
        (bool ok, bytes memory ret) =
            address(CUSTODY).staticcall(abi.encodeWithSignature("session(bytes32)", resultID));
        if (!ok) revert CustodyRead();
        (state,,,,) = abi.decode(ret, (uint8, bytes32, bytes32, uint64, bytes32));
    }

    /// @notice K's inputs: the incumbent assignment's custody digests, the digest of the policy terms it captured and the digest of the
    /// deployed modules (addresses and code hashes) the recovery authorization is made under.
    function kInputs(
        bytes32 incumbent,
        address election,
        address selection,
        address policySource,
        address roots
    )
        external
        view
        returns (
            bytes32 exposureDigest,
            bytes32 keyDigest,
            bytes32 policyDigest,
            bytes32 contractsDigest
        )
    {
        (,,,,,,,,,,,,, exposureDigest, keyDigest,) = _assignment(incumbent);
        policyDigest = keccak256(abi.encode(CUSTODY.policyTerms(incumbent)));
        contractsDigest = keccak256(
            abi.encode(
                CONTRACTS_DOMAIN,
                block.chainid,
                address(CUSTODY),
                address(CUSTODY).codehash,
                election,
                election.codehash,
                address(EVIDENCE),
                address(EVIDENCE).codehash,
                selection,
                selection.codehash,
                policySource,
                policySource.codehash,
                roots
            )
        );
    }

    /// @notice Whether a frozen member is still a valid primary at finalization: same open generation, no retirement request, not
    /// excluded, and the unreleased lots of its exposure still carry its committed weight.
    function covered(uint64 id, uint64 generation, uint64 weight, bytes32 exposureID)
        external
        view
        returns (bool)
    {
        return _covered(id, generation, weight, exposureID, true);
    }

    /// @notice Whether a member of a reserved result has kept its coverage since the snapshot, the predicate of a coverage LOSS: the same
    /// as `covered` without the retirement request. A retirement requested after the snapshot is not a loss (the exposure lots stay
    /// encumbered until their references close, so the committed weight is still backed), and the proven `lost` word must not depend
    /// on whether a third party called `reconcileCandidate`.
    function stillCovered(uint64 id, uint64 generation, uint64 weight, bytes32 exposureID)
        external
        view
        returns (bool)
    {
        return _covered(id, generation, weight, exposureID, false);
    }

    function _covered(
        uint64 id,
        uint64 generation,
        uint64 weight,
        bytes32 exposureID,
        bool retirementCounts
    ) private view returns (bool) {
        (bool read, bytes memory ret) = address(CUSTODY)
            .staticcall(abi.encodeCall(IStakeCustody.positions, (id)));
        if (!read) revert CustodyRead();
        Position memory pos = abi.decode(ret, (Position));
        if (
            pos.owner == address(0) || (retirementCounts && pos.retirementRequested)
                || pos.generation != generation || EVIDENCE.excluded(id)
        ) return false;
        uint256[] memory lots = CUSTODY.exposureLots(exposureID);
        uint256 backing = 0;
        for (uint256 j = 0; j < lots.length; ++j) {
            (uint256 remaining, uint256 category) = _lotWords(lots[j]);
            if (category == 4) return false;
            backing += remaining;
        }
        return backing >= uint256(weight) * CUSTODY.bondUnit();
    }

    /// @dev Only the first six words of the lot getter are read: (id, generation, initial, remaining, penalized, category).
    function _lotWords(uint256 lotID) private view returns (uint256 remaining, uint256 category) {
        address c = address(CUSTODY);
        bytes4 selector = IStakeCustody.lots.selector;
        bool ok;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, selector)
            mstore(add(ptr, 4), lotID)
            ok := staticcall(gas(), c, ptr, 0x24, ptr, 0xc0)
            ok := and(ok, iszero(lt(returndatasize(), 0xc0)))
            remaining := and(mload(add(ptr, 0x60)), 0xffffffffffffffffffffffffffffffff)
            category := and(mload(add(ptr, 0xa0)), 0xff)
        }
        if (!ok) revert CustodyRead();
    }

    /// @dev Every unreleased lot of the open generation, ascending, and their remaining principal.
    function _openLots(uint64 id, uint64 generation)
        private
        view
        returns (uint256[] memory lots, uint256 principal)
    {
        uint256[] memory all = CUSTODY.generationLots(id, generation);
        uint256[] memory keep = new uint256[](all.length);
        uint256 count = 0;
        for (uint256 i = 0; i < all.length; ++i) {
            (uint256 remaining, uint256 category) = _lotWords(all[i]);
            if (category == 4) continue; // released
            keep[count++] = all[i];
            principal += remaining;
        }
        lots = new uint256[](count);
        for (uint256 i = 0; i < count; ++i) {
            lots[i] = keep[i];
        }
    }
}

// forge-lint: disable-end(calls-loop)
