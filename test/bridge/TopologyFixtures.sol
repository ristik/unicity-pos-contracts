// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {BridgeBase} from "./BridgeBase.sol";
import {UcBuilder} from "./UcBuilder.sol";
import {CertGroups} from "../../src/bridge/CertGroups.sol";
import {Anchor} from "../../src/bridge/BridgeTypes.sol";

/// @notice Shard identifiers, state IDs inside a shard and structural anchors for the topology tests, shared by the composing-verifier
///         tests and the vault integration tests.
abstract contract TopologyFixtures is BridgeBase, UcBuilder {
    /// @dev The native shard id of the k-th shard of depth d: the d bits of k, the terminator bit 1, zero padding.
    function _shardId(uint256 d, uint256 k) internal pure returns (bytes memory out) {
        uint256 nbits = d + 1;
        uint256 nbytes = (nbits + 7) / 8;
        uint256 bitsv = ((k << 1) | 1) << (8 * nbytes - nbits);
        out = new bytes(nbytes);
        for (uint256 i = 0; i < nbytes; ++i) {
            out[nbytes - 1 - i] = bytes1(uint8(bitsv >> (8 * i)));
        }
    }

    /// @dev A state ID whose first d bits are the shard's prefix and whose other bits come from `salt`.
    function _sidIn(bytes memory shard, uint256 salt) internal pure returns (bytes32 sid) {
        uint256 d = CertGroups.shardDepth(shard);
        sid = keccak256(abi.encode("sid", salt));
        uint256 whole = d / 8;
        bytes memory raw = abi.encodePacked(sid);
        for (uint256 i = 0; i < whole; ++i) {
            raw[i] = shard[i];
        }
        if (d % 8 != 0) {
            uint8 keep = uint8(0xff << (8 - (d % 8)));
            raw[whole] = bytes1((uint8(raw[whole]) & ~keep) | (uint8(shard[whole]) & keep));
        }
        sid = bytes32(raw);
    }

    /// @dev A structurally valid, distinct synthetic UC in the shard (its shard certificate carries exactly the derived depth of siblings)
    ///      with a given IR in its input-record slot and `sigs` signatures; the native verdicts about it are the batch double's.
    function _synthUc(
        bytes memory shard,
        uint256 epoch,
        uint256 sigs,
        uint8 seed,
        bytes memory irSlot
    ) internal pure returns (bytes memory) {
        return _ucWith(shard, CertGroups.shardDepth(shard), 2, irSlot, _seal(epoch, sigs, seed));
    }

    function _synthAnchor(bytes memory shard, uint256 i, uint256 sigs, bytes memory irSlot)
        internal
        pure
        returns (Anchor memory a)
    {
        a = Anchor({
            partition: 11,
            shard: shard,
            shardConfHash: keccak256(abi.encode("conf", shard)),
            expectedStateRoot: STATE,
            expectedIRHash: sha256(_ok()),
            uc: _synthUc(shard, 10 + i, sigs, uint8(i + 1), irSlot),
            inputRecord: _ok()
        });
    }
}
