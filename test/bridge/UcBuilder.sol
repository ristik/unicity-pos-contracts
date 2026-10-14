// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Cbor} from "../../src/bridge/Cbor.sol";

/// @notice Hand-built UnicityCertificates for tests: the shape CertGroups scans, `tag(39001,[1, IR, h, h, shardTree, unicityTree, seal])`
///         with a shard-tree certificate of the requested number of siblings, a unicity-tree certificate of the requested steps and a
///         seal of the requested epoch and signature count. No signature is valid and no hash is real: these are structural fixtures
///         for the Solidity scan and grouping and for the composing verifier's coverage and gate, whose native verdicts are doubles.
abstract contract UcBuilder {
    function _tag(uint256 t) internal pure returns (bytes memory) {
        return Cbor.head(6, t);
    }

    function _seal(uint256 epoch, uint256 sigs, uint8 sigSeed)
        internal
        pure
        returns (bytes memory s)
    {
        bytes memory map = Cbor.head(5, sigs);
        for (uint256 i = 0; i < sigs; ++i) {
            map = bytes.concat(
                map,
                Cbor.head(3, 1),
                abi.encodePacked(bytes1(uint8(0x41 + i))),
                Cbor.head(2, 65),
                _fill(65, sigSeed)
            );
        }
        s = bytes.concat(
            _tag(39005),
            Cbor.head(4, 8),
            Cbor.uint_(1),
            Cbor.uint_(3),
            Cbor.uint_(1000),
            Cbor.uint_(epoch),
            Cbor.uint_(1_700_000_000),
            Cbor.bstr32(bytes32(uint256(1))),
            Cbor.bstr32(bytes32(uint256(2))),
            map
        );
    }

    function _fill(uint256 n, uint8 v) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            b[i] = bytes1(v);
        }
    }

    function _ucWith(
        bytes memory shard,
        uint256 siblings,
        uint256 steps,
        bytes memory ir,
        bytes memory seal
    ) internal pure returns (bytes memory) {
        bytes memory sib = Cbor.head(4, siblings);
        for (uint256 i = 0; i < siblings; ++i) {
            sib = bytes.concat(sib, Cbor.bstr32(bytes32(i + 100)));
        }
        bytes memory st = Cbor.head(4, steps);
        for (uint256 i = 0; i < steps; ++i) {
            st = bytes.concat(st, Cbor.bstr32(bytes32(i + 200)));
        }
        return bytes.concat(
            _tag(39001),
            Cbor.head(4, 7),
            Cbor.uint_(1),
            ir,
            Cbor.bstr32(bytes32(uint256(7))),
            Cbor.bstr32(bytes32(uint256(8))),
            _tag(39003),
            Cbor.head(4, 3),
            Cbor.uint_(1),
            Cbor.bstr(shard),
            sib,
            _tag(39004),
            Cbor.head(4, 3),
            Cbor.uint_(1),
            Cbor.uint_(9),
            st,
            seal
        );
    }

    /// shard 0x80 = depth 0 (the whole tree), 0xc0 = depth 1 ('1'), 0x60 = depth 2
    function _uc(
        bytes memory shard,
        uint256 siblings,
        uint256 steps,
        uint256 epoch,
        uint256 sigs,
        uint8 seed
    ) internal pure returns (bytes memory) {
        return _ucWith(shard, siblings, steps, Cbor.uint_(5), _seal(epoch, sigs, seed));
    }
}
