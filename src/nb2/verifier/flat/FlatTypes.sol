// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

// Fixed byte casts select the wire prefix before conversion to the corresponding integer width.
// forge-lint: disable-start(unsafe-typecast)

struct FlatConfig {
    bytes32 domain;
    uint16 network;
    uint32 evmPartition;
    uint32 aggPartition;
    bytes evmShard;
    address vault;
    bytes32 tokenType;
    bytes32 coin;
}

struct FlatOwner {
    bytes32 prefix;
    bytes1 tail;
}

struct FlatPart {
    FlatOwner owner;
    bytes32 state;
    bytes32 tokenID;
    uint256 amount;
    bytes32 parentLink;
    bytes32 parentManifest;
}

struct FlatVerdict {
    bytes32 domain;
    bytes32 eta;
    uint64 minSegment;
    bytes32 asset;
    address recipient;
    uint256 amount;
}

struct FlatClaim {
    bytes32 key;
    bytes32 value;
    bytes packed;
}

error BadPacket();
error BadPredecessor();
error BadPage();
error BadStep();
error BadGapProof(uint256 index);
error BadBinding();

library FlatHash {
    bytes32 internal constant ASSET = sha256("unicity-nb2-asset:native-uct");
    bytes32 internal constant STATE = keccak256("UNICITY/NB2/CONT/1.1/STATE");
    bytes32 internal constant PAGE = keccak256("UNICITY/NB2/CONT/1.1/PAGE");
    bytes32 internal constant PAGE_NODE = keccak256("UNICITY/NB2/CONT/1.1/PAGE_NODE");
    bytes32 internal constant PAD = keccak256("UNICITY/NB2/CONT/1.1/PAD");
    bytes32 internal constant SID = keccak256("UNICITY/NB2/CONT/1.1/SID");
    bytes32 internal constant SID_NODE = keccak256("UNICITY/NB2/CONT/1.1/SID_NODE");
    bytes32 internal constant CLAIM = keccak256("UNICITY/NB2/CONT/1.1/CLAIM");
    bytes32 internal constant CLAIM_NODE = keccak256("UNICITY/NB2/CONT/1.1/CLAIM_NODE");
    bytes32 internal constant CLAIM_KEY = keccak256("UNICITY/NB2/CONT/1.1/CLAIM_KEY");
    bytes32 internal constant CLAIM_VALUE = keccak256("UNICITY/NB2/CONT/1.1/CLAIM_VALUE");

    function node(bytes32 label, bytes32 left, bytes32 right) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let scratch := mload(0x40)
            mstore(scratch, label)
            mstore(add(scratch, 32), left)
            mstore(add(scratch, 64), right)
            h := keccak256(scratch, 96)
        }
    }
}

library FlatWire {
    uint16 internal constant VERSION = 0x0101;
    uint256 internal constant MAX_RECEIPT = 65536;
    uint256 internal constant MAX_MINT_PROOF = 40960 - 8;
    uint256 internal constant MAX_PAIR = 40960;

    function offset(bytes calldata b) internal pure returns (uint256 p) {
        assembly ("memory-safe") { p := b.offset }
    }

    // A caller establishes that [p, p+width) is inside the decoding unit.
    function number(bytes calldata b, uint256 p, uint256 width) internal pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(sub(256, mul(8, width)), calldataload(add(b.offset, p)))
        }
    }

    function word(bytes calldata b, uint256 p) internal pure returns (bytes32 v) {
        assembly ("memory-safe") { v := calldataload(add(b.offset, p)) }
    }

    function slice(uint256 p, uint256 length) internal pure returns (bytes calldata b) {
        assembly ("memory-safe") {
            b.offset := p
            b.length := length
        }
    }

    function mword(bytes memory b, uint256 p) internal pure returns (bytes32 v) {
        assembly ("memory-safe") { v := mload(add(add(b, 32), p)) }
    }

    function popcount(uint256 bits) internal pure returns (uint256 n) {
        while (bits != 0) {
            bits &= bits - 1;
            ++n;
        }
    }

    function allocationCap(uint8 phase) internal pure returns (uint256) {
        return phase == 1 ? 0 : 20480;
    }

    function mintCap(uint8 phase) internal pure returns (uint256) {
        return phase == 1 ? 66048 : 512;
    }

    function stepBlob(bytes calldata b, uint256 p, uint256 cap)
        internal
        pure
        returns (bytes calldata item, uint256 next)
    {
        if (p > b.length || b.length - p < 4) revert BadStep();
        uint256 n = number(b, p, 4);
        p += 4;
        if (n > cap || n > b.length - p) revert BadStep();
        next = p + n;
        item = b[p:next];
    }

    function freeMemory() internal pure returns (uint256 p) {
        assembly ("memory-safe") { p := mload(0x40) }
    }

    // Retain only data allocated before p. Clear reused words for ABI encoders
    // and decoders that expect fresh zeroed memory.
    function releaseMemory(uint256 p) internal pure {
        assembly ("memory-safe") {
            calldatacopy(p, calldatasize(), sub(mload(0x40), p))
            mstore(0x40, p)
        }
    }

    function copyPart(FlatPart memory out, FlatPart memory value) internal pure {
        out.owner.prefix = value.owner.prefix;
        out.owner.tail = value.owner.tail;
        out.state = value.state;
        out.tokenID = value.tokenID;
        out.amount = value.amount;
        out.parentLink = value.parentLink;
        out.parentManifest = value.parentManifest;
    }

    function prelude(bytes calldata b) internal pure returns (uint64 levels) {
        if (b.length < 14 || bytes6(word(b, 0)) != hex"4e42324c0101") revert BadStep();
        levels = uint64(number(b, 6, 8));
        if (levels == 0) revert BadStep();
    }
}
