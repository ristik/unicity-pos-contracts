// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {NB2Config} from "../NB2Config.sol";

/// @dev ERC20 Γ extends the canonical v1.1 array with three generation fields.
library ERC20Config {
    struct Chain {
        uint16 network;
        bytes32 rootGenesis;
        bytes32 executionGenesis;
        uint32 evmPartition;
        bytes evmShard;
        uint32 aggPartition;
        uint144 qmax;
    }

    struct Config {
        NB2Config.Config base;
        address token;
        bytes32 generation;
        bytes32 pins;
    }

    function identities(uint64 chainId, address token, bytes32 executionGenesis)
        internal
        pure
        returns (bytes32 asset, bytes32 coin, bytes32 tokenType)
    {
        bytes memory x = abi.encodePacked(chainId, token, executionGenesis);
        asset = sha256(bytes.concat("UNICITY/NB2/ERC20/ASSET/1/", x));
        coin = sha256(bytes.concat("UNICITY/NB2/ERC20/COIN/1/", x));
        tokenType = sha256(bytes.concat("UNICITY/NB2/ERC20/TYPE/1/", x));
    }

    function decode(bytes memory gamma) internal pure returns (Config memory c) {
        // bstr20, bstr32, bstr32. The preceding fields use the native canonical decoder.
        if (gamma.length <= 89 || gamma.length > 480 || gamma[0] != 0x96) {
            revert NB2Config.BadConfig(22);
        }
        uint256 end = gamma.length - 89;
        if (gamma[end] != 0x54) revert NB2Config.BadConfig(19);
        if (gamma[end + 21] != 0x58 || gamma[end + 22] != 0x20) revert NB2Config.BadConfig(20);
        if (gamma[end + 55] != 0x58 || gamma[end + 56] != 0x20) revert NB2Config.BadConfig(21);
        bytes memory base = new bytes(end);
        address token;
        bytes32 generation;
        bytes32 pins;
        assembly ("memory-safe") {
            let source := add(gamma, 32)
            let tail := add(source, end)
            token := shr(96, mload(add(tail, 1)))
            generation := mload(add(tail, 23))
            pins := mload(add(tail, 57))
            mcopy(add(base, 32), source, end)
        }
        base[0] = 0x93;
        c = Config(NB2Config.decode(base, 1 << 64, 1 << 16, 3), token, generation, pins);
        if (token == address(0)) revert NB2Config.BadConfig(19);
        if (generation == 0) revert NB2Config.BadConfig(20);
        if (pins == 0) revert NB2Config.BadConfig(21);
    }

    function checkEnvironment(Config memory c, address self) internal view {
        NB2Config.Config memory b = c.base;
        // The native decoder bounds the chain ID to uint64.
        // forge-lint: disable-next-line(unsafe-typecast)
        (bytes32 asset, bytes32 coin, bytes32 tokenType) =
            identities(uint64(b.chainId), c.token, b.executionGenesis);
        if (b.asset != asset) revert NB2Config.BadConfig(10);
        if (b.ty != tokenType) revert NB2Config.BadConfig(11);
        if (b.aid != coin) revert NB2Config.BadConfig(12);
        if (b.vault != self) revert NB2Config.BadConfig(9);
        if (b.chainId != block.chainid) revert NB2Config.BadConfig(5);
        if (b.verifier.codehash != b.verifierCodeHash) revert NB2Config.BadConfig(15);
    }

    function prefix(Chain memory chain, uint64 chainId) internal pure returns (bytes memory) {
        if (
            chain.network == 0 || chain.rootGenesis == 0 || chain.executionGenesis == 0
                || chain.evmPartition == 0 || chain.aggPartition == 0
                || chain.aggPartition == chain.evmPartition || chain.qmax == 0
                || chain.evmShard.length == 0 || chain.evmShard.length > 33 || chainId == 0
        ) revert NB2Config.BadConfig(22);
        return abi.encodePacked(
            hex"964f",
            "UNICITY_NB2_CFG",
            hex"03",
            uintItem(chain.network),
            hex"5820",
            chain.rootGenesis,
            hex"5820",
            chain.executionGenesis,
            uintItem(chainId),
            uintItem(chain.evmPartition),
            bytesHead(chain.evmShard.length),
            chain.evmShard,
            uintItem(chain.aggPartition)
        );
    }

    function suffix(bytes32 profile, address ordinary, bytes32 runtimeHash, uint144 qmax)
        internal
        pure
        returns (bytes memory)
    {
        uint256 width = 1;
        for (uint256 n = qmax; n > 255; n >>= 8) {
            ++width;
        }
        bytes memory amount = abi.encodePacked(qmax);
        bytes memory head = bytesHead(width);
        bytes memory boundedAmount = new bytes(width);
        assembly ("memory-safe") {
            mcopy(add(boundedAmount, 32), add(amount, sub(50, width)), width)
        }
        return abi.encodePacked(
            hex"5820",
            profile,
            hex"54",
            ordinary,
            hex"5820",
            runtimeHash,
            hex"184010",
            head,
            boundedAmount
        );
    }

    // Each narrowed value is bounded by the preceding condition or its uint64 input.
    // forge-lint: disable-start(unsafe-typecast)
    function uintItem(uint64 n) private pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(uint8(n));
        if (n <= type(uint8).max) return abi.encodePacked(uint8(24), uint8(n));
        if (n <= type(uint16).max) return abi.encodePacked(uint8(25), uint16(n));
        if (n <= type(uint32).max) return abi.encodePacked(uint8(26), uint32(n));
        return abi.encodePacked(uint8(27), n);
    }

    function bytesHead(uint256 n) private pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(uint8(0x40 + n));
        return abi.encodePacked(uint8(0x58), uint8(n));
    }
    // forge-lint: disable-end(unsafe-typecast)
}
