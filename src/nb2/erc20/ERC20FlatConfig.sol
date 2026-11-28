// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @dev ERC20 lineage inputs. The root receipt and terminal burn use the last two fields.
struct ERC20FlatConfig {
    bytes32 domain;
    uint16 network;
    uint32 evmPartition;
    uint32 aggPartition;
    bytes evmShard;
    address vault;
    bytes32 tokenType;
    bytes32 coin;
    address token;
    bytes32 asset;
}
