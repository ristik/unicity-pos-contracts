// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";

/// @notice Reads many keys of one large JSON document without re-encoding it on every cheatcode call. `vm.parseJson*(json, key)`
/// ABI-encodes the whole document into fresh memory each time, so a few hundred reads of the 388 KB state-machine vectors grow memory
/// quadratically and exhaust the test gas limit. Here the document is encoded once into a call buffer (selector, the two offsets,
/// the document, then a key slot); each read writes only its selector and key and STATICCALLs the cheatcode address with that buffer.
/// The buffer lives in the memory of the current external call: call `_jload` at the start of every test function.
abstract contract FastJson {
    address private constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    uint256 private constant KEY_ROOM = 1024;

    uint256 internal jptr; // buffer start (the selector goes here)
    uint256 internal jkeyOff; // offset of the key, relative to after the selector

    function _jload(string memory path) internal {
        string memory doc = Vm(VM_ADDRESS).readFile(path);
        uint256 len = bytes(doc).length;
        uint256 padded = (len + 31) / 32 * 32;
        uint256 keyOff = 0x40 + 0x20 + padded;
        uint256 total = 4 + keyOff + 0x20 + KEY_ROOM;
        uint256 ptr;
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, add(total, 32)))
            mstore(add(ptr, 4), 0x40)
            mstore(add(ptr, 36), keyOff)
            mstore(add(ptr, 68), len)
            let src := add(doc, 0x20)
            let dst := add(ptr, 100)
            for { let i := 0 } lt(i, padded) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
        jptr = ptr;
        jkeyOff = keyOff;
    }

    function _jcall(bytes4 sel, string memory key)
        internal
        view
        returns (bool ok, bytes memory ret)
    {
        uint256 ptr = jptr;
        uint256 keyOff = jkeyOff;
        uint256 kl = bytes(key).length;
        require(kl <= KEY_ROOM, "json key too long");
        uint256 size = 4 + keyOff + 0x20 + (kl + 31) / 32 * 32;
        address vmAddr = VM_ADDRESS;
        assembly ("memory-safe") {
            mstore(ptr, sel)
            mstore(add(ptr, 4), 0x40)
            mstore(add(ptr, 36), keyOff)
            let k := add(ptr, add(4, keyOff))
            mstore(k, kl)
            for { let i := 0 } lt(i, kl) { i := add(i, 32) } {
                mstore(add(add(k, 32), i), mload(add(add(key, 32), i)))
            }
            ok := staticcall(gas(), vmAddr, ptr, size, 0, 0)
            ret := mload(0x40)
            mstore(ret, returndatasize())
            returndatacopy(add(ret, 32), 0, returndatasize())
            mstore(0x40, add(add(ret, 32), and(add(returndatasize(), 31), not(31))))
        }
    }

    function _jget(bytes4 sel, string memory key) internal view returns (bytes memory ret) {
        bool ok;
        (ok, ret) = _jcall(sel, key);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function _js(string memory key) internal view returns (string memory) {
        return abi.decode(_jget(bytes4(keccak256("parseJsonString(string,string)")), key), (string));
    }

    function _ju(string memory key) internal view returns (uint256) {
        return abi.decode(_jget(bytes4(keccak256("parseJsonUint(string,string)")), key), (uint256));
    }

    function _jbool(string memory key) internal view returns (bool) {
        return abi.decode(_jget(bytes4(keccak256("parseJsonBool(string,string)")), key), (bool));
    }

    function _jhas(string memory key) internal view returns (bool) {
        return abi.decode(_jget(bytes4(keccak256("keyExistsJson(string,string)")), key), (bool));
    }

    function _juarr(string memory key) internal view returns (uint256[] memory) {
        return
            abi.decode(
                _jget(bytes4(keccak256("parseJsonUintArray(string,string)")), key), (uint256[])
            );
    }

    function _jkeys(string memory key) internal view returns (string[] memory) {
        return abi.decode(_jget(bytes4(keccak256("parseJsonKeys(string,string)")), key), (string[]));
    }

    /// @dev A wildcard path or an array of strings, through `parseJson` (one ABI-encoded value).
    function _jsarr(string memory key) internal view returns (string[] memory) {
        bytes memory raw =
            abi.decode(_jget(bytes4(keccak256("parseJson(string,string)")), key), (bytes));
        return abi.decode(raw, (string[]));
    }

    /// @dev A string array that may be JSON null: ok is false for null or a missing key.
    function _jsarrTry(string memory key) internal view returns (bool, string[] memory out) {
        (bool ok, bytes memory ret) =
            _jcall(bytes4(keccak256("parseJsonStringArray(string,string)")), key);
        if (!ok) return (false, out);
        return (true, abi.decode(ret, (string[])));
    }

    /// @dev A uint array that may be JSON null.
    function _juarrTry(string memory key) internal view returns (bool, uint256[] memory out) {
        (bool ok, bytes memory ret) =
            _jcall(bytes4(keccak256("parseJsonUintArray(string,string)")), key);
        if (!ok) return (false, out);
        return (true, abi.decode(ret, (uint256[])));
    }
}
