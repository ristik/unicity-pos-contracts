// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";
import {FlatHash, FlatVerdict} from "../../../src/nb2/verifier/flat/FlatTypes.sol";
import {FlatHarness} from "./FlatHarness.sol";

/// @notice Replays the oracle's verdicts and refusal stages for deterministic mutations of the
/// published evidence and packets (tools/nb2-flat-differential). Every line must agree exactly.
contract FlatDifferentialTest is FlatHarness {
    string private constant LINES = "test/nb2/flat/differential/";

    // Each line runs in its own call frame so that test memory stays bounded.
    string private loadedTrust;

    function testOrdinaryEvidenceMutations() external {
        vm.pauseGasMetering(); // 1440 whole-lineage calls exceed one test's gas budget
        string memory file = string.concat(LINES, "ordinary.txt");
        uint256 accepted;
        uint256 count;
        for (
            string memory line = vm.readLine(file);
            bytes(line).length != 0;
            line = vm.readLine(file)
        ) {
            if (this.ordinaryLine(line)) ++accepted;
            ++count;
        }
        assertEq(count, 1440);
        assertEq(accepted, 1);
        vm.closeFile(file);
    }

    function ordinaryLine(string calldata line) external returns (bool accepted) {
        string[] memory f = vm.split(line, " ");
        _trust(f[1]);
        bytes memory evidence = vm.readFileBinary(string.concat(_path(f[1]), "evidence.bin"));
        {
            bytes memory input = _mutate(evidence, f[2], f[3], f[4]);
            bool ok;
            bytes memory out;
            try ordinary.verifyReturn(gamma, input) returns (FlatVerdict memory v) {
                ok = true;
                out = abi.encode(v);
            } catch {}

            string memory want = f[5];
            if (_startsWith(want, "ok:")) {
                assertTrue(ok, line);
                assertEq(vm.toString(out), string.concat("0x", _tail(want, 3)), line);
                accepted = true;
            } else {
                assertFalse(ok, line);
            }
        }
    }

    function _trust(string memory name) private {
        if (keccak256(bytes(name)) == keccak256(bytes(loadedTrust))) return;
        loadedTrust = name;
        _loadTrust(_path(name));
    }

    function testRunPacketMutations() external {
        vm.pauseGasMetering();
        string memory file = string.concat(LINES, "run.txt");
        uint256 count;
        for (
            string memory line = vm.readLine(file);
            bytes(line).length != 0;
            line = vm.readLine(file)
        ) {
            this.runLine(line);
            ++count;
        }
        assertEq(count, 576);
        vm.closeFile(file);
    }

    function runLine(string calldata line) external {
        string[] memory f = vm.split(line, " ");
        _trust(f[1]);
        bytes memory trace = vm.readFileBinary(string.concat(_path(f[1]), "trace.bin"));
        bytes memory base = _record(trace, vm.parseUint(f[2]));
        _compare(RECOVERY, _mutate(base, f[3], f[4], f[5]), f[6], line);
    }

    function testAdvanceGapsMutations() external {
        vm.pauseGasMetering();
        string memory file = string.concat(LINES, "advance.txt");
        uint256 count;
        for (
            string memory line = vm.readLine(file);
            bytes(line).length != 0;
            line = vm.readLine(file)
        ) {
            this.advanceLine(line);
            ++count;
        }
        assertEq(count, 320);
        vm.closeFile(file);
    }

    function advanceLine(string calldata line) external {
        string[] memory f = vm.split(line, " ");
        _trust("root");
        bytes memory base =
            vm.readFileBinary(string.concat(_path(string.concat("cold/", f[1])), "calldata.bin"));
        _compare(RECOVERY, _mutate(base, f[2], f[3], f[4]), f[5], line);
    }

    // Start packets over mutated evidence. The page tree is rebuilt here from the bytes alone, so a
    // mutation always reaches the operation logic instead of failing page authentication.
    function testStartOverMutatedEvidence() external {
        vm.pauseGasMetering();
        string memory file = string.concat(LINES, "start.txt");
        uint256 count;
        for (
            string memory line = vm.readLine(file);
            bytes(line).length != 0;
            line = vm.readLine(file)
        ) {
            this.startLine(line);
            ++count;
        }
        assertEq(count, 2093);
        vm.closeFile(file);
    }

    function startLine(string calldata line) external {
        string[] memory f = vm.split(line, " ");
        _trust(f[1]);
        bytes memory evidence = vm.readFileBinary(string.concat(_path(f[1]), "evidence.bin"));
        uint256 end = 14;
        for (uint256 i; i < 3; ++i) {
            end += 4 + uint32(bytes4(_word(evidence, end)));
        }
        end += 8;
        bytes memory input = _startPacket(
            _mutate(evidence, f[3], f[4], f[5]),
            (end - 1) / 4096 + 1,
            vm.parseBytes(string.concat("0x", f[2]))
        );
        _compare(RECOVERY, input, f[6], line);
    }

    function _startPacket(bytes memory evidence, uint256 templatePages, bytes memory operation)
        private
        pure
        returns (bytes memory)
    {
        uint256 n = evidence.length;
        uint256 pages = (n - 1) / 4096 + 1;
        uint256 depth;
        for (uint256 v = pages - 1; v != 0; v >>= 1) {
            ++depth;
        }
        bytes32[][] memory tree = new bytes32[][](depth + 1);
        tree[0] = new bytes32[](1 << depth);
        for (uint256 i; i < tree[0].length; ++i) {
            if (i >= pages) {
                tree[0][i] = keccak256(abi.encode(FlatHash.PAD));
                continue;
            }
            tree[0][i] = keccak256(
                abi.encodePacked(
                    FlatHash.PAGE,
                    uint64(n),
                    uint64(i),
                    uint16(_pageLen(n, i)),
                    _slice(evidence, i * 4096, _pageLen(n, i))
                )
            );
        }
        for (uint256 h; h < depth; ++h) {
            tree[h + 1] = new bytes32[](tree[h].length / 2);
            for (uint256 i; i < tree[h + 1].length; ++i) {
                tree[h + 1][i] = keccak256(
                    abi.encodePacked(FlatHash.PAGE_NODE, tree[h][2 * i], tree[h][2 * i + 1])
                );
            }
        }
        uint256 used = templatePages < pages ? templatePages : pages;
        bytes memory body =
            abi.encodePacked(uint16(0x0101), uint64(n), tree[depth][0], uint8(0), uint8(used));
        for (uint256 i; i < used; ++i) {
            body = bytes.concat(
                body, abi.encodePacked(uint64(i), _slice(evidence, i * 4096, _pageLen(n, i)))
            );
            uint256 index = i;
            for (uint256 h; h < depth; ++h) {
                body = bytes.concat(body, tree[h][index ^ 1]);
                index >>= 1;
            }
        }
        body = bytes.concat(body, abi.encodePacked(uint8(1)), operation);
        return abi.encodePacked(
            bytes4(keccak256("run(bytes)")),
            uint256(32),
            body.length,
            body,
            new bytes((32 - body.length % 32) % 32)
        );
    }

    function _pageLen(uint256 n, uint256 i) private pure returns (uint256) {
        return n - i * 4096 < 4096 ? n - i * 4096 : 4096;
    }

    function _slice(bytes memory b, uint256 from, uint256 len)
        private
        pure
        returns (bytes memory out)
    {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = b[from + i];
        }
    }

    function _compare(address target, bytes memory input, string memory want, string memory line)
        private
    {
        vm.recordLogs();
        (bool ok, bytes memory why) = target.call(input);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        if (_startsWith(want, "ok:")) {
            assertTrue(ok, string.concat(line, vm.toString(why)));
            assertEq(logs.length, 1, line);
            assertEq(
                vm.toString(abi.encodePacked(logs[0].topics[0], logs[0].topics[1], logs[0].data)),
                string.concat("0x", _tail(want, 3)),
                line
            );
        } else {
            assertFalse(ok, line);
            assertEq(
                why, abi.encodePacked(bytes4(keccak256(bytes(string.concat(want, "()"))))), line
            );
            assertEq(logs.length, 0, line);
        }
    }

    function _mutate(bytes memory b, string memory op, string memory pos, string memory val)
        private
        pure
        returns (bytes memory out)
    {
        bytes1 o = bytes(op)[0];
        uint256 p = vm.parseUint(pos);
        if (o == "t") {
            out = new bytes(p);
            for (uint256 i; i < p; ++i) {
                out[i] = b[i];
            }
        } else if (o == "a") {
            out = bytes.concat(b, bytes1(uint8(vm.parseUint(string.concat("0x", val)))));
        } else {
            out = bytes.concat(b);
            out[p] ^= bytes1(uint8(vm.parseUint(string.concat("0x", val))));
        }
    }

    function _record(bytes memory trace, uint256 index) private pure returns (bytes memory input) {
        uint256 cursor;
        for (uint256 i; i <= index; ++i) {
            (input, cursor) = _field(trace, cursor);
            for (uint256 k; k < 5; ++k) {
                (, cursor) = _field(trace, cursor);
            }
        }
    }

    function _startsWith(string memory s, string memory prefix) private pure returns (bool) {
        bytes memory a = bytes(s);
        bytes memory b = bytes(prefix);
        if (a.length < b.length) return false;
        for (uint256 i; i < b.length; ++i) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    function _tail(string memory s, uint256 from) private pure returns (string memory) {
        bytes memory a = bytes(s);
        bytes memory out = new bytes(a.length - from);
        for (uint256 i; i < out.length; ++i) {
            out[i] = a[from + i];
        }
        return string(out);
    }
}
