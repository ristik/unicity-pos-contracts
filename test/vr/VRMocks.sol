// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {
    VRRecord,
    IVRRecordSource,
    IElectionModule,
    Member,
    IVR,
    Registration
} from "../../src/vr/VRTypes.sol";
import {VRCodec} from "../../src/vr/VRCodec.sol";
import {VRC} from "../../src/vr/VRConstants.sol";
import {Vm} from "forge-std/Vm.sol";

/// @notice The SealRegistry's record source and clock as VR reads them (etched at 0xff..02 by the tests): sequential records with
/// predecessors and uint8 kinds (6 to 8 included), progress and UC time.
contract MockSeal is IVRRecordSource {
    VRRecord[] internal _records;
    uint64 public progress;
    uint64 public ucTime;

    function recordCount() external view returns (uint64) {
        return uint64(_records.length);
    }

    function recordAt(uint64 index) external view returns (VRRecord memory) {
        return _records[index];
    }

    function setClock(uint64 p, uint64 t) external {
        progress = p;
        ucTime = t;
    }

    function push(uint8 kind, bytes memory data) external returns (uint64 index) {
        index = uint64(_records.length);
        bytes32 predecessor = index == 0 ? bytes32(0) : _records[index - 1].recordID;
        bytes32 id = keccak256(abi.encode(index, predecessor, kind, progress, ucTime, data));
        _records.push(VRRecord(index, id, predecessor, kind, progress, ucTime, data));
    }
}

/// @notice A configurable election module: every step can succeed, revert, burn its gas, return malformed or oversized data, or try to
/// re-enter VR. It logs the steps it receives (for the pointer-switch order).
contract MockModule is IElectionModule {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    // behaviours
    uint8 internal constant OK = 0;
    uint8 internal constant REVERT = 1;
    uint8 internal constant BURN = 2; // consume all forwarded gas
    uint8 internal constant MALFORMED = 3;
    uint8 internal constant HUGE = 4; // a 1 MiB return
    uint8 internal constant REENTER = 5; // call every VR mutator, then behave
    uint8 internal constant REENTER_BUBBLE = 6; // call a VR mutator and let its revert bubble
    uint8 internal constant GRIEF = 7; // burn up to the forwarded cap, then return a valid answer
    uint8 internal constant WRITE_THEN_REVERT = 8;
    uint8 internal constant INVALIDATE_OPEN = 9; // invalidate VR's open output (lock-exempt), then behave
    uint8 internal constant RETURN_WORD = 10; // a void step that returns one word
    uint8 internal constant OVERSIZE = 11; // outputOf: a successful Ready answer one byte above VR's cap (5408)

    // steps
    uint8 internal constant S_ELECT = 1;
    uint8 internal constant S_OUTPUT = 2;
    uint8 internal constant S_RECORDS = 3;
    uint8 internal constant S_RESOLVED = 4;
    uint8 internal constant S_ATTACH = 5;
    uint8 internal constant S_DETACH = 6;
    uint8 internal constant S_GOV = 7;
    uint8 internal constant S_ADOPT = 8;

    address public vr;
    bytes32 public tag;
    uint32 public caps;
    uint64[8] public bounds;
    uint64 public interval;
    address public holder;
    bytes32 public holderHash;

    mapping(uint8 => uint8) public mode;

    // elect behaviour
    uint8 public electOutcome = 1; // NotDue
    bool public electReady;
    bytes32 public nextResult;
    bytes32 public outputResultOverride; // nonzero: outputOf reports this resultId in its header
    bytes32 public predecessorOverride;
    uint8 public outputStatus; // 0 Ready, 1 Pending, 2 NotMine
    uint8 public adoptionStatus; // 0 Ready, 3 NotReady
    uint64 public attemptWord = 7;

    // custom output members (empty: the committee in force)
    Member[] internal _members;
    bool public useCustom;

    // logs
    string[] public log;
    uint256 public reentryAttempts;
    uint256 public reentryRefusals;
    /// @dev The refusal of each re-entry attempt, three bits per call and 64 bits per `_reenter` round (one write per round, so a
    /// void step's small cap still fits): 0 succeeded, 1 Locked, 2 NotSystemCaller, 3 NotSelf, 7 anything else.
    uint256 public reentryCodes;
    uint256 public reentryRounds;
    uint256 public sideEffect; // written by WRITE_THEN_REVERT before reverting
    bytes32 public lastAttachHash;
    uint8 public attachHolderIndex;
    address public attachPrevious;
    address public attachNamespace;
    uint256 public attachMembers;
    bytes32 public attachInitHash;
    bytes32 public lastContextHash;
    uint256 public griefLeave = 20_000;
    bool public invalidatedInStep;

    constructor(bytes32 tag_) {
        tag = tag_;
        bounds = [uint64(3_000_000), 800_000, 200_000, 200_000, 500_000, 200_000, 300_000, 200_000];
        // VR_BUILD=pos: the module declares VR's PoS-capable caps themselves (5.0 / 1.5 / 2.5 M), so the cap-consuming fixtures (BURN, GRIEF,
        // HUGE) spend the full new caps and the insufficient-budget fixtures run at the new step budgets
        if (keccak256(bytes(vm.envOr("VR_BUILD", string("")))) == keccak256("pos")) {
            bounds = [
                uint64(5_000_000),
                1_500_000,
                2_500_000,
                500_000,
                3_000_000,
                500_000,
                1_000_000,
                1_000_000
            ];
        }
        interval = 1_000;
    }

    // ---- configuration ----
    function setVR(address v) external {
        vr = v;
    }

    function setMode(uint8 step, uint8 m) external {
        mode[step] = m;
    }

    function setElect(uint8 outcome, bool ready, bytes32 rid) external {
        electOutcome = outcome;
        electReady = ready;
        nextResult = rid;
    }

    function setOutputStatus(uint8 s) external {
        outputStatus = s;
    }

    function setAdoption(uint8 s) external {
        adoptionStatus = s;
    }

    function setOverrides(bytes32 rid, bytes32 pred) external {
        outputResultOverride = rid;
        predecessorOverride = pred;
    }

    function setCaps(uint32 c) external {
        caps = c;
    }

    function setBounds(uint64[8] calldata b) external {
        bounds = b;
    }

    function setInterval(uint64 i) external {
        interval = i;
    }

    function setHolder(address h) external {
        holder = h;
        holderHash = h.codehash;
    }

    function setMembers(Member[] calldata ms) external {
        delete _members;
        for (uint256 i = 0; i < ms.length; ++i) {
            _members.push(ms[i]);
        }
        useCustom = true;
    }

    function clearMembers() external {
        delete _members;
        useCustom = false;
    }

    function logLength() external view returns (uint256) {
        return log.length;
    }

    function clearLog() external {
        delete log;
    }

    // ---- metadata ----
    function moduleTag() external view returns (bytes32) {
        return tag;
    }

    function capabilities() external view returns (uint32) {
        return caps;
    }

    function gasBounds()
        external
        view
        returns (uint64, uint64, uint64, uint64, uint64, uint64, uint64, uint64)
    {
        return (
            bounds[0], bounds[1], bounds[2], bounds[3], bounds[4], bounds[5], bounds[6], bounds[7]
        );
    }

    function maxElectionInterval() external view returns (uint64) {
        return interval;
    }

    function liabilityHolder() external view returns (address, bytes32) {
        return (holder, holderHash);
    }

    // ---- behaviour helpers ----
    function _burn() internal pure {
        assembly {
            for {} 1 {} {}
        }
    }

    function _grief() internal view {
        while (gasleft() > griefLeave) {}
    }

    function setGriefLeave(uint256 g) external {
        griefLeave = g;
    }

    function _huge() internal pure {
        assembly {
            return(0, 1048576)
        }
    }

    function _malformed() internal pure {
        assembly {
            mstore(0, 0x20)
            mstore(0x20, 0x40)
            return(0, 0x41)
        }
    }

    /// @notice The revert selector VR answered re-entry attempt `k` with (counting from the first round), zero for a success.
    function reentryErrors(uint256 k) external view returns (bytes4) {
        uint256 round = k / 14;
        require(round < reentryRounds, "no such attempt");
        uint256 code = (reentryCodes >> ((reentryRounds - 1 - round) * 64 + (k % 14) * 3)) & 7;
        if (code == 0) return bytes4(0);
        if (code == 1) return bytes4(keccak256("Locked()"));
        if (code == 2) return bytes4(keccak256("NotSystemCaller()"));
        if (code == 3) return bytes4(keccak256("NotSelf()"));
        return bytes4(0xffffffff);
    }

    /// @dev Calls every VR mutator with a well-formed ABI call: register and proposeBinding (refused with Locked), publish, queue,
    /// cancel, execute and setEndpoints (Locked), the system hooks (NotSystemCaller), the four step entry points (NotSelf), and the
    /// lock-exempt `invalidate`, which is total: for an unknown result it succeeds and changes nothing.
    function _reenter() internal {
        IVR v = IVR(vr);
        Registration memory r = Registration({
            rootNodeID: "reentrant-root",
            rootKey: new bytes(33),
            evmNodeID: "reentrant-evm",
            evmKey: new bytes(33),
            payee: address(this),
            nonce: 0
        });
        bytes[] memory calls = new bytes[](14);
        calls[0] = abi.encodeCall(v.publish, (bytes32(uint256(1))));
        calls[1] = abi.encodeCall(v.applyRootRecords, (1));
        calls[2] = abi.encodeCall(v.elect, (bytes32(0)));
        calls[3] = abi.encodeCall(v.queue, (4, abi.encode(uint32(1), uint32(2), uint32(3))));
        calls[4] = abi.encodeCall(v.cancel, (1));
        calls[5] = abi.encodeCall(v.execute, (1));
        calls[6] = abi.encodeCall(v.setEndpoints, (1, bytes("x")));
        calls[7] = abi.encodeCall(v.stepVoid, (address(this), 1000, bytes("")));
        calls[8] = abi.encodeCall(v.stepElect, (new bytes(256)));
        calls[9] = abi.encodeCall(v.stepPublish, (bytes32(uint256(1))));
        calls[10] = abi.encodeCall(v.stepAdoption, (address(this), 1000, bytes("")));
        calls[11] = abi.encodeCall(v.register, (r, new bytes(65), new bytes(65)));
        calls[12] = abi.encodeCall(v.proposeBinding, (uint64(1), r, new bytes(65), new bytes(65)));
        calls[13] = abi.encodeCall(v.invalidate, (keccak256("an unknown result"), 1));
        uint256 codes = 0;
        uint256 refused = 0;
        for (uint256 i = 0; i < calls.length; ++i) {
            (bool ok, bytes memory ret) = vr.call(calls[i]);
            uint256 code = 0;
            if (!ok) {
                ++refused;
                bytes4 e = ret.length < 4 ? bytes4(0) : bytes4(ret);
                code = e == bytes4(keccak256("Locked()"))
                    ? 1
                    : e == bytes4(keccak256("NotSystemCaller()"))
                        ? 2
                        : e == bytes4(keccak256("NotSelf()")) ? 3 : 7;
            }
            codes |= code << (i * 3);
        }
        reentryAttempts += calls.length;
        reentryRefusals += refused;
        reentryCodes = (reentryCodes << 64) | codes;
        ++reentryRounds;
    }

    function _bubble() internal {
        IVR(vr).publish(bytes32(uint256(1)));
    }

    /// @dev Applies the step's mode; returns true when the caller should go on with the normal answer.
    function _behave(uint8 step) internal returns (bool) {
        uint8 m = mode[step];
        if (m == OK) return true;
        if (m == REVERT) revert("module says no");
        if (m == BURN) _burn();
        if (m == MALFORMED) _malformed();
        if (m == HUGE) _huge();
        if (m == REENTER) {
            _reenter();
            return true;
        }
        if (m == REENTER_BUBBLE) _bubble();
        if (m == GRIEF) {
            _grief();
            return true;
        }
        if (m == WRITE_THEN_REVERT) {
            sideEffect += 1;
            revert("after a write");
        }
        if (m == INVALIDATE_OPEN) {
            invalidatedInStep = IVR(vr).invalidate(IVR(vr).openOutput(), 1);
            return true;
        }
        if (m == RETURN_WORD) {
            assembly {
                mstore(0, 1)
                return(0, 32)
            }
        }
        return true;
    }

    function _behaveView(uint8 step) internal view returns (bool) {
        uint8 m = mode[step];
        if (m == OK || m == REENTER) return true;
        if (m == REVERT || m == WRITE_THEN_REVERT) revert("module says no");
        if (m == BURN) _burn();
        if (m == MALFORMED) _malformed();
        if (m == HUGE) _huge();
        if (m == GRIEF) {
            _grief();
            return true;
        }
        return true;
    }

    // ---- steps ----
    function elect(bytes calldata context) external returns (bytes memory) {
        lastContextHash = keccak256(context);
        log.push("elect");
        _behave(S_ELECT);
        return
            VRCodec.packElect(electOutcome, electReady, electOutcome == 2 ? nextResult : bytes32(0));
    }

    function outputOf(bytes32 resultId) external view returns (bytes memory) {
        _behaveView(S_OUTPUT);
        if (outputStatus != 0) return VRCodec.packStatus(outputStatus);
        IVR v = IVR(vr);
        Member[] memory ms;
        if (useCustom) {
            ms = _members;
        } else {
            ms = v.committee();
        }
        for (uint256 i = 0; i < ms.length; ++i) {
            ms[i].exposureDigest =
                VRCodec.exposureDigest(v.config().network, vr, resultId, ms[i].id);
        }
        VRCodec.OutputHeader memory h = VRCodec.OutputHeader({
            resultId: outputResultOverride != 0 ? outputResultOverride : resultId,
            predecessor: predecessorOverride != 0
                ? predecessorOverride
                : v.output(resultId).predecessor,
            attempt: attemptWord,
            snapshotDigest: keccak256("snapshot"),
            policyDigest: keccak256("policy")
        });
        bytes memory packed = VRCodec.packOutput(h, ms);
        if (mode[S_OUTPUT] == OVERSIZE) {
            // the ABI envelope of the valid answer plus one byte: a successful return of cap + 1 bytes for a 16-member output
            bytes memory enc = abi.encodePacked(abi.encode(packed), bytes1(0));
            assembly {
                return(add(enc, 0x20), mload(enc))
            }
        }
        return packed;
    }

    function adoptionReady(bytes calldata) external view returns (bytes memory) {
        _behaveView(S_ADOPT);
        return VRCodec.packStatus(adoptionStatus);
    }

    function attach(bytes calldata attachContext) external {
        log.push("attach");
        lastAttachHash = keccak256(attachContext);
        (uint8 err, VRCodec.AttachContext memory a) = VRCodec.decodeAttachContext(attachContext);
        require(err == VRCodec.OK, "attach context");
        attachHolderIndex = a.holderIndex;
        attachPrevious = a.previousModule;
        attachNamespace = a.namespace;
        attachMembers = a.committee.length;
        attachInitHash = keccak256(a.initData);
        _behave(S_ATTACH);
    }

    function detach() external {
        log.push("detach");
        _behave(S_DETACH);
    }

    function onRecords(uint64 fromIndex, uint32 count) external {
        log.push(string.concat("onRecords:", _u(fromIndex), ":", _u(count)));
        _behave(S_RECORDS);
    }

    function onResolved(bytes32, uint8 resolution) external {
        log.push(string.concat("onResolved:", _u(resolution)));
        _behave(S_RESOLVED);
    }

    function onGovernance(bytes calldata) external {
        log.push("onGovernance");
        _behave(S_GOV);
    }

    /// @notice Lets a test invalidate one of this module's outputs (the module is the source).
    function invalidate(bytes32 rid, uint8 reason) external returns (bool) {
        return IVR(vr).invalidate(rid, reason);
    }

    function _u(uint256 x) internal pure returns (string memory) {
        if (x == 0) return "0";
        bytes memory b;
        while (x != 0) {
            b = bytes.concat(bytes1(uint8(48 + x % 10)), b);
            x /= 10;
        }
        return string(b);
    }
}

/// @notice A liability holder stand-in: any code works for the holder namespace tests.
contract MockHolder {
    uint256 public cursor;

    function version() external pure returns (uint256) {
        return 1;
    }
}
