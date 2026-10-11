// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {SealRegistry} from "../src/SealRegistry.sol";
import {SealRegistryBase} from "./SealRegistryBase.sol";
import {MockRootRecords} from "./p85/MockRootRecords.sol";
import {RootRecord, RecordKind} from "../src/p85/P85Types.sol";

/// @notice COLD gas of the reads custody and the hook make of the REAL registry (`recordAt`, `recordCount`, `progress`, `ucTime`,
/// `recordTargetCount`) against the stand-in the hook-gas measurements use (`MockRootRecords`), for the two record shapes that carry the most
/// words: the RecoveryAck (nine payload words) and the Closure (six). The state is built in `setUp`, so each test's read is the first touch of
/// every slot it reads. The difference is what `test/p85/HookGasCold.t.sol` leaves out (docs/p85/HOOK_GAS.md).
contract RegistryRecordAtGasTest is SealRegistryBase {
    SealRegistry internal reg;
    MockRootRecords internal mock;

    function setUp() public override {
        super.setUp();
        reg = SealRegistry(A_SR);
        OpenArgs memory a = firstPayload();
        openAsSystem(a);
        bytes memory ack = abi.encode(
            keccak256("r"),
            keccak256("k"),
            uint64(100),
            uint64(101),
            uint64(130),
            uint64(130),
            uint64(131),
            uint64(3),
            uint64(2)
        );
        bytes memory closure = abi.encode(
            keccak256("asg"),
            uint64(130),
            keccak256("h"),
            keccak256("root"),
            keccak256("ed"),
            keccak256("kh")
        );
        SealRegistry.ImportedRecord[] memory es = new SealRegistry.ImportedRecord[](2);
        RootRecord memory r0 = _rec(0, bytes32(0), RecordKind.RecoveryAck, ack);
        RootRecord memory r1 = _rec(1, r0.recordID, RecordKind.Closure, closure);
        es[0] = SealRegistry.ImportedRecord(r0, 0);
        es[1] = SealRegistry.ImportedRecord(r1, 1);
        (bool ok,) = callAs(
            A_SYS,
            abi.encodeCall(SealRegistry.importRootRecords, (a.n, 10, 1_010, 2, r1.recordID, es))
        );
        require(ok, "import");
        finalizeAsSystem(a.n, keccak256("R1"));

        mock = new MockRootRecords();
        mock.setClock(10, 1_010);
        mock.push(RecordKind.RecoveryAck, ack);
        mock.push(RecordKind.Closure, closure);
    }

    function _rec(uint64 index, bytes32 pred, RecordKind kind, bytes memory data)
        internal
        pure
        returns (RootRecord memory)
    {
        return RootRecord(
            index,
            keccak256(abi.encode(index, pred, kind, uint64(10), uint64(1_010), data)),
            pred,
            kind,
            10,
            1_010,
            data
        );
    }

    function _gas(string memory label, uint256 used) internal {
        emit log_named_uint(label, used);
    }

    function test_realRecordAtOfARecoveryAck() public {
        uint256 b = gasleft();
        reg.recordAt(0);
        _gas("REAL recordAt(RecoveryAck, 9 words)", b - gasleft());
    }

    function test_mockRecordAtOfARecoveryAck() public {
        uint256 b = gasleft();
        mock.recordAt(0);
        _gas("MOCK recordAt(RecoveryAck, 9 words)", b - gasleft());
    }

    function test_realRecordAtOfAClosure() public {
        uint256 b = gasleft();
        reg.recordAt(1);
        _gas("REAL recordAt(Closure, 6 words)", b - gasleft());
    }

    function test_mockRecordAtOfAClosure() public {
        uint256 b = gasleft();
        mock.recordAt(1);
        _gas("MOCK recordAt(Closure, 6 words)", b - gasleft());
    }

    function test_realCountTargetAndClock() public {
        uint256 b = gasleft();
        reg.recordCount();
        reg.recordTargetCount();
        reg.progress();
        reg.ucTime();
        _gas("REAL recordCount+recordTargetCount+progress+ucTime", b - gasleft());
    }

    function test_mockCountAndClock() public {
        uint256 b = gasleft();
        mock.recordCount();
        mock.progress();
        mock.ucTime();
        _gas("MOCK recordCount+progress+ucTime", b - gasleft());
    }
}
