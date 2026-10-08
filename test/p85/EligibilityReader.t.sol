// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {EligibilityReader} from "../../src/p85/EligibilityReader.sol";

/// @notice The stateless reader answers the same on any order of input and for any caller; ElectionPolicy depends on its output being
/// ascending by identity (the continuity rule and the selection walk both need it).
contract EligibilityReaderTest is P85Flow {
    function _reader() internal view returns (EligibilityReader) {
        return election.reader();
    }

    function test_positionsAreAscendingWhateverTheInputOrder() public view {
        uint64[] memory ids = new uint64[](4);
        ids[0] = gid(2);
        ids[1] = gid(0);
        ids[2] = gid(3);
        ids[3] = gid(1);
        EligibilityReader.Pos[] memory out = _reader().positions(ids);
        assertEq(out.length, 4);
        for (uint256 i; i < out.length; ++i) {
            assertEq(out[i].id, gid(i));
            assertEq(out[i].generation, 1);
        }
    }

    function test_unknownRetiringAndExcludedIdentitiesAreDropped() public {
        requestRetirement(1);
        uint64[] memory ids = new uint64[](4);
        ids[0] = gid(1); // retiring
        ids[1] = 99; // unknown
        ids[2] = gid(0);
        ids[3] = gid(2);
        EligibilityReader.Pos[] memory out = _reader().positions(ids);
        assertEq(out.length, 2);
        assertEq(out[0].id, gid(0));
        assertEq(out[1].id, gid(2));
    }

    function test_theReaderIsWiredToTheModulesTheElectionNames() public view {
        assertEq(address(_reader().CUSTODY()), address(custody));
        assertEq(address(_reader().EVIDENCE()), address(evidence));
    }
}
