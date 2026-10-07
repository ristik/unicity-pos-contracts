// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Base} from "./P85Base.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {KeyLib} from "../../src/p85/KeyLib.sol";
import {FixedPolicy} from "../../src/p85/FixedPolicy.sol";
import {Limits} from "../../src/p85/P85Types.sol";

/// @notice Registration, key uniqueness, bonding, roles and retirement requests.
contract IdentityTest is P85Base {
    address internal stranger = makeAddr("stranger");

    // --- register ---------------------------------------------------------------------------------

    function test_registerAllocatesNeverReusedIDsAndTombstonesTheKey() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        assertEq(id, N_GENESIS + 1);
        (address owner, address wd, bytes32 rootHash,, uint64 gen,, uint32 open,,) =
            custody.positions(id);
        assertEq(owner, vm.addr(0x9001));
        assertEq(wd, vm.addr(0x9201));
        assertEq(rootHash, keccak256(compressed(0x9101)));
        assertEq(gen, 1);
        assertEq(open, 0);
        (uint64 keyId, uint8 role) = custody.keyOwner(rootHash);
        assertEq(keyId, id);
        assertEq(role, 1);
        assertEq(custody.registerNonce(vm.addr(0x9001)), 1);
        uint64 second = register(0x9001, 0x9102, vm.addr(0x9201));
        assertEq(second, id + 1);
    }

    function test_registerRejectsWrongKeyProof() public {
        address owner = vm.addr(0x9001);
        bytes memory key = compressed(0x9101);
        // possession proof made by a different key
        bytes memory pop = sign(0x9102, registerDigest(owner, vm.addr(0x9201), key, 0));
        vm.prank(owner);
        vm.expectRevert(StakeCustody.BadPossessionProof.selector);
        custody.register(key, pop, vm.addr(0x9201));
    }

    function test_registerProofIsBoundToTheCaller() public {
        bytes memory key = compressed(0x9101);
        bytes memory pop = sign(0x9101, registerDigest(vm.addr(0x9001), vm.addr(0x9201), key, 0));
        vm.prank(stranger); // not the owner the proof names
        vm.expectRevert(StakeCustody.BadPossessionProof.selector);
        custody.register(key, pop, vm.addr(0x9201));
    }

    function test_registerProofIsBoundToTheWithdrawalAuthority() public {
        address owner = vm.addr(0x9001);
        bytes memory key = compressed(0x9101);
        bytes memory pop = sign(0x9101, registerDigest(owner, vm.addr(0x9201), key, 0));
        vm.prank(owner);
        vm.expectRevert(StakeCustody.BadPossessionProof.selector);
        custody.register(key, pop, vm.addr(0x9202));
    }

    function test_registerProofCannotBeReplayedAfterTheNonceAdvances() public {
        address owner = vm.addr(0x9001);
        bytes memory key = compressed(0x9101);
        bytes memory pop = sign(0x9101, registerDigest(owner, vm.addr(0x9201), key, 0));
        vm.prank(owner);
        custody.register(key, pop, vm.addr(0x9201));
        vm.prank(owner);
        vm.expectRevert(StakeCustody.BadPossessionProof.selector); // nonce is now 1
        custody.register(key, pop, vm.addr(0x9201));
    }

    function test_registerRejectsAnAlreadyTombstonedRootKey() public {
        register(0x9001, 0x9101, vm.addr(0x9201));
        address owner = vm.addr(0x9002);
        bytes memory key = compressed(0x9101);
        bytes memory pop = sign(0x9101, registerDigest(owner, vm.addr(0x9201), key, 0));
        vm.prank(owner);
        vm.expectRevert(StakeCustody.KeyAlreadyUsed.selector);
        custody.register(key, pop, vm.addr(0x9201));
    }

    function test_registerRejectsAnEvmKeyAsRootKey() public {
        // The genesis EVM key of identity 1 is tombstoned in the shared key space.
        address owner = vm.addr(0x9002);
        bytes memory key = compressed(evmPk(0));
        bytes memory pop = sign(evmPk(0), registerDigest(owner, vm.addr(0x9201), key, 0));
        vm.prank(owner);
        vm.expectRevert(StakeCustody.KeyAlreadyUsed.selector);
        custody.register(key, pop, vm.addr(0x9201));
    }

    function test_registerRejectsMalformedKeys() public {
        address owner = vm.addr(0x9001);
        vm.startPrank(owner);
        vm.expectRevert(KeyLib.BadKeyLength.selector);
        custody.register(hex"02aabb", hex"", vm.addr(0x9201));
        bytes memory badPrefix = compressed(0x9101);
        badPrefix[0] = 0x04;
        vm.expectRevert(KeyLib.BadKeyPrefix.selector);
        custody.register(badPrefix, hex"", vm.addr(0x9201));
        // x = 5 is not an x-coordinate of a secp256k1 point (5^3 + 7 = 132 is a non-residue)
        bytes memory offCurve = abi.encodePacked(uint8(2), bytes32(uint256(5)));
        vm.expectRevert(KeyLib.KeyNotOnCurve.selector);
        custody.register(offCurve, hex"", vm.addr(0x9201));
        vm.stopPrank();
    }

    function test_registerRejectsZeroWithdrawalAuthority() public {
        vm.prank(vm.addr(0x9001));
        vm.expectRevert(StakeCustody.ZeroAddress.selector);
        custody.register(compressed(0x9101), hex"", address(0));
    }

    // --- bond -------------------------------------------------------------------------------------

    function test_bondCreatesAFreeLotForTheActualValue() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        uint256 before_ = custody.totalFree();
        uint256 lotID = bondFor(id, 250 * UCT);
        (
            uint64 lotOwner,
            uint64 gen,
            uint128 initial,
            uint128 remaining,,
            uint8 cat,
            uint16 cap,,,,,,
        ) = custody.lots(lotID);
        assertEq(lotOwner, id);
        assertEq(gen, 1);
        assertEq(initial, 250 * UCT);
        assertEq(remaining, 250 * UCT);
        assertEq(cat, 1);
        assertEq(cap, 500, "lifetime cap is captured on lot creation");
        assertEq(custody.totalFree(), before_ + 250 * UCT);
        assertTrue(election.isIndexed(id), "first bond joins the live index");
        assertEq(address(custody).balance, N_GENESIS * GENESIS_BOND + 250 * UCT);
        assertConserved();
    }

    function test_bondRejectsZeroValue() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        vm.prank(vm.addr(0x9001));
        vm.expectRevert(StakeCustody.ZeroValue.selector);
        custody.bond(id);
    }

    function test_bondRejectsAnAmountThatDoesNotFitALot() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        uint256 huge = uint256(type(uint128).max) + 1;
        vm.deal(vm.addr(0x9001), huge);
        vm.prank(vm.addr(0x9001));
        vm.expectRevert(StakeCustody.AmountTooLarge.selector);
        custody.bond{value: huge}(id);
    }

    function test_bondOnlyByOwnerAndOnlyForKnownIdentities() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        vm.expectRevert(StakeCustody.NotOwner.selector);
        custody.bond{value: 1 ether}(id);
        vm.prank(vm.addr(0x9001));
        vm.expectRevert(StakeCustody.UnknownIdentity.selector);
        custody.bond(999);
    }

    function test_bondEnforcesLotCapacityPerGeneration() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        for (uint256 i; i < 8; ++i) {
            bondFor(id, 1 ether);
        }
        (address owner,,,,,,,,) = custody.positions(id);
        vm.deal(owner, 1 ether);
        vm.prank(owner);
        vm.expectRevert(StakeCustody.LotCapacity.selector);
        custody.bond{value: 1 ether}(id);
    }

    function test_bondRespectsTheBoundedLiveIndex() public {
        // vMax = 5: four genesis identities plus one more fit; the next first bond does not.
        roots = new MockRootRecordsHolder().roots();
        _deployManual(
            address(new FixedPolicy(_defaultPolicy())),
            Limits({vMax: 5, lMax: 8, rMax: 4, maxBatch: 32})
        );
        uint64 fifth = register(0x9001, 0x9101, vm.addr(0x9201));
        bondFor(fifth, 100 * UCT);
        assertEq(election.liveCount(), 5);
        uint64 sixth = register(0x9002, 0x9102, vm.addr(0x9202));
        vm.deal(vm.addr(0x9002), 100 * UCT);
        vm.prank(vm.addr(0x9002));
        vm.expectRevert(ElectionPolicy.IndexFull.selector);
        custody.bond{value: 100 * UCT}(sixth);
        // a second lot for an already-indexed identity is not a new index member
        bondFor(fifth, 1 ether);
        assertEq(election.liveCount(), 5);
    }

    // --- root key staging -------------------------------------------------------------------------

    function _rootKeyDigest(uint64 id, bytes memory key) internal view returns (bytes32) {
        (,,,, uint64 gen, uint64 roleNonce,,,) = custody.positions(id);
        return keccak256(
            abi.encode(
                keccak256("unicity.p85.pop.proposeRootKey"),
                NETWORK,
                block.chainid,
                address(custody),
                id,
                gen,
                keccak256(key),
                roleNonce
            )
        );
    }

    function test_proposeRootKeyStagesAUniqueKey() public {
        bytes memory key = compressed(0x9301);
        bytes memory pop = sign(0x9301, _rootKeyDigest(gid(0), key));
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRootKey(gid(0), key, pop);
        (,, bytes32 active, bytes32 staged,,,,,) = custody.positions(gid(0));
        assertEq(
            active, keccak256(compressed(rootPk(0))), "activation waits for committed membership"
        );
        assertEq(staged, keccak256(key));
        (uint64 keyId,) = custody.keyOwner(staged);
        assertEq(keyId, gid(0), "the staged key is already tombstoned");
    }

    function test_proposeRootKeyRequiresPossession() public {
        bytes memory key = compressed(0x9301);
        bytes memory pop = sign(0x9302, _rootKeyDigest(gid(0), key));
        vm.prank(vm.addr(ownerPk(0)));
        vm.expectRevert(StakeCustody.BadPossessionProof.selector);
        custody.proposeRootKey(gid(0), key, pop);
    }

    function test_proposeRootKeyOnlyByOwner() public {
        bytes memory key = compressed(0x9301);
        bytes memory pop = sign(0x9301, _rootKeyDigest(gid(0), key));
        vm.prank(stranger);
        vm.expectRevert(StakeCustody.NotOwner.selector);
        custody.proposeRootKey(gid(0), key, pop);
    }

    function test_proposeRootKeyRejectsKeysOfOtherIdentities() public {
        bytes memory key = compressed(rootPk(1)); // identity 2's root key
        bytes memory pop = sign(rootPk(1), _rootKeyDigest(gid(0), key));
        vm.prank(vm.addr(ownerPk(0)));
        vm.expectRevert(StakeCustody.KeyAlreadyUsed.selector);
        custody.proposeRootKey(gid(0), key, pop);
    }

    function test_proposeRootKeyProofExpiresWithTheRoleNonce() public {
        bytes memory key = compressed(0x9301);
        bytes memory pop = sign(0x9301, _rootKeyDigest(gid(0), key));
        // a completed role change advances the role nonce and invalidates the old proof
        address newOwner = makeAddr("newOwner");
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), newOwner, vm.addr(wdPk(0)), 0);
        vm.prank(newOwner);
        custody.acceptRoles(gid(0), 0);
        vm.prank(newOwner);
        vm.expectRevert(StakeCustody.BadPossessionProof.selector);
        custody.proposeRootKey(gid(0), key, pop);
    }

    // --- roles ------------------------------------------------------------------------------------

    function test_ownerChangeNeedsTheNominatedOwnerToAccept() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), newOwner, vm.addr(wdPk(0)), 0);
        (address owner,,,,, uint64 nonce,,,) = custody.positions(gid(0));
        assertEq(owner, vm.addr(ownerPk(0)), "not installed before acceptance");
        assertEq(nonce, 0);
        vm.prank(newOwner);
        custody.acceptRoles(gid(0), 0);
        (owner,,,,, nonce,,,) = custody.positions(gid(0));
        assertEq(owner, newOwner);
        assertEq(nonce, 1);
    }

    function test_withdrawalReplacementNeedsExistingConsentAndNomineeAcceptance() public {
        address newWd = makeAddr("newWithdrawal");
        address oldWd = vm.addr(wdPk(0));
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), vm.addr(ownerPk(0)), newWd, 0);
        vm.prank(newWd);
        custody.acceptRoles(gid(0), 0); // nominee alone is not enough
        (, address wd,,,,,,,) = custody.positions(gid(0));
        assertEq(wd, oldWd);
        vm.prank(oldWd);
        custody.acceptRoles(gid(0), 0); // existing authority's consent completes it
        (, wd,,,,,,,) = custody.positions(gid(0));
        assertEq(wd, newWd);
    }

    function test_withdrawalReplacementCannotCompleteWithoutTheExistingAuthority() public {
        address newWd = makeAddr("newWithdrawal");
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), vm.addr(ownerPk(0)), newWd, 0);
        vm.prank(newWd);
        custody.acceptRoles(gid(0), 0);
        vm.prank(vm.addr(ownerPk(0))); // the owner is not the withdrawal authority
        vm.expectRevert(StakeCustody.NotNominated.selector);
        custody.acceptRoles(gid(0), 0);
        (, address wd,,,,,,,) = custody.positions(gid(0));
        assertEq(wd, vm.addr(wdPk(0)));
    }

    function test_rolesRejectStrangersStaleNoncesAndNoOps() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(stranger);
        vm.expectRevert(StakeCustody.NotOwner.selector);
        custody.proposeRoles(gid(0), newOwner, vm.addr(wdPk(0)), 0);
        vm.prank(vm.addr(ownerPk(0)));
        vm.expectRevert(StakeCustody.RoleNonceMismatch.selector);
        custody.proposeRoles(gid(0), newOwner, vm.addr(wdPk(0)), 7);
        vm.prank(vm.addr(ownerPk(0)));
        vm.expectRevert(StakeCustody.NoRoleChange.selector);
        custody.proposeRoles(gid(0), vm.addr(ownerPk(0)), vm.addr(wdPk(0)), 0);
        vm.prank(vm.addr(ownerPk(0)));
        vm.expectRevert(StakeCustody.ZeroAddress.selector);
        custody.proposeRoles(gid(0), address(0), vm.addr(wdPk(0)), 0);
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), newOwner, vm.addr(wdPk(0)), 0);
        vm.prank(stranger);
        vm.expectRevert(StakeCustody.NotNominated.selector);
        custody.acceptRoles(gid(0), 0);
        vm.prank(newOwner);
        vm.expectRevert(StakeCustody.NoPendingRoles.selector);
        custody.acceptRoles(gid(0), 5);
        vm.prank(newOwner);
        vm.expectRevert(StakeCustody.NoPendingRoles.selector);
        custody.acceptRoles(gid(1), 0);
    }

    function test_acceptedRolesCannotBeReplayed() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), newOwner, vm.addr(wdPk(0)), 0);
        vm.prank(newOwner);
        custody.acceptRoles(gid(0), 0);
        vm.prank(newOwner);
        vm.expectRevert(StakeCustody.NoPendingRoles.selector);
        custody.acceptRoles(gid(0), 0);
    }

    // --- retirement requests -----------------------------------------------------------------------

    function test_requestRetirementMovesUnreferencedLotsToDrainingAndPaysNothing() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        uint256 lotID = bondFor(id, 150 * UCT);
        uint256 balance = address(custody).balance;
        vm.prank(vm.addr(0x9001));
        custody.requestRetirement(id);
        (,,,,, uint8 cat,,,,,,,) = custody.lots(lotID);
        assertEq(cat, 3);
        assertEq(custody.totalDraining(), 150 * UCT);
        assertEq(custody.totalFree(), 0);
        assertEq(custody.totalCredits(), 0);
        assertEq(address(custody).balance, balance, "a request releases nothing");
        (,,,,,,,, bool requested) = custody.positions(id);
        assertTrue(requested);
        assertConserved();
    }

    function test_requestRetirementKeepsReferencedLotsEncumbered() public {
        vm.prank(vm.addr(ownerPk(0)));
        custody.requestRetirement(gid(0));
        (,,,,, uint8 cat,,,,,,,) = custody.lots(1);
        assertEq(cat, 2, "an active reference still encumbers the lot");
    }

    function test_requestRetirementOncePerGenerationOnlyByOwnerWithLots() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        vm.prank(vm.addr(0x9001));
        vm.expectRevert(StakeCustody.NoOpenLots.selector);
        custody.requestRetirement(id);
        bondFor(id, 100 * UCT);
        vm.prank(stranger);
        vm.expectRevert(StakeCustody.NotOwner.selector);
        custody.requestRetirement(id);
        vm.prank(vm.addr(0x9001));
        custody.requestRetirement(id);
        vm.prank(vm.addr(0x9001));
        vm.expectRevert(StakeCustody.RetirementAlreadyRequested.selector);
        custody.requestRetirement(id);
    }

    function test_bondAfterRetirementRequestWaitsForEveryOldLotToMature() public {
        uint64 id = register(0x9001, 0x9101, vm.addr(0x9201));
        bondFor(id, 100 * UCT);
        vm.prank(vm.addr(0x9001));
        custody.requestRetirement(id);
        vm.deal(vm.addr(0x9001), 1 ether);
        vm.prank(vm.addr(0x9001));
        vm.expectRevert(StakeCustody.GenerationClosing.selector);
        custody.bond{value: 1 ether}(id);
    }

    function test_registerEvmKeyOnlyByElection() public {
        vm.expectRevert(StakeCustody.NotElection.selector);
        custody.registerEvmKey(gid(0), keccak256("k"));
    }
}

import {MockRootRecords} from "./MockRootRecords.sol";

contract MockRootRecordsHolder {
    MockRootRecords public roots = new MockRootRecords();
}
