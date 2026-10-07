// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Base} from "./P85Base.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {Delegation, DelegationRequest} from "../../src/p85/P85Types.sol";

/// @notice admitDelegation: owner authorization plus EVM possession over the exact payload, the
/// staged (binding, operatorPayee) storage and its replay nonce, and the live index guard.
contract DelegationTest is P85Base {
    address internal payeeB = makeAddr("payeeB");

    function _request(
        uint256 i,
        uint256 evmKeyPk,
        address payee,
        uint64 delegationNonce,
        uint64 expiry
    ) internal returns (DelegationRequest memory r) {
        r.id = gid(i);
        r.generation = 1;
        r.binding = Delegation({
            rootNodeID: keccak256(abi.encode("root", i)),
            rootKey: compressed(rootPk(i)),
            evmNodeID: keccak256(abi.encode("evm", i)),
            evmKey: compressed(evmKeyPk),
            operatorPayee: payee
        });
        r.roleNonce = 0;
        r.delegationNonce = delegationNonce;
        r.expiry = expiry;
    }

    function _admit(DelegationRequest memory r, uint256 ownerKey, uint256 evmKeyPk) internal {
        bytes32 digest = election.delegationDigest(r);
        election.admitDelegation(r, sign(ownerKey, digest), sign(evmKeyPk, digest));
    }

    function test_payeeOnlyNominationStagesTheNewPayeeAndConsumesTheNonce() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 1_000);
        vm.expectEmit(true, false, false, false, address(election));
        emit ElectionPolicy.DelegationAdmitted(gid(0), bytes32(0), payeeB, 0);
        _admit(r, ownerPk(0), evmPk(0));
        (Delegation memory d, bytes32 bindingHash, uint64 nextNonce) =
            election.delegation(gid(0), 1);
        assertEq(d.operatorPayee, payeeB);
        assertEq(keccak256(d.evmKey), keccak256(compressed(evmPk(0))), "unchanged keys");
        assertEq(nextNonce, 1);
        assertTrue(bindingHash != bytes32(0));
    }

    function test_rebindingToANewEvmKeyTombstonesItInTheSharedKeySpace() public {
        DelegationRequest memory r = _request(0, 0x9401, payeeB, 0, 1_000);
        _admit(r, ownerPk(0), 0x9401);
        (uint64 id, uint8 role) = custody.keyOwner(keccak256(compressed(0x9401)));
        assertEq(id, gid(0));
        assertEq(role, 2);
    }

    function test_consumedNonceCannotBeReplayed() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 1_000);
        bytes32 digest = election.delegationDigest(r);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        bytes memory evmSig = sign(evmPk(0), digest);
        election.admitDelegation(r, ownerSig, evmSig);
        vm.expectRevert(ElectionPolicy.DelegationNonceMismatch.selector);
        election.admitDelegation(r, ownerSig, evmSig);
    }

    function test_futureNonceIsRejectedToo() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 1, 1_000);
        bytes32 digest = election.delegationDigest(r);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        bytes memory evmSig = sign(evmPk(0), digest);
        vm.expectRevert(ElectionPolicy.DelegationNonceMismatch.selector);
        election.admitDelegation(r, ownerSig, evmSig);
    }

    function test_alteredPayeeInvalidatesBothSignatures() public {
        DelegationRequest memory signed = _request(0, evmPk(0), payeeB, 0, 1_000);
        bytes32 digest = election.delegationDigest(signed);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        bytes memory evmSig = sign(evmPk(0), digest);
        DelegationRequest memory forged = _request(0, evmPk(0), makeAddr("attackerPayee"), 0, 1_000);
        vm.expectRevert(ElectionPolicy.BadOwnerAuthorization.selector);
        election.admitDelegation(forged, ownerSig, evmSig);
    }

    function test_evmPossessionIsCheckedIndependentlyOfTheOwner() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 1_000);
        bytes32 digest = election.delegationDigest(r);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        // correct owner authorization, but the EVM proof is made by another key
        bytes memory wrongEvm = sign(evmPk(1), digest);
        vm.expectRevert(ElectionPolicy.BadEvmPossession.selector);
        election.admitDelegation(r, ownerSig, wrongEvm);
    }

    function test_ownerAuthorizationMustComeFromTheCurrentOwner() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 1_000);
        bytes32 digest = election.delegationDigest(r);
        bytes memory evmSig = sign(evmPk(0), digest);
        vm.expectRevert(ElectionPolicy.BadOwnerAuthorization.selector);
        election.admitDelegation(r, sign(ownerPk(1), digest), evmSig); // another identity's owner
        vm.expectRevert(ElectionPolicy.BadOwnerAuthorization.selector);
        election.admitDelegation(r, hex"00", evmSig); // malformed signature
    }

    function test_expiryBoundaryIsInclusiveInUcSeconds() public {
        clock(10, 500);
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 499);
        bytes32 digest = election.delegationDigest(r);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        bytes memory evmSig = sign(evmPk(0), digest);
        vm.expectRevert(ElectionPolicy.DelegationExpired.selector);
        election.admitDelegation(r, ownerSig, evmSig);
        r = _request(0, evmPk(0), payeeB, 0, 500); // expiry == UC time still valid
        _admit(r, ownerPk(0), evmPk(0));
    }

    function test_roleNonceChangeInvalidatesPendingAuthorizations() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 1_000);
        bytes32 digest = election.delegationDigest(r);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        bytes memory evmSig = sign(evmPk(0), digest);
        address newOwner = makeAddr("newOwner");
        vm.prank(vm.addr(ownerPk(0)));
        custody.proposeRoles(gid(0), newOwner, vm.addr(wdPk(0)), 0);
        vm.prank(newOwner);
        custody.acceptRoles(gid(0), 0, newOwner, vm.addr(wdPk(0)));
        vm.expectRevert(ElectionPolicy.RoleNonceMismatch.selector);
        election.admitDelegation(r, ownerSig, evmSig);
    }

    function test_staleGenerationAndUnknownIdentityAreRejected() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 1_000);
        bytes32 digest = election.delegationDigest(r);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        bytes memory evmSig = sign(evmPk(0), digest);
        r.generation = 2;
        vm.expectRevert(ElectionPolicy.StaleGeneration.selector);
        election.admitDelegation(r, ownerSig, evmSig);
        r.generation = 1;
        r.id = 99;
        vm.expectRevert(ElectionPolicy.UnknownIdentity.selector);
        election.admitDelegation(r, ownerSig, evmSig);
    }

    function test_zeroPayeeAndMalformedRootKeyAreRejected() public {
        DelegationRequest memory r = _request(0, evmPk(0), address(0), 0, 1_000);
        vm.expectRevert(ElectionPolicy.ZeroPayee.selector);
        election.admitDelegation(r, hex"", hex"");
        r = _request(0, evmPk(0), payeeB, 0, 1_000);
        r.binding.rootKey = hex"0102";
        vm.expectRevert(ElectionPolicy.BadRootKey.selector);
        election.admitDelegation(r, hex"", hex"");
    }

    function test_bindingMustNameTheIdentitysCurrentOrStagedRootKey() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 1_000);
        r.binding.rootKey = compressed(rootPk(1)); // another identity's key
        vm.expectRevert(ElectionPolicy.WrongRootKey.selector);
        election.admitDelegation(r, hex"", hex"");
    }

    function test_evmKeyOfAnotherIdentityIsRejected() public {
        // identity 1 tries to bind identity 2's EVM key, with valid signatures from both parties'
        // keys as far as the digest goes: only the shared tombstone stops it.
        DelegationRequest memory r = _request(0, evmPk(1), payeeB, 0, 1_000);
        bytes32 digest = election.delegationDigest(r);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        bytes memory evmSig = sign(evmPk(1), digest);
        vm.expectRevert(StakeCustody.KeyAlreadyUsed.selector);
        election.admitDelegation(r, ownerSig, evmSig);
    }

    function test_evmKeyEqualToTheRootKeyIsRejected() public {
        DelegationRequest memory r = _request(0, rootPk(0), payeeB, 0, 1_000);
        bytes32 digest = election.delegationDigest(r);
        bytes memory ownerSig = sign(ownerPk(0), digest);
        bytes memory evmSig = sign(rootPk(0), digest);
        vm.expectRevert(StakeCustody.KeyAlreadyUsed.selector);
        election.admitDelegation(r, ownerSig, evmSig);
    }

    function test_digestBindsEveryField() public {
        DelegationRequest memory base = _request(0, evmPk(0), payeeB, 0, 1_000);
        bytes32 d0 = election.delegationDigest(base);
        DelegationRequest memory v = _request(0, evmPk(0), payeeB, 0, 1_000);
        v.id = 2;
        assertTrue(election.delegationDigest(v) != d0, "id");
        v = _request(0, evmPk(0), payeeB, 0, 1_000);
        v.generation = 2;
        assertTrue(election.delegationDigest(v) != d0, "generation");
        v = _request(0, evmPk(0), payeeB, 0, 1_000);
        v.binding.rootNodeID = bytes32(uint256(1));
        assertTrue(election.delegationDigest(v) != d0, "rootNodeID");
        v = _request(0, evmPk(0), payeeB, 0, 1_000);
        v.binding.evmNodeID = bytes32(uint256(1));
        assertTrue(election.delegationDigest(v) != d0, "evmNodeID");
        v = _request(0, evmPk(0), payeeB, 0, 1_000);
        v.binding.rootKey = compressed(rootPk(1));
        assertTrue(election.delegationDigest(v) != d0, "rootKey");
        v = _request(0, evmPk(0), payeeB, 0, 1_000);
        v.binding.evmKey = compressed(evmPk(1));
        assertTrue(election.delegationDigest(v) != d0, "evmKey");
        v = _request(0, evmPk(0), makeAddr("other"), 0, 1_000);
        assertTrue(election.delegationDigest(v) != d0, "payee");
        v = _request(0, evmPk(0), payeeB, 0, 1_000);
        v.roleNonce = 1;
        assertTrue(election.delegationDigest(v) != d0, "roleNonce");
        v = _request(0, evmPk(0), payeeB, 1, 1_000);
        assertTrue(election.delegationDigest(v) != d0, "delegationNonce");
        v = _request(0, evmPk(0), payeeB, 0, 1_001);
        assertTrue(election.delegationDigest(v) != d0, "expiry");
    }

    function test_digestBindsTheElectionModuleAddress() public {
        DelegationRequest memory r = _request(0, evmPk(0), payeeB, 0, 1_000);
        bytes32 first = election.delegationDigest(r);
        _deploy(_defaultPolicy()); // a second deployment: same network, different module address
        assertTrue(address(election) != address(0));
        assertTrue(election.delegationDigest(r) != first, "signatures do not cross deployments");
    }

    function test_noncesAreKeyedByIdentityAndGeneration() public {
        DelegationRequest memory a = _request(0, evmPk(0), payeeB, 0, 1_000);
        _admit(a, ownerPk(0), evmPk(0));
        // identity 2's nonce is unaffected by identity 1's consumption
        DelegationRequest memory b = _request(1, evmPk(1), payeeB, 0, 1_000);
        _admit(b, ownerPk(1), evmPk(1));
        (,, uint64 n0) = election.delegation(gid(0), 1);
        (,, uint64 n1) = election.delegation(gid(1), 1);
        (,, uint64 gen2) = election.delegation(gid(0), 2);
        assertEq(n0, 1);
        assertEq(n1, 1);
        assertEq(gen2, 0);
    }

    function test_syncLiveIndexOnlyByCustody() public {
        vm.expectRevert(ElectionPolicy.NotCustody.selector);
        election.syncLiveIndex(gid(0));
    }
}
