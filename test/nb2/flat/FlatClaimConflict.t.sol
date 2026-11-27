// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Nb2Cert} from "../../../src/nb2/verifier/Nb2Cert.sol";
import {FlatNative} from "../../../src/nb2/verifier/flat/FlatNative.sol";
import {FlatPacket} from "../../../src/nb2/verifier/flat/FlatPacket.sol";
import {FlatSparse} from "../../../src/nb2/verifier/flat/FlatSparse.sol";
import {
    FlatClaim,
    FlatHash,
    FlatWire as W,
    BadStep
} from "../../../src/nb2/verifier/flat/FlatTypes.sol";

contract FlatClaimConflictTest is Test {
    string private constant FIXTURE = "test/nb2/flat/fixtures/cross-cut-conflict/";

    function testCrossCutClaimValueConflict() external {
        FlatClaim memory committed = this.claimFromWire(_read("committed-claim.bin"));
        FlatClaim memory candidate = this.claimFromWire(_read("conflicting-claim.bin"));
        assertEq(candidate.key, committed.key);
        assertNotEq(candidate.value, committed.value);

        bytes memory retryState = _read("retry-state.bin");
        assertEq(retryState.length, 290);
        bytes32 intermediateRoot = W.mword(retryState, 65);
        (bytes memory opening, bytes32 candidateRoot) =
            this.conflictOpening(_read("BadStep.calldata.bin"), candidate);
        assertEq(W.mword(opening, 2), committed.value);
        assertNotEq(candidateRoot, intermediateRoot);

        assertEq(this.applyClaim(opening, committed, intermediateRoot), intermediateRoot);
        vm.expectRevert(BadStep.selector);
        this.applyClaim(opening, candidate, intermediateRoot);

        // At candidateRoot, the candidate leaf and the siblings authenticate. The
        // unchanged wire opening still names the committed value, so only the
        // value check can reject it here. The test fails if that check is removed.
        vm.expectRevert(BadStep.selector);
        this.applyClaim(opening, candidate, candidateRoot);

        // With that one field corrected, the same root, path and candidate pass.
        for (uint256 i; i < 32; ++i) {
            opening[2 + i] = candidate.value[i];
        }
        assertEq(this.applyClaim(opening, candidate, candidateRoot), candidateRoot);
    }

    function applyClaim(bytes calldata opening, FlatClaim calldata claim, bytes32 root)
        external
        view
        returns (bytes32 updated)
    {
        bytes32[257] memory empty = FlatSparse.defaults(FlatHash.CLAIM_NODE);
        FlatSparse.Cache memory cache;
        FlatNative.Batch memory pending = FlatNative.batch();
        uint256 end;
        (updated, end) = FlatSparse.claim(opening, 0, claim, root, empty, cache, pending);
        assertEq(end, opening.length);
        // The production map queues a single claim. This probe is confined to the
        // sparse check, before any native batch can flush.
        assertEq(pending.count, 1);
        assertFalse(pending.failed);
    }

    function claimFromWire(bytes calldata packed) external view returns (FlatClaim memory claim) {
        uint256 prefixLen = 6 + W.number(packed, 4, 2);
        uint256 ucStart = prefixLen + 3 * 32 + 4;
        (bool ok, Nb2Cert.Uc memory uc) =
            Nb2Cert.parse(W.offset(packed) + ucStart, packed.length - ucStart);
        assertTrue(ok);
        assertEq(Nb2Cert.claim(uc, uc.partition), packed);
        bytes32 seal = sha256(W.slice(uc.sealPos, uc.pos + uc.len - uc.sealPos));
        claim = FlatClaim(
            keccak256(abi.encodePacked(FlatHash.CLAIM_KEY, seal, packed[:prefixLen])),
            keccak256(abi.encodePacked(FlatHash.CLAIM_VALUE, sha256(packed))),
            packed
        );
    }

    function conflictOpening(bytes calldata input, FlatClaim calldata candidate)
        external
        pure
        returns (bytes memory opening, bytes32 candidateRoot)
    {
        bytes calldata b = FlatPacket.argument(input);
        FlatPacket.Run memory packet = FlatPacket.frameRun(b);
        assertTrue(packet.resume);
        assertEq(packet.opCount, 2);
        assertEq(packet.operations[1].opcode, 3);
        uint256 sid = packet.operations[1].pos;
        uint256 p = sid + 32 + 32 * W.popcount(uint256(W.word(b, sid)));
        bytes calldata wire = b[p:];
        assertEq(W.number(wire, 0, 2), 1); // Mode 0, present 1.
        return (wire, _foldCandidate(wire, candidate));
    }

    function _foldCandidate(bytes calldata opening, FlatClaim calldata candidate)
        private
        pure
        returns (bytes32 root)
    {
        root = FlatHash.node(FlatHash.CLAIM, candidate.key, candidate.value);
        uint256 bitmap = uint256(W.word(opening, 34));
        uint256 p = 66;
        bytes32 empty;
        for (uint256 h; h < 256; ++h) {
            bytes32 sibling = empty;
            if ((bitmap >> h) & 1 != 0) {
                sibling = W.word(opening, p);
                p += 32;
            }
            root = (uint256(candidate.key) >> h) & 1 == 0
                ? FlatHash.node(FlatHash.CLAIM_NODE, root, sibling)
                : FlatHash.node(FlatHash.CLAIM_NODE, sibling, root);
            empty = FlatHash.node(FlatHash.CLAIM_NODE, empty, empty);
        }
        assertEq(p, opening.length);
    }

    function _read(string memory name) private view returns (bytes memory) {
        return vm.readFileBinary(string.concat(FIXTURE, name));
    }
}
