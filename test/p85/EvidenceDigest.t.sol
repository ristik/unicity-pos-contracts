// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {RootVoteCbor} from "../../src/p85/RootVoteCbor.sol";
import {KeyLib} from "../../src/p85/KeyLib.sol";

/// @dev External wrappers so the library's reverts and memory results are testable.
contract CodecHarness {
    function voteDomain(bytes32 g) external pure returns (bytes memory) {
        return RootVoteCbor.voteDomain(g);
    }

    function timeoutDomain(bytes32 g) external pure returns (bytes memory) {
        return RootVoteCbor.timeoutDomain(g);
    }

    function voteInfo(
        uint64 n,
        bytes calldata dv,
        uint64 epoch,
        uint64 round,
        uint64 parent,
        bytes32 exec,
        uint64 ts
    ) external pure returns (bytes memory) {
        return RootVoteCbor.voteInfo(n, dv, epoch, round, parent, exec, ts);
    }

    function votePreimage(
        uint64 n,
        bytes calldata dv,
        bytes32 vh,
        bool committing,
        bytes32 commitHash,
        uint64 commitRound
    ) external pure returns (bytes memory) {
        return RootVoteCbor.votePreimage(n, dv, vh, committing, commitHash, commitRound);
    }

    function sealSigBytes(uint64 n, uint64 round, uint64 epoch, uint64 ts, bytes32 vh, bytes32 hash)
        external
        pure
        returns (bytes memory)
    {
        return RootVoteCbor.sealSigBytes(n, round, epoch, ts, vh, hash);
    }

    function timeoutPreimage(
        uint64 n,
        bytes calldata dt,
        uint64 epoch,
        uint64 round,
        uint64 high,
        bool hasAnchor,
        bytes32 ag,
        uint64 ae,
        uint64 as_,
        bytes calldata author
    ) external pure returns (bytes memory) {
        return RootVoteCbor.timeoutPreimage(
            n, dt, epoch, round, high, hasAnchor, ag, ae, as_, author
        );
    }

    function verifyNative(address expected, bytes32 digest, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        return KeyLib.verifyNative(expected, digest, sig);
    }

    function toAddress(bytes calldata key) external view returns (address) {
        return KeyLib.toAddress(key);
    }
}

/// @notice The shared Go-generated corpus (`fixtures/evidence-digest-corpus-go-v1.json`, converted to `fixtures/evidence-digest-corpus-v1.json` by `script/evidence-corpus-convert.py`, bft-core s1ref `s1gen.BuildDigestCorpus`, checked there
/// against the production `votesig` encoder and verifier): Solidity reproduces VI, VH, PV, the digest, the native seal bytes and the timeout
/// preimages byte for byte, and accepts the Go keys' real signatures under the native rules.
///
/// Each context is decoded once with `vm.parseJson` into the structs below (their fields are in the alphabetical order foundry decodes a JSON object
/// in; every vote and timeout has the same fixed schema), so a test never re-parses the file.
abstract contract CorpusBase is Test {
    string internal constant CORPUS = "/test/p85/fixtures/evidence-digest-corpus-v1.json";

    // Hex values are 0x-prefixed in the file, so the decoder reads them as bytes (a 32-byte value as bytes32, never as a number); numbers are
    // JSON numbers. Absent commit data is the zero hash and "0x".
    struct SealJ {
        uint256 commitEpoch;
        bytes32 commitHash;
        uint256 commitRound;
        uint256 network;
        bytes32 previousHash;
        bytes sigBytes;
        bytes signature;
        uint256 timestamp;
    }

    struct VoteJ {
        bytes32 commitHash;
        uint256 commitRound;
        bool committing;
        string description;
        bytes32 digest;
        uint256 epoch;
        bytes32 exec;
        string id;
        bytes key;
        uint256 parent;
        bytes preimage;
        uint256 round;
        SealJ seal;
        bytes sig64;
        bytes sig65;
        bytes sigHighS;
        string signer;
        uint256 timestamp;
        bytes voteInfo;
        bytes32 voteInfoHash;
    }

    struct AnchorJ {
        uint256 epoch;
        bytes32 genesisId;
        uint256 slot;
    }

    struct TimeoutJ {
        AnchorJ anchor;
        string author;
        string description;
        bytes32 digest;
        uint256 epoch;
        bool hasAnchor;
        uint256 highQcRound;
        string id;
        bytes key;
        bytes preimage;
        uint256 round;
        bytes sig64;
        string signer;
    }

    struct PairJ {
        string a;
        string b;
        string description;
        bool equivocation;
        string id;
    }

    struct CtxJ {
        bytes32 genesis;
        uint256 network;
        PairJ[] pairs;
        string timeoutDomain;
        TimeoutJ[] timeouts;
        string voteDomain;
        VoteJ[] votes;
    }

    uint256 internal constant CONTEXTS = 5;

    // (Nothing of the file is kept in storage: a 260 KB string would cost more to store than a whole test may spend. Each access reads and decodes
    // the part it needs, in memory.)
    function _json() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), CORPUS));
    }

    function _ctx(uint256 c) internal view returns (CtxJ memory) {
        return
            abi.decode(
                vm.parseJson(_json(), string.concat(".contexts[", vm.toString(c), "]")), (CtxJ)
            );
    }

    function _key(string memory id) internal view returns (bytes memory) {
        return vm.parseJsonBytes(_json(), string.concat(".keys.", id));
    }
}

contract EvidenceDigestCorpusTest is CorpusBase {
    CodecHarness internal h;

    function setUp() public {
        h = new CodecHarness();
    }

    function test_domainsAreTheSignedStrings() public view {
        for (uint256 c; c < CONTEXTS; ++c) {
            CtxJ memory x = _ctx(c);
            assertEq(string(h.voteDomain(x.genesis)), x.voteDomain);
            assertEq(string(h.timeoutDomain(x.genesis)), x.timeoutDomain);
        }
    }

    function test_everyVoteReproducesVIVHPVAndTheDigest() public view {
        uint256 total;
        for (uint256 c; c < CONTEXTS; ++c) {
            CtxJ memory x = _ctx(c);
            bytes memory dv = h.voteDomain(x.genesis);
            uint64 n = uint64(x.network);
            for (uint256 i; i < x.votes.length; ++i) {
                VoteJ memory v = x.votes[i];
                ++total;
                bytes memory vi = h.voteInfo(
                    n,
                    dv,
                    uint64(v.epoch),
                    uint64(v.round),
                    uint64(v.parent),
                    v.exec,
                    uint64(v.timestamp)
                );
                assertEq(vi, v.voteInfo, string.concat("VI ", v.id));
                bytes32 vh = sha256(vi);
                assertEq(vh, v.voteInfoHash, string.concat("VH ", v.id));
                bytes32 commitHash = v.committing ? v.commitHash : bytes32(0);
                bytes memory pv =
                    h.votePreimage(n, dv, vh, v.committing, commitHash, uint64(v.commitRound));
                assertEq(pv, v.preimage, string.concat("PV ", v.id));
                assertEq(sha256(pv), v.digest, string.concat("digest ", v.id));
                if (v.committing) {
                    bytes memory sb = h.sealSigBytes(
                        n,
                        uint64(v.seal.commitRound),
                        uint64(v.seal.commitEpoch),
                        uint64(v.seal.timestamp),
                        vh,
                        commitHash
                    );
                    assertEq(sb, v.seal.sigBytes, string.concat("seal ", v.id));
                    assertEq(v.seal.previousHash, vh);
                }
            }
        }
        assertGe(total, 80, "the whole corpus was replayed");
    }

    function test_theGoKeysSignaturesVerifyUnderTheNativeRules() public view {
        for (uint256 c; c < CONTEXTS; ++c) {
            CtxJ memory x = _ctx(c);
            for (uint256 i; i < x.votes.length; ++i) {
                VoteJ memory v = x.votes[i];
                address signer = h.toAddress(v.key);
                bytes32 digest = v.digest;
                assertTrue(h.verifyNative(signer, digest, v.sig64), string.concat("sig64 ", v.id));
                assertTrue(h.verifyNative(signer, digest, v.sig65), string.concat("sig65 ", v.id));
                assertFalse(
                    h.verifyNative(signer, digest, v.sigHighS), string.concat("high s ", v.id)
                );
                if (v.committing) {
                    bytes32 sd = sha256(v.seal.sigBytes);
                    assertTrue(h.verifyNative(signer, sd, v.seal.signature), v.id);
                    // neither signature stands in for the other
                    assertFalse(h.verifyNative(signer, digest, v.seal.signature), v.id);
                    assertFalse(h.verifyNative(signer, sd, v.sig64), v.id);
                }
            }
        }
    }

    function test_timeoutPreimagesAndDigestsMatch() public view {
        uint256 total;
        for (uint256 c; c < CONTEXTS; ++c) {
            CtxJ memory x = _ctx(c);
            bytes memory dt = h.timeoutDomain(x.genesis);
            for (uint256 i; i < x.timeouts.length; ++i) {
                TimeoutJ memory t = x.timeouts[i];
                ++total;
                bytes memory pt = h.timeoutPreimage(
                    uint64(x.network),
                    dt,
                    uint64(t.epoch),
                    uint64(t.round),
                    uint64(t.highQcRound),
                    t.hasAnchor,
                    t.anchor.genesisId,
                    uint64(t.anchor.epoch),
                    uint64(t.anchor.slot),
                    bytes(t.author)
                );
                assertEq(pt, t.preimage, string.concat("PT ", t.id));
                bytes32 d = sha256(pt);
                assertEq(d, t.digest, t.id);
                assertTrue(h.verifyNative(h.toAddress(t.key), d, t.sig64), t.id);
            }
        }
        assertGe(total, 25);
    }

    /// A timeout is not a vote: a vote signature never verifies a timeout digest.
    function test_aTimeoutDigestIsNeverAVoteDigest() public view {
        CtxJ memory x = _ctx(0);
        address signer = h.toAddress(x.votes[0].key);
        for (uint256 i; i < x.timeouts.length; ++i) {
            assertFalse(h.verifyNative(signer, x.timeouts[i].digest, x.votes[0].sig64));
        }
    }

    function test_theHeadWidthBoundariesAreInTheCorpus() public view {
        string[11] memory widths = [
            "0",
            "1",
            "23",
            "24",
            "255",
            "256",
            "65535",
            "65536",
            "4294967295",
            "4294967296",
            "18446744073709551615"
        ];
        CtxJ memory x = _ctx(0);
        uint256 seen;
        for (uint256 i; i < x.votes.length; ++i) {
            for (uint256 w; w < widths.length; ++w) {
                if (
                    keccak256(bytes(x.votes[i].id))
                        == keccak256(bytes(string.concat("width.epoch.", widths[w])))
                ) ++seen;
            }
        }
        assertEq(seen, widths.length, "an epoch at every boundary");
    }
}

/// @dev The deployed Evidence module configured as the corpus' first context (N, G, the Go keys as the genesis identities' root keys).
abstract contract GoSignedBase is P85Flow, CorpusBase {
    uint8 internal constant ROOT = 1;
    string[4] internal signers = ["v1", "v2", "v3", "v5"];
    uint64 internal n0;
    bytes32 internal g0;

    function setUp() public virtual override {
        CtxJ memory x = _ctx(0);
        n0 = uint64(x.network);
        g0 = x.genesis;
        genesisRootEpoch = 2; // the corpus' votes are of voting epoch 2
        super.setUp();
    }

    function _rootNetwork() internal view virtual override returns (uint64) {
        return n0;
    }

    function _rootGenesis() internal view virtual override returns (bytes32) {
        return g0;
    }

    function _rootKey(uint256 i) internal view override returns (bytes memory) {
        return _key(signers[i]);
    }

    function _idx(string memory id) internal view returns (VoteJ memory) {
        VoteJ[] memory vs = _ctx(0).votes;
        for (uint256 i; i < vs.length; ++i) {
            if (keccak256(bytes(vs[i].id)) == keccak256(bytes(id))) return vs[i];
        }
        revert("no such corpus vote");
    }

    function _header(VoteJ memory v) internal pure returns (Evidence.VoteHeader memory) {
        return Evidence.VoteHeader(NETWORK, ROOT, v.key, uint64(v.epoch), uint64(v.round));
    }

    /// @dev The corpus vote as the contract takes it, with the Go signatures.
    function _vote(VoteJ memory j) internal pure returns (Evidence.SignedVote memory v) {
        v.parent = uint64(j.parent);
        v.exec = j.exec;
        v.timestamp = uint64(j.timestamp);
        v.signature = j.sig64;
        if (j.committing) {
            v.committing = true;
            v.commitHash = j.seal.commitHash;
            v.commitRound = uint64(j.seal.commitRound);
            v.commitEpoch = uint64(j.seal.commitEpoch);
            v.commitTimestamp = uint64(j.seal.timestamp);
            v.sealSignature = j.seal.signature;
        }
    }

    function _exposure(string memory signer) internal view returns (bytes32) {
        for (uint256 i; i < signers.length; ++i) {
            if (keccak256(bytes(signers[i])) == keccak256(bytes(signer))) {
                return genesisExposure(i);
            }
        }
        revert("no such signer");
    }

    function _pair(string memory id) internal view returns (PairJ memory) {
        PairJ[] memory ps = _ctx(0).pairs;
        for (uint256 p; p < ps.length; ++p) {
            if (keccak256(bytes(ps[p].id)) == keccak256(bytes(id))) return ps[p];
        }
        revert("no such pair");
    }
}

contract EvidenceGoSignedTest is GoSignedBase {
    // --- the offences the corpus says are offences ----------------------------------------------------

    function test_everyGoSignedEquivocatingPairIsAdmitted() public {
        // pair by pair on a fresh state: the offence ID is per slot
        PairJ[] memory ps = _ctx(0).pairs;
        uint256 admitted;
        for (uint256 k; k < ps.length; ++k) {
            if (!ps[k].equivocation) continue;
            uint256 snap = vm.snapshotState();
            VoteJ memory a = _idx(ps[k].a);
            bytes32 caseID = evidence.submitEvidence(
                _header(a), _vote(a), _vote(_idx(ps[k].b)), _exposure(a.signer)
            );
            assertEq(evidence.caseInfo(caseID).lotCount, 1, ps[k].id);
            ++admitted;
            vm.revertToState(snap);
        }
        assertEq(admitted, 4);
    }

    function test_theOrderOfTheStatementsDoesNotMatter() public {
        VoteJ memory ia = _idx("eq.a");
        VoteJ memory ib = _idx("eq.b");
        uint256 snap = vm.snapshotState();
        bytes32 first =
            evidence.submitEvidence(_header(ia), _vote(ia), _vote(ib), genesisExposure(0));
        vm.revertToState(snap);
        bytes32 second =
            evidence.submitEvidence(_header(ia), _vote(ib), _vote(ia), genesisExposure(0));
        assertEq(first, second);
    }

    // --- what is not an offence or does not verify -----------------------------------------------------

    function test_theSameStatementIsNotAnOffenceWhateverTheSignatureForm() public {
        VoteJ memory ia = _idx("eq.a");
        Evidence.SignedVote memory a = _vote(ia);
        Evidence.SignedVote memory withV = _vote(ia);
        withV.signature = ia.sig65; // the same statement, 65-byte form with the true recovery id
        Evidence.VoteHeader memory hdr = _header(ia);
        vm.expectRevert(Evidence.IdenticalStatements.selector);
        evidence.submitEvidence(hdr, a, withV, genesisExposure(0));
        vm.expectRevert(Evidence.IdenticalStatements.selector);
        evidence.submitEvidence(hdr, a, a, genesisExposure(0));
    }

    function test_aRecoveryByteOfEitherParityIsDiscardedAndOthersAreRefused() public {
        VoteJ memory ia = _idx("eq.a");
        VoteJ memory ib = _idx("eq.b");
        Evidence.VoteHeader memory hdr = _header(ia);
        Evidence.SignedVote memory a = _vote(ia);
        Evidence.SignedVote memory b = _vote(ib);
        bytes memory sig = a.signature;
        // v = 0 and v = 1 both pass whatever the true parity (the roots never match it)
        for (uint8 v = 0; v <= 1; ++v) {
            uint256 snap = vm.snapshotState();
            a.signature = abi.encodePacked(sig, v);
            evidence.submitEvidence(hdr, a, b, genesisExposure(0));
            vm.revertToState(snap);
        }
        for (
            uint8 v = 2; // 2 and 28: any other recovery byte is refused (27/28 included)
            v <= 28;
            v += 26
        ) {
            a.signature = abi.encodePacked(sig, v);
            vm.expectRevert(Evidence.BadSignature.selector);
            evidence.submitEvidence(hdr, a, b, genesisExposure(0));
        }
        a.signature = abi.encodePacked(sig, uint8(0), uint8(0)); // 66 bytes
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(0));
        a.signature = new bytes(63);
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(0));
    }

    function test_aHighSSignatureIsRefused() public {
        VoteJ memory ia = _idx("eq.a");
        VoteJ memory ib = _idx("eq.b");
        Evidence.SignedVote memory a = _vote(ia);
        a.signature = ia.sigHighS;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(_header(ia), a, _vote(ib), genesisExposure(0));
    }

    function test_eachTypedFieldIsBoundByTheSignature() public {
        VoteJ memory ia = _idx("eq.ts-a");
        VoteJ memory ib = _idx("eq.ts-b");
        Evidence.VoteHeader memory hdr = _header(ia);
        Evidence.SignedVote memory b = _vote(ib);
        // timestamp altered, dropped, added
        Evidence.SignedVote memory a = _vote(ia);
        a.timestamp += 1;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(0));
        a = _vote(ia);
        a.timestamp = 0;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(0));
        // exec, parent
        a = _vote(ia);
        a.exec ^= bytes32(uint256(1));
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(0));
        a = _vote(ia);
        a.parent -= 1;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(0));
        // the header's round and epoch, which are inside VI
        a = _vote(ia);
        Evidence.VoteHeader memory h2 = _header(ia);
        h2.votingRound += 1;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(h2, a, b, genesisExposure(0));
    }

    function test_aStatementSignedByAnotherKeyIsRefused() public {
        VoteJ memory ia = _idx("eq.a");
        VoteJ memory ib = _idx("eq.b");
        Evidence.VoteHeader memory hdr = _header(ia);
        Evidence.SignedVote memory b = _vote(_idx("other.signer")); // signed by v2 for the same slot
        b.exec = bytes32(ib.exec);
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, _vote(ia), b, genesisExposure(0));
        // the right statement under the wrong key in the header
        Evidence.VoteHeader memory wrongKey = _header(ia);
        wrongKey.key = _key("v2");
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(wrongKey, _vote(ia), _vote(ib), genesisExposure(1));
    }

    function test_nullAndHashAreNotConfused() public {
        // the committing statement presented as non-committing (and the reverse) changes PV
        VoteJ memory ia = _idx("eq.cm-a");
        VoteJ memory ib = _idx("eq.nc-cm");
        Evidence.VoteHeader memory hdr = _header(ia);
        Evidence.SignedVote memory a = _vote(ia);
        Evidence.SignedVote memory asPlain = _vote(ia);
        asPlain.committing = false;
        asPlain.commitHash = 0;
        asPlain.commitRound = 0;
        asPlain.commitEpoch = 0;
        asPlain.commitTimestamp = 0;
        asPlain.sealSignature = "";
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, asPlain, _vote(ib), genesisExposure(1));
        Evidence.SignedVote memory plainAsCommitting = _vote(ib);
        plainAsCommitting.committing = true;
        plainAsCommitting.commitHash = bytes32(0);
        plainAsCommitting.commitRound = 1;
        plainAsCommitting.commitEpoch = 1;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, plainAsCommitting, genesisExposure(1));
        // a half-empty pair is no statement at all
        Evidence.SignedVote memory half = _vote(ib);
        half.commitRound = 5;
        vm.expectRevert(Evidence.BadStatement.selector);
        evidence.submitEvidence(hdr, a, half, genesisExposure(1));
        half = _vote(ia);
        half.commitRound = 0;
        vm.expectRevert(Evidence.BadStatement.selector);
        evidence.submitEvidence(hdr, half, _vote(ib), genesisExposure(1));
    }

    /// A non-committing vote carries no commit data: each commit field alone is refused as a malformed statement (before any signature is looked at).
    function test_aNonCommittingVoteCarryingCommitDataIsRefused() public {
        VoteJ memory ia = _idx("eq.a");
        VoteJ memory ib = _idx("eq.b");
        Evidence.VoteHeader memory hdr = _header(ia);
        Evidence.SignedVote memory bad = _vote(ia);
        bad.commitHash = bytes32(uint256(1));
        vm.expectRevert(Evidence.BadStatement.selector);
        evidence.submitEvidence(hdr, bad, _vote(ib), genesisExposure(0));
        bad = _vote(ia);
        bad.commitEpoch = 1;
        vm.expectRevert(Evidence.BadStatement.selector);
        evidence.submitEvidence(hdr, bad, _vote(ib), genesisExposure(0));
        bad = _vote(ia);
        bad.commitTimestamp = 1;
        vm.expectRevert(Evidence.BadStatement.selector);
        evidence.submitEvidence(hdr, bad, _vote(ib), genesisExposure(0));
        // the unmodified pair is accepted: the refusals above are the commit fields and nothing else
        evidence.submitEvidence(hdr, _vote(ia), _vote(ib), genesisExposure(0));
    }

    function test_theSealSignatureNeverStandsInForTheVoteSignatureOrTheReverse() public {
        VoteJ memory ia = _idx("eq.cm-a");
        VoteJ memory ib = _idx("eq.cm-b");
        Evidence.VoteHeader memory hdr = _header(ia);
        Evidence.SignedVote memory b = _vote(ib);
        Evidence.SignedVote memory a = _vote(ia);
        (bytes memory vs, bytes memory ss) = (a.signature, a.sealSignature);
        a.signature = ss;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(1));
        a.signature = vs;
        a.sealSignature = vs;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(1));
        a.sealSignature = "";
        vm.expectRevert(Evidence.SealSignatureMissing.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(1));
        // a non-committing vote carries no seal signature
        VoteJ memory ic = _idx("eq.nc-cm");
        Evidence.SignedVote memory plain = _vote(ic);
        plain.sealSignature = vs;
        vm.expectRevert(Evidence.SealSignatureForbidden.selector);
        evidence.submitEvidence(hdr, _vote(ia), plain, genesisExposure(1));
        // a seal that names another timestamp or commit epoch is another message
        a = _vote(ia);
        a.commitTimestamp += 1;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(1));
        a = _vote(ia);
        a.commitEpoch = 2;
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(1));
        a = _vote(ia);
        a.commitEpoch = 3; // above the voting epoch
        vm.expectRevert(Evidence.CommitMismatch.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(1));
    }

    function test_theStatementRulesOfTheRootsAreEnforced() public {
        VoteJ memory ia = _idx("eq.a");
        VoteJ memory ib = _idx("eq.b");
        Evidence.VoteHeader memory hdr = _header(ia);
        Evidence.SignedVote memory b = _vote(ib);
        Evidence.SignedVote memory a = _vote(ia);
        a.parent = hdr.votingRound; // a parent at or above the voting round
        vm.expectRevert(Evidence.BadStatement.selector);
        evidence.submitEvidence(hdr, a, b, genesisExposure(0));
        Evidence.VoteHeader memory zero = _header(ia);
        zero.votingRound = 0;
        vm.expectRevert(Evidence.BadStatement.selector);
        evidence.submitEvidence(zero, _vote(ia), b, genesisExposure(0));
    }

    function test_theEvmDomainDoesNotRunThroughTheRootCodec() public {
        Evidence.VoteHeader memory hdr = _header(_idx("eq.a"));
        hdr.domain = 2;
        vm.expectRevert(Evidence.BadDomain.selector);
        evidence.submitEvidence(hdr, _vote(_idx("eq.a")), _vote(_idx("eq.b")), genesisExposure(0));
        hdr.domain = 1;
        Evidence.EvmVote memory e = Evidence.EvmVote(bytes32(uint256(1)), "");
        vm.expectRevert(Evidence.EvmEvidenceUndefined.selector); // the EVM path is fail-closed
        evidence.submitEvmEvidence(hdr, e, e, genesisExposure(0));
    }

    // --- authenticated configuration -----------------------------------------------------------------

    function test_theRootNetworkAndGenesisAreTheManifests() public view {
        assertEq(evidence.rootNetwork(), n0);
        assertEq(evidence.rootGenesis(), g0);
        assertEq(
            string(evidence.voteDomain()), vm.parseJsonString(_json(), ".contexts[0].voteDomain")
        );
    }

    // --- gas ---------------------------------------------------------------------------------------------

    /// COLD gas of the complete submission (the first touch of every account and slot: this test is its own transaction after setUp, so
    /// nothing is warm; the 21,000 transaction base and the calldata are not included), for two non-committing and for two committing votes.
    function test_gasColdOfACompleteSubmissionNonCommitting() public {
        VoteJ memory ja = _idx("eq.a");
        VoteJ memory jb = _idx("eq.b");
        Evidence.VoteHeader memory hdr = _header(ja);
        Evidence.SignedVote memory a = _vote(ja);
        Evidence.SignedVote memory b = _vote(jb);
        bytes32 expo = genesisExposure(0);
        uint256 before = gasleft();
        evidence.submitEvidence(hdr, a, b, expo);
        uint256 used = before - gasleft();
        emit log_named_uint("submitEvidence cold, two non-committing votes", used);
        assertLt(used, 1_000_000);
    }

    function test_gasColdOfACompleteSubmissionCommitting() public {
        VoteJ memory ja = _idx("eq.cm-a");
        VoteJ memory jb = _idx("eq.cm-b");
        Evidence.VoteHeader memory hdr = _header(ja);
        Evidence.SignedVote memory a = _vote(ja);
        Evidence.SignedVote memory b = _vote(jb);
        bytes32 expo = genesisExposure(1);
        uint256 before = gasleft();
        evidence.submitEvidence(hdr, a, b, expo);
        uint256 used = before - gasleft();
        emit log_named_uint("submitEvidence cold, two committing votes (four signatures)", used);
        assertLt(used, 1_000_000);
    }
}

/// @dev A deployment whose root network differs from the votes' refuses a valid Go pair: N is part of VI and PV.
contract EvidenceWrongNetworkTest is GoSignedBase {
    function _rootNetwork() internal view override returns (uint64) {
        return n0 + 1;
    }

    function test_theGoPairIsRefusedUnderAnotherRootNetwork() public {
        VoteJ memory ia = _idx("eq.a");
        VoteJ memory ib = _idx("eq.b");
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(_header(ia), _vote(ia), _vote(ib), genesisExposure(0));
    }
}

/// @dev ... and one with another root genesis (another vote domain).
contract EvidenceWrongGenesisTest is GoSignedBase {
    function _rootGenesis() internal pure override returns (bytes32) {
        return keccak256("another root genesis");
    }

    function test_theGoPairIsRefusedUnderAnotherRootGenesis() public {
        VoteJ memory ia = _idx("eq.a");
        VoteJ memory ib = _idx("eq.b");
        vm.expectRevert(Evidence.BadSignature.selector);
        evidence.submitEvidence(_header(ia), _vote(ia), _vote(ib), genesisExposure(0));
    }
}
