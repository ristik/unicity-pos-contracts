// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the immutable V/L/R/batch ceilings validated by custody at genesis.
// Fixed deployment modules are trusted; guard failures must revert the entire bounded operation.
// forge-lint: disable-start(require-revert-in-loop, calls-loop)

import {AssignmentSeat, Manifest, Policy} from "./P85Types.sol";
import {
    IRootRecords,
    IStakeCustody,
    IElectionPolicy,
    IPolicySource,
    ISealHistory,
    SealEpoch,
    CaseView
} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";
import {RootVoteCbor} from "./RootVoteCbor.sol";

/// @title Evidence
/// @notice Ordinary-EVM objective evidence for the P85 PoS profile (design v5 sections 3-4).
///
/// The verifier checks two distinct signed vote statements for one network, domain, key, voting epoch and round. A ROOT statement is
/// the typed scheme 2 vote of the root consensus: the contract rebuilds the canonical CBOR the roots sign (RootVoteCbor: VI, VH, PV) from
/// the typed fields and the authenticated root network N and genesis G of the manifest, and verifies the signature over sha256(PV), plus,
/// for a committing vote, the native seal signature, with the exposure's exact key. EVM-validator evidence needs its own authenticated
/// format, which is not defined yet; until it is, submitEvmEvidence is fail-closed and always reverts with EvmEvidenceUndefined, so no
/// EVM-domain statement can hold or debit stake. The canonical offence ID excludes signatures and statement order, so a reordered, re-encoded or third conflicting statement is the same offence.
/// Historical attribution comes from the exposure custody recorded for the assignment that held the
/// key in that epoch, never from a current key. Admission installs a hold on every attributable lot
/// atomically; settlement debits ascending lots through StakeCustody and removes each hold once its
/// work is done. Evidence protection is option A: the complete valid pair must execute as an
/// ordinary EVM transaction by the inclusive cutoff.
///
/// The second offence (#1297) is a post-term seal: a quorum of ROOT epoch e's installed committee signed a native seal of commit epoch e
/// at a commit round at or after the installed successor's start, over a root other than the authenticated handoff root R_H of e's
/// applied Closure. The statement is the seal's signed fields with an opaque PreviousHash, so the seal alone suffices. Every seal over R_H is exempt (H's own late commit and the honest frozen-root suffix). One submission charges one
/// signer of the verified quorum subset, through the custody term of epoch e. Root-only terms (no custody assignment for e, or a successor
/// activated by another H) and scheme 1 epochs are not attributable in this version and fail closed.
contract Evidence {
    /// @dev v2: typed by offence kind and bound to the deployment, chain, this contract and the root network and genesis (#1297).
    bytes32 internal constant OFFENCE_DOMAIN = keccak256("unicity.p85.offence.v2");
    bytes32 internal constant CASE_DOMAIN = keccak256("unicity.p85.case");

    uint8 public constant DOMAIN_ROOT = 1;
    uint8 public constant DOMAIN_EVM = 2;
    uint8 public constant KIND_EQUIVOCATION = 1;
    uint8 public constant KIND_POST_TERM = 2;
    /// @dev The B1 signing scheme of the domain-bound scheme 2 votes and seals.
    uint64 internal constant SCHEME_2 = 2;
    /// @dev The largest quorum subset one submission may carry (N_verify of the B1 registry).
    uint256 public constant MAX_QUORUM = 16;

    error NotFactory();
    error AlreadyInitialized();
    error NotInitialized();
    error ManifestMismatch();
    error WrongNetwork();
    error BadDomain();
    error IdenticalStatements();
    error BadSignature();
    error ExposureUnknown();
    error NotAttributable();
    error KeyMismatch();
    error EpochMismatch();
    error AssignmentNotActivated();
    error RoundBeforeEpoch();
    error EvidenceLate();
    error DuplicateOffence();
    error UnknownCase();
    error CaseSettled();
    error NotNextLot();
    error EmptyBatch();
    error BatchTooLarge();
    error BadRootConfig();
    error BadStatement();
    error CommitMismatch();
    error SealSignatureMissing();
    error SealSignatureForbidden();
    error EvmEvidenceUndefined();
    error BadQuorum();
    error QuorumTooSmall();
    error SuccessorUnknown();
    error UnsupportedScheme();
    error NotPostTerm();
    error TermNotClosed();
    error TermNotAnchored();
    error RootOnlyTerm();
    error HandoffMismatch();
    error FrozenRoot();

    event Initialized(bytes32 manifestHash);
    event EvidenceAccepted(
        bytes32 indexed caseID,
        bytes32 indexed offenceID,
        bytes32 exposureID,
        address reporter,
        uint256 budget
    );
    event EvidenceSettled(
        bytes32 indexed caseID, uint32 cursor, uint256 actualDebit, uint256 bounty
    );

    /// @notice One signed ROOT vote statement (scheme 2): the typed fields of the vote besides the header's voting epoch and round.
    /// `timestamp` is the proposal time and is signed exactly when non-zero. A committing vote names the committed state hash and round and the
    /// native seal it signs (commit epoch and timestamp); a non-committing vote leaves all of those zero. `signature` is the vote signature
    /// (65 bytes r||s||v, v in {0, 1} the recovery parity, low s: KeyLib.verifyNative) over sha256(PV); `sealSignature` is the committing vote's signature over the native
    /// seal bytes and must be empty otherwise. Neither stands in for the other.
    struct SignedVote {
        uint64 parent;
        bytes32 exec;
        uint64 timestamp;
        bool committing;
        bytes32 commitHash;
        uint64 commitRound;
        uint64 commitEpoch;
        uint64 commitTimestamp;
        bytes signature;
        bytes sealSignature;
    }

    /// @notice One EVM-domain statement (the authenticated EVM format is not defined yet; submitEvmEvidence refuses every one).
    struct EvmVote {
        bytes32 payload;
        bytes signature;
    }

    /// @notice The signed fields of a native tag-39005 v1 seal of commit epoch `epoch` (#1297), as a seal consumer holds them. The
    /// verifier rebuilds the exact signing bytes C(39005([1, N, commitRound, epoch, commitTimestamp, previousHash, commitHash, null])) under
    /// the installed root network N. `previousHash` is an opaque signed word: the signers choose it and no seal consumer opens it, so a
    /// report needs nothing beyond the seal itself (a VoteInfo opening is never required). The root genesis G does not enter the signed
    /// bytes; it enters the deployment-bound offence ID, and the consensus keys of a root history are genesis-specific (bft-core tooling),
    /// so a seal of another root history sharing N is signed by keys this registry never installed.
    struct PostTermSeal {
        uint64 epoch;
        uint64 commitRound; // the seal's RootChainRoundNumber, compared with the successor's start
        uint64 commitTimestamp;
        bytes32 previousHash;
        bytes32 commitHash; // the seal's Hash
    }

    /// @notice A quorum subset of epoch `epoch`'s installed members: strictly increasing member indices (at most MAX_QUORUM) and one
    /// signature each over sha256(seal bytes). Every signature must verify; a bad, unknown or repeated entry refuses the submission.
    struct SealQuorum {
        uint8[] members;
        bytes[] signatures;
    }

    struct VoteHeader {
        bytes32 network;
        uint8 domain;
        bytes key;
        uint64 votingEpoch;
        uint64 votingRound;
    }

    struct Case {
        bytes32 offenceID;
        bytes32 exposureID;
        uint64 id;
        address reporter;
        uint256 budget;
        uint256 debited;
        uint32 cursor;
        uint32 lotCount;
    }

    address public immutable FACTORY;
    bool public initialized;
    bytes32 public manifestHash;
    bytes32 public network;
    IStakeCustody public custody;
    IElectionPolicy public election;
    IRootRecords public roots;
    uint32 public maxBatch;
    /// @notice The root consensus' numeric network N and genesis identity G, pinned by the manifest: the signed vote domain derives from them.
    uint64 public rootNetwork;
    bytes32 public rootGenesis;
    /// @notice The post-term report window (UC seconds), the policy source's deployment immutable (#1297).
    uint64 public reportWindow;

    mapping(bytes32 => Case) internal _cases;
    mapping(bytes32 => bool) public offenceSeen;
    mapping(uint256 => uint32) internal _holds;
    mapping(uint64 => bool) internal _excluded;
    mapping(bytes32 => bytes32) internal _caseAssignments;
    mapping(bytes32 => uint256) internal _caseOrdinals;

    /// @param factory_ the deployment factory that will initialize this module, fixed at construction. The module is deployed first so
    /// the factory's own creation code stays small; only that factory can initialize it, and it can do so once.
    // forge-lint: disable-next-line(missing-zero-check)
    constructor(address factory_) {
        FACTORY = factory_;
    }

    function initialize(bytes32 manifestHash_, Manifest calldata m) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (initialized) revert AlreadyInitialized();
        if (m.evidence != address(this)) {
            revert ManifestMismatch();
        }
        initialized = true;
        manifestHash = manifestHash_;
        network = m.network;
        // forge-lint: disable-next-line(missing-events-access-control)
        custody = IStakeCustody(m.custody);
        election = IElectionPolicy(m.election);
        roots = IRootRecords(m.roots);
        maxBatch = m.limits.maxBatch;
        // N is a uint16 in the roots' signing configuration and G must name a root genesis: a manifest that cannot describe the signed domain
        // is refused at genesis rather than producing evidence that no signature can match.
        if (m.rootNetwork > type(uint16).max || m.rootGenesis == bytes32(0)) {
            revert BadRootConfig();
        }
        rootNetwork = m.rootNetwork;
        rootGenesis = m.rootGenesis;
        reportWindow = IPolicySource(m.policySource).reportWindow();
        emit Initialized(manifestHash_);
    }

    modifier whenInitialized() {
        _requireInitialized();
        _;
    }

    function _requireInitialized() private view {
        if (!initialized) revert NotInitialized();
    }

    /// @notice The vote domain Dv = "root-vote/" + hex(G) of this deployment.
    function voteDomain() public view returns (bytes memory) {
        return RootVoteCbor.voteDomain(rootGenesis);
    }

    /// @notice VI, the canonical vote info the roots hash into VH.
    function voteInfo(VoteHeader calldata h, SignedVote calldata v)
        public
        view
        returns (bytes memory)
    {
        return RootVoteCbor.voteInfo(
            rootNetwork, voteDomain(), h.votingEpoch, h.votingRound, v.parent, v.exec, v.timestamp
        );
    }

    /// @notice PV, the byte string the vote signature covers (the signer hashes it with SHA-256 itself).
    function votePreimage(VoteHeader calldata h, SignedVote calldata v)
        public
        view
        returns (bytes memory)
    {
        bytes memory dv = voteDomain();
        return _preimage(dv, h, v);
    }

    /// @notice The digest of one ROOT statement: sha256(PV). Reverts on a statement the roots could not have signed.
    function voteDigest(VoteHeader calldata h, SignedVote calldata v)
        public
        view
        returns (bytes32)
    {
        bytes memory dv = voteDomain();
        _checkStatement(h, v);
        return sha256(_preimage(dv, h, v));
    }

    function _preimage(bytes memory dv, VoteHeader calldata h, SignedVote calldata v)
        private
        view
        returns (bytes memory)
    {
        uint64 n = rootNetwork;
        bytes32 vh = sha256(
            RootVoteCbor.voteInfo(
                n, dv, h.votingEpoch, h.votingRound, v.parent, v.exec, v.timestamp
            )
        );
        return RootVoteCbor.votePreimage(n, dv, vh, v.committing, v.commitHash, v.commitRound);
    }

    /// @dev The statement rules of votesig and S1: a voting round above zero and above its parent; a half-empty commit pair refused (a
    /// committing vote names a hash and a commit round above zero and below the voting round); for a committing vote the commit epoch is
    /// within [1, voting epoch]; a non-committing vote carries none of the commit data.
    function _checkStatement(VoteHeader calldata h, SignedVote calldata v) private pure {
        if (h.votingRound == 0 || v.parent >= h.votingRound) revert BadStatement();
        if (v.committing) {
            if (v.commitRound == 0 || v.commitRound >= h.votingRound) revert BadStatement();
            if (v.commitEpoch == 0 || v.commitEpoch > h.votingEpoch) revert CommitMismatch();
        } else if (
            v.commitHash != bytes32(0) || v.commitRound != 0 || v.commitEpoch != 0
                || v.commitTimestamp != 0
        ) {
            revert BadStatement();
        }
    }

    /// @dev Verifies one statement against the exposure's key: the vote signature over sha256(PV) and, for a committing vote, the seal
    /// signature over the native seal bytes. Returns the statement digest.
    function _verifyStatement(
        VoteHeader calldata h,
        SignedVote calldata v,
        bytes memory dv,
        address signer
    ) private view returns (bytes32 digest) {
        _checkStatement(h, v);
        uint64 n = rootNetwork;
        bytes32 vh = sha256(
            RootVoteCbor.voteInfo(
                n, dv, h.votingEpoch, h.votingRound, v.parent, v.exec, v.timestamp
            )
        );
        digest =
            sha256(RootVoteCbor.votePreimage(n, dv, vh, v.committing, v.commitHash, v.commitRound));
        if (!KeyLib.verifyNative(signer, digest, v.signature)) revert BadSignature();
        if (v.committing) {
            if (v.sealSignature.length == 0) revert SealSignatureMissing();
            bytes32 sealDigest = sha256(
                RootVoteCbor.sealSigBytes(
                    n, v.commitRound, v.commitEpoch, v.commitTimestamp, vh, v.commitHash
                )
            );
            if (!KeyLib.verifyNative(signer, sealDigest, v.sealSignature)) revert BadSignature();
        } else if (v.sealSignature.length != 0) {
            revert SealSignatureForbidden();
        }
    }

    /// @notice Canonical equivocation offence ID: independent of signatures and statement order; typed by kind and bound to this
    /// deployment, chain, contract and root network and genesis.
    function offenceIDOf(VoteHeader calldata h) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                OFFENCE_DOMAIN,
                KIND_EQUIVOCATION,
                h.network,
                block.chainid,
                address(this),
                rootNetwork,
                rootGenesis,
                h.domain,
                keccak256(h.key),
                h.votingEpoch,
                h.votingRound
            )
        );
    }

    /// @notice Canonical post-term offence ID of one charged key: the native seal digest and the charged key hash under the typed,
    /// deployment-bound domain. Reporter, signatures, quorum subset, seat ordinal and order are not part of it.
    function postTermOffenceID(uint64 epoch, bytes32 sealDigest, bytes32 keyHash)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                OFFENCE_DOMAIN,
                KIND_POST_TERM,
                network,
                block.chainid,
                address(this),
                rootNetwork,
                rootGenesis,
                DOMAIN_ROOT,
                epoch,
                sealDigest,
                keyHash
            )
        );
    }

    /// @notice sha256 of the native seal signing bytes (Signatures null) under the installed N: what every seal signer signed.
    function postTermSealDigest(PostTermSeal calldata s) public view returns (bytes32) {
        return sha256(
            RootVoteCbor.sealSigBytes(
                rootNetwork, s.commitRound, s.epoch, s.commitTimestamp, s.previousHash, s.commitHash
            )
        );
    }

    /// @notice Admit an objective ROOT-domain offence and install holds on every attributable lot.
    /// @param exposureID The historical exposure of the assignment that held `h.key` in the epoch.
    function submitEvidence(
        VoteHeader calldata h,
        SignedVote calldata a,
        SignedVote calldata b,
        bytes32 exposureID
    ) external whenInitialized returns (bytes32 caseID) {
        _verifyEvidence(h, a, b);
        (bytes32 assignmentID, uint64 id, bytes32 rootKeyHash) = _exposure(exposureID);
        _attributeVote(h, assignmentID, rootKeyHash);
        return
            _admit(offenceIDOf(h), exposureID, assignmentID, id, custody.exposureLots(exposureID));
    }

    /// @notice Submit evidence by ordered seat locator and authenticate the claimed exposure ID.
    function submitSeatEvidence(
        VoteHeader calldata h,
        SignedVote calldata a,
        SignedVote calldata b,
        bytes32 assignmentID,
        uint256 ordinal,
        bytes32 exposureID
    ) external whenInitialized returns (bytes32 caseID) {
        _verifyEvidence(h, a, b);
        AssignmentSeat memory m = _seat(assignmentID, ordinal, exposureID);
        _attributeVote(h, assignmentID, m.binding.rootKeyHash);
        caseID = _admitSeat(offenceIDOf(h), exposureID, assignmentID, ordinal, m);
    }

    /// @notice Admit a post-term seal offence (#1297) against the historical exposure of the charged key's epoch-e assignment
    /// (legacy layout: every lot of the exposure).
    function submitPostTermEvidence(
        PostTermSeal calldata s,
        SealQuorum calldata q,
        bytes32 exposureID
    ) external whenInitialized returns (bytes32 caseID) {
        (bytes32 assignmentID, uint64 id, bytes32 rootKeyHash) = _exposure(exposureID);
        bytes32 offenceID = _verifyPostTerm(s, q, assignmentID, rootKeyHash);
        return _admit(offenceID, exposureID, assignmentID, id, custody.exposureLots(exposureID));
    }

    /// @notice Admit a post-term seal offence (#1297) by the exact seat of the charged key in its epoch-e assignment (compact layout:
    /// the seat's lot).
    function submitPostTermSeatEvidence(
        PostTermSeal calldata s,
        SealQuorum calldata q,
        bytes32 assignmentID,
        uint256 ordinal,
        bytes32 exposureID
    ) external whenInitialized returns (bytes32 caseID) {
        AssignmentSeat memory m = _seat(assignmentID, ordinal, exposureID);
        bytes32 offenceID = _verifyPostTerm(s, q, assignmentID, m.binding.rootKeyHash);
        caseID = _admitSeat(offenceID, exposureID, assignmentID, ordinal, m);
    }

    function _exposure(bytes32 exposureID)
        private
        view
        returns (bytes32 assignmentID, uint64 id, bytes32 rootKeyHash)
    {
        // This lookup needs only the assignment, staking ID and historical root key.
        // forge-lint: disable-start(unused-return)
        (assignmentID, id,,,, rootKeyHash,,,,) = custody.exposures(exposureID);
        // forge-lint: disable-end(unused-return)
        if (assignmentID == bytes32(0)) revert ExposureUnknown();
    }

    function _seat(bytes32 assignmentID, uint256 ordinal, bytes32 exposureID)
        private
        view
        returns (AssignmentSeat memory m)
    {
        if (ordinal >= custody.assignmentSeatCount(assignmentID)) revert ExposureUnknown();
        m = custody.assignmentSeat(assignmentID, ordinal);
        if (m.exposureID != exposureID) revert ExposureUnknown();
    }

    function _admitSeat(
        bytes32 offenceID,
        bytes32 exposureID,
        bytes32 assignmentID,
        uint256 ordinal,
        AssignmentSeat memory m
    ) private returns (bytes32 caseID) {
        uint256[] memory lotIDs = new uint256[](1);
        lotIDs[0] = m.lotID;
        caseID = _admit(offenceID, exposureID, assignmentID, m.binding.id, lotIDs);
        _caseAssignments[caseID] = assignmentID;
        _caseOrdinals[caseID] = ordinal;
    }

    /// @dev The post-term statement (#1297), checked against installed and authenticated state only:
    /// - the native seal digest rebuilt under the installed N, PreviousHash taken as the opaque signed word;
    /// - installed consecutive epochs e and e+1 with end[e] == start[e+1], e signing with scheme 2;
    /// - the offence: commitRound >= start[e+1] (equality counts) and Hash != R_H;
    /// - attribution: the custody assignment of root epoch e, closed by its applied Closure whose H RecordID activated e+1 and whose
    ///   ordered round precedes start[e+1], with its report anchors captured;
    /// - the deadline: progress <= p0 + suffixEvidenceWindow OR UC time <= t0 + reportWindow (both inclusive);
    /// - one verified quorum subset of e's members holding the charged key.
    function _verifyPostTerm(
        PostTermSeal calldata s,
        SealQuorum calldata q,
        bytes32 assignmentID,
        bytes32 keyHash
    ) private view returns (bytes32 offenceID) {
        ISealHistory reg = ISealHistory(address(roots));
        SealEpoch memory pre = reg.sealEpoch(s.epoch);
        SealEpoch memory succ = reg.sealEpoch(s.epoch + 1);
        if (!pre.present || !succ.present || !pre.hasEnd || pre.end != succ.start) {
            revert SuccessorUnknown();
        }
        if (pre.signingScheme != SCHEME_2) revert UnsupportedScheme();
        if (s.commitRound < succ.start) revert NotPostTerm();

        Asg memory a = _assignment(assignmentID);
        if (a.rootEpoch != s.epoch) revert EpochMismatch();
        if (!a.closed) revert TermNotClosed();
        (bytes32 terminalRoot, bytes32 hRecordID, uint64 p0, uint64 t0, bool anchored) =
            custody.termAnchors(assignmentID);
        if (!anchored) revert TermNotAnchored();
        if (hRecordID != succ.activationCommitID) revert RootOnlyTerm();
        if (a.hRound >= succ.start) revert HandoffMismatch();
        if (s.commitHash == terminalRoot) revert FrozenRoot();
        Policy memory terms = custody.policyTerms(assignmentID);
        if (
            roots.progress() > uint256(p0) + terms.suffixEvidenceWindow
                && roots.ucTime() > uint256(t0) + reportWindow
        ) revert EvidenceLate();

        bytes32 digest = postTermSealDigest(s);
        _verifyQuorum(reg, s.epoch, pre, digest, q, keyHash);
        offenceID = postTermOffenceID(s.epoch, digest, keyHash);
    }

    /// @dev One strictly increasing subset of epoch e's member indices, every signature valid under the strict native rule, the checked
    /// weight sum at least floor(2 * total / 3) + 1, and the charged key among the signers.
    function _verifyQuorum(
        ISealHistory reg,
        uint64 epoch,
        SealEpoch memory pre,
        bytes32 digest,
        SealQuorum calldata q,
        bytes32 keyHash
    ) private view {
        uint256 count = q.members.length;
        if (count == 0 || count > MAX_QUORUM || q.signatures.length != count) revert BadQuorum();
        // the indices first: strictly increasing (no repeat) and installed
        for (uint256 i = 0; i < count; ++i) {
            if (q.members[i] >= pre.memberCount || (i != 0 && q.members[i] <= q.members[i - 1])) {
                revert BadQuorum();
            }
        }
        uint256 weight = 0;
        bool charged = false;
        for (uint256 i = 0; i < count; ++i) {
            (uint64 w, bool isCharged) =
                _verifyMember(reg, epoch, q.members[i], digest, q.signatures[i], keyHash);
            weight += w;
            if (isCharged) charged = true;
        }
        if (!charged) revert KeyMismatch();
        if (weight < (uint256(pre.totalWeight) * 2) / 3 + 1) revert QuorumTooSmall();
    }

    /// @dev One subset member: its installed key must have produced `sig` over the seal digest (strict native rule). Returns its weight
    /// and whether it holds the charged key. (A helper of its own keeps the quorum loop within the stack under every profile.)
    function _verifyMember(
        ISealHistory reg,
        uint64 epoch,
        uint8 index,
        bytes32 digest,
        bytes calldata sig,
        bytes32 keyHash
    ) private view returns (uint64 weight, bool charged) {
        bytes memory key;
        (key, weight) = reg.sealMember(epoch, index);
        if (!KeyLib.verifyNative(KeyLib.toAddress(key), digest, sig)) revert BadSignature();
        charged = keccak256(key) == keyHash;
    }

    function _verifyEvidence(VoteHeader calldata h, SignedVote calldata a, SignedVote calldata b)
        private
        view
    {
        if (h.network != network) revert WrongNetwork();
        if (h.domain != DOMAIN_ROOT) revert BadDomain();
        // The key is decompressed once and the domain built once; both statements and both seals are checked against that address.
        address signer = KeyLib.toAddress(h.key);
        bytes memory dv = RootVoteCbor.voteDomain(rootGenesis);
        bytes32 da = _verifyStatement(h, a, dv, signer);
        bytes32 db = _verifyStatement(h, b, dv, signer);
        if (da == db) revert IdenticalStatements();
    }

    /// @notice EVM-domain evidence. The EVM-validator vote needs its own authenticated format, which is not defined yet; until it is,
    /// this path is fail-closed: every call reverts with EvmEvidenceUndefined, whatever it carries, so no EVM-domain statement can hold
    /// or debit stake. Root votes go through `submitEvidence`, which verifies the real signed message.
    function submitEvmEvidence(VoteHeader calldata, EvmVote calldata, EvmVote calldata, bytes32)
        external
        pure
        returns (bytes32)
    {
        revert EvmEvidenceUndefined();
    }

    /// @dev The equivocation's attribution and deadline: a non-aborted assignment of the voting epoch holding the exact key, timely.
    function _attributeVote(VoteHeader calldata h, bytes32 assignmentID, bytes32 rootKeyHash)
        private
        view
    {
        if (offenceSeen[offenceIDOf(h)]) revert DuplicateOffence();
        Asg memory asg = _assignment(assignmentID);
        if (asg.state == 3) revert NotAttributable();
        // only the root domain is admitted (submitEvmEvidence is fail-closed)
        if (keccak256(h.key) != rootKeyHash) revert KeyMismatch();
        if (h.votingEpoch != asg.rootEpoch) revert EpochMismatch();
        _requireTimely(h.votingRound, asg, custody.policyTerms(assignmentID));
    }

    function _admit(
        bytes32 offenceID,
        bytes32 exposureID,
        bytes32 assignmentID,
        uint64 identity,
        uint256[] memory lotIDs
    ) private returns (bytes32 caseID) {
        if (offenceSeen[offenceID]) revert DuplicateOffence();
        Policy memory terms = custody.policyTerms(assignmentID);
        offenceSeen[offenceID] = true;
        caseID =
            keccak256(abi.encode(CASE_DOMAIN, network, block.chainid, address(this), offenceID));
        uint256 total = 0;
        for (uint256 i = 0; i < lotIDs.length; ++i) {
            // forge-lint: disable-start(unused-return)
            (,, uint128 initialPrincipal,,,,,,,,,,) = custody.lots(lotIDs[i]);
            // forge-lint: disable-end(unused-return)
            total += initialPrincipal;
            _holds[lotIDs[i]]++;
        }
        uint256 budget = (total * terms.penaltyBps) / 10_000;
        _excluded[identity] = true;
        election.coverageChanged(identity);
        _cases[caseID] = Case({
            offenceID: offenceID,
            exposureID: exposureID,
            id: identity,
            reporter: msg.sender,
            budget: budget,
            debited: 0,
            cursor: 0,
            // forge-lint: disable-next-line(unsafe-typecast)
            lotCount: uint32(lotIDs.length) // bounded by lMax, a uint32
        });
        emit EvidenceAccepted(caseID, offenceID, exposureID, msg.sender, budget);
    }

    /// @dev Option A cutoff. Rounds through h use p(offence) + window inclusive; suffix rounds above
    /// h have no expiry before closure and p_close + suffix window inclusive afterwards. Before the
    /// replaced assignment's H is imported every round classifies as ordinary.
    function _requireTimely(uint64 round, Asg memory asg, Policy memory terms) private view {
        if (!asg.offsetSet) revert AssignmentNotActivated();
        if (round < asg.firstRound) revert RoundBeforeEpoch();
        uint256 progress = roots.progress();
        if (asg.hKnown && round > asg.hRound) {
            if (asg.closed && progress > uint256(asg.pClose) + terms.suffixEvidenceWindow) {
                revert EvidenceLate();
            }
            return;
        }
        uint256 offenceProgress = uint256(asg.offset) + (round - asg.firstRound);
        if (progress > offenceProgress + terms.evidenceWindow) revert EvidenceLate();
    }

    function caseLocation(bytes32 caseID)
        external
        view
        returns (bytes32 assignmentID, uint256 ordinal)
    {
        return (_caseAssignments[caseID], _caseOrdinals[caseID]);
    }

    /// @notice Settle the next ascending lots of a case. Each lot's hold is removed once its
    /// penalty work is done; custody reads the case itself and caps the debit.
    function settleEvidence(bytes32 caseID, uint256[] calldata lotIDs)
        external
        whenInitialized
        returns (uint256 actualDebit)
    {
        Case storage c = _cases[caseID];
        if (c.reporter == address(0)) revert UnknownCase();
        if (c.cursor == c.lotCount) revert CaseSettled();
        if (lotIDs.length == 0) revert EmptyBatch();
        if (lotIDs.length > maxBatch) revert BatchTooLarge();
        bytes32 assignmentID = _caseAssignments[caseID];
        uint256[] memory lots;
        if (assignmentID == bytes32(0)) {
            lots = custody.exposureLots(c.exposureID);
        } else {
            lots = new uint256[](1);
            lots[0] = custody.assignmentSeat(assignmentID, _caseOrdinals[caseID]).lotID;
        }
        uint256 bounty = 0;
        for (uint256 i = 0; i < lotIDs.length; ++i) {
            if (c.cursor >= c.lotCount || lotIDs[i] != lots[c.cursor]) revert NotNextLot();
            // forge-lint: disable-start(unused-return)
            (uint256 debit, uint256 b,) = custody.applyPenalty(caseID, lotIDs[i]);
            // forge-lint: disable-end(unused-return)
            c.cursor++;
            c.debited += debit;
            actualDebit += debit;
            bounty += b;
            _holds[lotIDs[i]]--;
        }
        election.coverageChanged(c.id);
        emit EvidenceSettled(caseID, c.cursor, actualDebit, bounty);
    }

    struct Asg {
        uint8 state;
        uint64 rootEpoch;
        uint64 evmEpoch;
        uint64 offset;
        uint64 firstRound;
        bool offsetSet;
        bool hKnown;
        uint64 hRound;
        bool closed;
        uint64 pClose;
    }

    function _assignment(bytes32 assignmentID) private view returns (Asg memory a) {
        // forge-lint: disable-start(unused-return)
        (
            a.state,,
            a.rootEpoch,
            a.evmEpoch,
            a.offset,
            a.firstRound,
            a.offsetSet,
            a.hKnown,
            a.hRound,
            a.closed,
            a.pClose,,,,,
        ) = custody.assignments(assignmentID);
        // forge-lint: disable-end(unused-return)
    }

    function caseInfo(bytes32 caseID) external view returns (CaseView memory v) {
        Case storage c = _cases[caseID];
        v = CaseView(
            c.offenceID, c.exposureID, c.id, c.reporter, c.budget, c.debited, c.cursor, c.lotCount
        );
    }

    /// @notice Release status of a lot from authenticated state only: references, imported
    /// retirement, round/evidence/time gates and accepted-case holds. No off-chain receipt or
    /// clearance exists. The lot matures once every gate below is met and no hold is pending.
    /// While a closed term of the lot awaits its report anchors (#1297/#1298) its time gate is not
    /// determined yet and `timeUntil` reads as type(uint64).max.
    function releaseState(uint256 lotID)
        external
        view
        returns (
            bool released,
            uint32 references,
            bool retirementImported,
            uint64 roundUntil,
            uint64 evidenceUntil,
            uint64 timeUntil,
            uint32 holds
        )
    {
        // forge-lint: disable-start(unused-return)
        (
            uint64 id,
            uint64 generation,,,,
            uint8 category,,
            uint32 refCount,
            uint64 holdRetirement,
            uint64 timeFloor,
            uint64 holdUntil,
            uint64 evidenceUntilLot,
            uint64 timeUntilLot
        ) = custody.lots(lotID);
        // forge-lint: disable-end(unused-return)
        (bool imported, uint64 pRet, uint64 tRet) = custody.retirements(id, generation);
        released = category == 4;
        references = refCount;
        retirementImported = imported;
        roundUntil = pRet + holdRetirement;
        if (holdUntil > roundUntil) roundUntil = holdUntil;
        evidenceUntil = evidenceUntilLot;
        timeUntil = tRet + timeFloor;
        if (timeUntilLot > timeUntil) timeUntil = timeUntilLot;
        if (custody.lotUnanchoredTerms(lotID) != 0) timeUntil = type(uint64).max;
        holds = _holds[lotID];
    }

    function pendingHolds(uint256 lotID) external view returns (uint32) {
        return _holds[lotID];
    }

    function excluded(uint64 id) external view returns (bool) {
        return _excluded[id];
    }
}

// forge-lint: disable-end(require-revert-in-loop, calls-loop)
