// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the immutable V/L/R/batch ceilings validated by custody at genesis.
// Fixed deployment modules are trusted; guard failures must revert the entire bounded operation.
// forge-lint: disable-start(require-revert-in-loop, calls-loop)

import {Manifest, Policy} from "./P85Types.sol";
import {IRootRecords, IStakeCustody, IElectionPolicy, CaseView} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";

/// @title Evidence
/// @notice Ordinary-EVM objective evidence for the P85 PoS profile (design v5 sections 3-4).
///
/// The fixed verifier (S1 fixture format below) checks two distinct signed vote statements for one
/// network, domain, key, voting epoch and round. The canonical offence ID excludes signatures and
/// statement order, so a reordered, re-encoded or third conflicting statement is the same offence.
/// Historical attribution comes from the exposure custody recorded for the assignment that held the
/// key in that epoch, never from a current key. Admission installs a hold on every attributable lot
/// atomically; settlement debits ascending lots through StakeCustody and removes each hold once its
/// work is done. Evidence protection is option A: the complete valid pair must execute as an
/// ordinary EVM transaction by the inclusive cutoff.
contract Evidence {
    bytes32 internal constant VOTE_DOMAIN = keccak256("unicity.p85.s1.vote");
    bytes32 internal constant OFFENCE_DOMAIN = keccak256("unicity.p85.offence");
    bytes32 internal constant CASE_DOMAIN = keccak256("unicity.p85.case");

    uint8 public constant DOMAIN_ROOT = 1;
    uint8 public constant DOMAIN_EVM = 2;

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

    /// @notice One signed vote statement; `payload` is the digest of the canonical VoteInfo bytes
    /// (S1 canonical decoding is the PR1 fixture boundary).
    struct SignedVote {
        bytes32 payload;
        bytes signature;
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

    mapping(bytes32 => Case) internal _cases;
    mapping(bytes32 => bool) public offenceSeen;
    mapping(uint256 => uint32) internal _holds;
    mapping(uint64 => bool) internal _excluded;

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
        emit Initialized(manifestHash_);
    }

    modifier whenInitialized() {
        _requireInitialized();
        _;
    }

    function _requireInitialized() private view {
        if (!initialized) revert NotInitialized();
    }

    /// @notice The signed digest of one statement.
    function voteDigest(VoteHeader calldata h, bytes32 payload) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VOTE_DOMAIN,
                h.network,
                h.domain,
                keccak256(h.key),
                h.votingEpoch,
                h.votingRound,
                payload
            )
        );
    }

    /// @notice Canonical offence ID: independent of signatures and statement order.
    function offenceIDOf(VoteHeader calldata h) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                OFFENCE_DOMAIN, h.network, h.domain, keccak256(h.key), h.votingEpoch, h.votingRound
            )
        );
    }

    /// @notice Admit an objective offence and install holds on every attributable lot.
    /// @param exposureID The historical exposure of the assignment that held `h.key` in the epoch.
    function submitEvidence(
        VoteHeader calldata h,
        SignedVote calldata a,
        SignedVote calldata b,
        bytes32 exposureID
    ) external whenInitialized returns (bytes32 caseID) {
        if (h.network != network) revert WrongNetwork();
        if (h.domain != DOMAIN_ROOT && h.domain != DOMAIN_EVM) revert BadDomain();
        if (a.payload == b.payload) revert IdenticalStatements();
        if (!KeyLib.verify(h.key, voteDigest(h, a.payload), a.signature)) revert BadSignature();
        if (!KeyLib.verify(h.key, voteDigest(h, b.payload), b.signature)) revert BadSignature();

        bytes32 offenceID = offenceIDOf(h);
        if (offenceSeen[offenceID]) revert DuplicateOffence();

        // forge-lint: disable-start(unused-return)
        (bytes32 assignmentID, uint64 identity,, bytes32 rootKeyHash, bytes32 evmKeyHash,,,,) =
            custody.exposures(exposureID);
        // forge-lint: disable-end(unused-return)
        if (assignmentID == bytes32(0)) revert ExposureUnknown();
        Asg memory asg = _assignment(assignmentID);
        if (asg.state == 3) revert NotAttributable();
        bytes32 keyHash = keccak256(h.key);
        if (h.domain == DOMAIN_ROOT) {
            if (keyHash != rootKeyHash) revert KeyMismatch();
            if (h.votingEpoch != asg.rootEpoch) revert EpochMismatch();
        } else {
            if (keyHash != evmKeyHash) revert KeyMismatch();
            if (h.votingEpoch != asg.evmEpoch) revert EpochMismatch();
        }
        Policy memory terms = custody.policyTerms(assignmentID);
        _requireTimely(h.votingRound, asg, terms);

        offenceSeen[offenceID] = true;
        caseID =
            keccak256(abi.encode(CASE_DOMAIN, network, block.chainid, address(this), offenceID));
        uint256[] memory lotIDs = custody.exposureLots(exposureID);
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
        uint256[] memory lots = custody.exposureLots(c.exposureID);
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
