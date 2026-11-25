// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the immutable V/L/R/batch ceilings validated by custody at genesis.
// Fixed deployment modules are trusted; guard failures must revert the entire bounded operation.
// forge-lint: disable-start(require-revert-in-loop, calls-loop, reentrancy-no-eth)

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {
    Policy,
    Limits,
    CustodyConfig,
    ReserveInput,
    ReserveMember,
    RootRecord,
    RecordKind,
    SessionClosedData,
    AckData,
    RecoveryAckData,
    ClosureData,
    RetirementData,
    Position,
    Exposure,
    Assignment,
    SeatBinding,
    AssignmentSeat
} from "./P85Types.sol";
import {IRootRecords, IPolicySource, IEvidence, IElectionPolicy, CaseView} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";
import {Quantize} from "./Quantize.sol";
import {VRC} from "../vr/VRConstants.sol";
import {VRLiability} from "../vr/VRLiability.sol";

/// @title CustodyStorage
/// @notice The storage, types, errors, events and the helpers shared by StakeCustody and its genesis implementation (CustodyGenesis). Both
/// inherit THIS contract and nothing declares a state variable elsewhere, so the storage layout is one: the genesis implementation runs by
/// delegatecall in the custody's storage and the custody's runtime does not carry the genesis-only code (EIP-170 headroom).
abstract contract CustodyStorage is ReentrancyGuard {
    uint256 internal constant BPS = 10_000;

    // Lot categories: free bonded F, encumbered E, draining D; Released once matured into credit.
    uint8 internal constant CAT_FREE = 1;
    uint8 internal constant CAT_ENCUMBERED = 2;
    uint8 internal constant CAT_DRAINING = 3;
    uint8 internal constant CAT_RELEASED = 4;

    uint8 internal constant ASSIGN_RESERVED = 1;
    uint8 internal constant ASSIGN_ACTIVE = 2;
    uint8 internal constant ASSIGN_ABORTED = 3;

    uint8 internal constant SESSION_OPEN = 1;
    uint8 internal constant SESSION_ACKED = 2;
    uint8 internal constant SESSION_CLOSED = 3;
    uint8 internal constant SESSION_RECOVERED = 4;

    uint8 internal constant ROLE_BIT_OWNER = 1;
    uint8 internal constant ROLE_BIT_WITHDRAWAL = 2;
    uint8 internal constant ROLE_BIT_CONSENT = 4;

    uint8 internal constant ROLE_ROOT = 1;
    uint8 internal constant ROLE_EVM = 2;

    bytes32 internal constant POP_REGISTER = keccak256("unicity.p85.pop.register");
    bytes32 internal constant POP_ROOT_KEY = keccak256("unicity.p85.pop.proposeRootKey");
    bytes32 internal constant BINDING_DOMAIN = keccak256("unicity.p85.delegation-binding");
    bytes32 internal constant EXPOSURE_DOMAIN = keccak256("unicity.p85.exposure");
    /// @dev The profile cap B on a committee's total committed weight.
    uint256 internal constant WEIGHT_CAP_B = Quantize.WEIGHT_CAP_B;
    bytes32 internal constant EXPOSURE_DIGEST_DOMAIN = keccak256("unicity.p85.exposure-digest");
    bytes32 internal constant KEY_DIGEST_DOMAIN = keccak256("unicity.p85.key-history-digest");
    bytes32 internal constant CHAIN_DOMAIN = keccak256("unicity.p85.exposure-chain");
    bytes32 internal constant CLOSURE_DOMAIN = keccak256("unicity.p85.closure");

    // --- errors -------------------------------------------------------------------------------
    error NotFactory();
    error AlreadyInitialized();
    error NotInitialized();
    error ManifestMismatch();
    error InvalidGenesis();
    error NotElection();
    error NotEvidence();
    error NotOwner();
    error UnknownIdentity();
    error InvalidRootKey();
    error KeyAlreadyUsed();
    error BadPossessionProof();
    error ZeroAddress();
    error ZeroValue();
    error AmountTooLarge();
    error GenerationClosing();
    error LotCapacity();
    error NoOpenLots();
    error RetirementAlreadyRequested();
    error RoleNonceMismatch();
    error RoleTupleMismatch();
    error NoPendingRoles();
    error NoRoleChange();
    error NotNominated();
    error StaleGeneration();
    error PrimaryRetiring();
    error IdentityExcluded();
    error InvalidCandidate();
    error SessionExists();
    error AssignmentExists();
    error IncumbentMismatch();
    error LineageMismatch();
    error MembersUnsorted();
    error WrongKey();
    error LotSetMismatch();
    error LotNotEligible();
    error ReferenceCapacity();
    error InsufficientCoverage();
    error ZeroWeight();
    error InvalidMemberCount();
    error RecordsPending();
    error RecordOutOfOrder();
    error UnknownRecordKind();
    error BatchTooLarge();
    error SessionNotOpen();
    error UnknownSession();
    error AssignmentNotReserved();
    error AssignmentNotActive();
    error PendingClosureUnresolved();
    error ClosureDigestMismatch();
    error ConflictingClosure();
    error HRoundMismatch();
    error HRoundBeforeActivation();
    error RetirementNotRequested();
    error RetirementAlreadyImported();
    error RefsStillLive();
    error RefDigestMismatch();
    error RetirementBeforeLiability();
    error LotUnknown();
    error LotAlreadyReleased();
    error LotStillReferenced();
    error RetirementNotImported();
    error EvidenceHoldPending();
    error RoundGateNotMet();
    error EvidenceGateNotMet();
    error TimeGateNotMet();
    error PenaltyAlreadyApplied();
    error LotNotInExposure();
    error ExposureUnknown();
    error InsufficientCredit();
    error TransferFailed();
    error EmptyBatch();
    error TermAnchorPending();
    error TermNotPending();
    error SuccessorNotInstalled();
    error ClosureOpeningMismatch();

    // --- events -------------------------------------------------------------------------------
    event Initialized(bytes32 manifestHash);
    event Registered(
        uint64 indexed id, address indexed owner, bytes32 rootKeyHash, address withdrawal
    );
    event Bonded(uint64 indexed id, uint64 generation, uint256 indexed lotID, uint256 amount);
    event RolesProposed(uint64 indexed id, address owner, address withdrawal, uint64 nonce);
    event RolesAccepted(uint64 indexed id, address owner, address withdrawal, uint64 nonce);
    /// @dev The generic holder event (design 3.9.2): both words are topics, which is what the generic `posretire` scan reads.
    event RetirementRequested(uint64 indexed id, uint64 indexed generation);
    event CandidateReserved(bytes32 indexed resultID, bytes32 sessionID, bytes32 exposureDigest);
    event RootRecordsApplied(uint64 firstIndex, uint64 lastIndex, bytes32 lastRecordID);
    event LiabilityClosed(
        bytes32 indexed assignmentID, uint64 pClose, uint64 tClose, uint64 anchor
    );
    event RetirementImported(uint64 indexed id, uint64 generation, uint64 pRet, uint64 tRet);
    event TermAnchored(bytes32 indexed assignmentID, uint64 p0, uint64 t0);
    event PenaltyApplied(
        bytes32 indexed caseID,
        uint256 indexed lotID,
        uint256 debit,
        uint256 bounty,
        uint256 treasuryCredit
    );
    event LotMatured(uint256 indexed lotID, address indexed creditor, uint256 amount);
    event CreditClaimed(address indexed creditor, address indexed to, uint256 amount);

    // --- storage ------------------------------------------------------------------------------
    struct PendingRoles {
        address newOwner;
        address newWithdrawal;
        uint64 nonce;
        uint8 required; // bit set of ROLE_BIT_*
        uint8 given;
    }

    struct Lot {
        uint64 id;
        uint64 generation;
        uint128 initial;
        uint128 remaining;
        uint128 penalized;
        uint8 category;
        uint16 capBps;
        uint32 refCount;
        uint64 holdRetirement;
        uint64 timeFloor;
        // Maxima over closed obligations; later policy reductions cannot shorten them.
        uint64 holdUntil;
        uint64 evidenceUntil;
        uint64 timeUntil;
        // #1297/#1298: closed terms of this lot whose report anchors are not captured yet (`anchorTerm`); the lot cannot mature
        // while any is. Packed into the word of evidenceUntil and timeUntil, which every closure writes anyway.
        uint32 unanchoredTerms;
    }

    struct Session {
        uint8 state;
        bytes32 assignmentID;
        bytes32 lineage;
        uint64 attempt;
        bytes32 incumbentAssignmentID;
    }

    struct KeyRecord {
        uint64 id;
        uint8 role;
    }

    struct RetirementInfo {
        bool imported;
        uint64 pRet;
        uint64 tRet;
    }

    address public immutable FACTORY;
    bool internal genesisStarted;
    bool public initialized;
    bytes32 internal genesisAssignmentID;
    bytes32 public manifestHash;
    bytes32 public network;
    address public election;
    address public evidence;
    address public policySource;
    address public roots;
    address public treasury;
    uint128 public bondUnit;
    uint128 public minBond;
    Limits public limits;

    uint64 public nextStakingID;
    uint256 public nextLotID;
    bytes32 public lastAckedAssignment;
    // forge-lint: disable-next-line(uninitialized-state)
    uint64 public recordCursor;
    // forge-lint: disable-next-line(uninitialized-state)
    bytes32 public lastRecordID;

    // Accounting: balance = totalFree + totalEncumbered + totalDraining + totalCredits + surplus.
    uint256 public totalFree;
    uint256 public totalEncumbered;
    uint256 public totalDraining;
    // forge-lint: disable-next-line(uninitialized-state)
    uint256 public totalCredits;
    mapping(address => uint256) public credit;

    mapping(uint64 => Position) public positions;
    mapping(uint64 => PendingRoles) internal _pendingRoles;
    mapping(address => uint64) public registerNonce;
    mapping(bytes32 => KeyRecord) internal _keys;
    mapping(uint64 => mapping(uint64 => uint256[])) internal _generationLots;
    mapping(uint256 => Lot) internal _lots;
    mapping(uint64 => mapping(uint64 => RetirementInfo)) public retirements;
    mapping(uint64 => mapping(uint64 => bytes32)) internal _legacyExposureChain;
    mapping(uint64 => mapping(uint64 => uint64)) internal _legacyMaxLiabilityAnchor;
    mapping(uint64 => mapping(uint64 => uint32)) internal _legacyLiveExposures;
    mapping(bytes32 => Assignment) public assignments;
    mapping(bytes32 => Exposure) public exposures;
    mapping(bytes32 => mapping(uint256 => bool)) internal _exposureHasLot;
    mapping(bytes32 => Session) internal _sessions;
    mapping(bytes32 => uint256) public caseDebited;
    mapping(bytes32 => mapping(uint256 => bool)) internal penaltyApplied;
    /// @dev The Reserved J whose closure the root ordered before the session's resolving record, zero when none. Its closure identity and anchors
    /// wait in J's own Assignment (closureKey, hRound, pClose, tClose), unused until J activates; the RecoveryAck applies them. Appended last: no
    /// existing slot moves.
    bytes32 internal pendingAssignment;
    /// @dev The deployment-domain address of the exposure ids (design 3.8 change 3): the VR address on a validator-registry generation,
    /// zero (custody itself) otherwise. Appended last: no slot moves.
    address internal deploymentDomain;
    /// @dev The member-level digest an exposure carries into an output and into the assignment digest, where it is not the lot list's
    /// (VT-04): a genesis exposure on a VR generation carries the VR genesis seat's digest, a recovery copy keeps its incumbent's. Zero: the
    /// keccak of the exposure's lot list (the plain P85 formula). Appended last: no slot moves.
    mapping(bytes32 => bytes32) public exposureMemberDigest;

    struct SlateState {
        bytes32 source;
        uint32 locks;
        bool released;
    }

    // Appended after the proof-facing assignment and session slots.
    uint64 internal _nextBinding;
    mapping(uint64 => SeatBinding) internal _bindings;
    mapping(uint64 => mapping(uint64 => uint64)) internal _latestBinding;
    mapping(bytes32 => uint256[]) internal _seats;
    mapping(bytes32 => SlateState) internal _slateState;

    /// @dev #1297/#1298: a closed term's report anchors. `terminalRoot` (R_H) and `hRecordID` open the applied Closure's closure key;
    /// `p0`/`t0` are the authenticated progress and UC time captured once the Closure, its attribution and the installed successor root
    /// epoch are jointly usable (`anchored`). Appended last: no existing slot moves.
    struct TermAnchor {
        bytes32 terminalRoot;
        bytes32 hRecordID;
        uint64 p0;
        uint64 t0;
        bool anchored;
    }

    mapping(bytes32 => TermAnchor) public termAnchors;

    function _compact() internal view returns (bool) {
        return limits.lMax == 1 && limits.vMax > 8 && deploymentDomain != address(this);
    }

    function _source(bytes32 assignmentID) internal view returns (bytes32 source) {
        source = _slateState[assignmentID].source;
        if (source == bytes32(0)) source = assignmentID;
    }

    function _recordBinding(SeatBinding memory b) internal returns (uint64 handle) {
        handle = ++_nextBinding;
        _bindings[handle] = b;
        _latestBinding[b.id][b.generation] = handle;
    }

    function _exposureID(bytes32 assignmentID, uint64 id) internal view returns (bytes32) {
        return keccak256(
            abi.encode(EXPOSURE_DOMAIN, network, block.chainid, deploymentDomain, assignmentID, id)
        );
    }

    function _packSeat(uint64 id, uint64 handle, uint64 q, uint64 x)
        internal
        pure
        returns (uint256)
    {
        return uint256(id) | (uint256(handle) << 64) | (uint256(q) << 128) | (uint256(x) << 192);
    }

    function _seatLot(uint256 word)
        internal
        view
        returns (uint64 id, uint64 generation, uint256 lotID)
    {
        // The first two packed fields are the id and binding handle.
        // forge-lint: disable-start(unsafe-typecast)
        id = uint64(word);
        generation = _bindings[uint64(word >> 64)].generation;
        // forge-lint: disable-end(unsafe-typecast)
        lotID = _generationLots[id][generation][0];
    }

    function _readSeat(bytes32 assignmentID, bytes32 source, uint256 word)
        internal
        view
        returns (AssignmentSeat memory m)
    {
        // The packed seat fields occupy successive 64-bit words.
        // forge-lint: disable-start(unsafe-typecast)
        m.binding = _bindings[uint64(word >> 64)];
        m.weight = uint64(word >> 128);
        m.rawWeight = uint64(word >> 192);
        uint64 id = uint64(word);
        // forge-lint: disable-end(unsafe-typecast)
        assert(m.binding.id == id);
        m.lotID = _generationLots[id][m.binding.generation][0];
        m.exposureID = _exposureID(assignmentID, id);
        if (source == genesisAssignmentID) {
            m.memberDigest = _exposureID(VRC.GENESIS_RESULT, id);
        } else {
            // ABI encoding of a single dynamic uint256[] with one element.
            m.memberDigest = keccak256(abi.encode(uint256(32), uint256(1), m.lotID));
        }
        m.bindingHash = keccak256(abi.encode(BINDING_DOMAIN, m.binding));
    }

    function _referenceSeat(uint64 id, uint64 generation, uint256 lotID, bytes32 eid) internal {
        Lot storage l = _lots[lotID];
        if (l.refCount >= limits.rMax) revert ReferenceCapacity();
        l.refCount++;
        if (l.category == CAT_FREE) _move(l, CAT_ENCUMBERED);
        VRLiability.Facts storage f = VRLiability.load().facts[id][generation];
        f.liveExposures++;
        f.lotReferences++;
        f.refDigest = keccak256(abi.encode(CHAIN_DOMAIN, f.refDigest, eid));
    }

    function _foldCompact(bytes32 assignmentID, bool referenceSeats) internal {
        bytes32 source = _source(assignmentID);
        uint256[] storage seats = _seats[source];
        bytes32 exposureDigest = EXPOSURE_DIGEST_DOMAIN;
        bytes32 keyDigest = KEY_DIGEST_DOMAIN;
        for (uint256 i = 0; i < seats.length; ++i) {
            AssignmentSeat memory m = _readSeat(assignmentID, source, seats[i]);
            SeatBinding memory b = m.binding;
            if (referenceSeats) _referenceSeat(b.id, b.generation, m.lotID, m.exposureID);
            exposureDigest = keccak256(
                abi.encode(
                    exposureDigest,
                    m.exposureID,
                    b.id,
                    m.weight,
                    m.rawWeight,
                    b.payee,
                    m.memberDigest
                )
            );
            keyDigest = keccak256(abi.encode(keyDigest, b.id, b.rootKeyHash, b.evmKeyHash));
        }
        assignments[assignmentID].exposureDigest = exposureDigest;
        assignments[assignmentID].keyDigest = keyDigest;
    }

    /// @param factory_ the deployment factory that will initialize this module, fixed at construction. The module is deployed first so
    /// the factory's own creation code stays small; only that factory can initialize it, and it can do so once.
    // forge-lint: disable-next-line(missing-zero-check)
    constructor(address factory_) {
        FACTORY = factory_;
    }

    // --- shared internals ---------------------------------------------------------------------

    function _claimKey(bytes memory key, uint64 id, uint8 role) internal returns (bytes32 keyHash) {
        if (key.length != KeyLib.KEY_LENGTH) revert InvalidRootKey();
        keyHash = keccak256(key);
        KeyRecord storage k = _keys[keyHash];
        if (k.id != 0) revert KeyAlreadyUsed();
        k.id = id;
        k.role = role;
    }

    function _newLot(uint64 id, uint256 amount) internal returns (uint256 lotID) {
        Policy memory terms = IPolicySource(policySource).policy();
        Position storage p = positions[id];
        if (amount > type(uint128).max) revert AmountTooLarge();
        lotID = ++nextLotID;
        Lot storage l = _lots[lotID];
        l.id = id;
        l.generation = p.generation;
        // forge-lint: disable-next-line(unsafe-typecast)
        l.initial = uint128(amount); // bounded by the check above
        // forge-lint: disable-next-line(unsafe-typecast)
        l.remaining = uint128(amount);
        l.category = CAT_FREE;
        l.capBps = terms.lifetimeCapBps;
        l.holdRetirement = terms.holdRetirement;
        l.timeFloor = terms.timeFloor;
        totalFree += amount;
        p.openLots++;
        p.lotCount++;
        _generationLots[id][p.generation].push(lotID);
    }

    function _createExposure(
        bytes32 assignmentID,
        uint64 id,
        uint64 generation,
        uint64 weight,
        uint64 rawWeight,
        bytes32 rootKeyHash,
        bytes32 evmKeyHash,
        address operatorPayee,
        uint256[] memory lotIDs
    ) internal returns (bytes32 exposureID) {
        exposureID = keccak256(
            abi.encode(
                EXPOSURE_DOMAIN,
                network,
                block.chainid,
                deploymentDomain == address(0) ? address(this) : deploymentDomain,
                assignmentID,
                id
            )
        );
        Exposure storage e = exposures[exposureID];
        e.assignmentID = assignmentID;
        e.id = id;
        e.generation = generation;
        e.rootKeyHash = rootKeyHash;
        e.evmKeyHash = evmKeyHash;
        e.weight = weight;
        e.rawWeight = rawWeight;
        e.operatorPayee = operatorPayee;
        for (uint256 i = 0; i < lotIDs.length; ++i) {
            Lot storage l = _lots[lotIDs[i]];
            if (l.refCount >= limits.rMax) revert ReferenceCapacity();
            l.refCount++;
            // An unreferenced lot is never draining here: a retiring identity cannot be reserved and
            // K is derived only from locked, still-referenced exposures.
            if (l.category == CAT_FREE) _move(l, CAT_ENCUMBERED);
            e.lotIDs.push(lotIDs[i]);
            _exposureHasLot[exposureID][lotIDs[i]] = true;
        }
        _legacyLiveExposures[id][generation]++;
        _legacyExposureChain[id][generation] =
            keccak256(abi.encode(CHAIN_DOMAIN, _legacyExposureChain[id][generation], exposureID));
        _writeFacts(id, generation);
    }

    /// @dev The holder-owned facts of (id, generation) in the frozen generic layout (design 3.9.2, ERC-7201 `unicity.vr.liability.v1`),
    /// written in the same function as every liability mutation: the live exposure count, the sum of the generation's lot reference
    /// counts, the exposure chain, the maximum liability anchor. `requested` is written by `_requestFact` (sticky). The lots are at
    /// most lMax (8).
    function _writeFacts(uint64 id, uint64 generation) internal {
        VRLiability.Facts storage f = VRLiability.load().facts[id][generation];
        f.liveExposures = _legacyLiveExposures[id][generation];
        uint256[] storage ids = _generationLots[id][generation];
        uint32 refs = 0;
        for (uint256 i = 0; i < ids.length; ++i) {
            refs += _lots[ids[i]].refCount;
        }
        f.lotReferences = refs;
        f.maxLiabilityAnchor = _legacyMaxLiabilityAnchor[id][generation];
        f.refDigest = _legacyExposureChain[id][generation];
    }

    function _digestExposures(bytes32[] storage ids) internal view returns (bytes32 digest) {
        digest = EXPOSURE_DIGEST_DOMAIN;
        for (uint256 i = 0; i < ids.length; ++i) {
            Exposure storage e = exposures[ids[i]];
            digest = keccak256(
                abi.encode(
                    digest,
                    ids[i],
                    e.id,
                    e.weight,
                    e.rawWeight,
                    e.operatorPayee,
                    exposureMemberDigest[ids[i]] != bytes32(0)
                        ? exposureMemberDigest[ids[i]]
                        : keccak256(abi.encode(e.lotIDs))
                )
            );
        }
    }

    function _digestKeys(bytes32[] storage ids) internal view returns (bytes32 digest) {
        digest = KEY_DIGEST_DOMAIN;
        for (uint256 i = 0; i < ids.length; ++i) {
            Exposure storage e = exposures[ids[i]];
            digest = keccak256(abi.encode(digest, e.id, e.rootKeyHash, e.evmKeyHash));
        }
    }

    function _move(Lot storage l, uint8 to) internal {
        _subCategory(l.category, l.remaining);
        _addCategory(to, l.remaining);
        l.category = to;
    }

    function _addCategory(uint8 category, uint256 amount) internal {
        if (category == CAT_FREE) totalFree += amount;
        else if (category == CAT_ENCUMBERED) totalEncumbered += amount;
        else if (category == CAT_DRAINING) totalDraining += amount;
    }

    function _subCategory(uint8 category, uint256 amount) internal {
        if (category == CAT_FREE) totalFree -= amount;
        else if (category == CAT_ENCUMBERED) totalEncumbered -= amount;
        else if (category == CAT_DRAINING) totalDraining -= amount;
    }
}
