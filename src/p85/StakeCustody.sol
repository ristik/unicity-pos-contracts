// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the immutable V/L/R/batch ceilings validated by custody at genesis.
// Fixed deployment modules are trusted; guard failures must revert the entire bounded operation.
// forge-lint: disable-start(require-revert-in-loop, calls-loop)

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
    Assignment
} from "./P85Types.sol";
import {IRootRecords, IPolicySource, IEvidence, IElectionPolicy, CaseView} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";

/// @title StakeCustody
/// @notice Immutable native-UCT self-bond custody for the P85 PoS profile (design v5 sections 2-4).
/// Clean-room implementation written from the design; see docs/p85/PROVENANCE.md.
///
/// Holds identities, roles, lots, key history, assignment exposures and their references, retirement
/// anchors, penalty debit guards, and principal/bounty/treasury credits. Only verified reservation,
/// lifecycle, penalty and maturity transitions change principal; only a credit owner can claim.
///
/// Conservation after every successful call (section 3):
///     balance = F + E + D + C + U,  F + E + D = sum(remaining),  C = sum(credits),  U >= 0.
/// No proxy, delegatecall, arbitrary call, sweep, administrator withdrawal or module setter exists.
contract StakeCustody is ReentrancyGuard {
    uint256 public constant BPS = 10_000;

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
    bytes32 internal constant EXPOSURE_DOMAIN = keccak256("unicity.p85.exposure");
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

    // --- events -------------------------------------------------------------------------------
    event Initialized(bytes32 manifestHash);
    event Registered(
        uint64 indexed id, address indexed owner, bytes32 rootKeyHash, address withdrawal
    );
    event Bonded(uint64 indexed id, uint64 generation, uint256 indexed lotID, uint256 amount);
    event RolesProposed(uint64 indexed id, address owner, address withdrawal, uint64 nonce);
    event RolesAccepted(uint64 indexed id, address owner, address withdrawal, uint64 nonce);
    event RetirementRequested(uint64 indexed id, uint64 generation);
    event CandidateReserved(bytes32 indexed resultID, bytes32 sessionID, bytes32 exposureDigest);
    event RootRecordsApplied(uint64 firstIndex, uint64 lastIndex, bytes32 lastRecordID);
    event LiabilityClosed(
        bytes32 indexed assignmentID, uint64 pClose, uint64 tClose, uint64 anchor
    );
    event RetirementImported(uint64 indexed id, uint64 generation, uint64 pRet, uint64 tRet);
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
    bool public genesisStarted;
    bool public initialized;
    bytes32 public genesisAssignmentID;
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
    uint64 public recordCursor;
    bytes32 public lastRecordID;

    // Accounting: balance = totalFree + totalEncumbered + totalDraining + totalCredits + surplus.
    uint256 public totalFree;
    uint256 public totalEncumbered;
    uint256 public totalDraining;
    uint256 public totalCredits;
    mapping(address => uint256) public credit;

    mapping(uint64 => Position) public positions;
    mapping(uint64 => PendingRoles) internal _pendingRoles;
    mapping(address => uint64) public registerNonce;
    mapping(bytes32 => KeyRecord) internal _keys;
    mapping(uint64 => mapping(uint64 => uint256[])) internal _generationLots;
    mapping(uint256 => Lot) public lots;
    mapping(uint64 => mapping(uint64 => RetirementInfo)) public retirements;
    mapping(uint64 => mapping(uint64 => bytes32)) public exposureChain;
    mapping(uint64 => mapping(uint64 => uint64)) public maxLiabilityAnchor;
    mapping(uint64 => mapping(uint64 => uint32)) public liveExposures;
    mapping(bytes32 => Assignment) public assignments;
    mapping(bytes32 => Exposure) public exposures;
    mapping(bytes32 => mapping(uint256 => bool)) internal _exposureHasLot;
    mapping(bytes32 => Session) internal _sessions;
    mapping(bytes32 => uint256) public caseDebited;
    mapping(bytes32 => mapping(uint256 => bool)) public penaltyApplied;

    constructor() {
        FACTORY = msg.sender;
    }

    // --- initialization -----------------------------------------------------------------------

    /// @notice Factory-only genesis step 1: wire the fixed modules and parameters. The factory then
    /// calls `seedGenesis` once per manifest identity and `sealGenesis`, all in its constructor.
    function initialize(bytes32 manifestHash_, CustodyConfig calldata c) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (genesisStarted) revert AlreadyInitialized();
        if (
            c.treasury == address(0) || c.bondUnit == 0 || c.limits.vMax == 0 || c.limits.lMax == 0
                || c.limits.rMax < 3 || c.limits.maxBatch == 0
                || c.genesis.assignmentID == bytes32(0)
        ) revert InvalidGenesis();
        // Immutable development resource ceilings; alternative test genesis remains bounded.
        if (c.limits.vMax > 128) revert InvalidGenesis();
        if (c.limits.lMax > 8) revert InvalidGenesis();
        if (c.limits.rMax > 4) revert InvalidGenesis();
        if (c.limits.maxBatch > 32) revert InvalidGenesis();
        genesisStarted = true;
        manifestHash = manifestHash_;
        network = c.network;
        // forge-lint: disable-start(missing-events-access-control)
        election = c.election;
        evidence = c.evidence;
        policySource = c.policySource;
        roots = c.roots;
        treasury = c.treasury;
        bondUnit = c.bondUnit;
        minBond = c.minBond;
        limits = c.limits;
        // forge-lint: disable-end(missing-events-access-control)
        genesisAssignmentID = c.genesis.assignmentID;
        Assignment storage a = assignments[c.genesis.assignmentID];
        a.state = ASSIGN_ACTIVE;
        a.lineage = c.genesis.lineage;
        a.rootEpoch = c.genesis.rootEpoch;
        a.evmEpoch = c.genesis.evmEpoch;
        a.firstRound = c.genesis.firstRound;
        a.offsetSet = true;
        a.policyID = IPolicySource(policySource).currentPolicyID();
    }

    /// @notice Factory-only genesis step 2: one manifest identity with its bond (msg.value) and an
    /// Active exposure in the genesis assignment. Manifest authentication replaces fresh possession.
    function seedGenesis(
        address owner,
        address withdrawal,
        bytes calldata rootKey,
        bytes calldata evmKey,
        address operatorPayee
    ) external payable {
        if (msg.sender != FACTORY) revert NotFactory();
        if (!genesisStarted || initialized) revert NotInitialized();
        uint256 weight = msg.value / bondUnit;
        if (
            owner == address(0) || withdrawal == address(0) || operatorPayee == address(0)
                || weight == 0 || weight > type(uint64).max || nextStakingID >= limits.vMax
        ) revert InvalidGenesis();
        uint64 id = ++nextStakingID;
        bytes32 rootHash = _claimKey(rootKey, id, ROLE_ROOT);
        bytes32 evmHash = _claimKey(evmKey, id, ROLE_EVM);
        positions[id] = Position(owner, withdrawal, rootHash, bytes32(0), 1, 0, 0, 0, false);
        uint256[] memory seeded = new uint256[](1);
        seeded[0] = _newLot(id, msg.value);
        assignments[genesisAssignmentID].exposureIDs
            .push(
                _createExposure(
                    genesisAssignmentID,
                    id,
                    1,
                    // weight <= type(uint64).max is checked in seedGenesis
                    // forge-lint: disable-next-line(unsafe-typecast)
                    uint64(weight),
                    rootHash,
                    evmHash,
                    operatorPayee,
                    seeded
                )
            );
    }

    /// @notice Factory-only genesis step 3: commit the exposure digests and seal initialization.
    function sealGenesis() external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (!genesisStarted || initialized || nextStakingID == 0) revert NotInitialized();
        Assignment storage a = assignments[genesisAssignmentID];
        a.exposureDigest = _digestExposures(a.exposureIDs);
        a.keyDigest = _digestKeys(a.exposureIDs);
        lastAckedAssignment = genesisAssignmentID;
        initialized = true;
        emit Initialized(manifestHash);
    }

    modifier whenInitialized() {
        _requireInitialized();
        _;
    }

    function _requireInitialized() private view {
        if (!initialized) revert NotInitialized();
    }

    // --- registration, keys, roles ------------------------------------------------------------

    /// @notice Register a new identity owned by the caller, proving possession of its root key.
    function register(bytes calldata rootKey, bytes calldata pop, address withdrawal)
        external
        whenInitialized
        returns (uint64 id)
    {
        if (withdrawal == address(0)) revert ZeroAddress();
        bytes32 digest = keccak256(
            abi.encode(
                POP_REGISTER,
                network,
                block.chainid,
                address(this),
                msg.sender,
                withdrawal,
                keccak256(rootKey),
                registerNonce[msg.sender]
            )
        );
        _requireRootKeyProof(rootKey, digest, pop);
        registerNonce[msg.sender]++;
        id = ++nextStakingID;
        bytes32 keyHash = _claimKey(rootKey, id, ROLE_ROOT);
        positions[id] = Position({
            owner: msg.sender,
            withdrawal: withdrawal,
            rootKeyHash: keyHash,
            stagedRootKeyHash: bytes32(0),
            generation: 1,
            roleNonce: 0,
            openLots: 0,
            lotCount: 0,
            retirementRequested: false
        });
        emit Registered(id, msg.sender, keyHash, withdrawal);
    }

    /// @notice Create a lot for the value actually received. A new generation opens only when
    /// every old lot, including zero-balance ones, has matured.
    function bond(uint64 id) external payable whenInitialized returns (uint256 lotID) {
        Position storage p = _owned(id);
        if (msg.value == 0) revert ZeroValue();
        if (p.retirementRequested) {
            if (p.openLots != 0) revert GenerationClosing();
            p.generation++;
            p.retirementRequested = false;
            p.lotCount = 0;
        }
        if (p.lotCount >= limits.lMax) revert LotCapacity();
        bool first = p.openLots == 0;
        lotID = _newLot(id, msg.value);
        if (first) IElectionPolicy(election).syncLiveIndex(id);
        emit Bonded(id, p.generation, lotID, msg.value);
    }

    /// @notice Stage a future root key; it activates only with committed membership.
    function proposeRootKey(uint64 id, bytes calldata key, bytes calldata pop)
        external
        whenInitialized
    {
        Position storage p = _owned(id);
        bytes32 digest = keccak256(
            abi.encode(
                POP_ROOT_KEY,
                network,
                block.chainid,
                address(this),
                id,
                p.generation,
                keccak256(key),
                p.roleNonce
            )
        );
        _requireRootKeyProof(key, digest, pop);
        bytes32 keyHash = _claimKey(key, id, ROLE_ROOT);
        p.stagedRootKeyHash = keyHash;
    }

    /// @notice The owner proposes a role tuple at the exact current role nonce. Every nominated
    /// holder must accept; replacing the withdrawal authority also needs the current withdrawal
    /// authority's consent, given by calling `acceptRoles` as that authority.
    function proposeRoles(uint64 id, address newOwner, address newWithdrawal, uint64 nonce)
        external
        whenInitialized
    {
        Position storage p = _owned(id);
        if (nonce != p.roleNonce) revert RoleNonceMismatch();
        if (newOwner == address(0) || newWithdrawal == address(0)) revert ZeroAddress();
        uint8 required = 0;
        if (newOwner != p.owner) required |= ROLE_BIT_OWNER;
        if (newWithdrawal != p.withdrawal) required |= ROLE_BIT_WITHDRAWAL | ROLE_BIT_CONSENT;
        if (required == 0) revert NoRoleChange();
        _pendingRoles[id] = PendingRoles(newOwner, newWithdrawal, nonce, required, 0);
        emit RolesProposed(id, newOwner, newWithdrawal, nonce);
    }

    /// @notice A nominated holder accepts (or the current withdrawal authority consents); once
    /// every required acceptance is in, the tuple installs atomically. Calldata binds both nominated
    /// addresses, so replacing a pending proposal cannot redirect an already prepared acceptance.
    /// Existing credits keep their creditor.
    function acceptRoles(uint64 id, uint64 nonce, address newOwner, address newWithdrawal)
        external
        whenInitialized
    {
        Position storage p = positions[id];
        PendingRoles storage r = _pendingRoles[id];
        if (r.required == 0 || r.nonce != nonce) revert NoPendingRoles();
        if (nonce != p.roleNonce) revert RoleNonceMismatch();
        if (newOwner != r.newOwner || newWithdrawal != r.newWithdrawal) revert RoleTupleMismatch();
        uint8 bits = 0;
        if (msg.sender == r.newOwner) bits |= ROLE_BIT_OWNER;
        if (msg.sender == r.newWithdrawal) bits |= ROLE_BIT_WITHDRAWAL;
        if (msg.sender == p.withdrawal) bits |= ROLE_BIT_CONSENT;
        bits &= r.required;
        if (bits == 0) revert NotNominated();
        r.given |= bits;
        if (r.given != r.required) return;
        p.owner = r.newOwner;
        p.withdrawal = r.newWithdrawal;
        p.roleNonce++;
        emit RolesAccepted(id, r.newOwner, r.newWithdrawal, nonce);
        delete _pendingRoles[id];
    }

    /// @notice Request full-generation retirement. It stops new lots and future primary
    /// eligibility; it releases nothing.
    function requestRetirement(uint64 id) external whenInitialized {
        Position storage p = _owned(id);
        if (p.retirementRequested) revert RetirementAlreadyRequested();
        if (p.openLots == 0) revert NoOpenLots();
        p.retirementRequested = true;
        uint256[] storage ids = _generationLots[id][p.generation];
        for (uint256 i = 0; i < ids.length; ++i) {
            Lot storage l = lots[ids[i]];
            if (l.category == CAT_FREE) _move(l, CAT_DRAINING);
        }
        emit RetirementRequested(id, p.generation);
    }

    /// @notice Cross-role key uniqueness for the EVM key bound through admitDelegation.
    function registerEvmKey(uint64 id, bytes32 evmKeyHash) external whenInitialized {
        if (msg.sender != election) revert NotElection();
        KeyRecord storage k = _keys[evmKeyHash];
        if (k.id != 0) {
            if (k.id == id && k.role == ROLE_EVM) return;
            revert KeyAlreadyUsed();
        }
        k.id = id;
        k.role = ROLE_EVM;
    }

    // --- reservation --------------------------------------------------------------------------

    /// @notice Reserve a primary candidate's exact lots and lock the incumbent exposures (the
    /// recovery slate K) for the session. Primary coverage and eligibility only; K is never
    /// filtered, never re-collateralized and never recreated.
    function reserveCandidate(ReserveInput calldata in_)
        external
        whenInitialized
        returns (bytes32 exposureDigest)
    {
        if (msg.sender != election) revert NotElection();
        if (_sessions[in_.resultID].state != 0) revert SessionExists();
        if (in_.assignmentID == bytes32(0) || assignments[in_.assignmentID].state != 0) {
            revert AssignmentExists();
        }
        if (in_.incumbentAssignmentID != lastAckedAssignment) revert IncumbentMismatch();
        Assignment storage incumbent = assignments[in_.incumbentAssignmentID];
        if (incumbent.lineage != in_.lineage) revert LineageMismatch();
        if (in_.members.length == 0 || in_.members.length > limits.vMax) {
            revert InvalidMemberCount();
        }

        Assignment storage a = assignments[in_.assignmentID];
        a.state = ASSIGN_RESERVED;
        a.lineage = in_.lineage;
        a.rootEpoch = in_.rootEpoch;
        a.evmEpoch = in_.evmEpoch;
        a.policyID = IPolicySource(policySource).currentPolicyID();

        uint64 previous = 0;
        for (uint256 i = 0; i < in_.members.length; ++i) {
            ReserveMember calldata m = in_.members[i];
            if (m.id <= previous) revert MembersUnsorted();
            previous = m.id;
            _checkPrimaryMember(m);
            a.exposureIDs
                .push(
                    _createExposure(
                        in_.assignmentID,
                        m.id,
                        positions[m.id].generation,
                        m.weight,
                        m.rootKeyHash,
                        m.evmKeyHash,
                        m.operatorPayee,
                        m.lotIDs
                    )
                );
        }
        a.exposureDigest = _digestExposures(a.exposureIDs);
        a.keyDigest = _digestKeys(a.exposureIDs);
        exposureDigest = a.exposureDigest;

        _sessions[in_.resultID] = Session({
            state: SESSION_OPEN,
            assignmentID: in_.assignmentID,
            lineage: in_.lineage,
            attempt: in_.attempt,
            incumbentAssignmentID: in_.incumbentAssignmentID
        });
        // Lock the incumbent slate (K) for the session and keep one reference slot per incumbent lot
        // free for deriving K at recovery, so recovery can never be blocked by reference capacity.
        bytes32[] storage ids = incumbent.exposureIDs;
        for (uint256 i = 0; i < ids.length; ++i) {
            Exposure storage inc = exposures[ids[i]];
            inc.sessionLocks++;
            for (uint256 j = 0; j < inc.lotIDs.length; ++j) {
                if (lots[inc.lotIDs[j]].refCount >= limits.rMax) revert ReferenceCapacity();
            }
        }
        emit CandidateReserved(in_.resultID, in_.resultID, exposureDigest);
    }

    function _checkPrimaryMember(ReserveMember calldata m) private view {
        Position storage p = positions[m.id];
        if (p.owner == address(0)) revert UnknownIdentity();
        if (p.retirementRequested) revert PrimaryRetiring();
        if (IEvidence(evidence).excluded(m.id)) revert IdentityExcluded();
        if (m.weight == 0) revert ZeroWeight();
        if (
            m.rootKeyHash != p.rootKeyHash
                && (p.stagedRootKeyHash == bytes32(0) || m.rootKeyHash != p.stagedRootKeyHash)
        ) revert WrongKey();
        KeyRecord storage ek = _keys[m.evmKeyHash];
        if (ek.id != m.id || ek.role != ROLE_EVM) revert WrongKey();
        if (m.operatorPayee == address(0)) revert ZeroAddress();
        if (m.lotIDs.length != p.openLots) revert LotSetMismatch();
        uint256 backing = 0;
        uint256 previousLot = 0;
        for (uint256 j = 0; j < m.lotIDs.length; ++j) {
            uint256 lotID = m.lotIDs[j];
            if (lotID <= previousLot) revert LotSetMismatch();
            previousLot = lotID;
            Lot storage l = lots[lotID];
            if (l.id != m.id || l.generation != p.generation || l.category == CAT_RELEASED) {
                revert LotNotEligible();
            }
            if (l.refCount >= limits.rMax) revert ReferenceCapacity();
            backing += l.remaining;
        }
        if (backing < uint256(m.weight) * bondUnit) revert InsufficientCoverage();
    }

    // --- root records -------------------------------------------------------------------------

    /// @notice Apply the next bounded prefix of authenticated root records, in order. Derived
    /// exposures are instantiated before the references they replace are closed.
    function applyRootRecords(uint32 maxRecords) external whenInitialized {
        // maxRecords == 0 yields an empty prefix and reverts below with EmptyBatch.
        if (maxRecords > limits.maxBatch) revert BatchTooLarge();
        IRootRecords source = IRootRecords(roots);
        uint64 available = source.recordCount();
        uint64 first = recordCursor;
        uint64 end = available;
        if (end - first > maxRecords) end = first + maxRecords;
        if (end == first) revert EmptyBatch();
        for (uint64 i = first; i < end; ++i) {
            RootRecord memory r = source.recordAt(i);
            if (r.index != i || r.predecessor != lastRecordID) revert RecordOutOfOrder();
            _applyRecord(r);
            lastRecordID = r.recordID;
        }
        recordCursor = end;
        emit RootRecordsApplied(first, end - 1, lastRecordID);
    }

    function _applyRecord(RootRecord memory r) private {
        if (r.kind == RecordKind.SessionClosed) {
            _closeSession(abi.decode(r.data, (SessionClosedData)));
        } else if (r.kind == RecordKind.Ack) {
            _acknowledge(abi.decode(r.data, (AckData)));
        } else if (r.kind == RecordKind.RecoveryAck) {
            _recover(abi.decode(r.data, (RecoveryAckData)));
        } else if (r.kind == RecordKind.Closure) {
            _closeLiability(abi.decode(r.data, (ClosureData)), r.progress, r.ucTime);
        } else if (r.kind == RecordKind.Retirement) {
            _importRetirement(abi.decode(r.data, (RetirementData)), r.progress, r.ucTime);
        } else {
            revert UnknownRecordKind();
        }
    }

    /// @dev Exact pre-H abort or ordered rejection: closes only this attempt.
    function _closeSession(SessionClosedData memory d) private {
        Session storage s = _sessions[d.resultID];
        if (s.state == 0) revert UnknownSession();
        if (s.state != SESSION_OPEN) revert SessionNotOpen();
        Assignment storage j = assignments[s.assignmentID];
        if (j.state != ASSIGN_RESERVED) revert AssignmentNotReserved();
        j.state = ASSIGN_ABORTED;
        s.state = SESSION_CLOSED;
        for (uint256 i = 0; i < j.exposureIDs.length; ++i) {
            _forceRelease(exposures[j.exposureIDs[i]]);
        }
        _unlockIncumbent(s.incumbentAssignmentID);
    }

    function _acknowledge(AckData memory d) private {
        Session storage s = _sessions[d.resultID];
        if (s.state == 0) revert UnknownSession();
        if (s.state != SESSION_OPEN) revert SessionNotOpen();
        Assignment storage j = assignments[s.assignmentID];
        if (j.state != ASSIGN_RESERVED) revert AssignmentNotReserved();
        if (s.incumbentAssignmentID != lastAckedAssignment) revert IncumbentMismatch();
        j.state = ASSIGN_ACTIVE;
        j.offset = d.offset;
        j.firstRound = d.firstRound;
        j.offsetSet = true;
        _setH(assignments[s.incumbentAssignmentID], d.replacedHRound);
        // Root-key rotation activates only with committed membership.
        for (uint256 i = 0; i < j.exposureIDs.length; ++i) {
            Exposure storage e = exposures[j.exposureIDs[i]];
            Position storage p = positions[e.id];
            p.rootKeyHash = e.rootKeyHash;
            if (e.rootKeyHash == p.stagedRootKeyHash) p.stagedRootKeyHash = bytes32(0);
        }
        lastAckedAssignment = s.assignmentID;
        s.state = SESSION_ACKED;
        _unlockIncumbent(s.incumbentAssignmentID);
    }

    /// @dev J committed H and never acknowledged; the exact incumbent slate K was committed and
    /// acknowledged instead. Derive K's exposures from the incumbent's locked records first.
    function _recover(RecoveryAckData memory d) private {
        Session storage s = _sessions[d.resultID];
        if (s.state == 0) revert UnknownSession();
        if (s.state != SESSION_OPEN) revert SessionNotOpen();
        Assignment storage j = assignments[s.assignmentID];
        if (j.state != ASSIGN_RESERVED) revert AssignmentNotReserved();
        if (s.incumbentAssignmentID != lastAckedAssignment) revert IncumbentMismatch();
        Assignment storage incumbent = assignments[s.incumbentAssignmentID];
        if (d.recoveryAssignmentID == bytes32(0) || assignments[d.recoveryAssignmentID].state != 0)
        {
            revert AssignmentExists();
        }
        j.state = ASSIGN_ACTIVE;
        j.offset = d.jOffset;
        j.firstRound = d.jFirstRound;
        j.offsetSet = true;
        _setH(j, d.jHRound);

        Assignment storage k = assignments[d.recoveryAssignmentID];
        k.state = ASSIGN_ACTIVE;
        k.lineage = s.lineage;
        k.rootEpoch = d.kRootEpoch;
        k.evmEpoch = d.kEvmEpoch;
        k.offset = d.kOffset;
        k.firstRound = d.kFirstRound;
        k.offsetSet = true;
        k.policyID = incumbent.policyID; // captured policies of the incumbent slate
        bytes32[] storage ids = incumbent.exposureIDs;
        for (uint256 i = 0; i < ids.length; ++i) {
            Exposure storage old = exposures[ids[i]];
            uint256[] memory oldLots = old.lotIDs;
            k.exposureIDs
                .push(
                    _createExposure(
                        d.recoveryAssignmentID,
                        old.id,
                        old.generation,
                        old.weight,
                        old.rootKeyHash,
                        old.evmKeyHash,
                        old.operatorPayee,
                        oldLots
                    )
                );
        }
        k.exposureDigest = _digestExposures(k.exposureIDs);
        k.keyDigest = _digestKeys(k.exposureIDs);
        lastAckedAssignment = d.recoveryAssignmentID;
        s.state = SESSION_RECOVERED;
        _unlockIncumbent(s.incumbentAssignmentID);
    }

    function _setH(Assignment storage a, uint64 hRound) private {
        if (a.hKnown) {
            if (a.hRound != hRound) revert HRoundMismatch();
            return;
        }
        if (a.offsetSet && hRound < a.firstRound) revert HRoundBeforeActivation();
        a.hKnown = true;
        a.hRound = hRound;
    }

    /// @dev CloseLiability: the first closure fixes p_close and its UC time; repeats are no-ops.
    function _closeLiability(ClosureData memory d, uint64 pClose, uint64 tClose) private {
        Assignment storage a = assignments[d.assignmentID];
        if (a.state != ASSIGN_ACTIVE) revert AssignmentNotActive();
        if (d.exposureDigest != a.exposureDigest || d.keyHistoryDigest != a.keyDigest) {
            revert ClosureDigestMismatch();
        }
        bytes32 key =
            keccak256(abi.encode(CLOSURE_DOMAIN, a.rootEpoch, d.hRecordID, d.terminalRoot));
        if (a.closed) {
            if (a.closureKey != key) revert ConflictingClosure();
            return;
        }
        _setH(a, d.hRound);
        a.closed = true;
        a.closureKey = key;
        a.pClose = pClose;
        a.tClose = tClose;
        uint64 endProgress = a.offset + (a.hRound - a.firstRound);
        uint64 anchor = endProgress > pClose ? endProgress : pClose;
        Policy memory terms = IPolicySource(policySource).policyAt(a.policyID);
        uint64 hold = terms.holdNormal > terms.holdSuffix ? terms.holdNormal : terms.holdSuffix;
        uint64 window = terms.evidenceWindow > terms.suffixEvidenceWindow
            ? terms.evidenceWindow
            : terms.suffixEvidenceWindow;
        for (uint256 i = 0; i < a.exposureIDs.length; ++i) {
            Exposure storage e = exposures[a.exposureIDs[i]];
            if (anchor > maxLiabilityAnchor[e.id][e.generation]) {
                maxLiabilityAnchor[e.id][e.generation] = anchor;
            }
            for (uint256 j = 0; j < e.lotIDs.length; ++j) {
                Lot storage l = lots[e.lotIDs[j]];
                if (anchor + hold > l.holdUntil) l.holdUntil = anchor + hold;
                if (anchor + window > l.evidenceUntil) l.evidenceUntil = anchor + window;
                uint64 t = tClose + terms.timeFloor;
                if (t > l.timeUntil) l.timeUntil = t;
            }
            _releaseIfClear(e);
        }
        emit LiabilityClosed(d.assignmentID, pClose, tClose, anchor);
    }

    function _importRetirement(RetirementData memory d, uint64 pRet, uint64 tRet) private {
        Position storage p = positions[d.id];
        if (p.owner == address(0)) revert UnknownIdentity();
        if (p.generation != d.generation) revert StaleGeneration();
        if (!p.retirementRequested) revert RetirementNotRequested();
        RetirementInfo storage info = retirements[d.id][d.generation];
        if (info.imported) revert RetirementAlreadyImported();
        if (liveExposures[d.id][d.generation] != 0) revert RefsStillLive();
        if (d.refDigest != exposureChain[d.id][d.generation]) revert RefDigestMismatch();
        if (pRet < maxLiabilityAnchor[d.id][d.generation]) revert RetirementBeforeLiability();
        info.imported = true;
        info.pRet = pRet;
        info.tRet = tRet;
        emit RetirementImported(d.id, d.generation, pRet, tRet);
    }

    // --- evidence penalty ---------------------------------------------------------------------

    /// @notice Apply the capped penalty of an accepted case to one attributable lot. The case,
    /// exposure, remaining budget, remaining lifetime cap and debit marker are all read here; the
    /// caller (the fixed Evidence module) only triggers the transition.
    function applyPenalty(bytes32 caseID, uint256 lotID)
        external
        whenInitialized
        returns (uint256 debit, uint256 bounty, uint256 treasuryCredit)
    {
        if (msg.sender != evidence) revert NotEvidence();
        if (penaltyApplied[caseID][lotID]) revert PenaltyAlreadyApplied();
        CaseView memory c = IEvidence(evidence).caseInfo(caseID);
        bytes32 exposureID = c.exposureID;
        if (!_exposureHasLot[exposureID][lotID]) revert LotNotInExposure();
        penaltyApplied[caseID][lotID] = true;
        Lot storage l = lots[lotID];
        Policy memory terms = IPolicySource(policySource)
            .policyAt(assignments[exposures[exposureID].assignmentID].policyID);
        uint256 budgetLeft = c.budget - caseDebited[caseID];
        uint256 capRoom = (uint256(l.initial) * l.capBps) / BPS - l.penalized;
        // capRoom <= remaining always holds (cap <= 100% of initial and remaining = initial - penalized
        // until maturity, which Evidence's windows precede), so the cap also bounds the principal.
        debit = budgetLeft < capRoom ? budgetLeft : capRoom;
        if (debit != 0) {
            uint256 before_ = _bountyFor(caseDebited[caseID], terms);
            caseDebited[caseID] += debit;
            bounty = _bountyFor(caseDebited[caseID], terms) - before_;
            treasuryCredit = debit - bounty;
            // debit <= l.remaining, a uint128
            // forge-lint: disable-next-line(unsafe-typecast)
            l.remaining -= uint128(debit);
            // debit <= l.remaining, a uint128
            // forge-lint: disable-next-line(unsafe-typecast)
            l.penalized += uint128(debit);
            _subCategory(l.category, debit);
            credit[c.reporter] += bounty;
            credit[treasury] += treasuryCredit;
            totalCredits += debit;
        }
        emit PenaltyApplied(caseID, lotID, debit, bounty, treasuryCredit);
    }

    function _bountyFor(uint256 cumulativeDebit, Policy memory terms)
        private
        pure
        returns (uint256 amount)
    {
        amount = (cumulativeDebit * terms.bountyBps) / BPS;
        if (amount > terms.bountyCap) amount = terms.bountyCap;
    }

    // --- maturity and claims ------------------------------------------------------------------

    /// @notice Convert matured lots' remaining principal into withdrawal credit. Requires the full
    /// root-record prefix, closed references, imported retirement, strict round gates, the UC-time
    /// gate and no unsettled accepted evidence.
    function mature(uint256[] calldata lotIDs) external nonReentrant whenInitialized {
        if (lotIDs.length == 0) revert EmptyBatch();
        if (lotIDs.length > limits.maxBatch) revert BatchTooLarge();
        if (recordCursor != IRootRecords(roots).recordCount()) revert RecordsPending();
        uint64 p = IRootRecords(roots).progress();
        uint64 t = IRootRecords(roots).ucTime();
        for (uint256 i = 0; i < lotIDs.length; ++i) {
            _matureLot(lotIDs[i], p, t);
        }
    }

    function _matureLot(uint256 lotID, uint64 p, uint64 t) private {
        Lot storage l = lots[lotID];
        if (l.id == 0) revert LotUnknown();
        if (l.category == CAT_RELEASED) revert LotAlreadyReleased();
        if (l.refCount != 0) revert LotStillReferenced();
        RetirementInfo storage info = retirements[l.id][l.generation];
        if (!info.imported) revert RetirementNotImported();
        if (IEvidence(evidence).pendingHolds(lotID) != 0) revert EvidenceHoldPending();
        uint64 roundUntil = info.pRet + l.holdRetirement;
        if (l.holdUntil > roundUntil) roundUntil = l.holdUntil;
        if (p <= roundUntil) revert RoundGateNotMet();
        if (p <= l.evidenceUntil) revert EvidenceGateNotMet();
        uint64 timeUntil = info.tRet + l.timeFloor;
        if (l.timeUntil > timeUntil) timeUntil = l.timeUntil;
        if (t < timeUntil) revert TimeGateNotMet();

        Position storage pos = positions[l.id];
        uint256 amount = l.remaining;
        _subCategory(l.category, amount);
        l.remaining = 0;
        l.category = CAT_RELEASED;
        credit[pos.withdrawal] += amount;
        totalCredits += amount;
        emit LotMatured(lotID, pos.withdrawal, amount);
        // forge-lint: disable-next-line(reentrancy-no-eth)
        if (--pos.openLots == 0) IElectionPolicy(election).syncLiveIndex(l.id); // guarded by nonReentrant; fixed module
    }

    /// @notice Pull a credit. Debits before the guarded transfer; a failing recipient only reverts
    /// its own claim.
    function claim(uint256 amount, address to) external nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroValue();
        if (credit[msg.sender] < amount) revert InsufficientCredit();
        credit[msg.sender] -= amount;
        totalCredits -= amount;
        // the recipient is chosen by the creditor spending its own credit; debit precedes the call
        // forge-lint: disable-next-line(arbitrary-send-eth)
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit CreditClaimed(msg.sender, to, amount);
    }

    // --- internals ----------------------------------------------------------------------------

    function _owned(uint64 id) private view returns (Position storage p) {
        p = positions[id];
        if (p.owner == address(0)) revert UnknownIdentity();
        if (p.owner != msg.sender) revert NotOwner();
    }

    function _requireRootKeyProof(bytes memory key, bytes32 digest, bytes memory pop) private view {
        if (!KeyLib.verify(key, digest, pop)) revert BadPossessionProof();
    }

    function _claimKey(bytes memory key, uint64 id, uint8 role) private returns (bytes32 keyHash) {
        if (key.length != KeyLib.KEY_LENGTH) revert InvalidRootKey();
        keyHash = keccak256(key);
        KeyRecord storage k = _keys[keyHash];
        if (k.id != 0) revert KeyAlreadyUsed();
        k.id = id;
        k.role = role;
    }

    function _newLot(uint64 id, uint256 amount) private returns (uint256 lotID) {
        Policy memory terms = IPolicySource(policySource).policy();
        Position storage p = positions[id];
        if (amount > type(uint128).max) revert AmountTooLarge();
        lotID = ++nextLotID;
        Lot storage l = lots[lotID];
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
        bytes32 rootKeyHash,
        bytes32 evmKeyHash,
        address operatorPayee,
        uint256[] memory lotIDs
    ) private returns (bytes32 exposureID) {
        exposureID = keccak256(
            abi.encode(EXPOSURE_DOMAIN, network, block.chainid, address(this), assignmentID, id)
        );
        Exposure storage e = exposures[exposureID];
        e.assignmentID = assignmentID;
        e.id = id;
        e.generation = generation;
        e.rootKeyHash = rootKeyHash;
        e.evmKeyHash = evmKeyHash;
        e.weight = weight;
        e.operatorPayee = operatorPayee;
        for (uint256 i = 0; i < lotIDs.length; ++i) {
            Lot storage l = lots[lotIDs[i]];
            if (l.refCount >= limits.rMax) revert ReferenceCapacity();
            l.refCount++;
            // An unreferenced lot is never draining here: a retiring identity cannot be reserved and
            // K is derived only from locked, still-referenced exposures.
            if (l.category == CAT_FREE) _move(l, CAT_ENCUMBERED);
            e.lotIDs.push(lotIDs[i]);
            _exposureHasLot[exposureID][lotIDs[i]] = true;
        }
        liveExposures[id][generation]++;
        exposureChain[id][generation] =
            keccak256(abi.encode(CHAIN_DOMAIN, exposureChain[id][generation], exposureID));
    }

    function _digestExposures(bytes32[] storage ids) private view returns (bytes32 digest) {
        digest = EXPOSURE_DIGEST_DOMAIN;
        for (uint256 i = 0; i < ids.length; ++i) {
            Exposure storage e = exposures[ids[i]];
            digest = keccak256(
                abi.encode(
                    digest, ids[i], e.id, e.weight, e.operatorPayee, keccak256(abi.encode(e.lotIDs))
                )
            );
        }
    }

    function _digestKeys(bytes32[] storage ids) private view returns (bytes32 digest) {
        digest = KEY_DIGEST_DOMAIN;
        for (uint256 i = 0; i < ids.length; ++i) {
            Exposure storage e = exposures[ids[i]];
            digest = keccak256(abi.encode(digest, e.id, e.rootKeyHash, e.evmKeyHash));
        }
    }

    function _unlockIncumbent(bytes32 incumbentAssignmentID) private {
        bytes32[] storage ids = assignments[incumbentAssignmentID].exposureIDs;
        for (uint256 i = 0; i < ids.length; ++i) {
            Exposure storage e = exposures[ids[i]];
            e.sessionLocks--;
            _releaseIfClear(e);
        }
    }

    /// @dev References are released only when the obligation is closed (or never committed) and no
    /// session lock remains.
    function _releaseIfClear(Exposure storage e) private {
        if (e.referencesReleased || e.sessionLocks != 0) return;
        if (!assignments[e.assignmentID].closed) return;
        _forceRelease(e);
    }

    function _forceRelease(Exposure storage e) private {
        if (e.referencesReleased) return;
        e.referencesReleased = true;
        liveExposures[e.id][e.generation]--;
        Position storage p = positions[e.id];
        for (uint256 i = 0; i < e.lotIDs.length; ++i) {
            Lot storage l = lots[e.lotIDs[i]];
            l.refCount--;
            if (l.refCount == 0 && l.category == CAT_ENCUMBERED) {
                bool retiring = p.retirementRequested && p.generation == l.generation;
                _move(l, retiring ? CAT_DRAINING : CAT_FREE);
            }
        }
    }

    function _move(Lot storage l, uint8 to) private {
        _subCategory(l.category, l.remaining);
        _addCategory(to, l.remaining);
        l.category = to;
    }

    function _addCategory(uint8 category, uint256 amount) private {
        if (category == CAT_FREE) totalFree += amount;
        else if (category == CAT_ENCUMBERED) totalEncumbered += amount;
        else if (category == CAT_DRAINING) totalDraining += amount;
    }

    function _subCategory(uint8 category, uint256 amount) private {
        if (category == CAT_FREE) totalFree -= amount;
        else if (category == CAT_ENCUMBERED) totalEncumbered -= amount;
        else if (category == CAT_DRAINING) totalDraining -= amount;
    }

    // --- getters ------------------------------------------------------------------------------

    function generationLots(uint64 id, uint64 generation) external view returns (uint256[] memory) {
        return _generationLots[id][generation];
    }

    function keyOwner(bytes32 keyHash) external view returns (uint64 id, uint8 role) {
        KeyRecord storage k = _keys[keyHash];
        return (k.id, k.role);
    }

    function exposureLots(bytes32 exposureID) external view returns (uint256[] memory) {
        return exposures[exposureID].lotIDs;
    }

    function assignmentExposures(bytes32 assignmentID) external view returns (bytes32[] memory) {
        return assignments[assignmentID].exposureIDs;
    }

    function policyTerms(bytes32 assignmentID) public view returns (Policy memory) {
        return IPolicySource(policySource).policyAt(assignments[assignmentID].policyID);
    }

    function session(bytes32 resultID) external view returns (Session memory) {
        return _sessions[resultID];
    }
}

// forge-lint: disable-end(require-revert-in-loop, calls-loop)
