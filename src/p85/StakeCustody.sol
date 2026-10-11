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
    Assignment
} from "./P85Types.sol";
import {IRootRecords, IPolicySource, IEvidence, IElectionPolicy, CaseView} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";
import {Quantize} from "./Quantize.sol";

import {CustodyStorage} from "./CustodyStorage.sol";

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
/// No proxy, arbitrary call, sweep, administrator withdrawal or module setter exists. The one delegatecall is the factory's genesis step:
/// `initialize`, `seedGenesis` and `sealGenesis` run in CustodyGenesis (an immutable address fixed at construction) in this contract's storage,
/// reachable only by the factory and only until genesis is sealed (afterwards each of them reverts); the code is not here to keep the runtime
/// under EIP-170.
contract StakeCustody is CustodyStorage {
    /// @notice The address of the genesis implementation the genesis stubs delegate to.
    address public immutable GENESIS_IMPL;

    /// @param factory_ the deployment factory that will initialize this module, fixed at construction. The module is deployed first so
    /// the factory's own creation code stays small; only that factory can initialize it, and it can do so once.
    // forge-lint: disable-next-line(missing-zero-check)
    constructor(address factory_, address genesisImpl_) CustodyStorage(factory_) {
        GENESIS_IMPL = genesisImpl_;
    }

    // --- genesis (delegated) ------------------------------------------------------------------

    /// @notice Factory-only genesis steps 1-3 run in CustodyGenesis, by delegatecall: the code lives there so this runtime keeps the room.
    /// `initialize` wires the fixed modules and parameters, `seedGenesis` takes one manifest identity with its bond (msg.value) and an Active
    /// exposure in the genesis assignment, `sealGenesis` fixes the genesis digests. The factory calls all of them in its constructor.
    function initialize(bytes32, CustodyConfig calldata) external {
        _genesis();
    }

    function seedGenesis(address, address, bytes calldata, bytes calldata, address)
        external
        payable
    {
        _genesis();
    }

    function sealGenesis() external {
        _genesis();
    }

    function _genesis() private {
        if (msg.sender != FACTORY) revert NotFactory();
        // the genesis functions return nothing; a revert of the implementation is passed on as it is
        // the target is the immutable genesis implementation fixed at construction, and only the factory reaches this line
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool ok, bytes memory ret) = GENESIS_IMPL.delegatecall(msg.data);
        if (!ok) {
            // forge-lint: disable-next-line(unsafe-typecast)
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
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
                        m.rawWeight,
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
        // the lots must cover the RAW weight x the committed q was derived from (q <= x), not q itself
        if (backing < uint256(m.rawWeight) * bondUnit) revert InsufficientCoverage();
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
        // Session records name their result in the first word; election learns how it ended, at the record's own anchors.
        uint8 outcome = SESSION_CLOSED;
        if (r.kind == RecordKind.SessionClosed) {
            _closeSession(abi.decode(r.data, (SessionClosedData)));
        } else if (r.kind == RecordKind.Ack) {
            _acknowledge(abi.decode(r.data, (AckData)));
            outcome = SESSION_ACKED;
        } else if (r.kind == RecordKind.RecoveryAck) {
            _recover(abi.decode(r.data, (RecoveryAckData)));
            outcome = SESSION_RECOVERED;
        } else if (r.kind == RecordKind.Closure) {
            _closeLiability(abi.decode(r.data, (ClosureData)), r.progress, r.ucTime);
        } else if (r.kind == RecordKind.Retirement) {
            _importRetirement(abi.decode(r.data, (RetirementData)), r.progress, r.ucTime);
        } else {
            revert UnknownRecordKind();
        }
        if (r.kind <= RecordKind.RecoveryAck) {
            IElectionPolicy(election)
                .resultResolved(abi.decode(r.data, (bytes32)), outcome, r.progress, r.ucTime);
        }
    }

    /// @dev Exact pre-H abort or ordered rejection: closes only this attempt.
    /// @dev The open session of a result and its Reserved assignment: the resolving records' common precondition.
    function _openSession(bytes32 resultID, bool recovers)
        private
        view
        returns (Session storage s, Assignment storage j)
    {
        s = _sessions[resultID];
        if (s.state == 0) revert UnknownSession();
        if (s.state != SESSION_OPEN) revert SessionNotOpen();
        j = assignments[s.assignmentID];
        if (j.state != ASSIGN_RESERVED) revert AssignmentNotReserved();
        // A saved J closure is resolved only by the RecoveryAck of J's own session: an ordinary Ack or a SessionClosed of J is an impossible
        // root history, and a RecoveryAck of another session would leave the closure pending and derive a second K.
        if (pendingAssignment != bytes32(0) && (pendingAssignment == s.assignmentID) != recovers) {
            revert PendingClosureUnresolved();
        }
    }

    function _activate(Assignment storage j, uint64 offset, uint64 firstRound) private {
        j.state = ASSIGN_ACTIVE;
        j.offset = offset;
        j.firstRound = firstRound;
        j.offsetSet = true;
    }

    function _closeSession(SessionClosedData memory d) private {
        (Session storage s, Assignment storage j) = _openSession(d.resultID, false);
        j.state = ASSIGN_ABORTED;
        s.state = SESSION_CLOSED;
        for (uint256 i = 0; i < j.exposureIDs.length; ++i) {
            _forceRelease(exposures[j.exposureIDs[i]]);
        }
        _unlockIncumbent(s.incumbentAssignmentID);
    }

    function _acknowledge(AckData memory d) private {
        (Session storage s, Assignment storage j) = _openSession(d.resultID, false);
        if (s.incumbentAssignmentID != lastAckedAssignment) revert IncumbentMismatch();
        _activate(j, d.offset, d.firstRound);
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
        (Session storage s, Assignment storage j) = _openSession(d.resultID, true);
        if (s.incumbentAssignmentID != lastAckedAssignment) revert IncumbentMismatch();
        Assignment storage incumbent = assignments[s.incumbentAssignmentID];
        if (d.recoveryAssignmentID == bytes32(0) || assignments[d.recoveryAssignmentID].state != 0)
        {
            revert AssignmentExists();
        }
        if (pendingAssignment == s.assignmentID) {
            if (j.hRound != d.jHRound) revert HRoundMismatch();
        }
        _activate(j, d.jOffset, d.jFirstRound);
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
                        old.rawWeight,
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
        if (pendingAssignment == s.assignmentID) {
            pendingAssignment = bytes32(0);
            _closeActive(s.assignmentID, j.closureKey, j.hRound, j.pClose, j.tClose, j);
        }
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
        // The Reserved J of the open session can be closed by the root before custody learns how the session ends: the closure is saved with
        // its own anchors and applied by the RecoveryAck that materializes J. Unknown and aborted assignments stay rejected.
        if (a.state != ASSIGN_ACTIVE && a.state != ASSIGN_RESERVED) revert AssignmentNotActive();
        if (d.exposureDigest != a.exposureDigest || d.keyHistoryDigest != a.keyDigest) {
            revert ClosureDigestMismatch();
        }
        // The closure identity is (closed root epoch, H record, H round) with the terminal root as part of its immutable value:
        // an assignment closes once, so any other H record, H round or terminal root conflicts with the first closure.
        bytes32 key = keccak256(
            abi.encode(CLOSURE_DOMAIN, a.rootEpoch, d.hRecordID, d.hRound, d.terminalRoot)
        );
        if (a.state == ASSIGN_ACTIVE) {
            _closeActive(d.assignmentID, key, d.hRound, pClose, tClose, a);
        } else if (pendingAssignment == bytes32(0)) {
            pendingAssignment = d.assignmentID;
            a.closureKey = key;
            a.hRound = d.hRound;
            a.pClose = pClose;
            a.tClose = tClose;
        } else if (pendingAssignment != d.assignmentID || a.closureKey != key) {
            revert ConflictingClosure(); // an identical repeat keeps the first anchors; another assignment never shares the one slot
        }
    }

    function _closeActive(
        bytes32 assignmentID,
        bytes32 key,
        uint64 hRound,
        uint64 pClose,
        uint64 tClose,
        Assignment storage a
    ) private {
        if (a.closed) {
            if (a.closureKey != key) revert ConflictingClosure();
            return;
        }
        _setH(a, hRound);
        a.closed = true;
        a.closureKey = key;
        a.pClose = pClose;
        a.tClose = tClose;
        uint64 endProgress = a.offset + (a.hRound - a.firstRound);
        uint64 anchor = endProgress > pClose ? endProgress : pClose;
        Policy memory terms = policyTerms(assignmentID);
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
        emit LiabilityClosed(assignmentID, pClose, tClose, anchor);
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
        Policy memory terms = policyTerms(exposures[exposureID].assignmentID);
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
        if (recordCursor != IRootRecords(roots).recordCount() || pendingAssignment != bytes32(0)) {
            revert RecordsPending();
        }
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

// forge-lint: disable-end(require-revert-in-loop, calls-loop, reentrancy-no-eth)
