// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the immutable V/L/R/batch ceilings validated by custody at genesis.
// Fixed deployment modules are trusted; guard failures must revert the entire bounded operation.
// forge-lint: disable-start(require-revert-in-loop, calls-loop, reentrancy-no-eth)

import {
    Manifest,
    GenesisIdentity,
    Delegation,
    DelegationRequest,
    ElectionParams,
    Position,
    ReserveInput,
    ReserveMember
} from "./P85Types.sol";
import {IRootRecords, IStakeCustody, IPolicySource, IEvidence} from "./IP85.sol";
import {KeyLib} from "./KeyLib.sol";
import {Continuity} from "./Continuity.sol";
import {Selection} from "./Selection.sol";
import {SelectionEngine} from "./SelectionEngine.sol";

/// @title ElectionPolicy
/// @notice The bounded live index, the owner-authenticated `admitDelegation` mutator with its staged (binding, operatorPayee) storage and
/// replay nonces keyed by (StakingID, generation) (PR2), and the threshold election (PR3 slice 3): `elect(origin)` is called by the
/// system hook once per block, snapshots the first observed threshold, selects the successor committee over the frozen snapshot and
/// reserves it through custody, or records an ordered `NoCandidate`. Primary proof slots, finalization and the K body are slice 4.
///
/// `elect` never reverts for a reason the chain state can produce: a failure of the election or of the reservation is recorded as a
/// `NoCandidate` result and the existing authority continues. The only revert is a foreign caller.
///
/// `admitDelegation` is the sole post-genesis operator-payee nomination path. The signed payload is
/// (network, chain, ElectionPolicyAddress, admitDelegation, StakingID, generation, rootNodeID,
/// rootVerificationKey, evmNodeID, evmVerificationKey, operatorPayee, roleNonce, delegationNonce,
/// expiry); both the owner and the EVM key sign that exact digest.
contract ElectionPolicy {
    bytes32 internal constant DELEGATION_DOMAIN = keccak256("unicity.p85.admitDelegation");
    bytes32 internal constant BINDING_DOMAIN = keccak256("unicity.p85.delegation-binding");
    bytes32 internal constant SIGNING_DOMAIN = keccak256("unicity.p85.signing-binding");
    bytes32 internal constant RESULT_DOMAIN = keccak256("unicity.p85.election-result");
    bytes32 internal constant ASSIGNMENT_DOMAIN = keccak256("unicity.p85.primary-assignment");
    bytes32 internal constant SNAPSHOT_DOMAIN = keccak256("unicity.p85.election-snapshot");
    bytes32 internal constant POP_DOMAIN = keccak256("unicity.p85.assignment-pop");
    bytes32 internal constant POPSET_DOMAIN = keccak256("unicity.p85.pop-set");
    bytes32 internal constant PRIMARY_DOMAIN = keccak256("unicity.p85.primary-commitment");
    bytes32 internal constant K_DOMAIN = keccak256("unicity.p85.recovery-authorization");
    bytes32 internal constant CONTRACTS_DOMAIN = keccak256("unicity.p85.contracts");
    /// @dev The EIP-4788 system address the mandatory hook calls from.
    address internal constant SYSTEM_CALLER = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;

    error NotFactory();
    error AlreadyInitialized();
    error NotInitialized();
    error ManifestMismatch();
    error NotCustody();
    error UnknownIdentity();
    error StaleGeneration();
    error RoleNonceMismatch();
    error DelegationNonceMismatch();
    error DelegationExpired();
    error ZeroPayee();
    error BadRootKey();
    error WrongRootKey();
    error BadOwnerAuthorization();
    error BadEvmPossession();
    error IndexFull();
    error NotSystem();
    error NotSelf();
    error InvalidParams();
    error CustodyRead();
    error NotReserved();
    error AlreadyPublished();
    error BatchSize();
    error NotMember(uint64 id);
    error WrongEvmKey(uint64 id);
    error BadPossession(uint64 id);
    error PoPConflict(uint64 id);
    error MissingProofs();
    error SessionNotOpen();
    error NotCovered(uint64 id);
    error ReferenceCapacity();

    event Initialized(bytes32 manifestHash);
    event DelegationAdmitted(
        uint64 indexed id, bytes32 bindingHash, address operatorPayee, uint64 nonce
    );
    event LiveIndexChanged(uint64 indexed id, bool included);
    event ElectionOpened(
        bytes32 indexed resultID,
        uint64 attempt,
        bytes32 assignmentID,
        bytes32 snapshotDigest,
        bytes32 origin
    );
    event NoCandidate(bytes32 indexed resultID, uint64 attempt, Reason reason, bytes32 origin);
    event ResultResolved(bytes32 indexed resultID, uint8 outcome);
    event PoPAccepted(bytes32 indexed resultID, uint64 indexed id, bytes32 signatureHash);
    event CandidatePublished(bytes32 indexed resultID, bytes32 primaryHash);

    /// @dev Why an election produced no candidate. 1-4 are Selection.Reason; the others are the election's own.
    enum Reason {
        None,
        InvalidProfile,
        Cardinality,
        MembershipChurn,
        WeightChurn,
        ReferenceCapacity,
        ReservationRefused,
        InternalFailure
    }

    enum ResultState {
        None,
        Reserved,
        NoCandidate,
        Acknowledged,
        Recovered,
        Closed
    }

    /// @dev What one `elect` call did.
    enum Outcome {
        Disabled, // incomplete mandatory prefix, unresolved result, not initialized or unreadable clock
        NotDue, // no threshold reached
        Reserved,
        NoCandidateRecorded
    }

    /// @dev One frozen election identity record (design v5 section 5): the member, its generation, assigned weight and the hash of the
    /// complete delegated binding including the operator payee at snapshot time.
    struct Frozen {
        uint64 id;
        uint64 generation;
        uint64 weight;
        bytes32 bindingHash;
    }

    /// @dev The fixed proof slots of one result (design v5 section 5): everything Prepare proves at the last certified EVM state. The
    /// first ten words are one hash each; `published` and `popCount` share the last. The K fields are written when the result is
    /// reserved and never change; `primaryHash`, `popSetDigest` and `published` are written by `finalizeCandidate`.
    struct Publication {
        bytes32 primaryHash;
        bytes32 kCommit; // the mandatory recovery-authorization commitment
        bytes32 incumbent; // K: the last acknowledged assignment this result replaces
        bytes32 incumbentExposureDigest; // K's custody exposure digest
        bytes32 incumbentKeyDigest; // K's custody key-history digest
        bytes32 policyDigest; // the policy terms captured by K's assignment
        bytes32 contractsDigest; // the module addresses and code hashes
        bytes32 snapshotDigest;
        bytes32 assignmentID;
        bytes32 popSetDigest;
        bool published; // the last word packs, from the low-order byte: published (1), popCount (4), attempt (8)
        uint32 popCount;
        uint64 attempt; // the election attempt that produced the result (the root's own attempt number is another count)
    }

    /// @dev One member's possession proof: its EVM key and a signature by it over `popDigest`.
    struct PoPInput {
        uint64 id;
        bytes evmKey;
        bytes signature;
    }

    /// @dev The read-only view of the recovery authorization of one result (K is exactly the incumbent committee).
    struct RecoveryAuthorization {
        bytes32 resultID;
        bytes32 snapshotDigest;
        bytes32 incumbent;
        bytes32 incumbentExposureDigest;
        bytes32 incumbentKeyDigest;
        bytes32 policyDigest;
        bytes32 contractsDigest;
        bytes32 kCommit;
    }

    struct Result {
        ResultState state;
        Reason reason;
        uint64 attempt;
        uint64 progress;
        uint64 ucTime;
        uint32 policyID;
        bytes32 origin;
        bytes32 predecessor; // the last acknowledged assignment the election started from
        bytes32 assignmentID;
        bytes32 snapshotDigest;
    }

    struct Staged {
        Delegation binding;
        bytes32 bindingHash;
        uint64 nextNonce;
        // The key hashes of `binding`, kept beside it so a snapshot reads two words instead of two long byte strings per identity.
        bytes32 rootKeyHash;
        bytes32 evmKeyHash;
    }

    address public immutable FACTORY;
    bool public initialized;
    bytes32 public manifestHash;
    bytes32 public network;
    IStakeCustody public custody;
    IRootRecords public roots;
    IEvidence public evidence;
    SelectionEngine public selection;
    IPolicySource public policySource;
    uint32 public vMax;
    ElectionParams public params;

    /// @dev The anchors of the last acknowledged ordinary rotation (genesis at first). A RecoveryAck never moves them.
    uint64 public anchorProgress;
    uint64 public anchorTime;
    /// @dev The anchors of the last election attempt; a threshold is a cadence past both, so a NoCandidate retries one cadence later.
    uint64 public attemptProgress;
    uint64 public attemptTime;
    uint64 public attemptCursor;
    bytes32 public openResult; // the one unresolved result, zero when none

    mapping(bytes32 => Result) internal _results;
    mapping(bytes32 => Frozen[]) internal _frozen;
    uint32 public maxBatch;
    mapping(bytes32 => Publication) internal _publications;
    mapping(bytes32 => mapping(uint64 => bytes32)) internal _popHashes;

    mapping(uint64 => mapping(uint64 => Staged)) internal _staged;
    uint64[] internal _index;
    mapping(uint64 => uint32) internal _indexPosition; // 1-based; zero means absent

    /// @param factory_ the deployment factory that will initialize this module, fixed at construction. The module is deployed first so
    /// the factory's own creation code stays small; only that factory can initialize it, and it can do so once.
    // forge-lint: disable-next-line(missing-zero-check)
    constructor(address factory_) {
        FACTORY = factory_;
    }

    /// @notice Seeds the genesis live index and staged bindings from the manifest. Custody has
    /// already assigned StakingIDs 1..n in manifest order.
    function initialize(bytes32 manifestHash_, Manifest calldata m) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (initialized) revert AlreadyInitialized();
        if (m.election != address(this)) {
            revert ManifestMismatch();
        }
        initialized = true;
        manifestHash = manifestHash_;
        network = m.network;
        // forge-lint: disable-next-line(missing-events-access-control)
        custody = IStakeCustody(m.custody);
        roots = IRootRecords(m.roots);
        vMax = m.limits.vMax;
        evidence = IEvidence(m.evidence);
        maxBatch = m.limits.maxBatch;
        if (m.selection.code.length == 0) revert InvalidParams();
        selection = SelectionEngine(m.selection);
        policySource = IPolicySource(m.policySource);
        ElectionParams calldata p = m.electionParams;
        if (
            p.nMin == 0 || p.nTarget < p.nMin || p.nMax < p.nTarget || p.nMax > 32 || p.distDen == 0
                || p.cadenceRounds == 0 || p.cadenceSeconds == 0
        ) revert InvalidParams();
        params = p;
        anchorProgress = IRootRecords(m.roots).progress();
        anchorTime = IRootRecords(m.roots).ucTime();
        for (uint256 i = 0; i < m.identities.length; ++i) {
            GenesisIdentity calldata g = m.identities[i];
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 id = uint64(i + 1); // identities are bounded by vMax (a uint32)
            Staged storage s = _staged[id][1];
            s.binding = Delegation(g.rootNodeID, g.rootKey, g.evmNodeID, g.evmKey, g.operatorPayee);
            s.bindingHash = _bindingHash(id, 1, s.binding);
            s.rootKeyHash = keccak256(g.rootKey);
            s.evmKeyHash = keccak256(g.evmKey);
            _addIndex(id);
        }
        emit Initialized(manifestHash_);
    }

    modifier whenInitialized() {
        _requireInitialized();
        _;
    }

    function _requireInitialized() private view {
        if (!initialized) revert NotInitialized();
    }

    /// @notice The digest both the owner and the EVM key sign.
    function delegationDigest(DelegationRequest calldata r) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DELEGATION_DOMAIN,
                network,
                block.chainid,
                address(this),
                r.id,
                r.generation,
                r.binding.rootNodeID,
                keccak256(r.binding.rootKey),
                r.binding.evmNodeID,
                keccak256(r.binding.evmKey),
                r.binding.operatorPayee,
                r.roleNonce,
                r.delegationNonce,
                r.expiry
            )
        );
    }

    /// @notice Stage a future EVM binding and operator payee for (id, generation). Anyone may relay;
    /// authority is the owner's signature plus EVM-key possession over the exact payload. The
    /// delegation nonce is consumed atomically. Frozen election records, exact K and existing
    /// credits are untouched: a nomination affects only later election snapshots.
    function admitDelegation(
        DelegationRequest calldata r,
        bytes calldata ownerSignature,
        bytes calldata evmPossession
    ) external whenInitialized {
        // forge-lint: disable-start(unused-return)
        (
            address owner,,
            bytes32 activeRootKey,
            bytes32 stagedRootKey,
            uint64 generation,
            uint64 roleNonce,,,
        ) = custody.positions(r.id);
        // forge-lint: disable-end(unused-return)
        if (owner == address(0)) revert UnknownIdentity();
        if (generation != r.generation) revert StaleGeneration();
        if (roleNonce != r.roleNonce) revert RoleNonceMismatch();
        Staged storage s = _staged[r.id][r.generation];
        if (s.nextNonce != r.delegationNonce) revert DelegationNonceMismatch();
        if (r.expiry < roots.ucTime()) revert DelegationExpired();
        if (r.binding.operatorPayee == address(0)) revert ZeroPayee();
        if (r.binding.rootKey.length != KeyLib.KEY_LENGTH) revert BadRootKey();
        bytes32 rootHash = keccak256(r.binding.rootKey);
        if (rootHash != activeRootKey && (stagedRootKey == 0 || rootHash != stagedRootKey)) {
            revert WrongRootKey();
        }
        bytes32 digest = delegationDigest(r);
        address signer = KeyLib.recover(digest, ownerSignature);
        if (signer == address(0) || signer != owner) revert BadOwnerAuthorization();
        if (!KeyLib.verify(r.binding.evmKey, digest, evmPossession)) revert BadEvmPossession();
        bytes32 evmHash = keccak256(r.binding.evmKey);
        custody.registerEvmKey(r.id, evmHash);

        s.binding = r.binding;
        s.rootKeyHash = rootHash;
        s.evmKeyHash = evmHash;
        s.bindingHash = _bindingHash(r.id, r.generation, r.binding);
        s.nextNonce = r.delegationNonce + 1;
        emit DelegationAdmitted(r.id, s.bindingHash, r.binding.operatorPayee, r.delegationNonce);
    }

    /// @notice Custody-only: reconcile the bounded live index with custody's open-lot state.
    function syncLiveIndex(uint64 id) external whenInitialized {
        if (msg.sender != address(custody)) revert NotCustody();
        // forge-lint: disable-start(unused-return)
        (,,,,,, uint32 openLots,,) = custody.positions(id);
        // forge-lint: disable-end(unused-return)
        bool included = openLots != 0;
        bool present = _indexPosition[id] != 0;
        if (included && !present) {
            _addIndex(id);
            emit LiveIndexChanged(id, true);
        } else if (!included && present) {
            uint32 slot = _indexPosition[id] - 1;
            uint64 last = _index[_index.length - 1];
            _index[slot] = last;
            _indexPosition[last] = slot + 1;
            _index.pop();
            delete _indexPosition[id];
            emit LiveIndexChanged(id, false);
        }
    }

    function _addIndex(uint64 id) private {
        if (_index.length >= vMax) revert IndexFull();
        _index.push(id);
        // forge-lint: disable-next-line(unsafe-typecast)
        _indexPosition[id] = uint32(_index.length); // bounded by vMax, a uint32
    }

    function _bindingHash(uint64 id, uint64 generation, Delegation memory d)
        private
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                BINDING_DOMAIN,
                id,
                generation,
                d.rootNodeID,
                keccak256(d.rootKey),
                d.evmNodeID,
                keccak256(d.evmKey),
                d.operatorPayee
            )
        );
    }

    // --- election ------------------------------------------------------------------------------

    /// @notice Custody-only: a reserved result ended. An acknowledged ordinary rotation moves the cadence anchors to the record's own
    /// anchors; a recovery restores the incumbent and moves nothing; a closed result leaves the anchors where they were. Results this
    /// module did not create are ignored.
    function resultResolved(bytes32 resultID, uint8 outcome, uint64 progress, uint64 ucTime)
        external
        whenInitialized
    {
        if (msg.sender != address(custody)) revert NotCustody();
        Result storage r = _results[resultID];
        if (r.state != ResultState.Reserved) return;
        if (outcome == 2) {
            r.state = ResultState.Acknowledged;
            anchorProgress = progress;
            anchorTime = ucTime;
        } else if (outcome == 4) {
            r.state = ResultState.Recovered;
        } else {
            r.state = ResultState.Closed;
        }
        if (openResult == resultID) openResult = bytes32(0);
        emit ResultResolved(resultID, outcome);
    }

    /// @notice The first block at which an election is due: the cadence past the last acknowledged ordinary rotation and past the last
    /// attempt, in ordinary progress rounds and in UC seconds. A threshold missed while an election was disabled is skipped, not
    /// replayed: the one election that runs is the first observed.
    function thresholds() public view returns (uint256 progress, uint256 ucTime) {
        uint256 ap = anchorProgress > attemptProgress ? anchorProgress : attemptProgress;
        uint256 aTime = anchorTime > attemptTime ? anchorTime : attemptTime;
        return (ap + params.cadenceRounds, aTime + params.cadenceSeconds);
    }

    /// @notice The system hook's election step (design v5 section 5, step 4). `origin` is the authenticated root origin of the block.
    /// Never reverts for a chain-state reason: an election or reservation failure is stored as an ordered `NoCandidate`.
    function elect(bytes32 origin) external returns (Outcome) {
        if (msg.sender != SYSTEM_CALLER) revert NotSystem();
        if (!initialized || openResult != bytes32(0)) return Outcome.Disabled;
        (bool ok, uint64 p, uint64 t) = _clock();
        if (!ok) return Outcome.Disabled;
        (uint256 dueP, uint256 dueT) = thresholds();
        if (p < dueP || t < dueT) return Outcome.NotDue;
        bytes32 predecessor = bytes32(0);
        try custody.lastAckedAssignment() returns (bytes32 last) {
            predecessor = last;
        } catch {
            return Outcome.Disabled;
        }
        try this.electNow(origin, p, t, predecessor) returns (Outcome o) {
            return o;
        } catch {
            _record(origin, p, t, predecessor, bytes32(0), Reason.InternalFailure);
            return Outcome.NoCandidateRecorded;
        }
    }

    /// @dev Reads the clock and checks that every authenticated record has been applied; an incomplete prefix disables the election.
    function _clock() private view returns (bool ok, uint64 p, uint64 t) {
        uint64 count = 0;
        uint64 cursor = 0;
        try roots.recordCount() returns (uint64 c1) {
            count = c1;
        } catch {
            return (ok, p, t);
        }
        try custody.recordCursor() returns (uint64 c2) {
            cursor = c2;
        } catch {
            return (ok, p, t);
        }
        try roots.progress() returns (uint64 progress) {
            p = progress;
        } catch {
            return (ok, p, t);
        }
        try roots.ucTime() returns (uint64 ucTime) {
            t = ucTime;
        } catch {
            return (ok, p, t);
        }
        ok = cursor == count;
    }

    /// @dev Self-call so that every revert of the election body is caught by `elect` and the attempt is recorded instead.
    function electNow(bytes32 origin, uint64 p, uint64 t, bytes32 predecessor)
        external
        returns (Outcome)
    {
        if (msg.sender != address(this)) revert NotSelf();
        Continuity.Member[] memory o = _committed(predecessor);
        Cand[] memory c = _eligible();
        Selection.Entry[] memory e = new Selection.Entry[](c.length);
        for (uint256 i = 0; i < c.length; ++i) {
            e[i] = Selection.Entry(c[i].id, c[i].binding, c[i].weight);
        }
        ElectionParams memory q = params;
        (Selection.Reason reason, Continuity.Member[] memory chosen) = selection.select(
            o,
            e,
            Selection.Config(
                q.nMin, q.nTarget, q.nMax, Continuity.Params(q.maxM, q.distNum, q.distDen)
            )
        );
        bytes32 digest = _snapshotDigest(origin, p, t, predecessor, c);
        if (reason != Selection.Reason.None) {
            _record(origin, p, t, predecessor, digest, Reason(uint8(reason)));
            return Outcome.NoCandidateRecorded;
        }
        return _reserve(origin, p, t, predecessor, digest, c, chosen);
    }

    /// @dev One eligible identity of the snapshot with everything the reservation needs.
    struct Cand {
        uint64 id;
        uint64 generation;
        uint64 weight;
        bytes32 binding; // the signing binding the continuity rule compares
        bytes32 bindingHash; // the complete delegation record including the operator payee
        bytes32 rootKeyHash;
        bytes32 evmKeyHash;
        address payee;
        uint256[] lots;
    }

    function _reserve(
        bytes32 origin,
        uint64 p,
        uint64 t,
        bytes32 predecessor,
        bytes32 digest,
        Cand[] memory c,
        Continuity.Member[] memory chosen
    ) private returns (Outcome) {
        uint64 attempt = attemptCursor + 1;
        bytes32 resultID = _resultID(predecessor, attempt, origin);
        ReserveInput memory in_ = ReserveInput({
            resultID: resultID,
            assignmentID: keccak256(abi.encode(ASSIGNMENT_DOMAIN, resultID)),
            lineage: bytes32(0),
            attempt: attempt,
            rootEpoch: 0,
            evmEpoch: 0,
            incumbentAssignmentID: predecessor,
            members: new ReserveMember[](chosen.length)
        });
        {
            AssignmentView memory inc = _assignment(predecessor);
            in_.lineage = inc.lineage;
            in_.rootEpoch = inc.rootEpoch + 1;
            in_.evmEpoch = inc.evmEpoch + 1;
        }
        uint256 k = 0;
        for (uint256 i = 0; i < chosen.length; ++i) {
            while (c[k].id != chosen[i].id) ++k;
            in_.members[i] = ReserveMember(
                c[k].id, c[k].weight, c[k].rootKeyHash, c[k].evmKeyHash, c[k].payee, c[k].lots
            );
        }
        try custody.reserveCandidate(in_) returns (bytes32) {}
        catch (bytes memory err) {
            // forge-lint: disable-next-line(unsafe-typecast)
            Reason why = err.length >= 4 && bytes4(err) == ReferenceCapacity.selector
                ? Reason.ReferenceCapacity
                : Reason.ReservationRefused;
            _record(origin, p, t, predecessor, digest, why);
            return Outcome.NoCandidateRecorded;
        }
        Result storage r = _results[resultID];
        r.state = ResultState.Reserved;
        r.attempt = attempt;
        r.progress = p;
        r.ucTime = t;
        r.policyID = policySource.currentPolicyID();
        r.origin = origin;
        r.predecessor = predecessor;
        r.assignmentID = in_.assignmentID;
        r.snapshotDigest = digest;
        Frozen[] storage f = _frozen[resultID];
        k = 0;
        for (uint256 i = 0; i < chosen.length; ++i) {
            while (c[k].id != chosen[i].id) ++k;
            f.push(Frozen(c[k].id, c[k].generation, c[k].weight, c[k].bindingHash));
        }
        _openPublication(resultID, in_.assignmentID, predecessor, digest);
        attemptCursor = attempt;
        attemptProgress = p;
        attemptTime = t;
        openResult = resultID;
        emit ElectionOpened(resultID, attempt, in_.assignmentID, digest, origin);
        return Outcome.Reserved;
    }

    /// @dev Stores an ordered NoCandidate: the attempt is consumed, nothing is reserved, no root record is produced.
    function _record(
        bytes32 origin,
        uint64 p,
        uint64 t,
        bytes32 predecessor,
        bytes32 digest,
        Reason why
    ) private {
        uint64 attempt = attemptCursor + 1;
        bytes32 resultID = _resultID(predecessor, attempt, origin);
        Result storage r = _results[resultID];
        r.state = ResultState.NoCandidate;
        r.reason = why;
        r.attempt = attempt;
        r.progress = p;
        r.ucTime = t;
        r.origin = origin;
        r.predecessor = predecessor;
        r.snapshotDigest = digest;
        attemptCursor = attempt;
        attemptProgress = p;
        attemptTime = t;
        emit NoCandidate(resultID, attempt, why, origin);
    }

    function _resultID(bytes32 predecessor, uint64 attempt, bytes32 origin)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                RESULT_DOMAIN, network, block.chainid, address(this), predecessor, attempt, origin
            )
        );
    }

    /// @dev custody's assignment record, all static fields.
    struct AssignmentView {
        uint8 state;
        bytes32 lineage;
        uint64 rootEpoch;
        uint64 evmEpoch;
        uint64 offset;
        uint64 firstRound;
        bool offsetSet;
        bool hKnown;
        uint64 hRound;
        bool closed;
        uint64 pClose;
        uint64 tClose;
        bytes32 closureKey;
        bytes32 exposureDigest;
        bytes32 keyDigest;
        uint32 policyID;
    }

    function _assignment(bytes32 assignmentID) private view returns (AssignmentView memory) {
        (bool ok, bytes memory ret) =
            address(custody).staticcall(abi.encodeCall(IStakeCustody.assignments, (assignmentID)));
        if (!ok) revert CustodyRead();
        return abi.decode(ret, (AssignmentView));
    }

    /// @dev The last committed committee O with its committed weights, from custody's exposures of the last acknowledged assignment
    /// (ascending by StakingID). The binding is the hash of the committed root and EVM key hashes.
    function _committed(bytes32 assignmentID) private view returns (Continuity.Member[] memory o) {
        bytes32[] memory ids = custody.assignmentExposures(assignmentID);
        o = new Continuity.Member[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            (bool ok, bytes memory ret) =
                address(custody).staticcall(abi.encodeCall(IStakeCustody.exposures, (ids[i])));
            if (!ok) revert CustodyRead();
            ExposureHead memory h = abi.decode(ret, (ExposureHead));
            o[i] = Continuity.Member(h.id, _signingBinding(h.rootKeyHash, h.evmKeyHash), h.weight);
        }
    }

    struct ExposureHead {
        bytes32 assignmentID;
        uint64 id;
        uint64 generation;
        bytes32 rootKeyHash;
        bytes32 evmKeyHash;
        uint64 weight;
    }

    function _signingBinding(bytes32 rootKeyHash, bytes32 evmKeyHash)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(SIGNING_DOMAIN, rootKeyHash, evmKeyHash));
    }

    /// @dev The snapshot's eligible identities, ascending by StakingID. Primary eligibility (design v5 section 5): no earlier
    /// retirement request or exclusion, a delegated binding of the open generation whose root key is the identity's current or staged
    /// root key and whose EVM key custody registered, and principal of at least B_min with a positive assigned weight.
    function _eligible() private view returns (Cand[] memory out) {
        uint256 n = _index.length;
        uint64[] memory ids = new uint64[](n);
        for (uint256 i = 0; i < n; ++i) {
            uint64 id = _index[i];
            uint256 j = i;
            while (j > 0 && ids[j - 1] > id) {
                ids[j] = ids[j - 1];
                --j;
            }
            ids[j] = id;
        }
        Cand[] memory tmp = new Cand[](n);
        uint256 count = 0;
        uint128 unit = custody.bondUnit();
        uint128 floor_ = custody.minBond();
        for (uint256 i = 0; i < n; ++i) {
            (bool ok, Cand memory c) = _candidate(ids[i], unit, floor_);
            if (ok) tmp[count++] = c;
        }
        out = new Cand[](count);
        for (uint256 i = 0; i < count; ++i) {
            out[i] = tmp[i];
        }
    }

    function _candidate(uint64 id, uint128 unit, uint128 floor_)
        private
        view
        returns (bool eligible, Cand memory c)
    {
        (bool read, bytes memory ret) =
            address(custody).staticcall(abi.encodeCall(IStakeCustody.positions, (id)));
        if (!read) revert CustodyRead();
        Position memory pos = abi.decode(ret, (Position));
        if (pos.owner == address(0) || pos.retirementRequested || evidence.excluded(id)) {
            return (eligible, c);
        }
        Staged storage s = _staged[id][pos.generation];
        if (s.bindingHash == bytes32(0)) return (eligible, c);
        c.id = id;
        c.generation = pos.generation;
        c.bindingHash = s.bindingHash;
        c.rootKeyHash = s.rootKeyHash;
        c.evmKeyHash = s.evmKeyHash;
        c.payee = s.binding.operatorPayee;
        if (
            c.rootKeyHash != pos.rootKeyHash
                && (pos.stagedRootKeyHash == bytes32(0) || c.rootKeyHash != pos.stagedRootKeyHash)
        ) return (eligible, c);
        (uint64 keyID, uint8 role) = custody.keyOwner(c.evmKeyHash);
        if (keyID != id || role != 2) return (eligible, c);
        uint256 principal;
        (c.lots, principal) = _openLots(id, pos.generation);
        if (principal < floor_) return (eligible, c);
        uint256 w = principal / unit;
        if (w == 0 || w > type(uint64).max) return (eligible, c);
        // forge-lint: disable-next-line(unsafe-typecast)
        c.weight = uint64(w); // checked above
        c.binding = _signingBinding(c.rootKeyHash, c.evmKeyHash);
        eligible = c.weight != 0;
        return (eligible, c);
    }

    /// @dev Only the first six words of the lot getter are read: (id, generation, initial, remaining, penalized, category).
    function _lotWords(uint256 lotID) private view returns (uint256 remaining, uint256 category) {
        address c = address(custody);
        bytes4 selector = IStakeCustody.lots.selector;
        bool ok;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, selector)
            mstore(add(ptr, 4), lotID)
            ok := staticcall(gas(), c, ptr, 0x24, ptr, 0xc0)
            ok := and(ok, iszero(lt(returndatasize(), 0xc0)))
            remaining := and(mload(add(ptr, 0x60)), 0xffffffffffffffffffffffffffffffff)
            category := and(mload(add(ptr, 0xa0)), 0xff)
        }
        if (!ok) revert CustodyRead();
    }

    /// @dev Every unreleased lot of the open generation, ascending, and their remaining principal.
    function _openLots(uint64 id, uint64 generation)
        private
        view
        returns (uint256[] memory lots, uint256 principal)
    {
        uint256[] memory all = custody.generationLots(id, generation);
        uint256[] memory keep = new uint256[](all.length);
        uint256 count = 0;
        for (uint256 i = 0; i < all.length; ++i) {
            (uint256 remaining, uint256 category) = _lotWords(all[i]);
            if (category == 4) continue; // released
            keep[count++] = all[i];
            principal += remaining;
        }
        lots = new uint256[](count);
        for (uint256 i = 0; i < count; ++i) {
            lots[i] = keep[i];
        }
    }

    function _snapshotDigest(
        bytes32 origin,
        uint64 p,
        uint64 t,
        bytes32 predecessor,
        Cand[] memory c
    ) private view returns (bytes32 d) {
        d = keccak256(
            abi.encode(
                SNAPSHOT_DOMAIN,
                network,
                block.chainid,
                address(this),
                origin,
                p,
                t,
                policySource.currentPolicyID(),
                predecessor,
                attemptCursor + 1
            )
        );
        for (uint256 i = 0; i < c.length; ++i) {
            d = keccak256(
                abi.encode(
                    d,
                    c[i].id,
                    c[i].generation,
                    c[i].bindingHash,
                    c[i].weight,
                    keccak256(abi.encodePacked(c[i].lots))
                )
            );
        }
    }

    // --- primary assembly and K (slice 4) --------------------------------------------------------

    /// @dev Written when the result is reserved: K is exactly the incumbent committee, so its commitment is custody's own digests of
    /// the last acknowledged assignment plus the policy terms it captured and the deployed modules, all bound to the result.
    function _openPublication(
        bytes32 resultID,
        bytes32 assignmentID,
        bytes32 incumbent,
        bytes32 snapshotDigest
    ) private {
        Publication storage pub = _publications[resultID];
        AssignmentView memory inc = _assignment(incumbent);
        pub.incumbent = incumbent;
        pub.incumbentExposureDigest = inc.exposureDigest;
        pub.incumbentKeyDigest = inc.keyDigest;
        pub.policyDigest = keccak256(abi.encode(custody.policyTerms(incumbent)));
        pub.contractsDigest = _contractsDigest();
        pub.snapshotDigest = snapshotDigest;
        pub.assignmentID = assignmentID;
        pub.attempt = _results[resultID].attempt;
        pub.kCommit = keccak256(
            abi.encode(
                K_DOMAIN,
                network,
                block.chainid,
                resultID,
                snapshotDigest,
                incumbent,
                inc.exposureDigest,
                inc.keyDigest,
                pub.policyDigest,
                pub.contractsDigest
            )
        );
    }

    /// @dev The module addresses with their code hashes: a recovery authorization names the exact deployment it was made under.
    function _contractsDigest() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                CONTRACTS_DOMAIN,
                block.chainid,
                address(custody),
                address(custody).codehash,
                address(this),
                address(this).codehash,
                address(evidence),
                address(evidence).codehash,
                address(selection),
                address(selection).codehash,
                address(policySource),
                address(policySource).codehash,
                address(roots)
            )
        );
    }

    /// @notice The digest a member's EVM key signs to prove possession for one frozen result: it names the network, chain, this
    /// module, the result, its assignment and snapshot, the attempt and the member's identity, generation and EVM key. Registration and
    /// delegation signatures cover other domains and cannot substitute.
    function popDigest(bytes32 resultID, uint64 id, bytes32 evmKeyHash)
        public
        view
        returns (bytes32)
    {
        Result storage r = _results[resultID];
        Frozen[] storage f = _frozen[resultID];
        uint64 generation = 0;
        for (uint256 i = 0; i < f.length; ++i) {
            if (f[i].id == id) generation = f[i].generation;
        }
        return keccak256(
            abi.encode(
                POP_DOMAIN,
                network,
                block.chainid,
                address(this),
                resultID,
                r.assignmentID,
                r.snapshotDigest,
                r.attempt,
                id,
                generation,
                evmKeyHash
            )
        );
    }

    /// @notice Store the possession proofs of frozen members of a reserved result. Anyone may relay; a proof is valid only as a
    /// signature by the member's frozen EVM key over `popDigest`. An exact repeat is a no-op, a different proof for a stored slot is
    /// refused, and nothing is accepted once the result is published or no longer reserved.
    function submitAssignmentPoPs(bytes32 resultID, PoPInput[] calldata pops)
        external
        whenInitialized
    {
        Result storage r = _results[resultID];
        Publication storage pub = _publications[resultID];
        if (r.state != ResultState.Reserved) revert NotReserved();
        if (pub.published) revert AlreadyPublished();
        if (pops.length == 0 || pops.length > maxBatch) revert BatchSize();
        Frozen[] storage f = _frozen[resultID];
        bytes32[] memory eids = custody.assignmentExposures(r.assignmentID);
        for (uint256 n = 0; n < pops.length; ++n) {
            PoPInput calldata pop = pops[n];
            uint256 pos = f.length;
            for (uint256 i = 0; i < f.length; ++i) {
                if (f[i].id == pop.id) pos = i;
            }
            if (pos == f.length) revert NotMember(pop.id);
            bytes32 evmKeyHash = keccak256(pop.evmKey);
            if (_exposure(eids[pos]).evmKeyHash != evmKeyHash) revert WrongEvmKey(pop.id);
            if (!KeyLib.verify(pop.evmKey, popDigest(resultID, pop.id, evmKeyHash), pop.signature))
            {
                revert BadPossession(pop.id);
            }
            bytes32 h = keccak256(pop.signature);
            bytes32 stored = _popHashes[resultID][pop.id];
            if (stored == h) continue;
            if (stored != bytes32(0)) revert PoPConflict(pop.id);
            _popHashes[resultID][pop.id] = h;
            ++pub.popCount;
            emit PoPAccepted(resultID, pop.id, h);
        }
    }

    /// @notice Publish a reserved result: every member has a stored proof, the session and the assignment are still open, and every
    /// member is still eligible and fully covered by the unreleased lots of its exposure. A result that cannot be published stays
    /// reserved until the root orders its rejection. Publishing derives the primary commitment and writes the fixed proof slots.
    function finalizeCandidate(bytes32 resultID) external whenInitialized {
        Result storage r = _results[resultID];
        Publication storage pub = _publications[resultID];
        if (r.state != ResultState.Reserved) revert NotReserved();
        if (pub.published) revert AlreadyPublished();
        Frozen[] storage f = _frozen[resultID];
        if (pub.popCount != f.length) revert MissingProofs();
        AssignmentView memory a = _assignment(r.assignmentID);
        if (a.state != 1 || _sessionState(resultID) != 1) revert SessionNotOpen();
        bytes32[] memory eids = custody.assignmentExposures(r.assignmentID);
        bytes32 popSet = POPSET_DOMAIN;
        uint128 unit = custody.bondUnit();
        for (uint256 i = 0; i < f.length; ++i) {
            if (!_covered(f[i], eids[i], unit)) revert NotCovered(f[i].id);
            popSet = keccak256(abi.encode(popSet, f[i].id, _popHashes[resultID][f[i].id]));
        }
        pub.popSetDigest = popSet;
        pub.primaryHash = keccak256(
            abi.encode(
                PRIMARY_DOMAIN,
                network,
                block.chainid,
                address(custody),
                address(this),
                resultID,
                r.assignmentID,
                r.predecessor,
                pub.attempt,
                r.snapshotDigest,
                a.exposureDigest,
                a.keyDigest,
                popSet
            )
        );
        pub.published = true;
        emit CandidatePublished(resultID, pub.primaryHash);
    }

    /// @dev The member is still a valid primary: same open generation, no retirement request, not excluded, and the unreleased lots
    /// of its exposure still carry its committed weight.
    function _covered(Frozen storage m, bytes32 exposureID, uint128 unit)
        private
        view
        returns (bool)
    {
        (bool ok, bytes memory ret) =
            address(custody).staticcall(abi.encodeCall(IStakeCustody.positions, (m.id)));
        if (!ok) revert CustodyRead();
        Position memory pos = abi.decode(ret, (Position));
        if (
            pos.owner == address(0) || pos.retirementRequested || pos.generation != m.generation
                || evidence.excluded(m.id)
        ) return false;
        uint256[] memory lots = custody.exposureLots(exposureID);
        uint256 backing = 0;
        for (uint256 j = 0; j < lots.length; ++j) {
            (uint256 remaining, uint256 category) = _lotWords(lots[j]);
            if (category == 4) return false;
            backing += remaining;
        }
        return backing >= uint256(m.weight) * unit;
    }

    function _exposure(bytes32 exposureID) private view returns (ExposureHead memory) {
        (bool ok, bytes memory ret) =
            address(custody).staticcall(abi.encodeCall(IStakeCustody.exposures, (exposureID)));
        if (!ok) revert CustodyRead();
        return abi.decode(ret, (ExposureHead));
    }

    function _sessionState(bytes32 resultID) private view returns (uint8 state) {
        (bool ok, bytes memory ret) =
            address(custody).staticcall(abi.encodeWithSignature("session(bytes32)", resultID));
        if (!ok) revert CustodyRead();
        (state,,,,) = abi.decode(ret, (uint8, bytes32, bytes32, uint64, bytes32));
    }

    function publication(bytes32 resultID) external view returns (Publication memory) {
        return _publications[resultID];
    }

    function popHash(bytes32 resultID, uint64 id) external view returns (bytes32) {
        return _popHashes[resultID][id];
    }

    /// @notice The recovery authorization of a result: K, its custody commitments, the captured policies and the deployment.
    function recoveryAuthorization(bytes32 resultID)
        external
        view
        returns (RecoveryAuthorization memory a)
    {
        Publication storage p = _publications[resultID];
        return RecoveryAuthorization(
            resultID,
            p.snapshotDigest,
            p.incumbent,
            p.incumbentExposureDigest,
            p.incumbentKeyDigest,
            p.policyDigest,
            p.contractsDigest,
            p.kCommit
        );
    }

    function result(bytes32 resultID) external view returns (Result memory) {
        return _results[resultID];
    }

    function frozenMembers(bytes32 resultID) external view returns (Frozen[] memory) {
        return _frozen[resultID];
    }

    function delegation(uint64 id, uint64 generation)
        external
        view
        returns (Delegation memory binding, bytes32 bindingHash, uint64 nextNonce)
    {
        Staged storage s = _staged[id][generation];
        return (s.binding, s.bindingHash, s.nextNonce);
    }

    function liveCount() external view returns (uint32) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(_index.length); // bounded by vMax, a uint32
    }

    function isIndexed(uint64 id) external view returns (bool) {
        return _indexPosition[id] != 0;
    }

    function liveIndexAt(uint32 i) external view returns (uint64) {
        return _index[i];
    }
}

// forge-lint: disable-end(require-revert-in-loop, calls-loop, reentrancy-no-eth)
