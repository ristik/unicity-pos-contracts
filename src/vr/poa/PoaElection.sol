// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded: 16 committee members, a joiner queue of MAX_QUEUE, a pool of 6, and the hook's record batch (at most 32). VR calls
// this module only through contained steps (design section 3.3); the module calls VR views and the SealRegistry's record reader.
// forge-lint: disable-start(calls-loop, unsafe-typecast)

import {VRC} from "../VRConstants.sol";
import {VRCodec} from "../VRCodec.sol";
import {Member, ConfigView, VRRecord, IVR, IVRRecordSource, IElectionModule} from "../VRTypes.sol";
import {PoaComposer, PoaComposerEngine} from "./PoaComposer.sol";
import {Continuity} from "../../p85/Continuity.sol";

/// @notice The PoA module's own ABI (design section 3.7.1). `apply` is a reserved word in Solidity, so the application is
/// `submitApplication`.
interface IPoaElection is IElectionModule {
    function submitApplication(uint64 id) external; // owner; None | Exited -> Applied
    function withdrawApplication(uint64 id) external; // owner; Applied -> None
    function requestExit(uint64 id) external; // owner; Active -> ExitRequested
    function rejoin(uint64 id) external; // owner; Parked -> Admitted
    function status(uint64 id) external view returns (uint8 state, uint64 sinceProgress);
}

/// @title PoaElection (v1)
/// @notice The proof-of-authority election module behind the frozen `IElectionModule` interface (bft-core
/// briefs/validator-registry-design-final.md section 3.7; schema v1 sections 3 and 5). Validators apply, the Foundation multisig admits
/// or removes them by `ModuleAction`, and every membership effect happens at a boundary: Joining -> Active and Leaving -> Exited when
/// the Boundary record installs the output.
///
/// - **Due** (3.7.2): VR's own gate (record cursor caught up, no open output) plus `MIN_EPOCH_GAP` progress since the epoch's first
///   ordinary round, and some work: a Removing member, an Admitted joiner, a staged binding, `dueWork > 0` or a force-removed id (and a
///   boundary owed to an action without membership effect, see `_boundaryOwed`).
/// - **Composition** (3.7.3) is `PoaComposer`: a bounded deterministic trial search over at most 6 changes. The output is ready in the
///   same call; `outputOf` serves it from transient storage within that transaction (VR captures it there), and answers NotMine for
///   every other id or transaction.
/// - **Parking** (3.7.4) is a non-punitive retry: an expiry `OutputRejected` whose ready bitmap lacks a joiner parks it, and it is
///   Admitted again after `PARK_PERIOD` or on `rejoin`.
/// - **Exposure digests** use the VR address as the deployment domain (schema 4.7, FD-6).
///
/// The module reads its root records itself (`onRecords`), so `onResolved` is a no-op. Immutable, no proxy; not a liability holder.
contract PoaElection is IPoaElection {
    // ---- states (design 3.7.1) ----
    uint8 internal constant NONE = 0;
    uint8 internal constant APPLIED = 1;
    uint8 internal constant ADMITTED = 2;
    uint8 internal constant JOINING = 3;
    uint8 internal constant ACTIVE = 4;
    uint8 internal constant EXIT_REQUESTED = 5;
    uint8 internal constant REMOVING = 6;
    uint8 internal constant LEAVING = 7;
    uint8 internal constant EXITED = 8;
    uint8 internal constant PARKED = 9;

    // ---- ModuleAction payloads: abi.encode(uint64 action, uint64 id) (schema 6.1) ----
    uint64 internal constant ADMIT = 1;
    uint64 internal constant REMOVE = 2;
    uint64 internal constant CONFIRM_EXIT = 3;

    // ---- constants ----
    bytes32 public constant TAG = keccak256("unicity.vr.poa.v1");
    bytes32 internal constant RESULT_DOMAIN = keccak256("unicity.vr.poa.result.v1");
    bytes32 internal constant SNAPSHOT_DOMAIN = keccak256("unicity.vr.poa.snapshot.v1");
    bytes32 internal constant POLICY_DOMAIN = keccak256("unicity.vr.poa.policy.v1");
    uint64 public constant PARK_PERIOD = 2 * VRC.LIFETIME;
    /// @dev An election is due at most MIN_EPOCH_GAP after work appears; the interval leaves a tenfold margin.
    uint64 internal constant MAX_ELECTION_INTERVAL = 10 * VRC.MIN_EPOCH_GAP;
    uint256 internal constant MAX_QUEUE = 32;
    uint8 internal constant NO_CANDIDATE_LIMITS = 1; // NoCandidate(LimitsUnreachable)
    // ActionRefused reasons
    uint8 internal constant REFUSED_STATE = 1; // the action's guard (design 3.7.1)
    uint8 internal constant REFUSED_UNKNOWN = 2; // not Admit, Remove or ConfirmExit
    uint8 internal constant REFUSED_MALFORMED = 3; // not abi.encode(uint64 action, uint64 id)
    uint8 internal constant REFUSED_QUEUE_FULL = 4;

    // ---- gas bounds: the measured worst case x 5/4 (test/vr/poa/PoaGas.t.sol), below VR's caps ----
    /// @dev elect: the all-64-trials search over 16 staged members, 4 ForceRemoves and 2 joiners (2.51 M measured, NoCandidate),
    /// plus composing, serving and recording a 16-member output (under 0.2 M), x 5/4.
    uint64 internal constant GAS_ELECT = 3_600_000;
    uint64 internal constant GAS_OUTPUT = 100_000;
    uint64 internal constant GAS_RECORD = 900_000;
    uint64 internal constant GAS_RESOLVED = 10_000;
    uint64 internal constant GAS_ATTACH = 1_500_000;
    uint64 internal constant GAS_DETACH = 10_000;
    uint64 internal constant GAS_GOV = 100_000;
    uint64 internal constant GAS_ADOPT = 10_000;

    /// @dev Transient slots of the output served by `outputOf` in its reservation transaction: [rid, length, words...].
    bytes32 internal constant OUTPUT_SLOT = keccak256("unicity.vr.poa.output");

    address public immutable VR;
    PoaComposerEngine public immutable COMPOSER;

    struct Entry {
        uint8 state;
        uint64 since; // progress at the last transition
    }

    mapping(uint64 => Entry) internal _entries;
    uint64[] internal _members; // the committee in force (ascending id), synced at every Boundary and at attach
    uint64[] internal _queue; // tracked non-members in admission order: Admitted, Parked, Joining, and Removing non-members
    uint64 public outputCount;
    /// @dev An executed ModuleAction arms VR's work deadline until a boundary of this module's output (design 3.6.3). An action
    /// without a membership effect (a refused one, a Remove of a non-member) leaves the module nothing else to elect, so without this
    /// the module would stall with nothing for native repair to bind. The owed boundary counts as due work (the empty trial is a
    /// candidate while it is owed); the Boundary of the module's own output clears it.
    bool internal _boundaryOwed;

    // the module's open output: its joiners with their bit in the ready bitmap, and its leavers
    bytes32 internal _openRid;
    uint64[] internal _openJoiners;
    uint8[] internal _openJoinerBits;
    uint64[] internal _openLeavers;

    event StateChanged(uint64 indexed id, uint8 from, uint8 to);
    /// @dev `mask` selects the winning changes of the pool (bit i: the i-th change; the module's StateChanged events and VR's output
    /// show their effect).
    event Composed(bytes32 indexed resultId, uint256 mask, uint256 poolSize);
    event NoCandidate(uint8 reason);
    event ActionRefused(uint256 action, uint256 id, uint8 reason);

    error NotVR();
    error NotOwner();
    error BadState(uint8 state);
    error BadArgument();

    modifier onlyVR() {
        if (msg.sender != VR) revert NotVR();
        _;
    }

    /// @param vr the ValidatorRegistry (0xff..03 on a generation)
    /// @param composer the PoaComposerEngine (immutable, stateless; the genesis plan deploys it first). This module's code hash commits
    /// to the engine's address, not to its code: the genesis plan (VT-14) and every SetModule review must verify that the address holds
    /// the reviewed engine's runtime code (record and check its hash) and that it is no proxy. The constructor checks only that code
    /// exists.
    /// @param genesisMembers the genesis committee's ids, ascending (the genesis plan's VR alloc)
    constructor(address vr, PoaComposerEngine composer, uint64[] memory genesisMembers) {
        if (vr == address(0) || address(composer).code.length == 0) revert BadArgument();
        VR = vr;
        COMPOSER = composer;
        for (uint256 i = 0; i < genesisMembers.length; ++i) {
            if (i > 0 && genesisMembers[i - 1] >= genesisMembers[i]) revert BadArgument();
            _entries[genesisMembers[i]] = Entry(ACTIVE, 0);
            _members.push(genesisMembers[i]);
        }
    }

    // =============================================================================================
    // metadata (read by VR at SetModule queue and activation time only)
    // =============================================================================================

    function moduleTag() external pure returns (bytes32) {
        return TAG;
    }

    function capabilities() external pure returns (uint32) {
        return 0;
    }

    function gasBounds()
        external
        pure
        returns (uint64, uint64, uint64, uint64, uint64, uint64, uint64, uint64)
    {
        return (
            GAS_ELECT,
            GAS_OUTPUT,
            GAS_RECORD,
            GAS_RESOLVED,
            GAS_ATTACH,
            GAS_DETACH,
            GAS_GOV,
            GAS_ADOPT
        );
    }

    function maxElectionInterval() external pure returns (uint64) {
        return MAX_ELECTION_INTERVAL;
    }

    function liabilityHolder() external pure returns (address, bytes32) {
        return (address(0), bytes32(0));
    }

    // =============================================================================================
    // owners
    // =============================================================================================

    function submitApplication(uint64 id) external {
        _ownerMove(id, NONE, EXITED, APPLIED);
    }

    function withdrawApplication(uint64 id) external {
        _ownerMove(id, APPLIED, APPLIED, NONE);
    }

    function requestExit(uint64 id) external {
        _ownerMove(id, ACTIVE, ACTIVE, EXIT_REQUESTED);
    }

    function rejoin(uint64 id) external {
        _ownerMove(id, PARKED, PARKED, ADMITTED);
    }

    /// @dev An owner's transition of `id` from state `a` or `b` to `to`; an applicant is never a member.
    function _ownerMove(uint64 id, uint8 a, uint8 b, uint8 to) internal {
        address o = IVR(VR).ownerOf(id);
        if (o == address(0) || o != msg.sender) revert NotOwner();
        uint8 s = _entries[id].state;
        if ((s != a && s != b) || (to == APPLIED && _isMember(id))) revert BadState(s);
        _set(id, to, _now());
    }

    /// @notice The state of `id` and the progress of its last transition. A Parked joiner whose PARK_PERIOD has passed reads as
    /// Admitted (the automatic return, design 3.7.4).
    function status(uint64 id) external view returns (uint8 state, uint64 sinceProgress) {
        Entry memory e = _entries[id];
        if (e.state == PARKED && _parkOver(e, _now())) return (ADMITTED, e.since + PARK_PERIOD);
        return (e.state, e.since);
    }

    function members() external view returns (uint64[] memory) {
        return _members;
    }

    function queue() external view returns (uint64[] memory) {
        return _queue;
    }

    // =============================================================================================
    // contained steps (VR only)
    // =============================================================================================

    /// @notice ModuleAction (design 3.7.1): Admit `Applied -> Admitted`; Remove from any non-terminal state `-> Removing`; ConfirmExit
    /// `ExitRequested -> Removing`. A failing contained `onGovernance` faults the module (design 3.3.1), so an action the module cannot
    /// take (its guard, an unknown action, a malformed payload, a full queue) is refused without reverting: no transition, and an
    /// `ActionRefused` event. VR's Active state for the change then means "delivered and executed", not "accepted": clients read
    /// `ActionRefused` and `status`. Only these explicit payload, state and queue checks refuse; any other failure (a dependency call,
    /// an arithmetic or invariant failure) still reverts, and VR rejects the action with ActionFailed and faults the module.
    /// Every executed action arms VR's work deadline until the module's next boundary (design 3.6.3); an action that leaves the module
    /// no membership work (a refused one, a Remove of a non-member) therefore owes that boundary. Reserving or closing an output does
    /// not settle it; only the Boundary of the module's own output (or an attach) does.
    function onGovernance(bytes calldata action) external onlyVR {
        (uint8 refusal, uint256 a, uint256 w) = _govern(action);
        if (refusal != 0) emit ActionRefused(a, w, refusal);
        if (refusal != 0 || (a == REMOVE && !_isMember(uint64(w)))) _boundaryOwed = true;
    }

    function _govern(bytes calldata action) internal returns (uint8 refusal, uint256 a, uint256 w) {
        if (action.length != 64) return (REFUSED_MALFORMED, 0, 0);
        (a, w) = abi.decode(action, (uint256, uint256));
        if (w > type(uint64).max) return (REFUSED_MALFORMED, a, w);
        uint64 id = uint64(w);
        uint8 s = _entries[id].state;
        uint64 p = _now();
        if (a == ADMIT) {
            if (s != APPLIED) return (REFUSED_STATE, a, w);
            if (_queue.length >= MAX_QUEUE) return (REFUSED_QUEUE_FULL, a, w);
            _queue.push(id);
            _set(id, ADMITTED, p);
        } else if (a == REMOVE) {
            if (s == NONE || s == EXITED) return (REFUSED_STATE, a, w);
            if (s == REMOVING) return (0, a, w); // already Removing
            if (s == APPLIED) {
                // a Removing non-member is tracked in the queue and exits at the next boundary
                if (_queue.length >= MAX_QUEUE) return (REFUSED_QUEUE_FULL, a, w);
                _queue.push(id);
            }
            _set(id, REMOVING, p);
        } else if (a == CONFIRM_EXIT) {
            if (s != EXIT_REQUESTED) return (REFUSED_STATE, a, w);
            _set(id, REMOVING, p);
        } else {
            return (REFUSED_UNKNOWN, a, w);
        }
    }

    /// @notice The election (design 3.7.2, 3.7.3). Returns NotDue, NoCandidate (LimitsUnreachable: not a fault), or Reserved and ready.
    function elect(bytes calldata context) external onlyVR returns (bytes memory) {
        Election memory e;
        uint8 err;
        (err, e.c) = VRCodec.decodeContext(context);
        if (err != VRCodec.OK) revert BadArgument();
        e.contextHash = keccak256(context);
        e.cfg = IVR(VR).config();
        if (uint256(e.c.progress) < uint256(e.cfg.epochStartProgress) + VRC.MIN_EPOCH_GAP) {
            return VRCodec.packElect(VRC.ELECT_NOT_DUE, false, 0);
        }
        e.o = IVR(VR).committee();
        (e.inp, e.words) = _input(e.c, e.cfg, e.o);
        if (
            e.inp.dueWork == 0 && e.c.forceRemoved == 0 && e.inp.removing.length == 0
                && e.inp.staged.length == 0 && e.inp.joiners.length == 0
        ) return VRCodec.packElect(VRC.ELECT_NOT_DUE, false, 0);

        bool found;
        (found, e.mask, e.pl, e.s) = COMPOSER.compose(e.inp);
        if (!found) {
            emit NoCandidate(NO_CANDIDATE_LIMITS);
            return VRCodec.packElect(VRC.ELECT_NO_CANDIDATE, false, 0);
        }
        bytes32 rid = _compose(e);
        _record(rid, e.pl, e.mask, e.s, e.c.progress);
        return VRCodec.packElect(VRC.ELECT_RESERVED, true, rid);
    }

    /// @dev One election's working set.
    struct Election {
        VRCodec.Context c;
        bytes32 contextHash;
        ConfigView cfg;
        Member[] o; // the committee in force
        PoaComposer.Input inp;
        Member[] words; // staged and joiner binding words
        uint256 mask;
        PoaComposer.Pool pl;
        PoaComposer.Slot[] s; // the successor
    }

    /// @dev The output of a winning trial: a fresh result id, the members (incumbents' words, staged words at g + 1, joiners' words;
    /// quantized weights; VR-domain exposure digests), the header, served for `outputOf`.
    function _compose(Election memory e) internal returns (bytes32 rid) {
        uint64 attempt = ++outputCount;
        rid = keccak256(
            abi.encode(
                RESULT_DOMAIN, block.chainid, address(this), e.c.lastAcked, attempt, e.c.origin
            )
        );
        Member[] memory ms = new Member[](e.s.length);
        for (uint256 i = 0; i < e.s.length; ++i) {
            PoaComposer.Slot memory x = e.s[i];
            Member memory m = x.src < PoaComposer.MAX_COMMITTEE && !x.replaced
                ? e.o[x.src]
                : _wordsOf(e.words, x.id);
            m.weight = x.weight;
            m.rawWeight = x.rawWeight;
            m.exposureDigest = VRCodec.exposureDigest(e.cfg.network, VR, rid, m.id);
            ms[i] = m;
        }
        VRCodec.OutputHeader memory h;
        h.resultId = rid;
        h.predecessor = e.c.lastAcked;
        h.attempt = attempt;
        h.snapshotDigest =
            keccak256(abi.encode(SNAPSHOT_DOMAIN, e.contextHash, _poolDigest(e.pl), e.mask));
        h.policyDigest = keccak256(
            abi.encode(
                POLICY_DOMAIN,
                e.c.nMin,
                e.c.nTarget,
                e.c.nMax,
                e.inp.params.maxM,
                e.inp.params.distNum,
                e.inp.params.distDen,
                e.inp.forceDeadline
            )
        );
        _serve(rid, VRCodec.packOutput(h, ms));
    }

    /// @notice The output of `elect`, Ready within its reservation transaction; NotMine otherwise.
    function outputOf(bytes32 resultId) external view returns (bytes memory out) {
        bytes32 base = OUTPUT_SLOT;
        bytes32 rid;
        uint256 len;
        assembly ("memory-safe") {
            rid := tload(base)
            len := tload(add(base, 1))
        }
        if (rid != resultId || resultId == 0) return VRCodec.packStatus(VRC.STATUS_NOT_MINE);
        out = new bytes(len);
        for (uint256 i = 0; i < len / 32; ++i) {
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), shl(5, i)), tload(add(base, add(2, i))))
            }
        }
    }

    /// @notice Root records (design 3.4.2, 3.7.4), read from the SealRegistry. A Boundary syncs the membership with the committee VR
    /// actually installed: a primary Boundary installs the output (J), so its joiners become Active and its leavers Exited; a recovered
    /// Boundary keeps K, so the output's joiners return to Admitted and its leavers to Removing, and the next election retries them.
    /// The module's own expiry OutputRejected parks the joiners its ready bitmap lacks; its SessionClosed returns the rest (Joining ->
    /// Admitted, Leaving -> Removing).
    function onRecords(uint64 fromIndex, uint32 count) external onlyVR {
        IVRRecordSource seal = IVRRecordSource(VRC.SEAL_REGISTRY);
        for (uint64 i = fromIndex; i < fromIndex + count; ++i) {
            VRRecord memory r = seal.recordAt(i);
            if (!VRCodec.recordWellFormed(r.kind, r.data)) continue;
            bytes32 rid = bytes32(VRCodec.wordAt(r.data, 0));
            if (r.kind == VRC.REC_BOUNDARY) {
                uint64[] memory installed = IVR(VR).committeeIds();
                if (rid == _openRid && rid != 0) {
                    _resolveOpen(installed, r.progress);
                    _boundaryOwed = false;
                }
                _sync(installed, r.progress);
            } else if (rid == _openRid && rid != 0) {
                if (r.kind == VRC.REC_OUTPUT_REJECTED) {
                    if (VRCodec.wordAt(r.data, 1) == VRC.REJ_EXPIRED) {
                        _park(VRCodec.wordAt(r.data, 3), r.progress);
                    }
                } else if (r.kind == VRC.REC_SESSION_CLOSED) {
                    _returnOpen(r.progress);
                }
            }
        }
    }

    /// @notice Records are read in `onRecords`; nothing to do here.
    function onResolved(bytes32, uint8) external view onlyVR {}

    /// @notice Attached by a SetModule: the committee in force becomes the membership; Joining joiners of an earlier attachment are
    /// Admitted again.
    function attach(bytes calldata attachContext) external onlyVR {
        (uint8 err, VRCodec.AttachContext memory a) = VRCodec.decodeAttachContext(attachContext);
        if (err != VRCodec.OK) revert BadArgument();
        uint64[] memory ids = new uint64[](a.committee.length);
        for (uint256 k = 0; k < ids.length; ++k) {
            ids[k] = a.committee[k].id;
        }
        _sync(ids, a.progress);
        _clearOpen();
        _boundaryOwed = false;
        uint64[] memory q = _queue;
        for (uint256 k = 0; k < q.length; ++k) {
            if (_entries[q[k]].state == JOINING) _set(q[k], ADMITTED, a.progress);
        }
    }

    function detach() external view onlyVR {}

    /// @notice Not called (no ADOPTION_CHECK capability).
    function adoptionReady(bytes calldata) external pure returns (bytes memory) {
        return VRCodec.packStatus(VRC.STATUS_READY);
    }

    // =============================================================================================
    // internals
    // =============================================================================================

    function _now() internal view returns (uint64) {
        return IVRRecordSource(VRC.SEAL_REGISTRY).progress();
    }

    function _set(uint64 id, uint8 state, uint64 p) internal {
        uint8 from = _entries[id].state;
        _entries[id] = Entry(state, p);
        if (from != state) emit StateChanged(id, from, state);
    }

    function _parkOver(Entry memory e, uint64 p) internal pure returns (bool) {
        return uint256(p) >= uint256(e.since) + PARK_PERIOD;
    }

    function _isMember(uint64 id) internal view returns (bool) {
        uint256 n = _members.length;
        for (uint256 i = 0; i < n; ++i) {
            if (_members[i] == id) return true;
        }
        return false;
    }

    /// @dev The continuity binding (VR's: the four node and key words, not the payee).
    function _binding(Member memory m) internal pure returns (bytes32) {
        return keccak256(abi.encode(m.rootNodeWord, m.rootKeyHash, m.evmNodeWord, m.evmKeyHash));
    }

    /// @dev An identity's staged binding words, else (if `orCurrent`) its current ones; `found` is false when there is none.
    function _bindingWords(uint64 id, bool orCurrent)
        internal
        view
        returns (bool found, Member memory m)
    {
        m = IVR(VR).bindingOf(id, true);
        if (m.rootKeyHash == 0 && orCurrent) m = IVR(VR).bindingOf(id, false);
        found = m.rootKeyHash != 0;
    }

    function _wordsOf(Member[] memory words, uint64 id) internal pure returns (Member memory) {
        for (uint256 i = 0; i < words.length; ++i) {
            if (words[i].id == id) return words[i];
        }
        revert BadArgument(); // unreachable: every replaced or joining slot has its words
    }

    /// @dev The composer's input from the context, VR's views and the module's state; `words` holds the member words of every staged
    /// binding and every eligible joiner.
    function _input(VRCodec.Context memory c, ConfigView memory cfg, Member[] memory o)
        internal
        view
        returns (PoaComposer.Input memory inp, Member[] memory words)
    {
        words = new Member[](o.length + 2);
        uint256 nw;
        (inp.o, inp.removing) = _seats(o);
        (inp.staged, nw) = _staged(o, words);
        inp.joiners = _joiners(c.progress, words, nw);
        if (c.forceRemoved != 0) inp.forceRemoves = _forceRemoves();
        inp.progress = c.progress;
        inp.forceDeadline = MAX_ELECTION_INTERVAL + 2 * VRC.LIFETIME;
        inp.nMin = c.nMin;
        inp.nTarget = c.nTarget;
        inp.nMax = c.nMax;
        inp.dueWork = c.dueWork + (_boundaryOwed ? 1 : 0);
        inp.params =
            Continuity.Params(cfg.continuityMaxM, cfg.continuityDistNum, cfg.continuityDistDen);
    }

    /// @dev O for the composer, and its Removing members.
    function _seats(Member[] memory o)
        internal
        view
        returns (PoaComposer.Seat[] memory seats, uint64[] memory removing)
    {
        uint256 n = o.length;
        seats = new PoaComposer.Seat[](n);
        removing = new uint64[](n);
        uint256 nr = 0;
        for (uint256 i = 0; i < n; ++i) {
            seats[i] = PoaComposer.Seat(o[i].id, _binding(o[i]), o[i].weight, o[i].rawWeight);
            if (_entries[o[i].id].state == REMOVING) removing[nr++] = o[i].id;
        }
        removing = _shrink(removing, nr);
    }

    /// @dev The members with a staged binding (ascending id); their words go to `words[0 .. nw)`.
    function _staged(Member[] memory o, Member[] memory words)
        internal
        view
        returns (PoaComposer.Candidate[] memory staged, uint256 nw)
    {
        PoaComposer.Candidate[] memory all = new PoaComposer.Candidate[](o.length);
        for (uint256 i = 0; i < o.length; ++i) {
            (bool has, Member memory w) = _bindingWords(o[i].id, false);
            if (!has) continue;
            all[nw] = PoaComposer.Candidate(o[i].id, _binding(w));
            words[nw++] = w;
        }
        staged = new PoaComposer.Candidate[](nw);
        for (uint256 i = 0; i < nw; ++i) {
            staged[i] = all[i];
        }
    }

    /// @dev The first two eligible joiners in admission order (Admitted, or Parked past PARK_PERIOD); their words follow at `words[nw ..)`.
    function _joiners(uint64 p, Member[] memory words, uint256 nw)
        internal
        view
        returns (PoaComposer.Candidate[] memory joiners)
    {
        PoaComposer.Candidate[] memory two = new PoaComposer.Candidate[](2);
        uint256 nj = 0;
        uint256 nq = _queue.length;
        for (uint256 i = 0; i < nq && nj < 2; ++i) {
            uint64 id = _queue[i];
            Entry memory e = _entries[id];
            if (e.state != ADMITTED && !(e.state == PARKED && _parkOver(e, p))) continue;
            (bool has, Member memory w) = _bindingWords(id, true);
            if (!has) continue;
            two[nj++] = PoaComposer.Candidate(id, _binding(w));
            words[nw++] = w;
        }
        joiners = new PoaComposer.Candidate[](nj);
        for (uint256 i = 0; i < nj; ++i) {
            joiners[i] = two[i];
        }
    }

    function _forceRemoves() internal view returns (PoaComposer.ForceRemove[] memory fr) {
        (uint64[] memory cids, uint64[] memory targets, uint64[] memory sched) =
            IVR(VR).scheduledForceRemoves();
        fr = new PoaComposer.ForceRemove[](cids.length);
        for (uint256 i = 0; i < cids.length; ++i) {
            fr[i] = PoaComposer.ForceRemove(cids[i], targets[i], sched[i]);
        }
    }

    function _shrink(uint64[] memory xs, uint256 n) internal pure returns (uint64[] memory out) {
        out = new uint64[](n);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = xs[i];
        }
    }

    /// @dev Writes the packed output to the transient slots `outputOf` serves.
    function _serve(bytes32 rid, bytes memory content) internal {
        bytes32 base = OUTPUT_SLOT;
        uint256 len = content.length;
        assembly ("memory-safe") {
            tstore(base, rid)
            tstore(add(base, 1), len)
        }
        for (uint256 i = 0; i < len / 32; ++i) {
            assembly ("memory-safe") {
                tstore(add(base, add(2, i)), mload(add(add(content, 0x20), shl(5, i))))
            }
        }
    }

    /// @dev The pool the trial masks index: keccak over (kind, id, binding) per change, in pool order.
    function _poolDigest(PoaComposer.Pool memory pl) internal pure returns (bytes32 d) {
        for (uint256 i = 0; i < pl.changes.length; ++i) {
            PoaComposer.Change memory c = pl.changes[i];
            d = keccak256(abi.encode(d, c.kind, c.id, c.binding));
        }
    }

    /// @dev The chosen changes take effect in the module's state: joiners Joining, Removing removals Leaving; the open output is
    /// remembered for its records.
    function _record(
        bytes32 rid,
        PoaComposer.Pool memory pl,
        uint256 mask,
        PoaComposer.Slot[] memory s,
        uint64 p
    ) internal {
        _clearOpen();
        _openRid = rid;
        uint256 nc = pl.changes.length;
        for (uint256 i = 0; i < nc; ++i) {
            if (mask & (1 << i) == 0) continue;
            PoaComposer.Change memory ch = pl.changes[i];
            if (ch.kind == PoaComposer.REMOVE && _entries[ch.id].state == REMOVING) {
                _set(ch.id, LEAVING, p);
                _openLeavers.push(ch.id);
            } else if (ch.kind == PoaComposer.JOIN) {
                _set(ch.id, JOINING, p);
                _openJoiners.push(ch.id);
                for (uint256 k = 0; k < s.length; ++k) {
                    if (s[k].id == ch.id) _openJoinerBits.push(uint8(k));
                }
            }
        }
        emit Composed(rid, mask, nc);
    }

    function _clearOpen() internal {
        _openRid = 0;
        delete _openJoiners;
        delete _openJoinerBits;
        delete _openLeavers;
    }

    /// @dev Parking (design 3.7.4): the open output expired, and its joiners whose ready bit is clear are Parked.
    function _park(uint256 readyBitmap, uint64 p) internal {
        uint256 n = _openJoiners.length;
        for (uint256 i = 0; i < n; ++i) {
            uint64 id = _openJoiners[i];
            uint8 st = _entries[id].state;
            if ((readyBitmap >> _openJoinerBits[i]) & 1 != 0) continue;
            if (st == JOINING || st == ADMITTED) _set(id, PARKED, p);
        }
    }

    /// @dev The Boundary of the open output, before the membership sync: a joiner the installed committee lacks (a recovered Boundary
    /// keeps K) is Admitted again, a leaver it still holds is Removing again. Only entries still Joining or Leaving move, so a Remove
    /// or a parking that intervened stands. Then the open-output bookkeeping is released.
    function _resolveOpen(uint64[] memory installed, uint64 p) internal {
        uint256 n = _openJoiners.length;
        for (uint256 i = 0; i < n; ++i) {
            uint64 id = _openJoiners[i];
            if (_entries[id].state == JOINING && !_contains(installed, id)) _set(id, ADMITTED, p);
        }
        n = _openLeavers.length;
        for (uint256 i = 0; i < n; ++i) {
            uint64 id = _openLeavers[i];
            if (_entries[id].state == LEAVING && _contains(installed, id)) _set(id, REMOVING, p);
        }
        _clearOpen();
    }

    /// @dev The open output closed without a boundary: its joiners are Admitted again and its leavers Removing again.
    function _returnOpen(uint64 p) internal {
        uint256 n = _openJoiners.length;
        for (uint256 i = 0; i < n; ++i) {
            if (_entries[_openJoiners[i]].state == JOINING) _set(_openJoiners[i], ADMITTED, p);
        }
        n = _openLeavers.length;
        for (uint256 i = 0; i < n; ++i) {
            if (_entries[_openLeavers[i]].state == LEAVING) _set(_openLeavers[i], REMOVING, p);
        }
        _clearOpen();
    }

    /// @dev The membership becomes `ids` (ascending): members that left are Exited; arriving members are Active (a Removing joiner
    /// stays Removing, a Leaving one is Removing again); arrivals leave the queue, and Removing non-members exit at this boundary. Only
    /// arrivals, departures and queue entries are touched.
    function _sync(uint64[] memory ids, uint64 p) internal {
        uint64[] memory old = _members;
        for (uint256 i = 0; i < old.length; ++i) {
            if (!_contains(ids, old[i])) _set(old[i], EXITED, p);
        }
        for (uint256 k = 0; k < ids.length; ++k) {
            if (_contains(old, ids[k])) continue;
            uint8 st = _entries[ids[k]].state;
            if (st == LEAVING) _set(ids[k], REMOVING, p);
            else if (st != ACTIVE && st != EXIT_REQUESTED && st != REMOVING) _set(ids[k], ACTIVE, p);
        }
        uint64[] memory q = _queue;
        uint256 kept = 0;
        for (uint256 i = 0; i < q.length; ++i) {
            if (_contains(ids, q[i])) continue;
            if (_entries[q[i]].state == REMOVING) {
                _set(q[i], EXITED, p);
                continue;
            }
            q[kept++] = q[i];
        }
        _write(_queue, q, kept);
        _write(_members, ids, ids.length);
    }

    function _contains(uint64[] memory xs, uint64 x) internal pure returns (bool) {
        for (uint256 i = 0; i < xs.length; ++i) {
            if (xs[i] == x) return true;
        }
        return false;
    }

    /// @dev Makes the storage array equal to xs[0 .. n), writing only the slots that change.
    function _write(uint64[] storage a, uint64[] memory xs, uint256 n) internal {
        for (uint256 i = 0; i < n; ++i) {
            if (i < a.length) {
                if (a[i] != xs[i]) a[i] = xs[i];
            } else {
                a.push(xs[i]);
            }
        }
        while (a.length > n) a.pop();
    }
}
