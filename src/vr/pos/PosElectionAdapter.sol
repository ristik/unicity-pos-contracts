// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded: at most 16 committee members (VR's MAX_COMMITTEE) and the custody record batch (at most 32). VR calls this module only
// through contained steps (design section 3.3); the adapter calls the fixed, immutable P85 modules it is constructed with.
// forge-lint: disable-start(calls-loop, unsafe-typecast, unused-return)

import {VRC} from "../VRConstants.sol";
import {VRCodec} from "../VRCodec.sol";
import {Member, IVR, IElectionModule} from "../VRTypes.sol";
import {ElectionPolicy} from "../../p85/ElectionPolicy.sol";
import {IStakeCustody, IPosAdapter} from "../../p85/IP85.sol";
import {Limits} from "../../p85/P85Types.sol";

/// @notice The two custody calls the adapter makes that `IStakeCustody` does not carry.
interface IPosCustody is IStakeCustody {
    function applyRootRecords(uint32 maxRecords) external;
    function exposureMemberDigest(bytes32 exposureId) external view returns (bytes32);
    function limits() external view returns (uint32 vMax, uint32 lMax, uint32 rMax, uint32 maxBatch);
}

/// @title PosElectionAdapter
/// @notice The P85 proof-of-stake stack behind the frozen `IElectionModule` interface, on its own PoS-genesis generation (design section
/// 3.8; a live PoA -> PoS switch is VT-17). It owns no state: every fact is P85's (election, custody) or VR's.
///
/// | Call | Behaviour |
/// |---|---|
/// | `elect` | maps P85's outcome; Reserved returns P85's own result id with `ready = false` |
/// | `outputOf` | Pending until P85 publishes (`finalizeCandidate`), NotMine for a foreign or lost result, Ready for a published, not lost, Reserved result: `frozenMembers`, custody's exposures and the frozen node words, with custody's exposure digest per member |
/// | `onRecords` | `custody.applyRootRecords(n)` (custody pulls from the SealRegistry itself) |
/// | `onResolved`, `onGovernance` | no-ops: the economic policy stays in `GovernanceParams` under the multisig |
/// | `outputLost` | `ElectionPolicy` only, at the one place its `lost` bit is first set: `VR.invalidate(resultID, LOST)`, no try/catch |
///
/// **Liability holder.** The holder is custody itself (holder 0 of the generation): it writes the generic facts (design 3.9.2) in its own
/// storage in the same function as every liability mutation, so the adapter has nothing to mirror.
///
/// **Alignment (testnet prototype).** A member word is VR's binding word and the custody generation is the member generation: the prototype
/// requires an identity's VR binding (words, generation) to equal its P85 delegation. A result whose member does not match VR's current or
/// staged binding is never served (NotMine) and expires, so a misaligned identity cannot Fault the registry. Carry-over (native) boundaries
/// break custody's liability continuity; the adapter is then Faulted by its own records, which is the prototype's stated limit.
///
/// Immutable, no proxy. `ELECTION` and `CUSTODY` are the generation's fixed modules.
contract PosElectionAdapter is IElectionModule, IPosAdapter {
    bytes32 public constant TAG = keccak256("unicity.vr.pos-p85.v1");

    // ---- gas bounds: the measured worst case x 5/4, below VR's caps (test/vr/pos/PosGas.t.sol) ----
    uint64 internal constant GAS_ELECT = 4_000_000;
    uint64 internal constant GAS_OUTPUT = 1_000_000;
    uint64 internal constant GAS_RECORD = 1_500_000;
    uint64 internal constant GAS_RESOLVED = 10_000;
    uint64 internal constant GAS_ATTACH = 10_000;
    uint64 internal constant GAS_DETACH = 10_000;
    uint64 internal constant GAS_GOV = 10_000;
    uint64 internal constant GAS_ADOPT = 10_000;

    address public immutable VR;
    ElectionPolicy public immutable ELECTION;
    IPosCustody public immutable CUSTODY;

    error NotVR();
    error NotElection();
    error BadArgument();
    /// @dev `attach` is refused: this module lives on its own PoS genesis generation (a live switch to it is VT-17).
    error NotSupported();

    modifier onlyVR() {
        if (msg.sender != VR) revert NotVR();
        _;
    }

    constructor(address vr, ElectionPolicy election, IPosCustody custody) {
        if (vr == address(0) || address(election) == address(0) || address(custody) == address(0)) {
            revert BadArgument();
        }
        VR = vr;
        ELECTION = election;
        CUSTODY = custody;
    }

    // =============================================================================================
    // metadata (read by VR at SetModule queue and activation time, and at genesis; never on a hook path)
    // =============================================================================================

    function moduleTag() external pure returns (bytes32) {
        return TAG;
    }

    function capabilities() external pure returns (uint32) {
        return VRC.CAP_LIABILITY_HOLDER;
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

    /// @notice An election is due once the cadence (progress rounds past the last acknowledged rotation and past the last attempt) has
    /// passed, so the cadence is the interval after which work is overdue.
    function maxElectionInterval() external view returns (uint64 rounds) {
        (,,,,,, rounds,) = ELECTION.params();
    }

    /// @notice Custody is the liability holder (design 3.9: holder 0 of the PoS-prototype generation).
    function liabilityHolder() external view returns (address, bytes32) {
        return (address(CUSTODY), address(CUSTODY).codehash);
    }

    // =============================================================================================
    // contained steps (VR only)
    // =============================================================================================

    /// @notice Not a switch target: reports NotReady.
    function adoptionReady(bytes calldata) external pure returns (bytes memory) {
        return VRCodec.packStatus(VRC.STATUS_NOT_READY);
    }

    function attach(bytes calldata) external view onlyVR {
        revert NotSupported();
    }

    /// @dev Leaving a holder erases nothing (design 3.9.4): custody keeps consuming records permissionlessly.
    function detach() external onlyVR {}

    /// @notice Maps P85's outcome (design 3.8): Disabled, NotDue, Reserved (P85's own result id, `ready = false`: the result becomes
    /// Ready only after its possession proofs are in and `finalizeCandidate` has published it), NoCandidate.
    function elect(bytes calldata context) external onlyVR returns (bytes memory) {
        (uint8 err, VRCodec.Context memory c) = VRCodec.decodeContext(context);
        if (err != VRCodec.OK) revert BadArgument();
        ElectionPolicy.Outcome o = ELECTION.elect(c.origin);
        if (o == ElectionPolicy.Outcome.Reserved) {
            return VRCodec.packElect(VRC.ELECT_RESERVED, false, ELECTION.lastAttemptResult());
        }
        if (o == ElectionPolicy.Outcome.NotDue) return VRCodec.packElect(VRC.ELECT_NOT_DUE, false, 0);
        if (o == ElectionPolicy.Outcome.NoCandidateRecorded) {
            return VRCodec.packElect(VRC.ELECT_NO_CANDIDATE, false, 0);
        }
        return VRCodec.packElect(VRC.ELECT_DISABLED, false, 0);
    }

    /// @notice Pending while P85 has not published the result, NotMine for a result that is not P85's open Reserved one (or is lost, or
    /// names a member VR does not hold as P85 does), Ready for a published, not lost, Reserved result.
    function outputOf(bytes32 resultId) external view returns (bytes memory) {
        if (resultId == bytes32(0)) return VRCodec.packStatus(VRC.STATUS_NOT_MINE);
        ElectionPolicy.Result memory r = ELECTION.result(resultId);
        if (r.state != ElectionPolicy.ResultState.Reserved) {
            return VRCodec.packStatus(VRC.STATUS_NOT_MINE);
        }
        ElectionPolicy.Publication memory p = ELECTION.publication(resultId);
        if (p.lost) return VRCodec.packStatus(VRC.STATUS_NOT_MINE);
        if (!p.published) return VRCodec.packStatus(VRC.STATUS_PENDING);

        ElectionPolicy.Frozen[] memory f = ELECTION.frozenMembers(resultId);
        bytes32[] memory eids = CUSTODY.assignmentExposures(r.assignmentID);
        if (f.length == 0 || f.length > VRC.MAX_COMMITTEE || eids.length != f.length) {
            return VRCodec.packStatus(VRC.STATUS_NOT_MINE);
        }
        Member[] memory ms = new Member[](f.length);
        for (uint256 i = 0; i < f.length; ++i) {
            Member memory m = _member(f[i], eids[i]);
            if (!_aligned(m)) return VRCodec.packStatus(VRC.STATUS_NOT_MINE);
            ms[i] = m;
        }
        VRCodec.OutputHeader memory h;
        h.resultId = resultId;
        h.predecessor = IVR(VR).lastAcked();
        h.attempt = r.attempt;
        h.snapshotDigest = p.snapshotDigest;
        h.policyDigest = p.policyDigest;
        return VRCodec.packOutput(h, ms);
    }

    /// @dev One frozen member as VR's member words: the frozen node words and generation, the quantized and raw weights, the exposure's
    /// frozen key hashes and operator payee, and custody's member digest of the exposure (a recovery copy or genesis seat: VR's; a primary: the keccak of the lot list).
    function _member(ElectionPolicy.Frozen memory f, bytes32 exposureId)
        internal
        view
        returns (Member memory m)
    {
        (,,,,, bytes32 rootKeyHash, bytes32 evmKeyHash, address payee,,) =
            CUSTODY.exposures(exposureId);
        m.id = f.id;
        m.generation = f.generation;
        m.weight = f.weight;
        m.rawWeight = f.raw;
        m.rootNodeWord = f.rootNodeID;
        m.rootKeyHash = rootKeyHash;
        m.evmNodeWord = f.evmNodeID;
        m.evmKeyHash = evmKeyHash;
        m.payee = payee;
        bytes32 d = CUSTODY.exposureMemberDigest(exposureId);
        m.exposureDigest = d != bytes32(0) ? d : keccak256(abi.encode(CUSTODY.exposureLots(exposureId)));
    }

    /// @dev VR accepts only words equal to the identity's current binding (generation g) or its staged one (g + 1); a member that is not
    /// served as such would Fault the module, so it is not served.
    function _aligned(Member memory m) internal view returns (bool) {
        Member memory cur = IVR(VR).bindingOf(m.id, false);
        if (_sameBinding(cur, m)) return true;
        return _sameBinding(IVR(VR).bindingOf(m.id, true), m);
    }

    function _sameBinding(Member memory a, Member memory b) private pure returns (bool) {
        return a.generation != 0 && a.generation == b.generation && a.rootNodeWord == b.rootNodeWord
            && a.rootKeyHash == b.rootKeyHash && a.evmNodeWord == b.evmNodeWord
            && a.evmKeyHash == b.evmKeyHash && a.payee == b.payee;
    }

    /// @notice Root records (design 3.8): custody pulls them from the SealRegistry itself, from its own cursor, up to the end of this
    /// segment (a custody that is ahead has nothing to do; one that is behind catches up, within its batch limit).
    function onRecords(uint64 fromIndex, uint32 count) external onlyVR {
        uint64 end = fromIndex + count;
        uint64 cursor = CUSTODY.recordCursor();
        if (cursor >= end) return;
        (,,, uint32 maxBatch) = CUSTODY.limits();
        uint64 n = end - cursor;
        if (n > maxBatch) n = maxBatch;
        CUSTODY.applyRootRecords(uint32(n));
    }

    /// @dev Economic policy stays in `GovernanceParams` under the multisig.
    function onResolved(bytes32, uint8) external onlyVR {}

    function onGovernance(bytes calldata) external onlyVR {}

    /// @notice The atomic loss (design 3.8 change 2): `ElectionPolicy` calls it where its `lost` bit is first set. `VR.invalidate` is total
    /// for its source (a no-op in every state but Reserved or Published), and neither call is inside a `try/catch`.
    function outputLost(bytes32 resultID) external {
        if (msg.sender != address(ELECTION)) revert NotElection();
        IVR(VR).invalidate(resultID, VRC.INVALID_LOST);
    }
}

// forge-lint: disable-end(calls-loop, unsafe-typecast, unused-return)
