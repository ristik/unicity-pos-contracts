// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

// Loops are bounded by the frozen ceilings: 16 committee members, 32 pending changes, 16 bound changes, 64 activations, 8 holders and
// the hook's maxBatch (at most 32 records). Calls into modules are contained steps (design section 3.3), never bubbling.
// forge-lint: disable-start(calls-loop, reentrancy-no-eth, unsafe-typecast)

import {VRC} from "./VRConstants.sol";
import {VRChanges} from "./VRChanges.sol";
import {VRLayout} from "./VRLayout.sol";
import {VRShared} from "./VRShared.sol";
import {
    Registration,
    Binding,
    IdentityView,
    ChangeView,
    ModuleMeta,
    ModuleView,
    FeeSet,
    ConfigView,
    Activation,
    HolderView,
    IVRRecordSource,
    IElectionModule,
    IVRSteps
} from "./VRTypes.sol";
import {KeyLib} from "../p85/KeyLib.sol";

/// @title VRGovernanceFacet
/// @notice The ValidatorRegistry's governance queue, identity registry and views (design sections 3.1, 3.5), run by DELEGATECALL from
/// VR's fallback: VR's storage, VR's lock, VR's address in every digest. A direct call to this account touches only its own empty
/// storage and is refused for every mutator.
contract VRGovernanceFacet is VRShared {
    address internal immutable SELF;

    constructor() {
        SELF = address(this);
    }

    modifier onlyDelegated() {
        if (address(this) == SELF) revert NotSelf();
        _;
    }

    /// @notice Queues a change (governor only). Structural checks only (design 3.5.3); SetModule also reads and caps the module's
    /// metadata with bounded staticcalls and caches it.
    function queue(uint8 kind, bytes calldata payload)
        external
        onlyDelegated
        locked
        returns (uint64 id)
    {
        VRLayout.VRStorage storage $ = VRLayout.load();
        if (msg.sender != $.governor) revert NotGovernor();
        IVRRecordSource seal = IVRRecordSource(VRC.SEAL_REGISTRY);
        uint64 t = seal.ucTime();
        VRChanges.Env memory env = VRChanges.Env({
            knownRootEpoch: $.status.knownRootEpoch,
            ucTime: t,
            pending: $.pending.pendingCount,
            pendingForce: $.pending.pendingForce,
            committee: _committeeIds(),
            maxGas: $.params.maxGas,
            systemGas: $.params.systemGas
        });
        uint8 code = VRChanges.check(kind, payload, env);
        if (code != 0) revert QueueRefused(code);
        if (kind == VRC.K_SET_MODULE) {
            (uint8 me, VRLayout.ModuleCache memory meta) = _readModule(
                address(uint160(VRChanges.field(payload, 0))), bytes32(VRChanges.field(payload, 1))
            );
            if (me != 0) revert QueueRefused(me);
            $.changeModule[$.counters.nextChangeId] = meta;
        } else if (kind == VRC.K_SCHEDULE_ACTIVATION) {
            if (
                uint256($.status.activationCount) + $.pending.pendingSchedules
                    >= VRC.MAX_ACTIVATIONS
            ) revert QueueRefused(VRChanges.TOO_MANY_ACTIVATIONS);
            ++$.pending.pendingSchedules;
        }
        uint64 p = seal.progress();
        id = $.counters.nextChangeId;
        $.counters.nextChangeId = id + 1;
        VRLayout.Change storage ch = $.changes[id];
        ch.kind = kind;
        ch.state = VRC.CH_QUEUED;
        ch.notBeforeProgress = p + VRC.DELAY_ROUNDS;
        ch.notBeforeTime = t + VRC.DELAY_SECONDS;
        ch.payloadHash = keccak256(payload);
        ch.payloadLength = uint32(payload.length);
        $.changePayload[id] = payload;
        $.changeScope[id] = VRChanges.scope(kind, payload);
        $.pendingIds.push(id);
        ++$.pending.pendingCount;
        if (kind == VRC.K_FORCE_REMOVE) ++$.pending.pendingForce;
        emit ChangeQueued(id, kind, ch.payloadHash, ch.notBeforeProgress, ch.notBeforeTime);
    }

    /// @notice Cancels a Queued or Scheduled change (governor only); never once Bound.
    function cancel(uint64 changeId) external onlyDelegated locked {
        VRLayout.VRStorage storage $ = VRLayout.load();
        if (msg.sender != $.governor) revert NotGovernor();
        uint8 s = $.changes[changeId].state;
        if (s != VRC.CH_QUEUED && s != VRC.CH_SCHEDULED) revert NotCancellable();
        _terminate(changeId, VRC.CH_CANCELLED, 0);
        _settleWork();
        emit ChangeCancelled(changeId);
    }

    /// @notice Executes a Queued change after both delays (anyone). A ModuleAction executes into the active module through a contained
    /// `onGovernance` (Active, or Rejected with ActionFailed or NotActive); every other kind becomes Scheduled.
    function execute(uint64 changeId) external onlyDelegated locked {
        VRLayout.VRStorage storage $ = VRLayout.load();
        VRLayout.Change storage ch = $.changes[changeId];
        if (ch.state != VRC.CH_QUEUED) revert PreconditionFailed();
        if ($.status.health == VRC.INCONSISTENT) revert Inconsistent();
        IVRRecordSource seal = IVRRecordSource(VRC.SEAL_REGISTRY);
        uint64 p = seal.progress();
        if (p < ch.notBeforeProgress || seal.ucTime() < ch.notBeforeTime) {
            revert DelayNotElapsed();
        }
        if (ch.kind != VRC.K_MODULE_ACTION) {
            ch.state = VRC.CH_SCHEDULED;
            ch.scheduledAt = p;
            if (ch.kind != VRC.K_FORCE_REMOVE) _noteWork(p); // a ForceRemove ages by its own scheduledAt
            emit ChangeScheduled(changeId, p);
            return; // `locked` clears the lock on this path too
        }
        bytes memory payload = $.changePayload[changeId];
        address target = address(uint160(VRChanges.field(payload, 0)));
        if (target != $.activeModule) {
            _terminate(changeId, VRC.CH_REJECTED, VRC.R_NOT_ACTIVE);
            emit ModuleActionExecuted(changeId, VRC.CH_REJECTED);
            return;
        }
        uint256 cap = _cap($.module, G_GOV, CAP_GOV);
        bytes memory data =
            abi.encodeCall(IElectionModule.onGovernance, (VRChanges.dynField(payload, 1)));
        (bool ok, bool short) = _contained(
            STEP_GOVERNANCE,
            _inner(cap) + VOID_VR_GAS,
            abi.encodeCall(IVRSteps.stepVoid, (target, cap, data))
        );
        if (short) revert BudgetShort(STEP_GOVERNANCE);
        if (ok) {
            _terminate(changeId, VRC.CH_ACTIVE, 0);
            $.watch.actionWork = true;
            _noteWork(p);
        } else {
            // a fully funded contained step that failed: the action is Rejected and the module Faulted (design 3.3.1 outcome classes)
            _terminate(changeId, VRC.CH_REJECTED, VRC.R_ACTION_FAILED);
            _fault(STEP_GOVERNANCE);
        }
        emit ModuleActionExecuted(changeId, $.changes[changeId].state);
    }

    function _digest(bytes32 domain, uint64 id, Registration calldata r)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                domain,
                VRLayout.load().network,
                block.chainid,
                address(this),
                msg.sender,
                uint256(id),
                keccak256(bytes(r.rootNodeID)),
                keccak256(r.rootKey),
                keccak256(bytes(r.evmNodeID)),
                keccak256(r.evmKey),
                r.payee,
                uint256(r.nonce)
            )
        );
    }

    /// @notice Registers a new identity. Both keys prove possession over the registration digest; key hashes are tombstoned for good.
    function register(Registration calldata r, bytes calldata rootPoP, bytes calldata evmPoP)
        external
        onlyDelegated
        locked
        returns (uint64 id)
    {
        VRLayout.VRStorage storage $ = VRLayout.load();
        uint8 e = _shape(r.rootNodeID, r.rootKey, r.evmNodeID, r.evmKey, r.payee);
        if (e != 0) revert RegistrationRefused(e);
        if (r.nonce != $.registrationNonce[msg.sender]) revert RegistrationRefused(REG_NONCE);
        bytes32 rk = keccak256(r.rootKey);
        bytes32 ek = keccak256(r.evmKey);
        if ($.keyOwner[rk] != 0 || $.keyOwner[ek] != 0) revert RegistrationRefused(REG_KEY_IN_USE);
        bytes32 digest = _digest(VRC.REGISTER_DOMAIN, 0, r);
        if (!KeyLib.verify(r.rootKey, digest, rootPoP) || !KeyLib.verify(r.evmKey, digest, evmPoP))
        {
            revert RegistrationRefused(REG_BAD_POP);
        }
        $.registrationNonce[msg.sender] = r.nonce + 1;
        id = $.counters.identityCount + 1;
        $.counters.identityCount = id;
        VRLayout.Identity storage idn = $.identities[id];
        idn.owner = msg.sender;
        idn.generation = 1;
        idn.currentRef = _storeBinding(r.rootNodeID, r.rootKey, r.evmNodeID, r.evmKey, r.payee);
        $.keyOwner[rk] = (uint256(id) << 8) | 1;
        $.keyOwner[ek] = (uint256(id) << 8) | 2;
        emit Registered(id, msg.sender, idn.currentRef);
    }

    /// @notice Stages a binding replacement (owner only), effective at the boundary of the next output that captures it. A replacement
    /// proposal overwrites the staged binding; keys may be reused only by the same identity in the same role.
    function proposeBinding(
        uint64 id,
        Registration calldata r,
        bytes calldata rootPoP,
        bytes calldata evmPoP
    ) external onlyDelegated locked {
        VRLayout.VRStorage storage $ = VRLayout.load();
        VRLayout.Identity storage idn = $.identities[id];
        if (idn.owner != msg.sender || idn.generation == 0) revert NotOwner();
        uint8 e = _shape(r.rootNodeID, r.rootKey, r.evmNodeID, r.evmKey, r.payee);
        if (e != 0) revert RegistrationRefused(e);
        if (r.nonce != idn.bindingNonce) revert RegistrationRefused(REG_NONCE);
        bytes32 rk = keccak256(r.rootKey);
        bytes32 ek = keccak256(r.evmKey);
        uint256 ro = $.keyOwner[rk];
        uint256 eo = $.keyOwner[ek];
        if (
            (ro != 0 && ro != ((uint256(id) << 8) | 1))
                || (eo != 0 && eo != ((uint256(id) << 8) | 2))
        ) {
            revert RegistrationRefused(REG_KEY_IN_USE);
        }
        bytes32 ref =
            _ref(keccak256(bytes(r.rootNodeID)), rk, keccak256(bytes(r.evmNodeID)), ek, r.payee);
        if (ref == idn.currentRef) revert RegistrationRefused(REG_UNCHANGED);
        bytes32 digest = _digest(VRC.BINDING_DOMAIN, id, r);
        if (!KeyLib.verify(r.rootKey, digest, rootPoP) || !KeyLib.verify(r.evmKey, digest, evmPoP))
        {
            revert RegistrationRefused(REG_BAD_POP);
        }
        idn.bindingNonce = r.nonce + 1;
        _storeBinding(r.rootNodeID, r.rootKey, r.evmNodeID, r.evmKey, r.payee);
        idn.stagedRef = ref;
        $.keyOwner[rk] = (uint256(id) << 8) | 1;
        $.keyOwner[ek] = (uint256(id) << 8) | 2;
        emit BindingProposed(id, r.nonce, ref);
    }

    /// @notice Advisory endpoints (owner only); never consensus input.
    function setEndpoints(uint64 id, bytes calldata multiaddrs) external onlyDelegated locked {
        VRLayout.Identity storage idn = VRLayout.load().identities[id];
        if (idn.owner != msg.sender || idn.generation == 0) revert NotOwner();
        if (multiaddrs.length > ENDPOINTS_MAX) revert EndpointsTooLong();
        idn.endpoints = multiaddrs;
        emit EndpointsSet(id);
    }

    function identity(uint64 id) external view returns (IdentityView memory v) {
        VRLayout.VRStorage storage $ = VRLayout.load();
        VRLayout.Identity storage idn = $.identities[id];
        v.owner = idn.owner;
        v.generation = idn.generation;
        v.currentRef = idn.currentRef;
        v.stagedRef = idn.stagedRef;
        v.bindingNonce = idn.bindingNonce;
        v.registrationNonce = $.registrationNonce[idn.owner];
        v.current = binding(idn.currentRef);
        if (idn.stagedRef != 0) v.staged = binding(idn.stagedRef);
        v.endpoints = idn.endpoints;
    }

    function ownerOf(uint64 id) external view returns (address) {
        return VRLayout.load().identities[id].owner;
    }

    function registrationNonce(address owner) external view returns (uint64) {
        return VRLayout.load().registrationNonce[owner];
    }

    /// @notice The write-once binding store (schema FD-16): a captured binding's preimages stay retrievable after any later staging.
    function binding(bytes32 ref) public view returns (Binding memory b) {
        VRLayout.BindingRecord storage s = VRLayout.load().bindings[ref];
        b.rootNodeWord = s.rootNodeWord;
        b.rootKeyHash = s.rootKeyHash;
        b.evmNodeWord = s.evmNodeWord;
        b.evmKeyHash = s.evmKeyHash;
        b.payee = s.payee;
        b.rootNodeID = s.rootNodeID;
        b.rootKey = s.rootKey;
        b.evmNodeID = s.evmNodeID;
        b.evmKey = s.evmKey;
    }

    function change(uint64 changeId) external view returns (ChangeView memory v) {
        VRLayout.VRStorage storage $ = VRLayout.load();
        VRLayout.Change storage c = $.changes[changeId];
        v.kind = c.kind;
        v.state = c.state;
        v.rejectReason = c.rejectReason;
        v.notBeforeProgress = c.notBeforeProgress;
        v.notBeforeTime = c.notBeforeTime;
        v.activeRootEpoch = c.activeRootEpoch;
        v.scheduledAt = c.scheduledAt;
        v.payloadHash = c.payloadHash;
        v.boundTo = c.boundTo;
        v.payload = $.changePayload[changeId];
    }

    /// @notice Changes not Active, Cancelled or Rejected, ascending.
    function pendingChanges() external view returns (uint64[] memory) {
        return VRLayout.load().pendingIds;
    }

    function openOutput() external view returns (bytes32) {
        return VRLayout.load().openOutput;
    }

    function lastAcked() external view returns (bytes32) {
        return VRLayout.load().lastAcked;
    }

    function pendingPair() external view returns (bytes32) {
        return VRLayout.load().pendingPair;
    }

    function health() external view returns (uint8) {
        return VRLayout.load().status.health;
    }

    function activeModule() external view returns (ModuleView memory v) {
        VRLayout.VRStorage storage $ = VRLayout.load();
        v.module = $.activeModule;
        v.codeHash = $.activeModuleCodeHash;
        VRLayout.ModuleCache storage m = $.module;
        v.meta = ModuleMeta(
            m.moduleTag,
            m.capabilities,
            m.maxElectionInterval,
            m.gasBounds,
            m.liabilityHolder,
            m.liabilityHolderCodeHash
        );
        v.health = $.status.health;
        v.workPending = $.watch.workPending;
        v.workSince = $.watch.workSince;
        v.stallDeadline = uint64(_deadline());
    }

    function config() external view returns (ConfigView memory v) {
        VRLayout.VRStorage storage $ = VRLayout.load();
        v.network = $.network;
        v.governor = $.governor;
        v.nMin = $.committeeLimits.nMin;
        v.nTarget = $.committeeLimits.nTarget;
        v.nMax = $.committeeLimits.nMax;
        v.vMax = $.hookLimits.vMax;
        v.lMax = $.hookLimits.lMax;
        v.rMax = $.hookLimits.rMax;
        v.maxBatch = $.hookLimits.maxBatch;
        v.feesPrevious = FeeSet(
            $.feesPrevious.baseFeeFloor,
            $.feesPrevious.changeDenominator,
            $.feesPrevious.feeCollector
        );
        v.feesCurrent = FeeSet(
            $.feesCurrent.baseFeeFloor, $.feesCurrent.changeDenominator, $.feesCurrent.feeCollector
        );
        v.feesEffectiveBlock = $.feesEffectiveBlock;
        v.delayRounds = VRC.DELAY_ROUNDS;
        v.delaySeconds = VRC.DELAY_SECONDS;
        v.knownRootEpoch = $.status.knownRootEpoch;
        v.epochStartProgress = $.watch.epochStartProgress;
        v.maxGas = $.params.maxGas;
        v.systemGas = $.params.systemGas;
        v.continuityMaxM = $.params.maxM;
        v.continuityDistNum = $.params.distNum;
        v.continuityDistDen = $.params.distDen;
    }

    /// @notice F(N) (schema section 12): the fees of block `n`, read at n - 1's post-state.
    function feesFor(uint64 n) external view returns (FeeSet memory) {
        VRLayout.VRStorage storage $ = VRLayout.load();
        VRLayout.Fees storage f = n >= $.feesEffectiveBlock ? $.feesCurrent : $.feesPrevious;
        return FeeSet(f.baseFeeFloor, f.changeDenominator, f.feeCollector);
    }

    function activationCount() external view returns (uint32) {
        return VRLayout.load().status.activationCount;
    }

    function activationAt(uint32 i) external view returns (Activation memory a) {
        VRLayout.Activation storage s = VRLayout.load().activations[i];
        return
            Activation(
                s.ruleId, s.releaseDigest, s.rootEpoch, s.notBeforeUcTime, s.state, s.changeId
            );
    }

    function holderCount() external view returns (uint8) {
        return VRLayout.load().status.holderCount;
    }

    function holderAt(uint8 h) external view returns (HolderView memory) {
        VRLayout.Holder storage s = VRLayout.load().holders[h];
        return HolderView(s.holder, s.holderCodeHash, s.module, s.registeredEpoch);
    }

    function retired(uint8 holder, uint64 id, uint64 generation) external view returns (bool) {
        return VRLayout.load().retired[holder][id][generation];
    }
}
