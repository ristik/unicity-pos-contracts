// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {StdInvariant} from "forge-std/StdInvariant.sol";
import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {StakeCustody} from "../../src/p85/StakeCustody.sol";
import {ElectionPolicy} from "../../src/p85/ElectionPolicy.sol";
import {CaseView} from "../../src/p85/IP85.sol";
import {
    ReserveInput,
    ReserveMember,
    RecordKind,
    AckData,
    RecoveryAckData,
    SessionClosedData,
    RetirementData,
    ClosureData,
    Delegation,
    DelegationRequest
} from "../../src/p85/P85Types.sol";

/// @notice Drives the custody, election-index and evidence modules through random but structurally
/// valid sequences (registrations, bonds, retirements, reservations, root records, evidence,
/// settlement, maturity, claims, forced value, role changes) plus unauthorized-caller probes.
/// It plays the roles of the system hook (root records) and of the fixed Election.
contract InvariantHandler is P85Flow {
    struct Ident {
        uint256 ownerKey;
        uint256 rootKey;
        uint256 evmKey;
        address withdrawal;
        uint256 bondedLots;
    }

    uint64[] public ids;
    mapping(uint64 => Ident) public ident;
    mapping(bytes32 => uint256) internal keyOf; // key hash -> private key
    bytes32[] public assignmentList;
    bytes32[] public openSessions;
    bytes32[] public cases;
    address[] public creditors;
    mapping(address => bool) internal isCreditor;
    uint64[] public excludedIds;
    mapping(uint64 => bool) internal knownExcluded;

    uint64 public nextEpoch = 2;
    uint64 public nextAttempt = 1;
    uint256 public ghostSurplus;
    uint256 public ghostMatured;
    uint256 public ghostPenaltyCredit;
    uint256 public ghostClaimed;
    uint256 public ghostOffences;
    uint256 public ghostMatureCalls;
    uint256 public ghostReservations;
    uint256 public ghostAcks;
    uint256 public ghostRecoveries;
    uint256 public ghostClosures;
    uint256 public ghostRetirements;

    bool public permissionViolation;
    bool public badMaturity;
    bool public applyFailed;
    bool public unexpectedRevert;
    bytes4 public lastApplyError;

    mapping(bytes32 => bytes32) internal sessionAssignment;
    mapping(bytes32 => bytes32) internal sessionIncumbent;
    mapping(bytes32 => uint64) internal knownH;
    mapping(bytes32 => bool) internal knownHSet;
    uint64 internal hCounter = 500;
    uint64 internal offsetCounter = 1_000;

    constructor(P85Flow t) {
        custody = t.custodyAddr();
        election = t.electionAddr();
        evidence = t.evidenceAddr();
        roots = t.rootsAddr();
        treasury = t.treasuryAddr();
        reporter = t.reporterAddr();
        for (uint256 i; i < N_GENESIS; ++i) {
            uint64 id = gid(i);
            ids.push(id);
            ident[id] = Ident(ownerPk(i), rootPk(i), evmPk(i), vm.addr(wdPk(i)), 1);
            keyOf[keccak256(compressed(rootPk(i)))] = rootPk(i);
            keyOf[keccak256(compressed(evmPk(i)))] = evmPk(i);
            _creditor(vm.addr(wdPk(i)));
        }
        assignmentList.push(GENESIS_ASSIGNMENT);
        _creditor(treasury);
        _creditor(reporter);
        _creditor(makeAddr("reporter2"));
    }

    function _creditor(address a) internal {
        if (!isCreditor[a]) {
            isCreditor[a] = true;
            creditors.push(a);
        }
    }

    function idsLength() external view returns (uint256) {
        return ids.length;
    }

    function assignmentCount() external view returns (uint256) {
        return assignmentList.length;
    }

    function creditorCount() external view returns (uint256) {
        return creditors.length;
    }

    function sessionCount() external view returns (uint256) {
        return openSessions.length;
    }

    function sessionOf(uint256 i)
        external
        view
        returns (bytes32 res, bytes32 asg, bytes32 incumbent)
    {
        res = openSessions[i];
        return (res, sessionAssignment[res], sessionIncumbent[res]);
    }

    function excludedCount() external view returns (uint256) {
        return excludedIds.length;
    }

    function caseCount() external view returns (uint256) {
        return cases.length;
    }

    // --- identities and lots -----------------------------------------------------------------------

    function act_registerIdentity(uint256 seed) external {
        if (ids.length >= 12) return;
        uint256 n = ids.length + 1;
        uint256 ok = 0x6000 + n * 16 + (seed % 3);
        uint256 rk = 0x7000 + n * 16;
        uint256 ek = 0x8000 + n * 16;
        uint256 wk = 0x9000 + n * 16;
        address owner = vm.addr(ok);
        bytes memory key = compressed(rk);
        bytes memory pop =
            sign(rk, registerDigest(owner, vm.addr(wk), key, custody.registerNonce(owner)));
        vm.prank(owner);
        try custody.register(key, pop, vm.addr(wk)) returns (uint64 id) {
            ids.push(id);
            ident[id] = Ident(ok, rk, ek, vm.addr(wk), 0);
            keyOf[keccak256(key)] = rk;
            keyOf[keccak256(compressed(ek))] = ek;
            _creditor(vm.addr(wk));
            _delegate(id);
        } catch {
            // key reuse after identical seeds is the only expected failure
        }
    }

    function _delegate(uint64 id) internal {
        Ident storage x = ident[id];
        DelegationRequest memory r;
        r.id = id;
        r.generation = 1;
        r.binding = Delegation(
            keccak256(abi.encode("root", id)),
            compressed(x.rootKey),
            keccak256(abi.encode("evm", id)),
            compressed(x.evmKey),
            vm.addr(x.ownerKey)
        );
        r.expiry = type(uint64).max;
        (,, uint64 nextNonce) = election.delegation(id, 1);
        r.delegationNonce = nextNonce;
        bytes32 digest = election.delegationDigest(r);
        try election.admitDelegation(r, sign(x.ownerKey, digest), sign(x.evmKey, digest)) {}
        catch {
            unexpectedRevert = true;
        }
    }

    function act_bond(uint256 idSeed, uint256 amountSeed) external {
        uint64 id = ids[idSeed % ids.length];
        uint256 amount = bound(amountSeed, 100 * UCT, 2_000 * UCT);
        (address owner,,,,,,,,) = custody.positions(id);
        vm.deal(owner, owner.balance + amount);
        vm.prank(owner);
        try custody.bond{value: amount}(id) {
            ident[id].bondedLots++;
        } catch {
            // legal failures: lot capacity, a closing generation
        }
    }

    function act_requestRetirement(uint256 idSeed) external {
        uint64 id = ids[idSeed % ids.length];
        (address owner,,,,,,,,) = custody.positions(id);
        vm.prank(owner);
        try custody.requestRetirement(id) {} catch {}
    }

    function act_changeWithdrawal(uint256 idSeed, uint256 salt) external {
        uint64 id = ids[idSeed % ids.length];
        (address owner, address wd,,,, uint64 nonce,,,) = custody.positions(id);
        address newWd = makeAddr(string(abi.encode("wd", salt % 5)));
        if (newWd == wd) return;
        vm.prank(owner);
        try custody.proposeRoles(id, owner, newWd, nonce) {}
        catch {
            return;
        }
        vm.prank(newWd);
        try custody.acceptRoles(id, nonce) {} catch {}
        vm.prank(wd);
        try custody.acceptRoles(id, nonce) {
            ident[id].withdrawal = newWd;
            _creditor(newWd);
        } catch {}
    }

    function act_nominatePayee(uint256 idSeed, uint256 salt) external {
        uint64 id = ids[idSeed % ids.length];
        (address owner,,,, uint64 gen,,,,) = custody.positions(id);
        Ident storage x = ident[id];
        DelegationRequest memory r;
        r.id = id;
        r.generation = gen;
        r.binding = Delegation(
            keccak256(abi.encode("root", id)),
            compressed(x.rootKey),
            keccak256(abi.encode("evm", id)),
            compressed(x.evmKey),
            makeAddr(string(abi.encode("payee", salt % 7)))
        );
        r.expiry = type(uint64).max;
        (,, uint64 nextNonce) = election.delegation(id, gen);
        r.delegationNonce = nextNonce;
        (,,,,, uint64 roleNonce,,,) = custody.positions(id);
        r.roleNonce = roleNonce;
        bytes32 digest = election.delegationDigest(r);
        vm.prank(owner);
        try election.admitDelegation(r, sign(x.ownerKey, digest), sign(x.evmKey, digest)) {}
            catch {}
    }

    // --- the fixed Election: reservations -----------------------------------------------------------

    function act_reserveCandidate(uint256 seed) external {
        uint256 n = ids.length;
        uint64[] memory pick = new uint64[](n);
        uint256 count;
        for (uint256 i; i < n; ++i) {
            if ((seed >> i) & 1 == 0 && i >= 2) continue;
            uint64 id = ids[i];
            (,,,,,, uint32 open,, bool retiring) = custody.positions(id);
            if (open == 0 || retiring || evidence.excluded(id)) continue;
            pick[count++] = id;
        }
        if (count == 0) return;
        ReserveMember[] memory members = new ReserveMember[](count);
        for (uint256 k; k < count; ++k) {
            uint64 id = pick[k];
            uint256[] memory lots = lotsOf(id);
            uint256 backing;
            for (uint256 j; j < lots.length; ++j) {
                (,,, uint128 remaining,,,,,,,,,) = custody.lots(lots[j]);
                backing += remaining;
            }
            (,, bytes32 rootHash,,,,,,) = custody.positions(id);
            (Delegation memory d,,) = election.delegation(id, 1);
            members[k] = ReserveMember({
                id: id,
                weight: uint64(backing / (100 * UCT)),
                rootKeyHash: rootHash,
                evmKeyHash: keccak256(d.evmKey),
                operatorPayee: d.operatorPayee,
                lotIDs: lots
            });
        }
        bytes32 res = keccak256(abi.encode("res", nextAttempt));
        bytes32 asg = keccak256(abi.encode("asg", nextAttempt));
        ReserveInput memory in_ = ReserveInput({
            resultID: res,
            assignmentID: asg,
            lineage: LINEAGE,
            attempt: nextAttempt,
            rootEpoch: nextEpoch,
            evmEpoch: nextEpoch,
            incumbentAssignmentID: custody.lastAckedAssignment(),
            members: members
        });
        vm.prank(address(election));
        try custody.reserveCandidate(in_) {
            nextAttempt++;
            nextEpoch++;
            ghostReservations++;
            openSessions.push(res);
            sessionAssignment[res] = asg;
            sessionIncumbent[res] = in_.incumbentAssignmentID;
            assignmentList.push(asg);
        } catch {
            // legal: weight/coverage drift, reference ceiling, retiring identity raced in
        }
    }

    // --- the system hook: root records --------------------------------------------------------------

    function act_advanceClock(uint256 dp, uint256 dt) external {
        clock(
            roots.progress() + uint64(bound(dp, 0, 3_000)),
            roots.ucTime() + uint64(bound(dt, 0, 5_000))
        );
    }

    function act_rootStep(uint256 seed) external {
        uint256 choice = seed % 4;
        if (choice == 0 && openSessions.length != 0) _sessionRecord(seed);
        else if (choice == 1) _closureRecord(seed);
        else if (choice == 2) _retirementRecord(seed);
        else if (openSessions.length != 0) _sessionRecord(seed >> 8);
        _apply();
    }

    function _sessionRecord(uint256 seed) internal {
        uint256 slot = seed % openSessions.length;
        bytes32 res = openSessions[slot];
        bytes32 incumbent = sessionIncumbent[res];
        uint256 kind = (seed >> 4) % 3;
        bool incumbentCurrent = incumbent == custody.lastAckedAssignment();
        if (kind == 0 || !incumbentCurrent) {
            pushRecord(RecordKind.SessionClosed, abi.encode(SessionClosedData(res)));
        } else {
            Asg memory inc = asg(incumbent);
            uint64 h = knownHSet[incumbent] ? knownH[incumbent] : inc.firstRound + hCounter++;
            if (inc.hKnown) h = inc.hRound;
            knownH[incumbent] = h;
            knownHSet[incumbent] = true;
            uint64 offset = offsetCounter;
            offsetCounter += 1_000;
            if (kind == 1) {
                pushRecord(RecordKind.Ack, ackData(res, h, offset, h + 1));
                ghostAcks++;
            } else {
                bytes32 k = keccak256(abi.encode("asg/K", res));
                pushRecord(
                    RecordKind.RecoveryAck,
                    abi.encode(
                        RecoveryAckData(
                            res,
                            k,
                            offset,
                            h + 1,
                            h + 50,
                            offset + 1_000,
                            h + 51,
                            nextEpoch,
                            nextEpoch
                        )
                    )
                );
                nextEpoch++;
                assignmentList.push(k);
                ghostRecoveries++;
            }
        }
        openSessions[slot] = openSessions[openSessions.length - 1];
        openSessions.pop();
    }

    function _closureRecord(uint256 seed) internal {
        uint256 n = assignmentList.length;
        for (uint256 t; t < n; ++t) {
            bytes32 a = assignmentList[(seed % n + t) % n];
            Asg memory x = asg(a);
            if (x.state != 2 || x.closed || a == custody.lastAckedAssignment()) continue;
            // only close assignments whose successor is known to have replaced them
            if (!x.hKnown && !knownHSet[a]) continue;
            uint64 h = x.hKnown ? x.hRound : knownH[a];
            if (h < x.firstRound) continue;
            pushRecord(RecordKind.Closure, closureData(a, h, bytes32(uint256(uint160(uint256(a))))));
            ghostClosures++;
            return;
        }
    }

    function _retirementRecord(uint256 seed) internal {
        uint256 n = ids.length;
        for (uint256 t; t < n; ++t) {
            uint64 id = ids[(seed % n + t) % n];
            (,,,, uint64 gen,,,, bool retiring) = custody.positions(id);
            if (!retiring) continue;
            (bool imported,,) = custody.retirements(id, gen);
            if (imported || custody.liveExposures(id, gen) != 0) continue;
            // the root only issues a retirement record at or after the liability anchor
            uint64 anchor = custody.maxLiabilityAnchor(id, gen);
            if (roots.progress() < anchor) clock(anchor, roots.ucTime());
            retireRecordPushOnly(id, gen);
            ghostRetirements++;
            return;
        }
    }

    function retireRecordPushOnly(uint64 id, uint64 gen) internal {
        pushRecord(
            RecordKind.Retirement,
            abi.encode(RetirementData(id, gen, custody.exposureChain(id, gen)))
        );
    }

    function _apply() internal {
        uint64 count = roots.recordCount();
        uint64 done = custody.recordCursor();
        while (done < count) {
            uint64 step = count - done > 32 ? 32 : count - done;
            try custody.applyRootRecords(uint32(step)) {}
            catch (bytes memory reason) {
                applyFailed = true;
                lastApplyError = bytes4(reason);
                return;
            }
            done += step;
        }
    }

    // --- evidence -------------------------------------------------------------------------------------

    function act_submitEvidence(uint256 seed) external {
        bytes32 a = assignmentList[seed % assignmentList.length];
        Asg memory x = asg(a);
        if (x.state == 0 || x.state == 3 || !x.offsetSet) return;
        bytes32[] memory exps = custody.assignmentExposures(a);
        if (exps.length == 0) return;
        bytes32 e = exps[(seed >> 8) % exps.length];
        Expo memory ex = expo(e);
        uint8 domain = uint8(1 + ((seed >> 16) % 2));
        uint256 pk = keyOf[domain == 1 ? ex.rootKeyHash : ex.evmKeyHash];
        if (pk == 0) return;
        uint64 epoch = domain == 1 ? x.rootEpoch : x.evmEpoch;
        uint64 round = x.firstRound + uint64((seed >> 24) % 2_500);
        Evidence.VoteHeader memory h =
            Evidence.VoteHeader(NETWORK, domain, compressed(pk), epoch, round);
        Evidence.SignedVote memory v1 =
            Evidence.SignedVote(keccak256("A"), sign(pk, evidence.voteDigest(h, keccak256("A"))));
        Evidence.SignedVote memory v2 =
            Evidence.SignedVote(keccak256("B"), sign(pk, evidence.voteDigest(h, keccak256("B"))));
        address who = (seed >> 40) % 2 == 0 ? reporter : makeAddr("reporter2");
        vm.prank(who);
        try evidence.submitEvidence(h, v1, v2, e) returns (bytes32 caseID) {
            cases.push(caseID);
            ghostOffences++;
            if (!knownExcluded[ex.id]) {
                knownExcluded[ex.id] = true;
                excludedIds.push(ex.id);
            }
        } catch {
            // legal: late, duplicate offence, key mismatch for rotated keys
        }
    }

    function act_settle(uint256 seed, uint256 count) external {
        if (cases.length == 0) return;
        bytes32 caseID = cases[seed % cases.length];
        CaseView memory c = evidence.caseInfo(caseID);
        if (c.cursor >= c.lotCount) return;
        uint256[] memory lots = custody.exposureLots(c.exposureID);
        uint256 n = bound(count, 1, c.lotCount - c.cursor);
        uint256[] memory batch = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            batch[i] = lots[c.cursor + i];
        }
        try evidence.settleEvidence(caseID, batch) returns (uint256 debit) {
            ghostPenaltyCredit += debit;
        } catch {
            unexpectedRevert = true;
        }
    }

    // --- maturity, claims, forced value, probes ----------------------------------------------------------

    function act_mature(uint256 idSeed) external {
        uint64 id = ids[idSeed % ids.length];
        uint256[] memory lots = lotsOf(id);
        for (uint256 i; i < lots.length; ++i) {
            LotV memory l = lotv(lots[i]);
            if (l.category == 4) continue;
            uint256[] memory one = new uint256[](1);
            one[0] = lots[i];
            uint256 remaining = l.remaining;
            uint32 holds = evidence.pendingHolds(lots[i]);
            (bool imported,,) = custody.retirements(id, l.generation);
            try custody.mature(one) {
                ghostMatured += remaining;
                ghostMatureCalls++;
                if (holds != 0 || l.refCount != 0 || !imported) badMaturity = true;
            } catch {}
        }
    }

    function act_claim(uint256 who, uint256 amountSeed) external {
        address c = creditors[who % creditors.length];
        uint256 have = custody.credit(c);
        if (have == 0) return;
        uint256 amount = bound(amountSeed, 1, have);
        vm.prank(c);
        try custody.claim(amount, c) {
            ghostClaimed += amount;
        } catch {
            unexpectedRevert = true;
        }
    }

    function act_forceEther(uint256 amountSeed) external {
        uint256 amount = bound(amountSeed, 1, 10 ether);
        vm.deal(address(this), address(this).balance + amount);
        ForceSendInv force = new ForceSendInv{value: amount}(payable(address(custody)));
        (bool ok,) = address(force).call("");
        if (ok) ghostSurplus += amount;
    }

    /// @dev An unauthorized caller must never succeed at a privileged or owner-only operation.
    function act_probe(address caller, uint256 which, uint256 idSeed) external {
        // the fuzzer proposes deployed contract addresses; vm.deal on custody would overwrite its balance
        vm.assume(
            caller != address(election) && caller != address(evidence) && caller != address(this)
                && caller != address(custody) && caller != address(roots)
                && caller != address(factory)
        );
        uint64 id = ids[idSeed % ids.length];
        (address owner, address wd,,,,,,,) = custody.positions(id);
        vm.assume(caller != owner && caller != wd);
        bool ok;
        vm.deal(caller, 1 ether);
        vm.startPrank(caller);
        uint256 w = which % 8;
        if (w == 0) {
            ReserveInput memory in_;
            try custody.reserveCandidate(in_) {
                ok = true;
            } catch {}
        } else if (w == 1) {
            try custody.applyPenalty(keccak256("c"), 1) {
                ok = true;
            } catch {}
        } else if (w == 2) {
            try custody.registerEvmKey(id, keccak256("k")) {
                ok = true;
            } catch {}
        } else if (w == 3) {
            try election.syncLiveIndex(id) {
                ok = true;
            } catch {}
        } else if (w == 4) {
            try custody.bond{value: 1 ether}(id) {
                ok = true;
            } catch {}
        } else if (w == 5) {
            try custody.requestRetirement(id) {
                ok = true;
            } catch {}
        } else if (w == 6) {
            if (custody.credit(caller) == 0) {
                try custody.claim(1, caller) {
                    ok = true;
                } catch {}
            }
        } else {
            try custody.proposeRoles(id, caller, caller, 0) {
                ok = true;
            } catch {}
        }
        vm.stopPrank();
        if (ok) permissionViolation = true;
    }
}

contract ForceSendInv {
    constructor(address payable target) payable {
        bytes memory runtime = abi.encodePacked(hex"73", target, hex"ff");
        assembly ("memory-safe") {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}

/// forge-config: default.invariant.runs = 64
/// forge-config: default.invariant.depth = 96
contract P85InvariantTest is StdInvariant, P85Flow {
    InvariantHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new InvariantHandler(this);
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](14);
        selectors[0] = handler.act_registerIdentity.selector;
        selectors[1] = handler.act_bond.selector;
        selectors[2] = handler.act_requestRetirement.selector;
        selectors[3] = handler.act_reserveCandidate.selector;
        selectors[4] = handler.act_advanceClock.selector;
        selectors[5] = handler.act_rootStep.selector;
        selectors[6] = handler.act_submitEvidence.selector;
        selectors[7] = handler.act_settle.selector;
        selectors[8] = handler.act_mature.selector;
        selectors[9] = handler.act_claim.selector;
        selectors[10] = handler.act_forceEther.selector;
        selectors[11] = handler.act_probe.selector;
        selectors[12] = handler.act_changeWithdrawal.selector;
        selectors[13] = handler.act_nominatePayee.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @dev Guards the harness itself: a scripted run must reach acknowledgement, recovery, closure,
    /// retirement import, penalties and maturity, so the invariants below are checked on deep states.
    function test_regressionStalledCursor() public {
        handler.act_reserveCandidate(11076792350267370986);
        handler.act_registerIdentity(10815649736074030391);
        handler.act_registerIdentity(4097);
        handler.act_rootStep(11636368254831004743);
        handler.act_requestRetirement(15649177614366574514);
        handler.act_rootStep(7928556251629180041);
        handler.act_rootStep(16646);
        assertEq(handler.lastApplyError(), bytes4(0), "apply error");
    }

    function test_handlerReachesDeepStates() public {
        handler.act_requestRetirement(0);
        handler.act_reserveCandidate(7); // session 1 over the identities that did not retire
        handler.act_advanceClock(100, 100);
        handler.act_rootStep(1 << 4 | 1); // choice 1 -> closure (none yet); keeps the cursor honest
        handler.act_rootStep(0 | (1 << 4)); // session record: ack (kind 1)
        assertEq(handler.ghostAcks(), 1, "ack");
        handler.act_advanceClock(2_000, 2_000);
        handler.act_rootStep(1); // closure of the replaced assignment
        assertEq(handler.ghostClosures(), 1, "closure");
        handler.act_rootStep(2); // retirement record for the identity that requested it
        assertEq(handler.ghostRetirements(), 1, "retirement");
        for (uint256 i; i < 3; ++i) {
            handler.act_advanceClock(3_000, 5_000);
        }
        handler.act_mature(0);
        assertGt(handler.ghostMatureCalls(), 0, "maturity");
        handler.act_reserveCandidate(5);
        handler.act_rootStep(0 | (2 << 4)); // session record: recovery (kind 2)
        assertEq(handler.ghostRecoveries(), 1, "recovery");
        handler.act_submitEvidence(0);
        assertFalse(handler.applyFailed());
        assertFalse(handler.unexpectedRevert());
    }

    // --- invariants ------------------------------------------------------------------------------------

    /// B = F + E + D + C + U, with U exactly the value forced in from outside.
    function invariant_balanceIsPrincipalPlusCreditsPlusSurplus() public view {
        assertEq(
            address(custody).balance,
            custody.totalFree() + custody.totalEncumbered() + custody.totalDraining()
                + custody.totalCredits() + handler.ghostSurplus()
        );
    }

    /// F + E + D = sum of remaining principal, category by category.
    function invariant_categoriesEqualTheSumOfLotRemainders() public view {
        uint256 f;
        uint256 e;
        uint256 d;
        for (uint256 lotID = 1; lotID <= custody.nextLotID(); ++lotID) {
            LotV memory l = lotv(lotID);
            if (l.category == 1) f += l.remaining;
            else if (l.category == 2) e += l.remaining;
            else if (l.category == 3) d += l.remaining;
            else assertEq(l.remaining, 0, "a released lot holds no principal");
        }
        assertEq(f, custody.totalFree());
        assertEq(e, custody.totalEncumbered());
        assertEq(d, custody.totalDraining());
    }

    /// C = sum of credits; credits = matured principal + penalties - claims.
    function invariant_creditsAreTheSumOfCreditorBalances() public view {
        uint256 sum;
        for (uint256 i; i < handler.creditorCount(); ++i) {
            sum += custody.credit(handler.creditors(i));
        }
        assertEq(sum, custody.totalCredits());
        assertEq(
            custody.totalCredits(),
            handler.ghostMatured() + handler.ghostPenaltyCredit() - handler.ghostClaimed()
        );
    }

    function invariant_lotBoundsCapsAndCategories() public view {
        for (uint256 lotID = 1; lotID <= custody.nextLotID(); ++lotID) {
            LotV memory l = lotv(lotID);
            assertLe(l.remaining, l.initial);
            assertLe(l.penalized, (uint256(l.initial) * l.capBps) / 10_000, "lifetime cap");
            assertEq(uint256(l.initial) - l.remaining >= l.penalized, true);
            (,,,, uint64 gen,,,, bool retiring) = custody.positions(l.id);
            if (l.category == 4) {
                assertEq(l.refCount, 0);
            } else if (l.refCount > 0) {
                assertEq(l.category, 2, "referenced lots are encumbered");
            } else if (retiring && gen == l.generation) {
                assertEq(l.category, 3, "unreferenced lots of a retiring generation drain");
            } else {
                assertEq(l.category, 1, "unreferenced lots of an open generation are free");
            }
        }
    }

    /// Every reference counter equals the number of unreleased exposures that name the lot; session
    /// locks equal the open sessions; per-identity live counts equal unreleased exposures.
    function invariant_referencesAndLocksAreExact() public view {
        uint256 lotCount = custody.nextLotID();
        uint256[] memory refs = new uint256[](lotCount + 1);
        for (uint256 a; a < handler.assignmentCount(); ++a) {
            bytes32[] memory exps = custody.assignmentExposures(handler.assignmentList(a));
            for (uint256 k; k < exps.length; ++k) {
                Expo memory ex = expo(exps[k]);
                if (ex.released) continue;
                uint256[] memory lots = custody.exposureLots(exps[k]);
                for (uint256 j; j < lots.length; ++j) {
                    refs[lots[j]]++;
                }
            }
        }
        for (uint256 lotID = 1; lotID <= lotCount; ++lotID) {
            assertEq(
                lotv(lotID).refCount, refs[lotID], "refCount == unreleased exposures naming the lot"
            );
        }
        // per-identity live exposure counts
        for (uint256 i; i < handler.idsLength(); ++i) {
            uint64 id = handler.ids(i);
            (,,,, uint64 gen,,,,) = custody.positions(id);
            uint32 live;
            for (uint256 a; a < handler.assignmentCount(); ++a) {
                bytes32 ex = exposureID(handler.assignmentList(a), id);
                Expo memory e = expo(ex);
                if (e.assignmentID != bytes32(0) && !e.released && e.generation == gen) live++;
            }
            assertEq(custody.liveExposures(id, gen), live);
        }
        // session locks: one per open session whose incumbent slate contains the exposure
        for (uint256 a; a < handler.assignmentCount(); ++a) {
            bytes32[] memory exps = custody.assignmentExposures(handler.assignmentList(a));
            for (uint256 k; k < exps.length; ++k) {
                uint256 expected;
                for (uint256 s; s < handler.sessionCount(); ++s) {
                    (,, bytes32 incumbent) = handler.sessionOf(s);
                    if (incumbent == handler.assignmentList(a)) expected++;
                }
                assertEq(expo(exps[k]).locks, expected, "session locks");
            }
        }
    }

    /// Penalty debits never exceed the cases' frozen budgets, and bounty plus treasury credits equal
    /// the debits exactly.
    function invariant_penaltiesMatchTheirBudgetsAndCredits() public view {
        uint256 debited;
        for (uint256 i; i < handler.caseCount(); ++i) {
            bytes32 caseID = handler.cases(i);
            CaseView memory c = evidence.caseInfo(caseID);
            assertLe(custody.caseDebited(caseID), c.budget);
            assertEq(custody.caseDebited(caseID), c.debited);
            debited += c.debited;
        }
        assertEq(debited, handler.ghostPenaltyCredit());
    }

    function invariant_exclusionIsPermanent() public view {
        for (uint256 i; i < handler.excludedCount(); ++i) {
            assertTrue(evidence.excluded(handler.excludedIds(i)));
        }
    }

    function invariant_noUnauthorizedCallerEverSucceeded() public view {
        assertFalse(handler.permissionViolation());
    }

    function invariant_maturityNeverBypassesRefsHoldsOrRetirement() public view {
        assertFalse(handler.badMaturity());
    }

    function invariant_theHarnessItselfStaysConsistent() public view {
        assertFalse(handler.applyFailed(), "a valid root record stalled the cursor");
        assertFalse(handler.unexpectedRevert(), "an operation that must succeed reverted");
    }

    function invariant_liveIndexMatchesOpenLots() public view {
        for (uint256 i; i < handler.idsLength(); ++i) {
            uint64 id = handler.ids(i);
            (,,,,,, uint32 open,,) = custody.positions(id);
            assertEq(election.isIndexed(id), open != 0);
        }
        assertLe(election.liveCount(), 128);
    }

    function invariant_recordCursorTracksTheChainHead() public view {
        assertLe(custody.recordCursor(), roots.recordCount());
    }
}
