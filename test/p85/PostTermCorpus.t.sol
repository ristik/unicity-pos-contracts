// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {P85Flow} from "./P85Flow.sol";
import {Evidence} from "../../src/p85/Evidence.sol";
import {KeyLib} from "../../src/p85/KeyLib.sol";
import {RecordKind, ClosureData} from "../../src/p85/P85Types.sol";

contract PostTermSigHarness {
    function verifyNative(bytes memory key, bytes32 digest, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return KeyLib.verifyNative(KeyLib.toAddress(key), digest, sig);
    }
}

/// @notice The Go-signed post-term seal corpus (#1297; bft-core s1ref/s1gen `BuildPostTermCorpus`, `fixtures/post-term-corpus-go-v1.json`,
/// converted by `script/post-term-corpus-convert.py` to `fixtures/post-term-corpus-v1.json`) replayed through the real modules: the
/// scenario's committee is installed as epoch e and e+1 of the B1 history, four of its members are the genesis identities of the custody
/// term of epoch e, and that term is closed with the corpus' Closure facts and anchored. Every submission's rebuilt digest is the Go one,
/// every signature verdict of the strict native rule is the Go one, every accepted submission is admitted, every refused one reverts
/// with the error of its Go reason, and accepted submissions with the same offence label are one case. Each statement is the seal's
/// signed fields with the opaque PreviousHash (no VoteInfo opening); the corpus' statement-shape cases test an opening and are skipped.
abstract contract PostTermCorpusBase is P85Flow {
    string internal constant CORPUS = "/test/p85/fixtures/post-term-corpus-v1.json";
    string internal _json;
    string internal _sc;
    uint64 internal _n;
    bytes32 internal _g;
    bytes[] internal _ids; // the genesis identities' root keys

    function _scenario() internal pure virtual returns (uint256);

    function setUp() public override {
        _json = vm.readFile(string.concat(vm.projectRoot(), CORPUS));
        _sc = string.concat(".scenarios[", vm.toString(_scenario()), "]");
        _n = uint64(vm.parseJsonUint(_json, _p(".network")));
        _g = vm.parseJsonBytes32(_json, _p(".genesis"));
        genesisRootEpoch = uint64(vm.parseJsonUint(_json, _p(".epoch")));
        // the charged members first, then the others, until there are four distinct genesis identities
        uint256 subs = _count();
        for (uint256 k; k < subs && _ids.length < N_GENESIS; ++k) {
            _add(vm.parseJsonBytes(_json, _s(k, "chargedKey")));
        }
        bytes[] memory keys = vm.parseJsonBytesArray(_json, _p(".keys"));
        for (uint256 j; j < keys.length && _ids.length < N_GENESIS; ++j) {
            _add(keys[j]);
        }
        super.setUp();
        _history(keys);
    }

    function _p(string memory field) internal view returns (string memory) {
        return string.concat(_sc, field);
    }

    function _s(uint256 k, string memory field) internal view returns (string memory) {
        return string.concat(_sc, ".submissions[", vm.toString(k), "].", field);
    }

    function _count() internal view returns (uint256 n) {
        while (vm.keyExistsJson(_json, string.concat(_sc, ".submissions[", vm.toString(n), "]"))) {
            ++n;
        }
    }

    function _add(bytes memory key) internal {
        for (uint256 i; i < _ids.length; ++i) {
            if (keccak256(_ids[i]) == keccak256(key)) return;
        }
        _ids.push(key);
    }

    function _rootNetwork() internal view override returns (uint64) {
        return _n;
    }

    function _rootGenesis() internal view override returns (bytes32) {
        return _g;
    }

    function _rootKey(uint256 i) internal view override returns (bytes memory) {
        return _ids[i];
    }

    function _weights(string memory field) internal view returns (uint64[] memory w) {
        uint256[] memory raw = vm.parseJsonUintArray(_json, _p(field));
        w = new uint64[](raw.length);
        for (uint256 i; i < raw.length; ++i) {
            w[i] = uint64(raw[i]);
        }
    }

    /// @dev Epochs e and e+1 installed; G (the custody term of e) handed over by H at the corpus' round, closed and anchored.
    function _history(bytes[] memory keys) internal {
        uint64 e = genesisRootEpoch;
        uint64 aStar = uint64(vm.parseJsonUint(_json, _p(".activationRound")));
        uint64 hRound = uint64(vm.parseJsonUint(_json, _p(".hRound")));
        bytes32 hID = vm.parseJsonBytes32(_json, _p(".hRecordId"));
        bytes32 rH = vm.parseJsonBytes32(_json, _p(".terminalRoot"));
        roots.setStrictEpochs(true);
        roots.installEpoch(
            e,
            uint64(vm.parseJsonUint(_json, _p(".start"))),
            true,
            aStar,
            2,
            bytes32(0),
            keys,
            _weights(".weights")
        );
        roots.installEpoch(
            e + 1,
            aStar,
            false,
            0,
            2,
            hID,
            vm.parseJsonBytesArray(_json, _p(".successorKeys")),
            _weights(".successorWeights")
        );
        reserve(RES_J, ASG_J, allMembers(), 1);
        clock(10, 1_000);
        pushRecord(RecordKind.Ack, ackData(RES_J, hRound, 100, aStar));
        applyAll();
        Asg memory g = asg(GENESIS_ASSIGNMENT);
        clock(20, 1_100);
        pushRecord(
            RecordKind.Closure,
            abi.encode(
                ClosureData(GENESIS_ASSIGNMENT, hRound, hID, rH, g.exposureDigest, g.keyDigest)
            )
        );
        applyAll();
        custody.anchorTerm(GENESIS_ASSIGNMENT, hID, rH);
    }

    function _seal(uint256 k) internal view returns (Evidence.PostTermSeal memory s) {
        s.epoch = uint64(vm.parseJsonUint(_json, _s(k, "epoch")));
        s.previousHash = vm.parseJsonBytes32(_json, _s(k, "previousHash"));
        s.commitRound = uint64(vm.parseJsonUint(_json, _s(k, "commitRound")));
        s.commitTimestamp = uint64(vm.parseJsonUint(_json, _s(k, "commitTimestamp")));
        s.commitHash = vm.parseJsonBytes32(_json, _s(k, "hash"));
    }

    function _quorum(uint256 k) internal view returns (Evidence.SealQuorum memory q) {
        uint256[] memory idx = vm.parseJsonUintArray(_json, _s(k, "indices"));
        q.members = new uint8[](idx.length);
        for (uint256 i; i < idx.length; ++i) {
            q.members[i] = uint8(idx[i]);
        }
        q.signatures = vm.parseJsonBytesArray(_json, _s(k, "signatures"));
    }

    /// @dev The Go corpus' refusal reason as this verifier's error (P3-3).
    function _selector(string memory reason) internal pure returns (bytes4) {
        bytes32 r = keccak256(bytes(reason));
        if (r == keccak256("not-post-term")) return Evidence.NotPostTerm.selector;
        if (r == keccak256("exempt-terminal-root")) return Evidence.FrozenRoot.selector;
        if (r == keccak256("below-threshold")) return Evidence.QuorumTooSmall.selector;
        if (r == keccak256("charged-not-in-subset")) return Evidence.KeyMismatch.selector;
        if (r == keccak256("signature")) return Evidence.BadSignature.selector;
        if (r == keccak256("indices")) return Evidence.BadQuorum.selector;
        revert(string.concat("no selector for reason ", reason));
    }

    function _exposureOf(bytes memory key) internal view returns (bytes32) {
        for (uint256 i; i < N_GENESIS; ++i) {
            if (keccak256(_ids[i]) == keccak256(key)) return genesisExposure(i);
        }
        revert("charged key is no genesis identity");
    }

    function test_theGoDigestsAndSignatureVerdictsAreReproduced() public {
        PostTermSigHarness h = new PostTermSigHarness();
        bytes[] memory keys = vm.parseJsonBytesArray(_json, _p(".keys"));
        uint256 n = _count();
        uint256 checked;
        for (uint256 k; k < n; ++k) {
            Evidence.PostTermSeal memory s = _seal(k);
            bytes32 d = vm.parseJsonBytes32(_json, _s(k, "digest"));
            string memory id = vm.parseJsonString(_json, _s(k, "id"));
            assertEq(evidence.postTermSealDigest(s), d, id);
            Evidence.SealQuorum memory q = _quorum(k);
            bool[] memory valid = vm.parseJsonBoolArray(_json, _s(k, "signatureValid"));
            for (uint256 i; i < q.signatures.length && i < q.members.length; ++i) {
                if (q.members[i] >= keys.length) continue; // an unknown index has no installed key
                assertEq(h.verifyNative(keys[q.members[i]], d, q.signatures[i]), valid[i], id);
                ++checked;
            }
        }
        assertGt(checked, n, "every signature was judged");
    }

    function test_everySubmissionHasTheGoVerdictAndEachOffenceIsOneCase() public {
        uint256 n = _count();
        string[] memory seen = new string[](n);
        uint256 cases;
        uint256 accepted;
        for (uint256 k; k < n; ++k) {
            Evidence.PostTermSeal memory s = _seal(k);
            Evidence.SealQuorum memory q = _quorum(k);
            bytes32 eid = _exposureOf(vm.parseJsonBytes(_json, _s(k, "chargedKey")));
            string memory id = vm.parseJsonString(_json, _s(k, "id"));
            bool accept = vm.parseJsonBool(_json, _s(k, "accept"));
            if (!accept) {
                vm.prank(reporter);
                (bool ok, bytes memory ret) = address(evidence)
                    .call(abi.encodeCall(Evidence.submitPostTermEvidence, (s, q, eid)));
                assertFalse(ok, id);
                assertEq(bytes4(ret), _selector(vm.parseJsonString(_json, _s(k, "reason"))), id);
                continue;
            }
            ++accepted;
            string memory label = vm.parseJsonString(_json, _s(k, "offence"));
            bool repeat;
            for (uint256 c; c < cases; ++c) {
                if (keccak256(bytes(seen[c])) == keccak256(bytes(label))) repeat = true;
            }
            if (repeat) {
                vm.expectRevert(Evidence.DuplicateOffence.selector);
                vm.prank(makeAddr(id)); // another reporter, another subset: the same case
                evidence.submitPostTermEvidence(s, q, eid);
            } else {
                vm.prank(reporter);
                bytes32 caseID = evidence.submitPostTermEvidence(s, q, eid);
                assertEq(evidence.caseInfo(caseID).exposureID, eid, id);
                seen[cases++] = label;
            }
        }
        assertGt(accepted, cases, "the corpus repeats an offence");
        assertGt(cases, 0);
    }
}

contract PostTermCorpusWeightedTest is PostTermCorpusBase {
    function _scenario() internal pure override returns (uint256) {
        return 0;
    }
}

contract PostTermCorpusMaxCommitteeTest is PostTermCorpusBase {
    function _scenario() internal pure override returns (uint256) {
        return 1;
    }
}
