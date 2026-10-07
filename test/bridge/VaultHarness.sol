// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {BridgeVault} from "../../src/bridge/BridgeVault.sol";
import {Deployment, KernelResult, Leaf} from "../../src/bridge/BridgeTypes.sol";
import "../../src/bridge/BridgeErrors.sol";

/// @notice TEST DOUBLE for the composing verifier: returns the programmed kernel result for each
///         operation, or reverts with programmed data. It lets the vault's own guards be tested in
///         isolation from the verifier. The real `TokenVerifier` is exercised separately and in
///         `BridgeVaultIntegration.t.sol`.
contract VerifierDouble {
    KernelResult internal prep;
    KernelResult internal mint;
    KernelResult internal ret;
    bytes internal failure;

    function setPrepare(KernelResult memory r) external {
        prep = r;
    }

    function setMint(KernelResult memory r) external {
        mint = r;
    }

    function setReturn(KernelResult memory r) external {
        ret = r;
    }

    function setFailure(bytes memory data) external {
        failure = data;
    }

    function _out(KernelResult storage r) internal view returns (KernelResult memory) {
        if (failure.length != 0) {
            bytes memory f = failure;
            assembly ("memory-safe") {
                revert(add(f, 32), mload(f))
            }
        }
        return r;
    }

    function prepareLock(bytes calldata, uint256, uint256, bytes calldata)
        external
        view
        returns (KernelResult memory)
    {
        return _out(prep);
    }

    function verifyMint(bytes calldata, bytes calldata)
        external
        view
        returns (KernelResult memory)
    {
        return _out(mint);
    }

    function verifyReturn(bytes calldata, bytes calldata)
        external
        view
        returns (KernelResult memory)
    {
        return _out(ret);
    }
}

/// @notice A claim payee with programmable behavior: accept, revert, or attempt to reenter the vault
///         while the payout is in flight (recording each attempt's error, or propagating it).
contract Payee {
    enum Mode {
        Accept,
        Revert,
        ReenterSwallow,
        ReenterPropagateClaim
    }

    BridgeVault public vault;
    Mode public mode;
    bytes4[] public errors;
    uint256 public received;
    uint256 public seenClaimable;
    uint256 public seenPaid;

    function set(BridgeVault v, Mode m) external {
        vault = v;
        mode = m;
        delete errors;
    }

    function claim(uint256 amount, address to) external {
        vault.claim(amount, to);
    }

    function errorCount() external view returns (uint256) {
        return errors.length;
    }

    receive() external payable {
        received += msg.value;
        if (mode == Mode.Revert) revert("payee refuses");
        // Effects precede the value call: the credit is already gone and P already counts the amount.
        seenClaimable = vault.claimable(address(this));
        seenPaid = vault.paid();
        if (mode == Mode.ReenterSwallow) {
            try vault.claim(1, address(this)) {
                errors.push(0x00000000);
            } catch (bytes memory e) {
                errors.push(bytes4(e));
            }
            try vault.redeem("") returns (uint256) {
                errors.push(0x00000000);
            } catch (bytes memory e) {
                errors.push(bytes4(e));
            }
            try vault.lock{value: 0}("") returns (uint256) {
                errors.push(0x00000000);
            } catch (bytes memory e) {
                errors.push(bytes4(e));
            }
        } else if (mode == Mode.ReenterPropagateClaim) {
            vault.claim(1, address(this));
        }
    }
}

/// @notice Shared deployment and helpers for vault tests that use the verifier double.
abstract contract VaultHarness is Test {
    VerifierDouble internal vd;
    BridgeVault internal vault;
    bytes32 internal cfgHash;

    bytes32 internal constant ROOT_GENESIS = keccak256("root-genesis");
    bytes32 internal constant EXEC_GENESIS = keccak256("exec-genesis");
    uint16 internal constant NETWORK = 3;
    uint32 internal constant EVM_PARTITION = 7;
    // The merged oracle's fixture policy: partition 11, empty-prefix shard, configuration hash below.
    bytes internal constant POLICY =
        hex"8452554e49434954595f42525f4147475f4f4e450b41805820c20ce7724f24578d66aebec43c08ef934f89bb4841b8756a0deca9af3c2104fc";

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant CAROL = address(0xCA201);

    function _deployment(address verifier) internal view returns (Deployment memory d) {
        d = Deployment({
            network: NETWORK,
            rootGenesis: ROOT_GENESIS,
            executionGenesis: EXEC_GENESIS,
            evmPartition: EVM_PARTITION,
            evmShard: hex"80",
            semanticProfileHash: keccak256("semantic"),
            tokenVerifier: verifier,
            tokenVerifierCodeHash: verifier.codehash,
            b1ProfileHash: keccak256("b1"),
            policyBody: POLICY
        });
    }

    function _setUpVault() internal {
        vd = new VerifierDouble();
        vault = new BridgeVault(_deployment(address(vd)));
        cfgHash = vault.CFG();
    }

    /// @dev Lock digest the doubles hand back for a (nonce, amount); the vault stores it opaquely.
    function _digest(uint256 n, uint256 amount) internal pure returns (bytes32) {
        return keccak256(abi.encode("digest", n, amount));
    }

    function _eta(uint256 n, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode("eta", n, salt));
    }

    function _prepareResult(uint256 n, uint256 amount)
        internal
        view
        returns (KernelResult memory r)
    {
        r.cfg = cfgHash;
        r.nonce = n;
        r.amount = amount;
        r.tokenId = keccak256(abi.encode("id", n));
        r.salt = keccak256(abi.encode("salt", n));
        r.firstPredicateHash = keccak256(abi.encode("rcpt", n));
        r.lockDigest = _digest(n, amount);
        r.leaves = new Leaf[](0);
    }

    function _returnResult(uint256 n, uint256 amount, address to, bytes32 eta)
        internal
        view
        returns (KernelResult memory r)
    {
        r = _prepareResult(n, amount);
        r.releaseTo = to;
        r.nullifier = eta;
        r.leaves = new Leaf[](2);
    }

    function _lock(address who, uint256 amount) internal returns (uint256 n) {
        n = vault.lastNonce() + 1;
        vd.setPrepare(_prepareResult(n, amount));
        vm.deal(who, who.balance + amount);
        vm.prank(who);
        uint256 got = vault.lock{value: amount}(hex"d9");
        assertEq(got, n);
    }

    function _redeem(uint256 n, uint256 amount, address to, bytes32 eta) internal {
        vd.setReturn(_returnResult(n, amount, to, eta));
        vault.redeem("");
    }
}
