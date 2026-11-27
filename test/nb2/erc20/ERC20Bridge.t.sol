// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC20BridgeFactory} from "../../../src/nb2/erc20/ERC20BridgeFactory.sol";
import {ERC20BridgeVault} from "../../../src/nb2/erc20/ERC20BridgeVault.sol";
import {ERC20Config} from "../../../src/nb2/erc20/ERC20Config.sol";
import {ERC20BridgeVerifier} from "../../../src/nb2/erc20/generated/ERC20BridgeVerifier.sol";
import {ERC20FlatLineage} from "../../../src/nb2/erc20/generated/ERC20FlatLineage.sol";
import {ERC20VaultBase} from "../../../src/nb2/erc20/generated/ERC20VaultBase.sol";
import {FlatBindings} from "../../../src/nb2/verifier/flat/FlatBindings.sol";
import {FlatReceipts} from "../../../src/nb2/verifier/flat/FlatReceipts.sol";
import {FlatClaim, FlatVerdict} from "../../../src/nb2/verifier/flat/FlatTypes.sol";

contract HostileToken {
    enum Mode {
        Standard,
        FeeFromCredit,
        FeeFromSender,
        NoReturn,
        FalseReturn,
        OversizedReturn,
        Callback
    }

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    Mode public mode;
    bool public paused;
    address public blocked;

    error Blocked();

    function configure(Mode m, bool p, address b) external {
        mode = m;
        paused = p;
        blocked = b;
    }

    // A positive/negative rebase of one account in the fixture.
    function rebase(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }

    function approve(address to, uint256 value) external returns (bool) {
        allowance[msg.sender][to] = value;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        return _move(from, to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _move(msg.sender, to, amount);
    }

    function _move(address from, address to, uint256 amount) internal virtual returns (bool) {
        if (paused || from == blocked || to == blocked) revert Blocked();
        Mode m = mode;
        balanceOf[from] -= amount + (m == Mode.FeeFromSender ? 1 : 0);
        balanceOf[to] += amount - (m == Mode.FeeFromCredit ? 1 : 0);
        if (m == Mode.Callback) {
            (bool ok, bytes memory reason) = msg.sender
                .call(abi.encodeCall(ERC20BridgeVault.depositERC20, (1, 1, "", bytes32(0))));
            require(!ok && bytes4(reason) == ERC20VaultBase.Reentrancy.selector);
        }
        if (m == Mode.NoReturn) {
            assembly ("memory-safe") { return(0, 0) }
        }
        if (m == Mode.OversizedReturn) {
            assembly ("memory-safe") { return(0, 64) }
        }
        return m != Mode.FalseReturn;
    }
}

contract TaxAfterUpgrade is HostileToken {
    function _move(address from, address to, uint256 amount) internal override returns (bool) {
        return super._move(from, to, amount - 1);
    }
}

contract SwitchableToken {
    address private immutable _owner = msg.sender;
    bytes32 private constant _LOGIC = keccak256("erc20-fixture.logic");

    constructor(address logic) {
        upgradeTo(logic);
    }

    function upgradeTo(address logic) public {
        require(msg.sender == _owner);
        bytes32 slot = _LOGIC;
        assembly ("memory-safe") { sstore(slot, logic) }
    }

    fallback() external {
        bytes32 slot = _LOGIC;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), sload(slot), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

contract ERC20BridgeTest is Test {
    address private constant REGISTRY = 0xff00000000000000000000000000000000000002;
    address private constant RECIPIENT = address(0xcafe);
    bytes private constant OWNER =
        hex"d998788301410158210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    FlatReceipts private receipts;
    ERC20BridgeVerifier private ordinary;
    ERC20BridgeFactory private factory;
    bytes private vaultInit;
    bytes private recoveryInit;

    function setUp() public {
        vm.etch(REGISTRY, hex"600200");
        receipts = FlatReceipts(deployCode("FlatReceipts.sol:FlatReceipts"));
        ERC20FlatLineage lineage = ERC20FlatLineage(
            deployCode("ERC20FlatLineage.sol:ERC20FlatLineage", abi.encode(receipts))
        );
        bytes32 profile = sha256("erc20 test semantic profile");
        ordinary = ERC20BridgeVerifier(
            deployCode(
                "ERC20BridgeVerifier.sol:ERC20BridgeVerifier",
                abi.encode(lineage, address(lineage).codehash, profile, REGISTRY.codehash)
            )
        );
        vaultInit = vm.getCode("ERC20BridgeVault.sol:ERC20BridgeVault");
        recoveryInit = vm.getCode("ERC20BridgeRecovery.sol:ERC20BridgeRecovery");
        ERC20Config.Chain memory chain = ERC20Config.Chain(
            3, sha256("erc20 root"), sha256("erc20 execution"), 8, hex"80", 7, 10 ** 27
        );
        FlatBindings.ReleaseInputs memory inputs = FlatBindings.ReleaseInputs(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6))
        );
        factory = new ERC20BridgeFactory(
            chain,
            ERC20BridgeFactory.Release(
                ordinary,
                address(ordinary).codehash,
                profile,
                sha256("erc20 generation"),
                keccak256(vaultInit),
                keccak256(recoveryInit),
                inputs
            )
        );
    }

    function _activate(HostileToken token) private returns (ERC20BridgeVault vault) {
        (address v, address r, bytes32 d) =
            factory.activate(address(token), vaultInit, recoveryInit);
        vault = ERC20BridgeVault(v);
        assertEq(vault.RECOVERY(), r);
        assertEq(vault.domain(), d);
        assertEq(vault.config(), factory.config(address(token)));
        token.rebase(address(this), 1_000_000);
        token.approve(v, 1_000_000);
    }

    function _deposit(ERC20BridgeVault v, uint256 request, uint256 min) private {
        v.depositERC20(request, min, OWNER, bytes32(uint256(3)));
    }

    function _state(ERC20BridgeVault v)
        private
        view
        returns (uint64 n, uint64 c, uint16 m, uint256 q)
    {
        (n, c, m, q,,) = v.state();
    }

    function _verdict(ERC20BridgeVault v, uint256 eta, uint256 amount)
        private
        view
        returns (FlatVerdict memory)
    {
        return FlatVerdict(v.domain(), bytes32(eta), 0, v.ASSET(), RECIPIENT, amount);
    }

    function _ordinary(ERC20BridgeVault v, FlatVerdict memory vd) private {
        _ordinary(v, vd, "");
    }

    function _ordinary(ERC20BridgeVault v, FlatVerdict memory vd, bytes memory expectedError)
        private
    {
        bytes memory evidence = abi.encode(vd.eta);
        vm.mockCall(
            address(ordinary),
            abi.encodeCall(ordinary.verifyReturn, (v.config(), evidence)),
            abi.encode(vd)
        );
        if (expectedError.length != 0) vm.expectRevert(expectedError);
        v.redeem(evidence, vd.eta, vd.minSegment, "");
    }

    function _recoveredPacket(ERC20BridgeVault v, FlatVerdict memory vd)
        private
        returns (bytes memory)
    {
        bytes32 pageRoot = keccak256("page root");
        bytes32 session = FlatBindings.session(
            v.RECOVERY_GENERATION(),
            v.domain(),
            address(v),
            v.RECOVERY(),
            v.RECOVERY_RUNTIME(),
            v.RECOVERY_PINS(),
            14,
            pageRoot
        );
        bytes32[] memory topics = new bytes32[](2);
        topics[0] = keccak256(
            "NB2Complete11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256)"
        );
        topics[1] = session;
        bytes memory proof = abi.encode(vd.eta);
        bytes memory data = abi.encode(uint64(1), vd);
        vm.mockCall(
            address(receipts),
            abi.encodeCall(
                receipts.receipt, (FlatReceipts.ReceiptEnv(3, 8, hex"80", v.RECOVERY()), proof)
            ),
            abi.encode(FlatClaim(0, 0, ""), topics, data)
        );
        vm.mockCall(
            address(0x0100),
            abi.encodePacked(uint32(0x02000001)),
            abi.encode(uint256(2), uint256(1))
        );
        return abi.encodeWithSignature(
            "redeemRecovered(bytes)",
            abi.encodePacked(
                uint16(0x0101),
                uint64(14),
                pageRoot,
                uint8(1),
                uint32(proof.length),
                proof,
                uint16(0)
            )
        );
    }

    function _recovered(ERC20BridgeVault v, bytes memory packet) private {
        (bool ok, bytes memory reason) = address(v).call(packet);
        if (!ok) {
            assembly ("memory-safe") { revert(add(reason, 32), mload(reason)) }
        }
    }

    function testPermissionlessActivationRaceAndTemplatePins() public {
        HostileToken t = new HostileToken();
        (address vault, address recovery) = factory.predict(address(t));
        vm.expectRevert(ERC20BridgeFactory.BadTemplate.selector);
        factory.activate(address(t), bytes.concat(vaultInit, hex"00"), recoveryInit);
        vm.expectRevert(ERC20BridgeFactory.ConstructorOnly.selector);
        factory.recoveryContext();

        vm.recordLogs();
        vm.prank(address(1));
        (address a, address b, bytes32 d) = factory.activate(address(t), vaultInit, recoveryInit);
        assertEq(a, vault);
        assertEq(b, recovery);
        assertEq(d, sha256(factory.config(address(t))));
        vm.prank(address(2));
        (a, b, d) = factory.activate(address(t), "", "");
        assertEq(a, vault);
        assertEq(b, recovery);
        assertEq(d, ERC20BridgeVault(vault).domain());
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].emitter, address(factory));
    }

    function testIsolationSplitAndBothRaceOrders() public {
        HostileToken tokenA = new HostileToken();
        HostileToken tokenB = new HostileToken();
        ERC20BridgeVault a = _activate(tokenA);
        ERC20BridgeVault b = _activate(tokenB);
        _deposit(a, 100, 100);
        _deposit(b, 30, 30);
        FlatVerdict memory first = _verdict(a, 1, 40);
        _ordinary(b, first, abi.encodeWithSelector(ERC20VaultBase.DomainMismatch.selector));
        first.domain = b.domain();
        _ordinary(b, first, abi.encodeWithSelector(ERC20VaultBase.AssetMismatch.selector));
        first.domain = a.domain();
        bytes memory cold = _recoveredPacket(a, first);
        _ordinary(a, first);
        vm.expectRevert(abi.encodeWithSelector(ERC20VaultBase.AlreadyPaid.selector, first.eta));
        _recovered(a, cold);

        FlatVerdict memory second = _verdict(a, 2, 60);
        _recovered(a, _recoveredPacket(a, second));
        _ordinary(
            a, second, abi.encodeWithSelector(ERC20VaultBase.AlreadyPaid.selector, second.eta)
        );
        assertEq(tokenA.balanceOf(RECIPIENT), 100);
        assertEq(tokenB.balanceOf(RECIPIENT), 0);
        (,,, uint256 qA) = _state(a);
        (,,, uint256 qB) = _state(b);
        assertEq(qA, 0);
        assertEq(qB, 30);
        assertEq(tokenB.balanceOf(address(b)), 30);
    }

    function testFeesNoReturnAndCallbacks() public {
        HostileToken token = new HostileToken();
        ERC20BridgeVault vault = _activate(token);
        token.configure(HostileToken.Mode.FeeFromCredit, false, address(0));
        vm.expectRevert(ERC20BridgeVault.BadCredit.selector);
        _deposit(vault, 40, 40);
        _deposit(vault, 40, 39);
        (uint64 n,,, uint256 q) = _state(vault);
        assertEq(n, 1);
        assertEq(q, 39);
        token.configure(HostileToken.Mode.FeeFromSender, false, address(0));
        vm.expectRevert(ERC20BridgeVault.ExcessDebit.selector);
        _deposit(vault, 40, 40);
        FlatVerdict memory vd = _verdict(vault, 42, 39);
        token.rebase(address(vault), 40);
        _ordinary(vault, vd, abi.encodeWithSelector(ERC20VaultBase.PayoutFailed.selector));
        token.configure(HostileToken.Mode.NoReturn, false, address(0));
        _ordinary(vault, vd);
        token.configure(HostileToken.Mode.Callback, false, address(0));
        _deposit(vault, 1, 1);
        _ordinary(vault, _verdict(vault, 43, 1));
        assertEq(token.balanceOf(RECIPIENT), 40);
    }

    function testMalformedReturnsAndInsolvency() public {
        HostileToken token = new HostileToken();
        ERC20BridgeVault vault = _activate(token);
        token.configure(HostileToken.Mode.FalseReturn, false, address(0));
        vm.expectRevert(ERC20BridgeVault.TokenCallFailed.selector);
        _deposit(vault, 10, 10);
        token.configure(HostileToken.Mode.OversizedReturn, false, address(0));
        vm.expectRevert(ERC20BridgeVault.TokenCallFailed.selector);
        _deposit(vault, 10, 10);
        token.configure(HostileToken.Mode.Standard, false, address(0));
        token.rebase(address(vault), 1);
        _deposit(vault, 10, 10);
        token.rebase(address(vault), 9);
        vm.expectRevert(ERC20BridgeVault.InsufficientBacking.selector);
        _deposit(vault, 10, 10);
        _ordinary(
            vault,
            _verdict(vault, 1, 10),
            abi.encodeWithSelector(ERC20BridgeVault.InsufficientBacking.selector)
        );
        token.rebase(address(vault), 13);
        _ordinary(vault, _verdict(vault, 1, 10));
        assertEq(token.balanceOf(address(vault)), 3);
    }

    function testBlockedSealRollsBackAndAnotherPayerRetries() public {
        HostileToken token = new HostileToken();
        ERC20BridgeVault vault = _activate(token);
        _deposit(vault, 70, 70);
        for (uint256 i = 1; i < 64; ++i) {
            _ordinary(vault, _verdict(vault, i, 1));
        }

        FlatVerdict memory last = _verdict(vault, 64, 1);
        bytes memory packet = _recoveredPacket(vault, last);
        token.configure(HostileToken.Mode.Standard, false, RECIPIENT);
        (,, uint16 pop, uint256 liability, bytes32 beforeHead, bytes32 beforePrev) = vault.state();
        assertEq(pop, 63);
        assertEq(liability, 7);
        vm.expectRevert(ERC20BridgeVault.TokenCallFailed.selector);
        _recovered(vault, packet);
        (, uint64 c, uint16 m, uint256 q, bytes32 afterHead, bytes32 afterPrev) = vault.state();
        assertEq(c, 0);
        assertEq(m, pop);
        assertEq(q, liability);
        assertEq(afterHead, beforeHead);
        assertEq(afterPrev, beforePrev);
        assertEq(token.balanceOf(RECIPIENT), 63);

        token.configure(HostileToken.Mode.Standard, false, address(0));
        vm.prank(address(0xb1d));
        _recovered(vault, packet);
        (, c, m, q) = _state(vault);
        assertEq(c, 1);
        assertEq(m, 0);
        assertEq(q, 6);
        assertEq(token.balanceOf(RECIPIENT), 64);
    }

    function testPauseAndProxyUpgradeRetainTheSameBurn() public {
        HostileToken base = new HostileToken();
        SwitchableToken proxy = new SwitchableToken(address(base));
        HostileToken token = HostileToken(address(proxy));
        ERC20BridgeVault v = _activate(token);
        _deposit(v, 10, 10);
        FlatVerdict memory vd = _verdict(v, 1, 10);
        token.configure(HostileToken.Mode.Standard, true, address(0));
        _ordinary(v, vd, abi.encodeWithSelector(ERC20BridgeVault.TokenCallFailed.selector));
        token.configure(HostileToken.Mode.Standard, false, address(0));
        proxy.upgradeTo(address(new TaxAfterUpgrade()));
        _ordinary(v, vd, abi.encodeWithSelector(ERC20VaultBase.PayoutFailed.selector));
        proxy.upgradeTo(address(base));
        _ordinary(v, vd);
        assertEq(token.balanceOf(RECIPIENT), 10);
    }
}
