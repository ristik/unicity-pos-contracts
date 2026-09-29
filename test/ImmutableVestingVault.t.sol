// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Test} from "forge-std/Test.sol";
import {ImmutableVestingVault} from "../src/ImmutableVestingVault.sol";

contract RejectVestingEther {
    receive() external payable {
        revert("reject");
    }
}

contract ReentrantVestingReceiver {
    ImmutableVestingVault public vault;
    bool public nestedReleaseBlocked;

    function setVault(ImmutableVestingVault vault_) external {
        require(address(vault) == address(0));
        vault = vault_;
    }

    function claim() external {
        vault.release();
    }

    receive() external payable {
        try vault.release() {
            revert("nested release unexpectedly succeeded");
        } catch {
            nestedReleaseBlocked = true;
        }
    }
}

contract ForceVestingEther {
    constructor(address payable recipient) payable {
        bytes memory runtime = abi.encodePacked(hex"73", recipient, hex"ff");
        assembly ("memory-safe") {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}

contract VestingVaultHandler is Test {
    ImmutableVestingVault public immutable vault;
    uint64 public immutable scheduleEnd;

    constructor(ImmutableVestingVault vault_, uint64 scheduleEnd_) {
        vault = vault_;
        scheduleEnd = scheduleEnd_;
    }

    function advance(uint32 rawDelta) external {
        uint256 now_ = block.timestamp;
        if (now_ >= scheduleEnd) return;
        uint256 delta = bound(rawDelta, 0, scheduleEnd - now_);
        vm.warp(now_ + delta);
    }

    function release() external {
        vault.release();
    }

    receive() external payable {}
}

contract ImmutableVestingVaultTest is Test {
    uint64 internal constant START = 1_000;
    uint64 internal constant CLIFF = 20;
    uint64 internal constant DURATION = 80;
    uint256 internal constant PRINCIPAL = 100;

    receive() external payable {}

    function deploy(address payable recipient, uint256 principal)
        internal
        returns (ImmutableVestingVault)
    {
        return new ImmutableVestingVault(recipient, principal, START, CLIFF, DURATION);
    }

    function testCliffBoundaryAndRepeatedClaims() public {
        ImmutableVestingVault vault = deploy(payable(address(this)), PRINCIPAL);
        vm.deal(address(vault), PRINCIPAL);

        vm.warp(START + CLIFF - 1);
        assertEq(vault.vestedAmount(block.timestamp), 0);
        assertEq(vault.release(), 0);
        assertEq(vault.released(), 0);

        vm.warp(START + CLIFF);
        assertEq(vault.vestedAmount(block.timestamp), 25);
        assertEq(vault.release(), 25);
        assertEq(vault.release(), 0, "same-time repeated claims cannot double pay");
        assertEq(vault.released(), 25);
        assertEq(address(vault).balance, 75);
    }

    function testExactTerminalReleaseAfterPartialClaims() public {
        ImmutableVestingVault vault = deploy(payable(address(this)), PRINCIPAL);
        vm.deal(address(vault), PRINCIPAL);

        vm.warp(START + CLIFF);
        assertEq(vault.release(), 25);
        vm.warp(START + DURATION - 1);
        assertEq(vault.vestedAmount(block.timestamp), 98);
        assertEq(vault.release(), 73);
        assertEq(vault.release(), 0);
        vm.warp(START + DURATION);
        assertEq(vault.releasable(), 2);
        assertEq(vault.release(), 2);
        assertEq(vault.released(), PRINCIPAL);
        assertEq(address(vault).balance, 0);
    }

    function testDonationAndForcedTransferStayOutsidePrincipal() public {
        ImmutableVestingVault vault =
            new ImmutableVestingVault(payable(address(this)), PRINCIPAL, START, 0, DURATION);
        vm.deal(address(vault), PRINCIPAL);
        vm.deal(address(this), 17);
        (bool donated,) = address(vault).call{value: 17}("");
        assertTrue(donated);
        assertEq(vault.principal(), PRINCIPAL);
        assertEq(vault.surplusBalance(), 17);

        vm.warp(START + 40);
        assertEq(vault.releasable(), 50, "extra balance does not accelerate vesting");
        assertEq(vault.release(), 50);
        assertEq(vault.surplusBalance(), 17);

        ForceVestingEther force = new ForceVestingEther{value: 9}(payable(address(vault)));
        (bool ok,) = address(force).call("");
        assertTrue(ok);
        assertEq(vault.surplusBalance(), 26);

        vm.warp(START + DURATION);
        assertEq(vault.release(), 50);
        assertEq(vault.released(), PRINCIPAL);
        assertEq(
            vault.surplusBalance(), 26, "unexpected deposits remain separate after terminal release"
        );
    }

    function testFuzzLinearVestingAndClaim(uint96 rawPrincipal, uint8 rawElapsed) public {
        uint256 principal = bound(rawPrincipal, 0, type(uint96).max);
        uint256 elapsed = bound(rawElapsed, 0, DURATION);
        ImmutableVestingVault vault = deploy(payable(address(this)), principal);
        vm.deal(address(vault), principal);
        vm.warp(START + elapsed);

        uint256 expected;
        if (elapsed >= CLIFF) {
            expected = elapsed >= DURATION ? principal : principal * elapsed / DURATION;
        }
        assertEq(vault.vestedAmount(block.timestamp), expected);
        uint256 before = address(this).balance;
        assertEq(vault.release(), expected);
        assertEq(address(this).balance - before, expected);
        assertEq(vault.released(), expected);
        assertLe(vault.released(), vault.principal());
        assertEq(vault.release(), 0);
    }

    function testRejectingRecipientRollsBackReleaseState() public {
        RejectVestingEther rejector = new RejectVestingEther();
        ImmutableVestingVault vault = deploy(payable(address(rejector)), PRINCIPAL);
        vm.deal(address(vault), PRINCIPAL);
        vm.warp(START + DURATION);

        vm.expectRevert(ImmutableVestingVault.NativeTransferFailed.selector);
        vault.release();
        assertEq(vault.released(), 0);
        assertEq(address(vault).balance, PRINCIPAL);
    }

    function testReentrantRecipientCannotReleaseTwice() public {
        ReentrantVestingReceiver receiver = new ReentrantVestingReceiver();
        ImmutableVestingVault vault = deploy(payable(address(receiver)), PRINCIPAL);
        receiver.setVault(vault);
        vm.deal(address(vault), PRINCIPAL);
        vm.warp(START + DURATION);

        receiver.claim();
        assertTrue(receiver.nestedReleaseBlocked());
        assertEq(vault.released(), PRINCIPAL);
        assertEq(address(vault).balance, 0);
        assertEq(address(receiver).balance, PRINCIPAL);
    }

    function testConstructorRejectsInvalidInputs() public {
        vm.expectRevert(ImmutableVestingVault.InvalidRecipient.selector);
        new ImmutableVestingVault(payable(address(0)), PRINCIPAL, START, CLIFF, DURATION);
        vm.expectRevert(ImmutableVestingVault.InvalidSchedule.selector);
        new ImmutableVestingVault(payable(address(this)), PRINCIPAL, START, 1, 0);
        vm.expectRevert(ImmutableVestingVault.InvalidSchedule.selector);
        new ImmutableVestingVault(payable(address(this)), PRINCIPAL, START, DURATION + 1, DURATION);
        vm.expectRevert(ImmutableVestingVault.InvalidSchedule.selector);
        new ImmutableVestingVault(payable(address(this)), PRINCIPAL, type(uint64).max, 0, 1);
    }
}

contract ImmutableVestingVaultInvariantTest is StdInvariant, Test {
    uint64 internal constant START = 1_000_000;
    uint64 internal constant CLIFF = 1_000;
    uint64 internal constant DURATION = 100_000;
    uint256 internal constant PRINCIPAL = 1e24;

    ImmutableVestingVault internal vault;
    VestingVaultHandler internal handler;

    function setUp() public {
        vm.warp(START);
        handler = new VestingVaultHandler(
            new ImmutableVestingVault(payable(address(0xBEEF)), PRINCIPAL, START, CLIFF, DURATION),
            START + DURATION
        );
        vault = handler.vault();
        vm.deal(address(vault), PRINCIPAL);
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = VestingVaultHandler.advance.selector;
        selectors[1] = VestingVaultHandler.release.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_releasedNeverExceedsPrincipal() public view {
        assertLe(vault.released(), vault.principal());
    }

    function afterInvariant() public {
        vm.warp(START + DURATION);
        handler.release();
        assertEq(vault.released(), PRINCIPAL);
    }
}
