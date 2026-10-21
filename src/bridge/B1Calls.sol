// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {PrecompileFailed, PrecompileBadReturn} from "./BridgeErrors.sol";

/// @notice The native calls of the bridge: the semantics kernel at 0x0104 (prepareLock) and the composed relation
///         `BRIDGE_COMPOSE_V1` at 0x0105 (mint and return), which reads the B1 registry from the selected block's journal
///         itself. This library never reads or writes the registry and carries no authority.
library B1Calls {
    /// @dev Proposed B2 whole-token semantics kernel (0x0103 stays reserved for S1).
    address internal constant KERNEL = address(0x0104);
    /// @dev The native composition of one redemption (bft-core `bridgeprofile.NativeCompose`).
    address internal constant COMPOSE = address(0x0105);
    /// @dev Privileged B1 authority registry. Native-only: the precompiles read it through the execution journal.
    address internal constant REGISTRY = 0xff00000000000000000000000000000000000002;

    /// @dev STATICCALL forwarded `gasCap`, with the returndata size bounded before it is copied. A failed call (exceptional
    ///      halt, out of gas, host unavailable) reverts; a native call never reports failure as a result.
    function staticCall(address target, bytes memory input, uint256 maxReturn, uint256 gasCap)
        internal
        view
        returns (bytes memory out)
    {
        bool ok;
        uint256 size;
        assembly ("memory-safe") {
            ok := staticcall(gasCap, target, add(input, 32), mload(input), 0, 0)
            size := returndatasize()
        }
        if (!ok) revert PrecompileFailed(target);
        if (size > maxReturn) revert PrecompileBadReturn(target);
        out = new bytes(size);
        assembly ("memory-safe") {
            returndatacopy(add(out, 32), 0, size)
        }
    }
}
