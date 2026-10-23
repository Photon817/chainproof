// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal cheatcode surface used by generated proofs and self-checks.
/// @dev Mirrors the shape of forge-std's Vm interface so the project compiles
///      without a network-dependent `forge install` step. Only the cheatcodes
///      this repository actually calls are declared.
interface Vm {
    function startBroadcast() external;

    function startBroadcast(address sender) external;

    function startBroadcast(uint256 privateKey) external;

    function stopBroadcast() external;

    function deal(address account, uint256 newBalance) external;

    function prank(address msgSender) external;

    function startPrank(address msgSender) external;

    function stopPrank() external;

    function expectRevert() external;

    function expectRevert(bytes calldata revertData) external;

    function warp(uint256 newTimestamp) external;

    function roll(uint256 newHeight) external;

    function addr(uint256 privateKey) external returns (address);
}

address constant HEVM_ADDRESS = address(bytes20(uint160(uint256(keccak256("hevm cheat code")))));

/// @notice Base contract for generated Foundry scripts.
abstract contract Script {
    Vm internal constant vm = Vm(HEVM_ADDRESS);
}

/// @notice Tiny assertion base for `forge test`, keeping the project hermetic.
abstract contract ChainProofTest {
    Vm internal constant vm = Vm(HEVM_ADDRESS);

    function assertTrue(bool value, string memory message) internal pure {
        require(value, message);
    }

    function assertEq(uint256 left, uint256 right, string memory message) internal pure {
        require(left == right, message);
    }

    function assertEq(address left, address right, string memory message) internal pure {
        require(left == right, message);
    }

    function assertGt(uint256 left, uint256 right, string memory message) internal pure {
        require(left > right, message);
    }

    function assertLt(uint256 left, uint256 right, string memory message) internal pure {
        require(left < right, message);
    }
}
