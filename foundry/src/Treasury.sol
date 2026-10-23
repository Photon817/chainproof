// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Treasury
/// @notice Deliberately vulnerable target: an unguarded privilege setter
///         controls a function that can move the entire balance.
contract Treasury {
    address public operator;

    constructor() {
        operator = msg.sender;
    }

    /// @dev No authorization check: any caller can become the operator.
    function setOperator(address newOperator) external {
        operator = newOperator;
    }

    function emergencyWithdraw(address payable to) external {
        require(msg.sender == operator, "Treasury: not operator");

        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "Treasury: transfer failed");
    }

    receive() external payable {}
}
