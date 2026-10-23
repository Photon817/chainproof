// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Vault
/// @notice Deliberately vulnerable target: the classic reentrancy exercise.
/// @dev withdraw() performs the external call before zeroing the balance.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Vault: no balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Vault: transfer failed");

        balances[msg.sender] = 0;
    }
}
