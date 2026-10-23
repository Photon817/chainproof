// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GuardedVault
/// @notice Same CEI violation as Vault, but protected by nonReentrant.
///         The Attacker still flags it; the Reviewer must reject the path.
contract GuardedVault {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "GuardedVault: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "GuardedVault: no balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "GuardedVault: transfer failed");

        balances[msg.sender] = 0;
    }
}
