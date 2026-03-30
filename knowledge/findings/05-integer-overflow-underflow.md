# [H-05] Integer Underflow — Attacker can inflate balance to 2^256-1 and drain all funds

## Severity
High

## Description
`transfer()` wraps arithmetic in an `unchecked` block, disabling Solidity 0.8's
built-in overflow/underflow protection. An attacker with zero balance can call
`transfer(someAddress, 1)`, causing `balances[msg.sender]` to underflow from
`0` to `type(uint256).max` (2^256 - 1). The attacker can then pass the
`require(balances[msg.sender] >= amount)` check in `withdraw()` with any amount,
draining all ETH held by the contract.

## Vulnerable Code
```solidity
function transfer(address to, uint256 amount) external {
    // BUG: unchecked allows underflow — wraps to 2^256 - 1
    unchecked {
        balances[msg.sender] -= amount; // underflows if balance < amount
        balances[to] += amount;
    }
}

function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance"); // bypass via inflated balance
    unchecked {
        balances[msg.sender] -= amount;
    }
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
}
```

## Attack Scenario
1. Victim deposits 10 ETH → `token.balance: 10 ETH`
2. Attacker deploys `AttackOverflow` with zero balance
3. Attacker calls `attack()` → internally calls `transfer(address(1), 1)`
   - `balances[attacker] = 0 - 1` → underflows to `2^256 - 1` inside `unchecked`
   - `balances[address(1)] += 1` → separate address, no cancellation
4. Attacker calls `drain(10 ether)` → internally calls `withdraw(10 ether)`
   - `require(2^256-1 >= 10 ether)` → passes
   - Contract sends 10 ETH to attacker
5. Attacker calls `collectProfit()` → receives 10 ETH profit

Foundry PoC confirms: `test_underflowInflatesBalance` and `test_drainVictimFunds` both pass.

## Impact
Complete drainage of all contract funds. Any depositor loses their full balance.
Attacker needs zero initial capital — only gas costs.

Historical example: The BatchOverflow vulnerability (2018) affected multiple ERC-20
tokens (Beauty Chain, Smart Mesh, others). Attackers called `batchTransfer()` with
crafted values that overflowed `uint256`, minting trillions of tokens out of thin air.
Several exchanges suspended trading. Root cause: identical pattern — unchecked
arithmetic in token transfer logic.

## Recommendation
Remove `unchecked` from any arithmetic that handles user balances. Solidity 0.8+
reverts automatically on overflow/underflow by default:

```solidity
function transfer(address to, uint256 amount) external {
    // Safe: Solidity 0.8 reverts on underflow automatically
    balances[msg.sender] -= amount;
    balances[to] += amount;
}

function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount; // safe subtraction
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
}
```

Only use `unchecked` when you have mathematically proven the operation cannot
overflow/underflow (e.g., inside a `for` loop counter after a length check).

Alternative: for pre-0.8 contracts, use OpenZeppelin's SafeMath library:
```solidity
using SafeMath for uint256;
balances[msg.sender] = balances[msg.sender].sub(amount);
```

## References
- OWASP Smart Contract Top 10 (2025) — SC09 Integer Overflow and Underflow: https://owasp.org/www-project-smart-contract-top-10/
- SWC-101: Integer Overflow and Underflow: https://swcregistry.io/docs/SWC-101
- BatchOverflow vulnerability (2018): https://peckshield.medium.com/alert-new-batchoverflow-bug-in-multiple-erc20-smart-contracts-cve-2018-10299-511067db6536
- OpenZeppelin SafeMath: https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath
