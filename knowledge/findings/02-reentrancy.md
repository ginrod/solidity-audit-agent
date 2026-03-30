# [C-02] Reentrancy — Attacker can drain all vault funds

## Severity
Critical

## Description
`withdraw()` sends ETH to `msg.sender` via `call` before updating
`balances[msg.sender]`. A malicious contract can re-enter `withdraw()`
in its `receive()` function, draining the vault in a single transaction
before the balance is ever zeroed.

## Vulnerable Code
```solidity
function withdraw() public {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "Nothing to withdraw");

    (bool success, ) = payable(msg.sender).call{value: amount}("");
    require(success, "Transfer failed");

    balances[msg.sender] = 0; // state update too late
}
```

## Attack Scenario
1. Victim deposits 5 ETH → vault balance: 5 ETH
2. Attacker deploys `AttackReentrancy` pointing to the vault
3. Attacker calls `attack()` with 1 ETH
4. Vault sends 1 ETH to attacker contract → `receive()` fires
5. `receive()` calls `withdraw()` again — `balances[attacker]` is still 1 ETH
6. Loop repeats until vault is empty
7. Attacker calls `collectSteals()` → receives 6 ETH (5 ETH profit)

## Impact
Complete drainage of all vault funds in a single transaction.
Any depositor loses their entire balance.
Historical example: The DAO hack (2016) — $60M stolen via reentrancy.

## Recommendation
Apply the Checks-Effects-Interactions pattern — update state BEFORE
any external call:

```solidity
function withdraw() public {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "Nothing to withdraw");

    balances[msg.sender] = 0; // state update FIRST

    (bool success, ) = payable(msg.sender).call{value: amount}("");
    require(success, "Transfer failed");
}
```

Alternatively, use OpenZeppelin's `ReentrancyGuard`:

```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    function withdraw() public nonReentrant { ... }
}
```

## References
- OWASP Smart Contract Top 10 (2025) — SC05 Reentrancy: https://owasp.org/www-project-smart-contract-top-10/2025/en/src/SC05-reentrancy-attacks.html
- Consensys Diligence — Reentrancy: https://consensysdiligence.github.io/smart-contract-best-practices/attacks/reentrancy/
- OpenZeppelin ReentrancyGuard: https://docs.openzeppelin.com/contracts/4.x/api/security
- SWC-107: Reentrancy (archived): https://swcregistry.io/docs/SWC-107
- The DAO Hack (2016): first major reentrancy exploit in production
