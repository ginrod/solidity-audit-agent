# [H-04] Front-Running — Missing slippage protection allows sandwich attacks on DEX swaps

## Severity
High

## Description
`VulnerableDEX.swapETHForTokens()` accepts no `minAmountOut` parameter, meaning
the caller has no way to specify the minimum number of tokens they are willing
to accept. Any pending swap visible in the public mempool can be sandwiched:
an attacker buys tokens before the victim (pushing the price up), lets the
victim's swap execute at the inflated price, then sells back immediately for
profit — all at the victim's expense.

## Vulnerable Code
```solidity
// VULNERABILITY: no minAmountOut — caller accepts any amount of tokens
function swapETHForTokens() external payable returns (uint256 tokensOut) {
    require(msg.value > 0, "Must send ETH");

    // x * y = k: price depends on current reserves, which attacker can move
    tokensOut = (tokenReserve * msg.value) / (ethReserve + msg.value);

    ethReserve += msg.value;
    tokenReserve -= tokensOut;
    tokenBalances[msg.sender] += tokensOut;
    tokenBalances[address(this)] -= tokensOut;

    emit Swap(msg.sender, msg.value, tokensOut);
}
```

## Attack Scenario
Pool state: 10 ETH + 10,000 tokens (1 ETH = 1,000 tokens).

1. Victim submits `swapETHForTokens()` with 1 ETH — tx is visible in the mempool
2. Attacker sees the tx and sends `frontrun()` with 5 ETH at higher gas — executes first
3. Pool state after frontrun: 15 ETH + 6,667 tokens — price inflated
4. Victim's tx executes at the new price — receives 416 tokens instead of 909 (54% loss)
5. Attacker calls `backrun()` — sells all tokens back, recovering 5.565 ETH
6. Net attacker profit: **~0.565 ETH**, taken entirely from the victim

Proof of concept: `test/FrontRunTest.t.sol::test_SandwichAttack` — verified with Foundry.

## Impact
Any user swapping on the DEX is exposed to sandwich attacks from MEV bots
monitoring the mempool. In the PoC, the victim suffers a 54% slippage loss
on a 1 ETH swap. At scale, this makes the DEX unusable for any meaningful
trade size, as MEV bots operate continuously and profitably on unprotected pools.
Historical example: Over $1.38B extracted from Ethereum users via sandwich attacks
between 2020 and 2023 (EigenPhi MEV research).

## Recommendation
Add a `minAmountOut` parameter to `swapETHForTokens()` and revert if the
calculated output falls below it. This is the standard slippage guard used
by Uniswap and every production DEX:

```solidity
function swapETHForTokens(uint256 minAmountOut) external payable returns (uint256 tokensOut) {
    require(msg.value > 0, "Must send ETH");

    tokensOut = (tokenReserve * msg.value) / (ethReserve + msg.value);

    require(tokensOut >= minAmountOut, "Slippage exceeded"); // slippage guard

    ethReserve += msg.value;
    tokenReserve -= tokensOut;
    tokenBalances[msg.sender] += tokensOut;
    tokenBalances[address(this)] -= tokensOut;

    emit Swap(msg.sender, msg.value, tokensOut);
}
```

Alternatively, add a deadline parameter to reject transactions that sit in the
mempool longer than the user intended:

```solidity
function swapETHForTokens(uint256 minAmountOut, uint256 deadline) external payable returns (uint256 tokensOut) {
    require(block.timestamp <= deadline, "Transaction expired");
    require(msg.value > 0, "Must send ETH");

    tokensOut = (tokenReserve * msg.value) / (ethReserve + msg.value);
    require(tokensOut >= minAmountOut, "Slippage exceeded");
    ...
}
```

Callers should compute `minAmountOut` off-chain using `getAmountOut()` and apply
a tolerance (e.g. 0.5–1%) before submitting the transaction.

## References
- OWASP Smart Contract Top 10 — SC05 Front-Running: https://owasp.org/www-project-smart-contract-top-10/2023/en/src/SC05-front-running-attacks.html
- Consensys Diligence — Transaction Ordering Dependence: https://consensysdiligence.github.io/smart-contract-best-practices/attacks/frontrunning/
- Uniswap V2 — slippage protection reference: https://docs.uniswap.org/contracts/v2/reference/smart-contracts/router-02#swapexactethfortokens
- EigenPhi MEV Research (2023): $1.38B extracted via sandwich attacks
