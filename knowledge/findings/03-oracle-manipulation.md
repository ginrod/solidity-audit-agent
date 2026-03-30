# [H-03] Oracle Manipulation — Spot price from AMM pool allows inflated borrowing

## Severity
High

## Description
`VulnerableLending.borrow()` calculates collateral value using a spot price
fetched directly from `MockPool.getPrice()`, which returns `usdReserve / ethReserve`.
This spot price can be manipulated in a single transaction by trading large
amounts against the pool, inflating the reported price and allowing an attacker
to borrow far beyond the value of their actual collateral.

## Vulnerable Code
```solidity
function borrow(uint256 usdAmount) public {
    uint256 price = oracle.getPrice(); // spot price — manipulable in one tx
    uint256 collateralValue = collateral[msg.sender] * price;
    uint256 maxBorrow = (collateralValue * 80) / 100;

    require(borrowed[msg.sender] + usdAmount <= maxBorrow, "Undercollateralized");
    borrowed[msg.sender] += usdAmount;
}
```

## Attack Scenario
1. Attacker deposits 1 ETH as collateral → legitimate maxBorrow = 2400 USD (80% of 3000)
2. Attacker calls `pool.buyETH(500_000 ether)` — injects 500k USD into the pool
3. Pool price spikes from 3000 → 21,333 (7x increase) due to AMM reserve imbalance
4. `getMaxBorrow()` reads the inflated price → returns ~7x more than collateral justifies
5. Attacker calls `borrow(maxBorrow)` — drains protocol with undercollateralized position
6. In a real attack: step 2 uses a flash loan, step 5 repays it — all in one transaction

## Impact
An attacker with minimal collateral can drain the lending protocol by borrowing
far beyond their collateral value. The protocol becomes insolvent as borrowed
amounts exceed the actual ETH backing them.
Historical example: Mango Markets (2022) — $117M drained via oracle price manipulation.

## Recommendation
Never use spot prices from AMM pools as oracles. The core principle is that
any price readable and writable within the same transaction is manipulable.
A safe oracle must reflect a price that cannot be moved and read atomically
by an attacker. Practices to follow:

- Use time-averaged prices (TWAP) so a single block cannot move the price enough to be profitable
- Use decentralized price feeds (Chainlink) that aggregate from multiple independent sources
- Add circuit breakers: reject borrows if the price deviates more than X% from a reference
- Separate price reading from state-changing operations across blocks when possible

Use a manipulation-resistant price source:

```solidity
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface priceFeed = AggregatorV3Interface(chainlinkAddress);
(, int256 price,,,) = priceFeed.latestRoundData();
```

Alternatively, use a TWAP (Time-Weighted Average Price) from Uniswap V3,
which averages the price over a time window making single-block manipulation
economically infeasible.

## References
- OWASP Smart Contract Top 10 (2025) — SC02 Price Oracle Manipulation: https://owasp.org/www-project-smart-contract-top-10/2025/en/src/SC02-price-oracle-manipulation.html
- Chainlink Data Feeds: https://docs.chain.link/data-feeds
- Uniswap V3 TWAP Oracle: https://docs.uniswap.org/concepts/protocol/oracle
- Mango Markets Exploit (2022): $117M via oracle manipulation
