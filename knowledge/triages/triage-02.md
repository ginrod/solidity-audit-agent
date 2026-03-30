# AuditAgent Triage — Scan #2 (2026-03-20)

Contracts: MockPool.sol, VulnerableLending.sol
Scan run without comments or context to test unbiased detection.
Total findings: 7 (High: 1, Medium: 1, Low: 3, Info: 1, Best Practices: 1)

---

## Finding 1 — High: No repayment, collateral withdrawal, or liquidation functions

**Tool Severity:** High Risk
**Triage Decision:** Valid — out of scope for this PoC

`VulnerableLending` exposes only `depositCollateral()` and `borrow()`. There is
no `repay()`, `withdrawCollateral()`, or `liquidate()`. Any ETH deposited is
permanently locked. In a production protocol this would be a legitimate High:
users cannot recover funds and undercollateralized positions cannot be resolved.

In this context it is an artifact of the minimal PoC design — the contract was
built to demonstrate oracle manipulation, not to be a complete lending protocol.
Not a false positive; the finding is technically correct and would be filed in a
real audit.

---

## Finding 2 — Medium: Cost-free spot price manipulation bypasses 80% LTV

**Tool Severity:** Medium Risk
**Triage Decision:** Valid. Core vulnerability correctly detected without any context.

`VulnerableLending.borrow()` reads the price from `MockPool.getPrice()` at call
time. Because `MockPool.buyETH()` is public and requires no token transfer, an
attacker can inflate `usdReserve / ethReserve` arbitrarily and immediately call
`borrow()` in the same transaction, bypassing the 80% LTV check.

AuditAgent classified this as Medium (not High) with sound reasoning: `borrow()`
only increments an internal mapping and does not transfer real USD tokens, so
there is no direct economic extraction in the given code. In a real protocol with
actual ERC-20 transfers, this would be Critical.

The agent also correctly identified two distinct attack vectors:
- **Same-transaction:** manipulate price and borrow atomically — no mempool
  access required, executable at any time by anyone.
- **Front-running:** monitor the mempool for a victim's `borrow()` transaction,
  submit the manipulate+borrow bundle with higher gas to execute first.

The same-transaction vector is more dangerous because it does not depend on
victim activity. Documenting only the front-running vector would understate the
risk.

---

## Finding 3 — Low: Precision loss in price calculation

**Tool Severity:** Low Risk
**Triage Decision:** Partially valid — impact overstated.

`getPrice()` returns `usdReserve / ethReserve`. Both values are stored with 18
decimal places (`ether` units), so the division cancels them out and returns an
unscaled integer (e.g., `3000` instead of `3000e18`). Fractional prices are
truncated.

The finding is technically correct. However, AuditAgent does not note that the
downstream lending math compensates: `collateral[user]` is in wei, so
`collateral[user] * price` preserves 18 decimals of precision at the
`collateralValue` level. The practical impact is lower than described. In a real
protocol using this oracle pattern, precision loss at sub-1-USD ETH prices would
be a genuine issue worth flagging.

---

## Finding 4 — Low: Magic Numbers Instead Of Constants

**Tool Severity:** Low Risk
**Triage Decision:** Valid.

The LTV ratio (`80`) and denominator (`100`) are hardcoded literals in two
separate places (`borrow()` and `getMaxBorrow()`). A named constant such as
`uint256 constant LTV_NUMERATOR = 80` would make the intent explicit and prevent
inconsistent changes. Standard code quality finding, correct.

---

## Finding 5 — Low: Unoptimized Numeric Literal Format

**Tool Severity:** Low Risk
**Triage Decision:** False positive / noise.

AuditAgent flags `300_000 ether` and suggests scientific notation (`300e3 ether`).
`300_000` is valid Solidity and is arguably more readable than `300e3` for large
round numbers — it mirrors how humans write thousands separators. No security or
correctness impact. Would not file in a real audit.

---

## Finding 6 — Info: Spot price oracle trivially manipulable

**Tool Severity:** Info
**Triage Decision:** Duplicate of Finding 2 with consistent severity reasoning.

Same vulnerability as Finding 2. Downgraded to Info because `borrow()` does not
transfer assets, limiting real economic impact in the given code. The severity
note is the most valuable part: AuditAgent correctly distinguishes between a
design flaw and an exploit with measurable economic consequence, and lists the
conditions that would elevate it (actual token transfer or ETH withdrawal against
inflated collateral).

The front-running mention here is accurate — see Finding 2 notes on the two
attack vectors.

---

## Finding 7 — Best Practices: Missing events for state-changing operations

**Tool Severity:** Best Practices
**Triage Decision:** Valid.

Neither `depositCollateral()` nor `borrow()` emit events. Without events,
off-chain monitoring systems cannot detect suspicious borrowing patterns (e.g.,
unusually large borrows immediately after pool reserve changes — the oracle attack
signature). AuditAgent correctly notes that a `Borrowed` event including
`priceAtBorrow` would provide an on-chain audit trail for the exact manipulation
described in Findings 2 and 6.

---

## Summary

| # | Title | AA Severity | Triage |
|---|-------|-------------|--------|
| 1 | No repay/withdraw/liquidate — ETH locked | High | Valid (PoC artifact) |
| 2 | Oracle spot price manipulation bypasses LTV | Medium | Valid — core vulnerability detected |
| 3 | Precision loss in getPrice() | Low | Partially valid — impact overstated |
| 4 | Magic numbers (80, 100) | Low | Valid |
| 5 | Numeric literal format (300_000) | Low | False positive |
| 6 | Spot price manipulable (duplicate of #2) | Info | Duplicate — severity reasoning sound |
| 7 | Missing events | Best Practices | Valid |

**False positives:** 1 of 7 (Finding 5)
**Key observation:** AuditAgent detected the oracle manipulation vulnerability
without any hints, comments, or context. Severity was conservatively assessed
(Medium/Info instead of High) with correct reasoning: the attack is real but
economic extraction requires asset transfers not present in this PoC.
