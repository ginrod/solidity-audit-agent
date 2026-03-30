# AuditAgent Triage — Scan #3 (2026-03-22)

Contract: VulnerableDEX_clean.sol
Scan run without comments or context to test unbiased detection.
Total findings: 4 (High: 1, Medium: 2, Low: 1)

---

## Finding 1 — High: Missing slippage protection allows front-running and sandwich attacks

**Tool Severity:** High Risk
**Triage Decision:** Valid — core vulnerability correctly detected.

`swapETHForTokens()` accepts no `minAmountOut` parameter, leaving callers with
no on-chain guard against price movement between tx submission and execution.
AuditAgent correctly identifies the full sandwich attack flow: frontrun (higher
gas), victim executes at inflated price, backrun extracts the price difference.

This is the primary vulnerability the contract was designed to demonstrate.
Severity High is correct — any user swapping on a real deployment would be
exposed to continuous MEV extraction. The Foundry PoC (`FrontRunTest.t.sol`)
confirms a 54% slippage loss and ~0.565 ETH profit for the attacker on a
1 ETH swap against a 10 ETH pool.

AuditAgent also correctly flagged `swapTokensForETH` as lacking the same
protection — this direction is equally exploitable and was not explicitly
highlighted in our original finding H-04.

---

## Finding 2 — Medium: Missing transaction deadline allows stale execution

**Tool Severity:** Medium Risk
**Triage Decision:** Valid — legitimate secondary vulnerability.

Neither swap function accepts a `deadline` parameter. A transaction pending
in the mempool during high gas periods can be executed minutes or hours later,
when reserves have moved significantly, and the caller has no on-chain mechanism
to invalidate it. This is the standard pattern Uniswap V2/V3 guard against with
`require(block.timestamp <= deadline, "Expired")`.

This is not a duplicate of Finding 1 — slippage and deadline are complementary
protections. Slippage guards against price movement; deadline guards against
time. Combined, their absence maximizes the attack surface for MEV bots and
miner manipulation. AuditAgent correctly identifies the compounding effect.

Medium severity is appropriate — it amplifies Finding 1 but does not constitute
an independent critical vulnerability on its own.

---

## Finding 3 — Medium: `swapTokensForETH` denies redemption for contract-based users via `transfer`

**Tool Severity:** Medium Risk
**Triage Decision:** Valid — real DoS for a class of users.

`swapTokensForETH` sends ETH with `payable(msg.sender).transfer(ethOut)`.
`transfer` forwards only 2300 gas — insufficient for smart contract wallets,
multisigs, proxies, or any recipient that executes logic in its `receive()`
or `fallback`. For these users, every call to `swapTokensForETH` reverts,
permanently locking their internal token balance with no alternative exit path.

This is a well-known Solidity anti-pattern. The compiler itself emits a
deprecation warning for `transfer`, and our `forge build` output already
flagged it. The fix is to use `call{value: ethOut}("")` with explicit success
checking. Medium severity is correct — it is a DoS affecting a subset of users,
not a theft of funds.

This finding is independent of front-running and was not part of H-04. It
represents additional attack surface discovered by the agent.

---

## Finding 4 — Low: Integer rounding allows zero-output swaps that consume user input

**Tool Severity:** Low Risk
**Triage Decision:** Valid — correctly classified.

Both swap directions use integer floor division without verifying the output is
non-zero. A caller sending dust ETH can receive 0 tokens while the contract
keeps the ETH (donated to the pool). The same applies in the reverse direction.

AuditAgent's own severity notes are accurate: this primarily affects dust-sized
inputs in typical deployments, no adversary can force others into zero-output,
and the contract's own `getAmountOut()` helper allows callers to preview the
output before swapping. The fix is a `require(tokensOut > 0)` check before
updating state.

Low severity is correct. Would file in a real audit as a code quality issue.

---

## Summary

| # | Title | AA Severity | Triage |
|---|-------|-------------|--------|
| 1 | Missing slippage protection — sandwich attack | High | Valid — core vulnerability detected |
| 2 | Missing deadline — stale execution | Medium | Valid — complementary to Finding 1 |
| 3 | `transfer` DoS for contract-based users | Medium | Valid — independent secondary vulnerability |
| 4 | Integer rounding — zero-output swaps | Low | Valid |

**False positives:** 0 of 4
**Key observation:** AuditAgent detected the primary vulnerability at the correct
severity (High) with no hints or context. Findings 2 and 3 are legitimate
secondary vulnerabilities not explicitly designed into the contract — the agent
expanded the scope of the review beyond the intended vulnerability, which is the
expected behavior in a real audit. Finding 3 (`transfer` DoS) is particularly
notable: it was flagged by the compiler as a warning and by the agent as Medium,
both consistent signals that reinforce each other.
