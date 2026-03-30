# AuditAgent Triage — Scan #5 (2026-03-24)

Contract: MultiSigTimelock.sol (First Flight #55 — CodeHawks)
Scan run without comments or context to test unbiased detection.
Total findings: 3 (High: 0, Medium: 0, Low: 0, Info: 2, Best Practices: 1)

---

## Finding 1 — Info: Timelock bypass for ERC20 and non-ETH asset movements

**Tool Severity:** Info
**Triage Decision:** Valid — severity underestimated.

`_getTimelockDelay()` derives the delay exclusively from `txn.value` (ETH amount).
But `_executeTransaction()` sends an arbitrary `data` payload alongside that value.
Any transaction with `value == 0` receives `NO_TIME_DELAY`, regardless of what `data`
encodes — including `transfer(attacker, balance)` on an ERC20, NFT transfers, or
admin calls into external protocols.

```solidity
uint256 requiredDelay = _getTimelockDelay(txn.value); // only checks ETH value
// ...
(bool success,) = payable(txn.to).call{value: txn.value}(txn.data); // executes arbitrary data
```

AuditAgent correctly identified the mechanism and provided a concrete ERC20 drain
scenario. The severity note is accurate: impact depends on whether the wallet holds
non-ETH assets. In a real deployment this is Medium or High — a wallet managing
ERC20 treasury funds is the standard use case, making the bypass directly exploitable.

Classifying this as Info rather than at least Medium is an underseverity error.
The official CodeHawks contest did not validate this as a standalone finding
(likely because `proposeTransaction` is `onlyOwner`, which constrains the threat
model to a malicious or compromised owner). That context is missing from the scan,
which explains the difference.

---

## Finding 2 — Info: Ghost confirmations from removed signers permanently inflate confirmation counter

**Tool Severity:** Info
**Triage Decision:** Valid — severity significantly underestimated. This is a High.

`revokeSigningRole()` removes the signer's role and updates `s_isSigner`, but never
cleans up `s_signatures[txnId][removedSigner]` or decrements
`s_transactions[txnId].confirmations`. Ghost votes from the removed signer persist
permanently in all pending transactions.

```solidity
// revokeSigningRole() — no cleanup:
s_isSigner[_account] = false;
_revokeRole(SIGNING_ROLE, _account);
// s_signatures and confirmations counters are never touched

// _executeTransaction() — only checks raw counter:
if (txn.confirmations < REQUIRED_CONFIRMATIONS) { revert ... }
```

AuditAgent described the full attack path precisely:
1. Owner adds signers B and C (total: 3 active signers)
2. Owner proposes a malicious transaction
3. A, B, C each confirm → `confirmations = 3`
4. Owner revokes B and C → active signers drops to 1, but `confirmations` remains 3
5. Owner calls `executeTransaction` → passes the 3-confirmation check with a single
   active signer

Additionally, once revoked, ex-signers lose `SIGNING_ROLE` and cannot call
`revokeConfirmation` to retract their own vote — no cleanup path exists.

This is the primary vulnerability validated as High by the official CodeHawks report
(H-01 and H-02). AuditAgent detected it with full precision — root cause, attack path,
and the double compounding factor (no cleanup + no self-retraction) — but classified
it as Info instead of High. This is the most significant severity miscalibration in
this scan.

Likely reason: AuditAgent may have downgraded severity because the attack requires
the owner to cooperate with the initial confirmations (or be malicious), treating it
as a governance/trust issue rather than a direct exploit. But the H-01/H-02 framing
in the contest correctly identifies it as a security guarantee violation regardless
of intent.

---

## Finding 3 — Best Practices: Missing public view for per-signer confirmation status

**Tool Severity:** Best Practices
**Triage Decision:** Valid — correctly classified.

`s_signatures` is `private` with no external getter. Off-chain tools and front-ends
cannot determine which specific signers have confirmed a transaction without replaying
event logs. The only on-chain information available is the aggregate `confirmations`
count via `getTransaction(txnId)`.

```solidity
mapping(uint256 transactionId => mapping(address user => bool userHasSignedCorrectly))
    private s_signatures;
```

Fix: add a view function `hasConfirmed(uint256 txnId, address signer) external view returns (bool)`.
Not a security vulnerability, but a valid UX and tooling gap. Best Practices is correct.

---

## Summary

| # | Title | AA Severity | Triage |
|---|-------|-------------|--------|
| 1 | Timelock bypass via `value=0` + ERC20/data payload | Info | Valid — underseverity (Medium/High in real deployment) |
| 2 | Ghost confirmations from revoked signers | Info | Valid — **significant underseverity** (High per official report) |
| 3 | Missing `s_signatures` public getter | Best Practices | Valid |

**False positives:** 0 of 3
**False negatives (severity):** 2 of 3 — AuditAgent found both critical vulnerabilities
but classified them as Info instead of High/Medium.

**Key observation:** This is the most interesting scan so far from a triage perspective.
AuditAgent demonstrated strong detection — it identified the ghost confirmation attack
path with full precision, including the self-retraction lockout — but systematically
underseveritied both findings by two or more levels. In a real audit workflow, this
pattern (correct detection, wrong severity) is exactly what human triage is designed
to catch. A developer relying solely on the Info label might deprioritize both issues,
missing what the official contest judges classified as High.

Comparison with manual analysis: the ghost confirmation bug was missed entirely during
manual review. AuditAgent found it where the human auditor did not — a clear win for
AI-assisted scanning, even with the severity gap.
