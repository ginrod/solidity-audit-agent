"""
Front-running / MEV detector.
Flags DEX-like functions missing slippage or deadline protection.
"""
import re

VULN_CLASS = "front_running"

# DEX-like swap/liquidity operations
_SWAP_RE = re.compile(
    r"(?:swap|addLiquidity|removeLiquidity|buy|sell|trade|exchange)",
    re.IGNORECASE,
)

# Slippage / deadline protection patterns
_SLIPPAGE_RE = re.compile(
    r"(?:"
    r"\bminAmount\b|\bminOut\b|\bminReturn\b|\bminTokens\b"
    r"|\bamountOutMin\b|\bamountInMax\b"
    r"|\bdeadline\b"
    r"|\brequire\s*\(.*amount.*>=?"
    r"|\brequire\s*\(.*block\.timestamp"
    r")"
)


def detect(functions: list[dict], code: str) -> list[str]:
    candidates = []

    for fn in functions:
        if fn["visibility"] not in {"public", "external"}:
            continue
        if not _SWAP_RE.search(fn["name"]):
            continue
        if not _SLIPPAGE_RE.search(fn["body"]) and not _SLIPPAGE_RE.search(fn["signature"]):
            candidates.append(
                f"{VULN_CLASS}:function `{fn['name']}` — "
                f"swap-like operation without slippage/deadline protection"
            )

    return candidates
