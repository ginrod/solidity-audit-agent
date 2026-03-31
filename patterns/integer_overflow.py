"""
Integer overflow/underflow detector.
Flags unchecked arithmetic blocks and pre-0.8.x pragma.
"""
import re

VULN_CLASS = "integer_overflow"

_UNCHECKED_RE = re.compile(r"\bunchecked\s*\{")
_ARITHMETIC_RE = re.compile(r"[+\-\*]\s*=|[+]{2}|[-]{2}")  # +=, -=, ++, --
_OLD_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+[\^~<]?0\.[0-7]\.")


def detect(functions: list[dict], code: str) -> list[str]:
    candidates = []

    # Flag old compiler version (pre-0.8 has no built-in overflow checks)
    if _OLD_PRAGMA_RE.search(code):
        candidates.append(
            f"{VULN_CLASS}:pragma — compiler <0.8.x detected, "
            f"no built-in overflow protection"
        )

    # Flag unchecked blocks containing arithmetic
    for fn in functions:
        unchecked_blocks = re.findall(r"\bunchecked\s*\{([^}]*)\}", fn["body"], re.DOTALL)
        for block in unchecked_blocks:
            if _ARITHMETIC_RE.search(block):
                candidates.append(
                    f"{VULN_CLASS}:function `{fn['name']}` — "
                    f"arithmetic inside unchecked block"
                )
                break  # one candidate per function is enough

    return candidates
