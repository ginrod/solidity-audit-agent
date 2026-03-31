"""
Access control detector.
Flags public/external state-changing functions with no access restriction.
"""
import re

VULN_CLASS = "access_control"

# Common access-control modifiers / checks
_ACCESS_PATTERNS = re.compile(
    r"(?:"
    r"\bonlyOwner\b"
    r"|\bonlyRole\b"
    r"|\bonlyAdmin\b"
    r"|\brequire\s*\(\s*msg\.sender"
    r"|\brequire\s*\(\s*_msgSender"
    r"|\bhasRole\b"
    r"|\bAccessControl\b"
    r"|\bOwnable\b"
    r")"
)

# State-writing patterns (not pure/view)
_STATE_WRITE_RE = re.compile(
    r"(?:"
    r"\w+\[.*?\]\s*[+\-]?="
    r"|\bdelete\s+\w+"
    r"|\w+\s*=\s*(?!.*\breturn\b)"  # assignment that isn't a return
    r"|emit\s+\w+"                   # emitting events typically follows state write
    r"|\.transfer\s*\("
    r"|selfdestruct\s*\("
    r")"
)


def detect(functions: list[dict], code: str) -> list[str]:
    candidates = []

    for fn in functions:
        if fn["visibility"] not in {"public", "external"}:
            continue

        # Skip if function has a known access modifier
        if _ACCESS_PATTERNS.search(fn["signature"]) or _ACCESS_PATTERNS.search(fn["body"]):
            continue

        # Skip view/pure functions (read-only)
        sig_lower = fn["signature"].lower()
        if "view" in sig_lower or "pure" in sig_lower:
            continue

        # Flag if body contains state-writing patterns
        if _STATE_WRITE_RE.search(fn["body"]):
            candidates.append(
                f"{VULN_CLASS}:function `{fn['name']}` ({fn['visibility']}) — "
                f"no access control modifier, modifies state"
            )

    return candidates
