"""
Reentrancy detector — CEI (Checks-Effects-Interactions) violation.
Flags functions that make external calls before updating state variables.
"""
import re

VULN_CLASS = "reentrancy"

# Patterns that indicate an external call (Interactions)
_EXTERNAL_CALL_RE = re.compile(
    r"(?:"
    r"\.call\s*[\({]"           # low-level .call({value:...})
    r"|\.transfer\s*\("         # address.transfer()
    r"|\.send\s*\("             # address.send()
    r"|IERC20\.\w+\s*\("        # token interface calls
    r"|I\w+\(.*\)\.\w+\s*\("   # generic interface pattern
    r")"
)

# Patterns that indicate a state update (Effects)
_STATE_UPDATE_RE = re.compile(
    r"(?:"
    r"\w+\[.*?\]\s*[+\-]?="     # mapping/array assignment
    r"|\w+\s*[+\-]?=\s*\d"      # simple state var assignment
    r"|delete\s+\w+"             # delete keyword
    r"|balances\[|deposits\[|shares\["  # common balance vars
    r")"
)


def detect(functions: list[dict], code: str) -> list[str]:
    """Return list of candidate hints if reentrancy pattern is found."""
    candidates = []

    for fn in functions:
        body = fn["body"]
        lines = body.splitlines()

        first_call_idx = None
        first_state_update_after_call = None

        for idx, line in enumerate(lines):
            if first_call_idx is None and _EXTERNAL_CALL_RE.search(line):
                first_call_idx = idx
            elif first_call_idx is not None and _STATE_UPDATE_RE.search(line):
                first_state_update_after_call = idx
                break

        if first_call_idx is not None and first_state_update_after_call is not None:
            candidates.append(
                f"{VULN_CLASS}:function `{fn['name']}` — "
                f"external call at line {fn['start_line'] + first_call_idx} "
                f"before state update (CEI violation)"
            )

    return candidates
