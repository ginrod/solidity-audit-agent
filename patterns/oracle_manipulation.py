"""
Oracle price manipulation detector.
Flags spot-price reads without TWAP protection.
"""
import re

VULN_CLASS = "oracle_manipulation"

# Spot-price patterns (single-block manipulable)
_SPOT_PRICE_RE = re.compile(
    r"(?:"
    r"getReserves\s*\("          # Uniswap V2 reserves
    r"|\.reserve0\b|\.reserve1\b"
    r"|balanceOf\s*\(\s*address\s*\(\s*this"  # pool's own token balance as price
    r"|getAmountsOut\s*\("       # Uniswap router spot quote
    r"|getAmountsIn\s*\("
    r"|slot0\s*\("               # Uniswap V3 slot0 (manipulable)
    r"|\.sqrtPriceX96\b"
    r")"
)

# TWAP / safe oracle patterns (would cancel out the flag)
_TWAP_RE = re.compile(
    r"(?:"
    r"observe\s*\("              # Uniswap V3 TWAP
    r"|consult\s*\("             # common TWAP oracle method
    r"|IChainlinkAggregator"
    r"|AggregatorV3Interface"
    r"|latestRoundData\s*\("
    r")"
)


def detect(functions: list[dict], code: str) -> list[str]:
    # Check at contract level (price logic often in helpers or inline)
    if not _SPOT_PRICE_RE.search(code):
        return []
    if _TWAP_RE.search(code):
        return []  # TWAP present — likely protected

    # Find which functions contain the spot read
    candidates = []
    for fn in functions:
        if _SPOT_PRICE_RE.search(fn["body"]):
            candidates.append(
                f"{VULN_CLASS}:function `{fn['name']}` — "
                f"uses spot price (no TWAP), vulnerable to flash loan manipulation"
            )

    return candidates
