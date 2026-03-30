# Specter

**Smart contract vulnerability detection agent for [AgentArena](https://app.agentarena.nethermind.io)**

Specter is a LangGraph-powered audit agent that detects Solidity vulnerabilities through structured static analysis and pattern-based reasoning. Each finding is triaged, classified by severity, and reported in Immunefi/Code4rena format — with evidence, impact, and recommended fix.

---

## Architecture

```
specter/
├── agent/
│   ├── graph.py          # LangGraph state machine (main entrypoint)
│   ├── nodes/
│   │   ├── loader.py     # Contract ingestion + preprocessing
│   │   ├── scanner.py    # Pattern detection per vulnerability class
│   │   ├── reasoner.py   # LLM reasoning node (false positive filter)
│   │   └── reporter.py   # Finding formatter (severity + PoC + fix)
│   └── state.py          # AgentState TypedDict
├── knowledge/
│   ├── findings/         # Vulnerability reference docs (Code4rena/Immunefi format)
│   ├── triages/          # Human-triaged AuditAgent scan results (TP / FP decisions)
│   └── loader.py         # Parses knowledge files → few-shot examples for LLM
├── tools/
│   ├── slither_tool.py   # Slither wrapper (LangChain tool)
│   ├── abi_tool.py       # ABI decoder
│   └── storage_tool.py   # Storage layout reader
├── patterns/
│   ├── reentrancy.py
│   ├── access_control.py
│   ├── oracle_manipulation.py
│   ├── front_running.py
│   └── integer_overflow.py
├── prompts/
│   └── audit_system.txt  # Core system prompt
├── arena/
│   └── client.py         # AgentArena API integration
├── tests/
│   └── ...               # Unit + integration tests
├── .env.example
├── CLAUDE.md
└── README.md
```

---

## Knowledge Base

Specter's detection patterns and LLM calibration are grounded in real outputs from Nethermind's AuditAgent — not synthetic examples.

**Source:** [solidity-security-lab](https://github.com/ginrod/solidity-security-lab) — 5 AuditAgent scans run against purpose-built vulnerable contracts, manually triaged to label each finding as TRUE POSITIVE or FALSE POSITIVE with full reasoning.

| Scan | Contracts | Findings | Valid | False Positives |
|------|-----------|----------|-------|-----------------|
| #1 (2026-03-19) | ReentrancyVault, VulnerableBank | 6 | 5 | 1 — `.transfer()` misidentified as ERC20 |
| #2 (2026-03-20) | MockPool, VulnerableLending | 7 | 6 | 1 — numeric literal format flagged as risk |
| #3 (2026-03-22) | VulnerableDEX | 4 | 4 | 0 |
| #4 (2026-03-23) | VulnerableToken | 4 | 4 | 0 |
| #5 (2026-03-24) | MultiSigTimelock (CodeHawks) | 3 | 3 | 0 — but 2 findings underseveritied by 2+ levels |

**Total:** 24 findings across 5 scans · 22 valid · 2 false positives identified

**How it feeds the agent:**

1. `knowledge/loader.py` parses all findings + triage decisions into `KnowledgeEntry` structs (deterministic, no LLM)
2. `reasoner.py` injects the relevant `KnowledgeEntry` as few-shot context before each LLM call
3. The false positive examples train the reasoner to avoid the same mistakes AuditAgent makes (e.g., confusing `address.transfer()` with ERC20's `transfer()`)
4. The severity miscalibration data from scan #5 informs Specter's severity escalation logic

---

## Vulnerability Classes

| Class | Severity | Detection Method |
|-------|----------|-----------------|
| Reentrancy (CEI violation) | High/Critical | Control flow + state mutation order |
| Access Control | High | Role/modifier presence on state-changing functions |
| Oracle Price Manipulation | High | Single-source price feeds, no TWAP |
| Front-Running / MEV | Medium/High | Predictable tx ordering, missing slippage |
| Integer Overflow/Underflow | High | Unchecked blocks on arithmetic |

---

## Stack

- **LangGraph** — agent state machine orchestration
- **LangChain** — tool abstraction layer
- **Slither** — static analysis backend (optional)
- **Python 3.11+**

---

## Setup

```bash
git clone https://github.com/ginrod/specter
cd specter

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Add: OPENAI_API_KEY or ANTHROPIC_API_KEY, and ARENA_API_KEY
```

Run against a contract:

```bash
python agent.py --contract path/to/Contract.sol
```

---

## AgentArena Integration

Specter submits findings automatically via the AgentArena API:

```bash
python -m arena.client --task-id <TASK_ID>
```

Each finding maps to:
- `title` — short vulnerability description
- `severity` — Critical / High / Medium / Low / Informational
- `description` — technical explanation with code reference
- `impact` — what an attacker can do
- `recommendation` — specific code fix

---

## Design Principles

1. **Precision over recall** — a rejected finding damages ranking more than a missed one
2. **Evidence-first** — every finding must include the vulnerable code snippet and line reference
3. **No hallucination** — if the pattern isn't present, don't report it
4. **Human-readable output** — findings are written for auditors, not just machines
5. **Grounded in real triage** — detection patterns and false positive filters are calibrated against actual AuditAgent outputs, not abstract examples

---

## Related Work

- [solidity-security-lab](https://github.com/ginrod/solidity-security-lab) — vulnerable contracts, Foundry PoCs, and 5 AuditAgent scan triages that form Specter's knowledge base
- **Nethermind AuditAgent** — reference tool whose scan outputs were used to calibrate Specter's false positive filter and severity escalation logic

---

## License

MIT
