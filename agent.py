#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def main():
    parser = argparse.ArgumentParser(
        prog="specter",
        description="Solidity smart contract vulnerability audit agent",
    )
    parser.add_argument(
        "--contract",
        required=True,
        metavar="PATH",
        help="Path to the Solidity contract to audit",
    )
    parser.add_argument(
        "--output",
        metavar="DIR",
        default="reports",
        help="Output directory for the report (default: reports/)",
    )
    args = parser.parse_args()

    contract_path = Path(args.contract).resolve()
    if not contract_path.exists():
        print(f"Error: contract not found: {contract_path}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{contract_path.stem}_report.md"

    from agent.graph import specter

    initial_state = {
        "contract_path": str(contract_path),
        "contract_code": "",
        "functions": [],
        "candidates": [],
        "findings": [],
        "false_positives": [],
        "messages": [],
        "report_path": str(report_path),
    }

    print(f"[specter] auditing {contract_path.name} ...")
    specter.invoke(initial_state)
    print(f"[specter] report saved to {report_path}")


if __name__ == "__main__":
    main()
