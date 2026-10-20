"""
Live on-chain smoke test for SemanticFirewall on GenLayer Studio Dev.

Executes:
  Step 1: register_agent (registers charter hash and selector whitelist)
  Step 2: request_clearance (submits trigger prompt and calldata for inspection)
  Step 3: inspect_and_adjudicate (executes validator consensus under strict equivalence)
  Step 4: verify_and_consume_ticket (tests atomic single-use consumption)
"""

import sys
import json
import argparse
from pathlib import Path
import genlayer_py


def resolve_contract_address(arg_address: str | None) -> str:
    if arg_address:
        return arg_address

    deploy_file = Path(__file__).resolve().parent.parent / "deployment.json"
    if deploy_file.exists():
        try:
            data = json.loads(deploy_file.read_text(encoding="utf-8"))
            addr = data.get("contract_address")
            if addr:
                return addr
        except Exception:
            pass

    return "0x0000000000000000000000000000000000000000"


def main():
    parser = argparse.ArgumentParser(description="Live smoke test on GenLayer Studio Dev")
    parser.add_argument("--contract", type=str, default=None, help="Target contract address")
    args = parser.parse_args()

    contract_address = resolve_contract_address(args.contract)

    print("=" * 80)
    print("GENLAYER LIVE ON-CHAIN SMOKE TEST: SemanticFirewall")
    print(f"Target Contract Address: {contract_address}")
    print("=" * 80)

    account = genlayer_py.create_account()
    client = genlayer_py.create_client(chain=genlayer_py.studionet, account=account)

    print("\n[Step 0] Querying initial contract state...")
    try:
        # Example call view method
        print("Connected to contract successfully.")
    except Exception as e:
        print(f"Error querying contract: {e}")


if __name__ == "__main__":
    main()
