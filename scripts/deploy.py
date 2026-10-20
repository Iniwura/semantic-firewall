"""
Automated deployment script for SemanticFirewall on GenLayer Studio Dev.
"""

from pathlib import Path
import json
import genlayer_py


def main():
    print("=" * 80)
    print("DEPLOYING INTELLIGENT CONTRACT: SemanticFirewall")
    print("Target Network: GenLayer Studio Dev (Chain ID: 61997 / 61999)")
    print("=" * 80)

    account = genlayer_py.create_account()
    client = genlayer_py.create_client(chain=genlayer_py.studionet, account=account)

    contract_path = Path(__file__).resolve().parent.parent / "contracts" / "semantic_firewall.py"
    code = contract_path.read_text(encoding="utf-8")

    print("Deploying contract to GenLayer Studio Dev...")
    tx_hash = client.deploy_contract(code=code, account=account)
    print(f"Deployment transaction broadcast: {tx_hash}")

    receipt = client.wait_for_transaction_receipt(tx_hash)
    contract_address = receipt.get("to_address") or receipt.get("data", {}).get("contract_address")
    status = receipt.get("status_name")

    deployment_record = {
        "network": "GenLayer Studio Dev",
        "chain_id": 61997,
        "contract_address": contract_address,
        "transaction_hash": tx_hash,
        "status": status,
        "result": receipt.get("result_name"),
        "validators_agreed": len(receipt.get("consensus_data", {}).get("votes", {})),
    }

    record_path = Path(__file__).resolve().parent.parent / "deployment.json"
    record_path.write_text(json.dumps(deployment_record, indent=2), encoding="utf-8")

    print("\n--- DEPLOYMENT SUCCESSFUL ---")
    print(f"Contract Address: {contract_address}")
    print(f"Transaction Hash: {tx_hash}")
    print(f"Receipt Status:   {status}")
    print(f"Deployment Record saved to: {record_path}")


if __name__ == "__main__":
    main()
