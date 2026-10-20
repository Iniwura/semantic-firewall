# SemanticFirewall Portal Documentation

## Reviewer Quick Path

1. **Architecture & Security Model:** Read [ARCHITECTURE.md](ARCHITECTURE.md) for full invariant proofs and sequence flows.
2. **Contract Source:** Inspect [contracts/semantic_firewall.py](contracts/semantic_firewall.py).
3. **Run Test Suite:**
   ```bash
   pytest tests/ -v
   ```
   *Expected Result: 12 passed in ~0.15s covering selector whitelisting, prompt injection quarantine, circuit-breaker locking, single-use ticket consumption, replay protection, and fail-closed consensus.*

---

## Deployment & Verification Details

```text
network: GenLayer Studio Dev
chain_id: 61999
contract_name: SemanticFirewall
contract_address: 0xc8739f5263eD954ca38F41677ecAabe5383595A6
deployment_tx: 0xa9cc6ea9406ff9ee1b81b8234cf4464cc2fedf2ae24e3b805e843ef49d3267db
status: FINALIZED
source_sha256: 1540415c8e1d6efbe5d59284a9da1adbbf480b9da0fc43ce2894e04babe1b1cb
runtime: py-genlayer:1.0.0
consensus_mechanism: gl.eq_principle.strict_eq
live_transactions:
  - register_agent: 0x80f7beed672d23a5755afb890fe64cf6496fae4ae9d37b00707c6069e6a47bc5 (ACCEPTED, MAJORITY_AGREE)
  - request_clearance: 0x79fa0408d7eea1d544c73c671e282a0988df6504779b05995c4e358f882d8e4d (ACCEPTED, MAJORITY_AGREE)
explorer_url: https://explorer-studio.genlayer.com/address/0xc8739f5263eD954ca38F41677ecAabe5383595A6
```
