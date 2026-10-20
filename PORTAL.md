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
live_readback_verified: TRUE (is_selector_allowed('0x1111...1111', '0xa9059cbb') returned False)
```
