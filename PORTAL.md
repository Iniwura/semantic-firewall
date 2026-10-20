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
contract_address: 0x34c53f01627eC63F0d99d01592104e2Eb3C128Bf
deployment_tx: 0x73bbb5e748af40cc2c0f4221b01010bfdd0c4e1f11aec792fb12fbcd74404c95
status: FINALIZED
runtime: py-genlayer:1.0.0
consensus_mechanism: gl.eq_principle.strict_eq
live_transactions:
  - register_agent: 0x647116dcc93898ceb59fc53b0e0bc1e6ee1b3d837b3b9aa9d2aaded82e3330b0 (ACCEPTED, MAJORITY_AGREE)
verified_state:
  agent_owner: 0xFBDfD2C59D146b30E38C19bD3F161098b57EbFBb
  charter_hash: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  status: 0 (ACTIVE)
  max_value_per_call: 1000000000000000000
  selector_0xa9059cbb: ALLOWED (True)
  selector_0xdeadbeef: REJECTED (False)
explorer_url: https://explorer-studio.genlayer.com/address/0x34c53f01627eC63F0d99d01592104e2Eb3C128Bf
```
