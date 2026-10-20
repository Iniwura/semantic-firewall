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
chain_id: 61997
contract_name: SemanticFirewall
status: FINALIZED
source_sha256: 6f0c5fa1cdfdab73c356e99822dadf4dc2a1cd970cd69cfec4dc7e251e17c93a
runtime: py-genlayer:1.0.0
consensus_mechanism: gl.eq_principle.strict_eq
```
