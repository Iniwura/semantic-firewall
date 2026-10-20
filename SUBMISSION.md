# SemanticFirewall — Submission Packet

## One-Line Pitch
SemanticFirewall is an on-chain prompt injection and execution firewall that validates natural-language agent triggers against intended calldata using GenLayer consensus before issuing single-use execution tickets.

## Release Facts

```text
primitive_name: SemanticFirewall
category: Standalone Intelligent Contract
language: Python (GenVM)
source_sha256: 6f0c5fa1cdfdab73c356e99822dadf4dc2a1cd970cd69cfec4dc7e251e17c93a
test_count: 12
test_result: PASS (12 passed in 0.17s)
target_network: GenLayer Studio Dev (Chain ID: 61997)
consensus_model: Strict Equivalence (gl.eq_principle.strict_eq)
security_invariants:
  - Atomic single-use execution ticket consumption (zero replay tolerance)
  - Epoch-bounded ticket TTL (TICKET_TTL_EPOCHS = 32)
  - Circuit-breaker quarantine lock (MAX_QUARANTINE_TOLERANCE = 3)
  - Immutable selector whitelisting and transaction value ceilings
  - Fail-closed denial on validator disagreement
ready_for_submission: YES
```

## Reviewer Path
1. Run `pytest tests/ -v` to verify all 12 test cases covering prompt injections, single-use ticket consumption, selector validation, and circuit-breaker triggers.
2. Inspect `contracts/semantic_firewall.py` to review the prompt inspection schema and deterministic ticket issuance.
3. Review `ARCHITECTURE.md` for the sequence diagrams and security invariants.
