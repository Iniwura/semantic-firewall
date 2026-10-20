# SemanticFirewall — Submission Packet

## One-Line Pitch
SemanticFirewall is an on-chain prompt injection and execution firewall that validates natural-language agent triggers against intended calldata using GenLayer consensus before issuing single-use execution tickets.

## Release Facts

```text
primitive_name: SemanticFirewall
category: Standalone Intelligent Contract
language: Python (GenVM)
source_sha256: 1540415c8e1d6efbe5d59284a9da1adbbf480b9da0fc43ce2894e04babe1b1cb
contract_address: 0x34c53f01627eC63F0d99d01592104e2Eb3C128Bf
deployment_tx: 0x73bbb5e748af40cc2c0f4221b01010bfdd0c4e1f11aec792fb12fbcd74404c95
test_count: 12
test_result: PASS (12 passed in 0.09s)
target_network: GenLayer Studio Dev (Chain ID: 61999)
consensus_model: Strict Equivalence (gl.eq_principle.strict_eq)
live_verified_tx: 0x647116dcc93898ceb59fc53b0e0bc1e6ee1b3d837b3b9aa9d2aaded82e3330b0 (ACCEPTED, MAJORITY_AGREE)
explorer_url: https://explorer-studio.genlayer.com/address/0x34c53f01627eC63F0d99d01592104e2Eb3C128Bf
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
