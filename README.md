# SemanticFirewall — On-Chain Prompt Injection & Execution Firewall

An Intelligent Contract primitive for GenLayer providing on-chain prompt injection detection and single-use execution gating for autonomous AI agents.

---

## 1. Overview & Motivation

When autonomous AI agents manage high-value smart contracts (treasury management, automated trading, governance voting), they become primary targets for **indirect prompt injection** (adversarial instructions hidden in user input or external web data).

Because traditional smart contracts only check cryptographic ECDSA signatures, an agent tricked by a prompt injection will successfully execute harmful transactions.

`SemanticFirewall` introduces an on-chain semantic firewall:
1. Agents register an immutable **Security Charter** with allowed function selectors and transaction value ceilings.
2. When executing a transaction, the agent submits the natural-language trigger prompt alongside the proposed calldata.
3. GenLayer validators inspect the prompt for jailbreaks and verify that the proposed calldata accurately reflects authorized intent using `gl.eq_principle.strict_eq`.
4. If clean, an **Epoch-Bounded Single-Use Execution Ticket** is issued.
5. Downstream contracts atomically verify and consume the ticket, preventing replay attacks.
6. Repeated prompt injections trigger an automated circuit breaker, locking the agent until owner intervention.

---

## 2. Directory Structure

```
semantic-firewall/
├── contracts/
│   └── semantic_firewall.py     # GenLayer Intelligent Contract
├── tests/
│   ├── conftest.py              # In-memory direct GenVM simulation harness
│   └── test_semantic_firewall.py # 12 unit & adversarial tests
├── scripts/
│   ├── deploy.py                # Studio Dev deployment script
│   └── live_smoke_test.py       # On-chain smoke test script
├── ARCHITECTURE.md              # Security model & sequence diagrams
├── PORTAL.md                    # Reviewer quick path & deployment evidence
├── SUBMISSION.md                # Ecosystem grant submission facts
├── requirements.txt
└── pytest.ini
```

---

## 3. Local Verification

Run the test suite:

```bash
pytest tests/ -v
```
