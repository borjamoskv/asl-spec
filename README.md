# Agent Specification Language (ASL)

> **The open standard for formally verifying autonomous agent behavior.**

[![agents.archi Verified](https://agents.archi/api/badge?hash=asl-spec&coverage=100)](https://agents.archi)

## What is ASL?

ASL is a declarative language for specifying behavioral boundaries, capabilities, and invariants of autonomous AI agents. ASL specifications compile to **Z3 SMT-LIB2 assertions**, enabling mathematical proof that an agent cannot exceed its defined constraints.

```asl
agent PaymentBot {
  invariant: never_transfer > limit
  invariant: balance >= 0

  capability: read(balance)
  capability: write(transactions)

  deny: shell_exec(*)
  deny: write(user.credentials)

  temporal: max_transactions(50, per: "1h")
}
```

## Quick Start

```bash
pip install .
asl-check examples/
```

Output:

```
asl-check 0.1.0 — scanning 3 file(s)

────────────────────────────────────────────────────────────
  PASS  examples/payment-bot.asl
  agents: 1  statements: 11  threat coverage: 40%

────────────────────────────────────────────────────────────
  PASS  examples/data-pipeline.asl
  agents: 1  statements: 9  threat coverage: 50%

────────────────────────────────────────────────────────────
  PASS  examples/multi-agent.asl
  agents: 1  statements: 4  threat coverage: 40%

────────────────────────────────────────────────────────────
✓ all 3 specification(s) valid
```

Or check a single file:

```bash
asl-check my-agent.asl
```

Or without installing:

```bash
python -m asl_check ./
```

## What the Compiler Does

1. **Parse** — Recursive-descent parser implementing the full [EBNF grammar](./ASL-SPEC-v1.0.md#6-grammar-ebnf). Tokenizer with line/col tracking.
2. **Check** — 5-pass semantic validation:
   - Structural correctness (empty agents, duplicate declarations)
   - Capability/Deny consistency (shadow detection)
   - Threat coverage mapping (10-vector taxonomy)
   - Composition reference validation
   - Duplicate statement detection
3. **Report** — PASS/FAIL per file, threat coverage %, actionable diagnostics.

Zero dependencies. Python ≥3.10.

## Quick Links

- **[Full Specification (v1.0)](./ASL-SPEC-v1.0.md)**
- **[Example: Financial Agent](./examples/payment-bot.asl)**
- **[Example: Data Pipeline](./examples/data-pipeline.asl)**
- **[Example: Multi-Agent System](./examples/multi-agent.asl)**
- **[agents.archi — The Architecture of Agent Security](https://agents.archi)**

## Threat Model Coverage

ASL maps to the [agents.archi 10-Vector Threat Taxonomy](https://agents.archi/#threat-vectors):

| Vector | ASL Construct |
|---|---|
| Prompt Injection | `deny: eval(user_input)` |
| Tool Misuse | `capability` declarations |
| Memory Poisoning | `invariant: memory_integrity` |
| Multi-Agent Collusion | `compose` rules |
| Privilege Escalation | `deny` + capability scope |
| Data Exfiltration | `deny: network(*.external)` |
| Resource Exhaustion | `temporal` constraints |
| Identity Spoofing | `compose: trust` |
| Cascading Failures | `temporal: timeout` |
| Specification Drift | Version pinning |

## Contributing

ASL is an open standard. Contributions welcome via Issues and Pull Requests.

## License

MIT — See [LICENSE](./LICENSE)

---

*agents.archi — "Trust is computed, not assumed."*
