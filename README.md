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
