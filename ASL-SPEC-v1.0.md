# Agent Specification Language (ASL) — v1.0

> **Status:** Draft Specification
> **License:** MIT
> **Maintainer:** [agents.archi](https://agents.archi)
> **Date:** 2026-05-10

---

## 1. Abstract

The Agent Specification Language (ASL) is a declarative language for formally specifying the behavioral boundaries, capabilities, and invariants of autonomous AI agents. ASL specifications compile to Z3 SMT-LIB2 assertions, enabling mathematical proof that an agent's behavior satisfies its constraints under all possible execution traces.

## 2. Motivation

Autonomous AI agents are being deployed in production with:
- Access to financial APIs, databases, and shell execution
- Capability to make decisions without human supervision
- Multi-agent communication channels with no formal trust model

No formal specification language exists for defining **what an agent is allowed to do** and **proving it cannot exceed those bounds**.

ASL fills this gap.

## 3. Core Concepts

### 3.1 Agent Declaration

Every ASL specification begins with an `agent` declaration:

```asl
agent <AgentName> {
  <body>
}
```

### 3.2 Invariants

Invariants are properties that must hold at all times during agent execution:

```asl
agent PaymentBot {
  invariant: never_transfer > limit
  invariant: balance >= 0
  invariant: transaction_count <= max_daily
}
```

Invariants compile to universal quantifiers in Z3:
```smt2
(assert (forall ((t Transaction))
  (=> (is-valid t) (<= (transfer-amount t) limit))))
```

### 3.3 Capabilities

Capabilities define what resources an agent can access:

```asl
agent DataAnalyst {
  capability: read(database.analytics)
  capability: read(api.weather)
  capability: write(output.report)
}
```

Capability grammar:
```
capability: <permission>(<resource>[.<sub>])
permission := read | write | execute | delete
resource   := <identifier>[.<identifier>]*
```

### 3.4 Deny Rules

Deny rules explicitly prohibit dangerous operations:

```asl
agent CustomerBot {
  deny: shell_exec(*)
  deny: write(database.*)
  deny: network(*.internal)
  deny: read(secrets.*)
}
```

Deny rules take precedence over capabilities (deny-first semantics).

### 3.5 Composition Rules

When agents interact in multi-agent systems, composition rules define trust boundaries:

```asl
agent Orchestrator {
  compose: PaymentBot with {
    channel: encrypted
    trust: verify_output
    deny: delegate(shell_exec)
  }
}
```

### 3.6 Temporal Constraints

Rate limits and temporal bounds:

```asl
agent TradingBot {
  temporal: max_transactions(100, per: "1h")
  temporal: cooldown(30s, after: error)
  temporal: timeout(5s, per: api_call)
}
```

## 4. Threat Model Mapping

ASL specifications map to the [agents.archi 10-Vector Threat Taxonomy](https://agents.archi/#threat-vectors):

| Vector | ASL Construct | Z3 Encoding |
|---|---|---|
| V1: Prompt Injection | `deny: eval(user_input)` | Input sanitization assertions |
| V2: Tool Misuse | `capability` declarations | Resource access constraints |
| V3: Memory Poisoning | `invariant: memory_integrity` | State transition proofs |
| V4: Multi-Agent Collusion | `compose` rules | Cross-agent channel constraints |
| V5: Privilege Escalation | `deny` + capability scope | Least-privilege verification |
| V6: Data Exfiltration | `deny: network(*.external)` | Network boundary proofs |
| V7: Resource Exhaustion | `temporal` constraints | Bounded execution proofs |
| V8: Identity Spoofing | `compose: trust` | Authentication assertions |
| V9: Cascading Failures | `temporal: timeout` | Fault isolation proofs |
| V10: Specification Drift | Version pinning | Delta verification |

## 5. Verification Pipeline

```
┌────────────┐     ┌──────────────┐     ┌───────────┐     ┌────────────┐
│ .asl file  │────▶│ ASL Compiler │────▶│ Z3 Solver │────▶│ Scorecard  │
│            │     │ (asl-to-smt) │     │ (SAT/UNSAT│     │ Certificate│
└────────────┘     └──────────────┘     └───────────┘     └────────────┘
```

### 5.1 Output

- **SAT (satisfiable):** A counterexample exists — the agent CAN violate its specification.
- **UNSAT (unsatisfiable):** No counterexample exists — the specification holds.
- **UNKNOWN:** Solver timeout — specification may be too complex.

### 5.2 Scorecard

Verification produces an `agents.archi Security Scorecard`:
- Threat Coverage: % of 10 vectors addressed
- Formal Proofs: N proofs passed / N total
- Composition Safety: % of multi-agent interactions verified
- Certificate Hash: SHA-256 of the proof artifacts

## 6. Grammar (EBNF)

```ebnf
spec          = agent_decl+ ;
agent_decl    = 'agent' IDENT '{' statement* '}' ;
statement     = invariant | capability | deny | temporal | compose ;
invariant     = 'invariant:' expression ;
capability    = 'capability:' permission '(' resource ')' ;
deny          = 'deny:' action '(' target ')' ;
temporal      = 'temporal:' constraint ;
compose       = 'compose:' IDENT 'with' '{' compose_stmt* '}' ;
permission    = 'read' | 'write' | 'execute' | 'delete' ;
resource      = IDENT ('.' IDENT)* | '*' ;
action        = IDENT ;
target        = resource ;
constraint    = IDENT '(' params ')' ;
compose_stmt  = channel | trust | deny ;
channel       = 'channel:' IDENT ('(' params ')')? ;
trust         = 'trust:' IDENT ('(' params ')')? ;
```

## 7. Roadmap

- [x] v1.0 — Core language specification
- [ ] v1.1 — Runtime monitoring integration
- [ ] v1.2 — LangChain/CrewAI SDK bindings
- [ ] v2.0 — Probabilistic verification (Bayesian invariants)

## 8. License

MIT License. See [LICENSE](./LICENSE).

---

*agents.archi — The Architecture of Agent Security*
*"Trust is computed, not assumed."*
