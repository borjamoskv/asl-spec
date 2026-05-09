"""ASL semantic checker — threat coverage, cap/deny consistency, composition refs."""

from __future__ import annotations
from dataclasses import dataclass, field
from .parser import AgentDecl, Capability, Compose, Deny, Invariant, Spec, Temporal

THREAT_VECTORS = {
    "V1": "Prompt Injection", "V2": "Tool Misuse", "V3": "Memory Poisoning",
    "V4": "Multi-Agent Collusion", "V5": "Privilege Escalation",
    "V6": "Data Exfiltration", "V7": "Resource Exhaustion",
    "V8": "Identity Spoofing", "V9": "Cascading Failures",
    "V10": "Specification Drift",
}

@dataclass
class Diagnostic:
    level: str; message: str; agent: str = ""; line: int = 0
    def __str__(self) -> str:
        p = {"error": "✗", "warning": "⚠", "info": "·"}.get(self.level, "?")
        loc = f":{self.line}" if self.line else ""
        a = f" [{self.agent}]" if self.agent else ""
        return f"  {p} {self.message}{a}{loc}"

@dataclass
class CheckResult:
    passed: bool = True
    diagnostics: list[Diagnostic] = field(default_factory=list)
    agent_count: int = 0; statement_count: int = 0
    threat_coverage: dict[str, bool] = field(default_factory=dict)

    def error(self, msg: str, agent: str = "", line: int = 0) -> None:
        self.passed = False
        self.diagnostics.append(Diagnostic("error", msg, agent, line))
    def warn(self, msg: str, agent: str = "", line: int = 0) -> None:
        self.diagnostics.append(Diagnostic("warning", msg, agent, line))
    def info(self, msg: str, agent: str = "", line: int = 0) -> None:
        self.diagnostics.append(Diagnostic("info", msg, agent, line))
    @property
    def coverage_pct(self) -> int:
        if not self.threat_coverage: return 0
        return int(sum(1 for v in self.threat_coverage.values() if v) / len(self.threat_coverage) * 100)

def check(spec: Spec) -> CheckResult:
    r = CheckResult(); r.threat_coverage = {k: False for k in THREAT_VECTORS}
    names: set[str] = set(); total = 0
    for a in spec.agents:
        if a.name in names: r.error(f"duplicate agent '{a.name}'", a.name, a.line)
        names.add(a.name)
        if not a.statements: r.error("agent has no statements", a.name, a.line)
        total += len(a.statements); _check_agent(a, r)
    r.agent_count = len(spec.agents); r.statement_count = total
    for a in spec.agents:
        for s in a.statements:
            if isinstance(s, Compose) and s.target_agent not in names:
                r.warn(f"compose refs undeclared agent '{s.target_agent}'", a.name, s.line)
    uc = [f"{k}({v})" for k, v in THREAT_VECTORS.items() if not r.threat_coverage.get(k)]
    if uc: r.info(f"uncovered vectors: {', '.join(uc)}")
    return r

def _check_agent(a: AgentDecl, r: CheckResult) -> None:
    caps: list[Capability] = []; dns: list[Deny] = []; seen: set[str] = set()
    for s in a.statements:
        fp = _fp(s)
        if fp in seen: r.warn(f"duplicate: {fp}", a.name, s.line)
        seen.add(fp)
        if isinstance(s, Invariant): _inv_cov(s, r)
        elif isinstance(s, Capability): caps.append(s); r.threat_coverage["V2"] = True
        elif isinstance(s, Deny): dns.append(s); _deny_cov(s, r)
        elif isinstance(s, Temporal): _temp_cov(s, r)
        elif isinstance(s, Compose):
            r.threat_coverage["V4"] = True
            for cs in s.statements:
                if cs.kind == "channel" and "encrypted" in cs.value.lower(): r.threat_coverage["V8"] = True
                if cs.kind == "trust": r.threat_coverage["V8"] = True
                if cs.kind == "deny": r.threat_coverage["V5"] = True
    for c in caps:
        for d in dns:
            if d.action == c.permission and _overlap(d.target, c.resource):
                r.warn(f"deny '{d.action}({d.target})' shadows capability '{c.permission}({c.resource})'", a.name, d.line)

def _inv_cov(i: Invariant, r: CheckResult) -> None:
    e = i.expression.lower()
    if "memory" in e or "integrity" in e: r.threat_coverage["V3"] = True
    if "eval" in e or "input" in e: r.threat_coverage["V1"] = True
    if "verified" in e or "children" in e: r.threat_coverage["V4"] = True

def _deny_cov(d: Deny, r: CheckResult) -> None:
    a, t = d.action.lower(), d.target.lower()
    if a == "eval" or "user_input" in t: r.threat_coverage["V1"] = True
    if a in ("shell_exec", "execute"): r.threat_coverage["V5"] = True
    if "network" in a or "external" in t: r.threat_coverage["V6"] = True
    if "delegate" in a: r.threat_coverage["V5"] = True
    r.threat_coverage["V5"] = True

def _temp_cov(t: Temporal, r: CheckResult) -> None:
    n = t.name.lower()
    if any(k in n for k in ("max", "rate", "limit", "cooldown")): r.threat_coverage["V7"] = True
    if "timeout" in n: r.threat_coverage["V9"] = True
    if "heartbeat" in n: r.threat_coverage["V9"] = True

def _overlap(dt: str, cr: str) -> bool:
    if dt == "*": return True
    dp, cp = dt.split("."), cr.split(".")
    for d, c in zip(dp, cp):
        if d == "*" or c == "*": return True
        if d != c: return False
    return len(dp) == len(cp)

def _fp(s: object) -> str:
    if isinstance(s, Invariant): return f"invariant:{s.expression}"
    if isinstance(s, Capability): return f"cap:{s.permission}({s.resource})"
    if isinstance(s, Deny): return f"deny:{s.action}({s.target})"
    if isinstance(s, Temporal): return f"temp:{s.name}({s.params})"
    if isinstance(s, Compose): return f"compose:{s.target_agent}"
    return str(s)
