"""Tests for ASL parser and checker."""
import pytest
from pathlib import Path
from asl_check.parser import parse_file, parse_string, ParseError
from asl_check.checker import check

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

class TestParserExamples:
    def test_payment_bot(self):
        spec = parse_file(EXAMPLES_DIR / "payment-bot.asl")
        assert len(spec.agents) == 1
        a = spec.agents[0]
        assert a.name == "PaymentBot"
        assert len(a.statements) == 11  # 3 inv + 3 cap + 3 deny + 2 temporal

    def test_data_pipeline(self):
        spec = parse_file(EXAMPLES_DIR / "data-pipeline.asl")
        assert len(spec.agents) == 1
        assert spec.agents[0].name == "ETLWorker"

    def test_multi_agent(self):
        spec = parse_file(EXAMPLES_DIR / "multi-agent.asl")
        assert len(spec.agents) == 1
        assert spec.agents[0].name == "Orchestrator"

class TestParserEdgeCases:
    def test_empty_fails(self):
        with pytest.raises(ParseError):
            parse_string("")

    def test_minimal_agent(self):
        spec = parse_string('agent X { invariant: x > 0 }')
        assert spec.agents[0].name == "X"

    def test_comments_ignored(self):
        src = '// comment\nagent Y { capability: read(db) }'
        spec = parse_string(src)
        assert len(spec.agents) == 1

class TestChecker:
    def test_all_examples_pass(self):
        for f in EXAMPLES_DIR.glob("*.asl"):
            spec = parse_file(f)
            result = check(spec)
            assert result.passed, f"{f.name} failed: {[str(d) for d in result.diagnostics if d.level == 'error']}"

    def test_coverage_payment_bot(self):
        spec = parse_file(EXAMPLES_DIR / "payment-bot.asl")
        r = check(spec)
        assert r.threat_coverage["V2"]  # capabilities → Tool Misuse
        assert r.threat_coverage["V5"]  # deny → Privilege Escalation
        assert r.threat_coverage["V7"]  # temporal → Resource Exhaustion

    def test_coverage_multi_agent(self):
        spec = parse_file(EXAMPLES_DIR / "multi-agent.asl")
        r = check(spec)
        assert r.threat_coverage["V4"]  # compose → Multi-Agent Collusion
        assert r.threat_coverage["V8"]  # encrypted channel → Identity Spoofing

    def test_empty_agent_fails(self):
        spec = parse_string("agent Empty { }")
        # parser succeeds but checker should error
        r = check(spec)
        assert not r.passed
