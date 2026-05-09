"""ASL recursive-descent parser.

Implements the EBNF grammar from ASL-SPEC-v1.0:

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
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union


# ---------------------------------------------------------------------------
# AST nodes
# ---------------------------------------------------------------------------

@dataclass
class Invariant:
    expression: str
    line: int


@dataclass
class Capability:
    permission: str
    resource: str
    line: int


@dataclass
class Deny:
    action: str
    target: str
    line: int


@dataclass
class Temporal:
    name: str
    params: str
    line: int


@dataclass
class ComposeStmt:
    kind: str  # "channel" | "trust" | "deny"
    value: str
    line: int


@dataclass
class Compose:
    target_agent: str
    statements: list[ComposeStmt]
    line: int


Statement = Union[Invariant, Capability, Deny, Temporal, Compose]


@dataclass
class AgentDecl:
    name: str
    statements: list[Statement] = field(default_factory=list)
    line: int = 0


@dataclass
class Spec:
    agents: list[AgentDecl] = field(default_factory=list)
    source: str = ""


# ---------------------------------------------------------------------------
# Token types
# ---------------------------------------------------------------------------

class TokenKind:
    KEYWORD = "KEYWORD"
    IDENT = "IDENT"
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    COLON = "COLON"
    COMMA = "COMMA"
    STRING = "STRING"
    OP = "OP"
    STAR = "STAR"
    DOT = "DOT"
    EOF = "EOF"
    REST = "REST"  # catch-all for expression text


KEYWORDS = {
    "agent", "invariant", "capability", "deny", "temporal", "compose",
    "with", "channel", "trust",
    "read", "write", "execute", "delete",
}


@dataclass
class Token:
    kind: str
    value: str
    line: int
    col: int


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

_TOKEN_SPEC = [
    ("COMMENT", r"//[^\n]*"),
    ("STRING", r'"[^"]*"'),
    ("OP", r"[><=!]+"),
    ("IDENT", r"[A-Za-z_][A-Za-z0-9_\-]*"),
    ("LBRACE", r"\{"),
    ("RBRACE", r"\}"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("COLON", r":"),
    ("COMMA", r","),
    ("STAR", r"\*"),
    ("DOT", r"\."),
    ("NUMBER", r"[0-9]+[smh]?"),
    ("NEWLINE", r"\n"),
    ("SKIP", r"[ \t\r]+"),
]

_TOKEN_RE = re.compile(
    "|".join(f"(?P<{name}>{pattern})" for name, pattern in _TOKEN_SPEC)
)


class ParseError(Exception):
    def __init__(self, msg: str, line: int = 0, col: int = 0):
        self.line = line
        self.col = col
        super().__init__(f"line {line}, col {col}: {msg}")


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    line_num = 1
    line_start = 0

    for m in _TOKEN_RE.finditer(source):
        kind = m.lastgroup
        value = m.group()
        col = m.start() - line_start + 1

        if kind == "NEWLINE":
            line_num += 1
            line_start = m.end()
            continue
        if kind in ("SKIP", "COMMENT"):
            continue
        if kind == "IDENT" and value in KEYWORDS:
            kind = "KEYWORD"
        if kind == "NUMBER":
            kind = "IDENT"  # treat numbers/durations as identifiers for simplicity

        tokens.append(Token(kind=kind, value=value, line=line_num, col=col))

    tokens.append(Token(kind=TokenKind.EOF, value="", line=line_num, col=0))
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class Parser:
    def __init__(self, tokens: list[Token], source: str = ""):
        self.tokens = tokens
        self.pos = 0
        self.source = source
        self.errors: list[str] = []

    def peek(self) -> Token:
        return self.tokens[self.pos]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return tok

    def expect(self, kind: str, value: str | None = None) -> Token:
        tok = self.peek()
        if tok.kind != kind or (value is not None and tok.value != value):
            expected = f"{kind}" + (f" '{value}'" if value else "")
            raise ParseError(
                f"expected {expected}, got {tok.kind} '{tok.value}'",
                tok.line, tok.col,
            )
        return self.advance()

    def at(self, kind: str, value: str | None = None) -> bool:
        tok = self.peek()
        if tok.kind != kind:
            return False
        if value is not None and tok.value != value:
            return False
        return True

    # --- Top-level ---

    def parse_spec(self) -> Spec:
        spec = Spec(source=self.source)
        while not self.at(TokenKind.EOF):
            spec.agents.append(self.parse_agent_decl())
        if not spec.agents:
            raise ParseError("empty specification — at least one 'agent' block required", 1, 1)
        return spec

    def parse_agent_decl(self) -> AgentDecl:
        tok = self.expect(TokenKind.KEYWORD, "agent")
        name_tok = self.expect(TokenKind.IDENT)
        self.expect(TokenKind.LBRACE)
        agent = AgentDecl(name=name_tok.value, line=tok.line)

        while not self.at(TokenKind.RBRACE) and not self.at(TokenKind.EOF):
            agent.statements.append(self.parse_statement())

        self.expect(TokenKind.RBRACE)
        return agent

    def parse_statement(self) -> Statement:
        tok = self.peek()
        if tok.value == "invariant":
            return self.parse_invariant()
        if tok.value == "capability":
            return self.parse_capability()
        if tok.value == "deny":
            return self.parse_deny()
        if tok.value == "temporal":
            return self.parse_temporal()
        if tok.value == "compose":
            return self.parse_compose()
        raise ParseError(
            f"unexpected keyword '{tok.value}', expected one of: "
            "invariant, capability, deny, temporal, compose",
            tok.line, tok.col,
        )

    # --- Statement parsers ---

    def parse_invariant(self) -> Invariant:
        tok = self.expect(TokenKind.KEYWORD, "invariant")
        self.expect(TokenKind.COLON)
        # Collect everything until the next statement keyword or closing brace
        expr_parts: list[str] = []
        while not self._at_statement_boundary():
            expr_parts.append(self.advance().value)
        expr = " ".join(expr_parts)
        if not expr:
            raise ParseError("empty invariant expression", tok.line, tok.col)
        return Invariant(expression=expr, line=tok.line)

    def parse_capability(self) -> Capability:
        tok = self.expect(TokenKind.KEYWORD, "capability")
        self.expect(TokenKind.COLON)
        perm_tok = self.expect(TokenKind.KEYWORD)
        if perm_tok.value not in ("read", "write", "execute", "delete"):
            raise ParseError(
                f"invalid permission '{perm_tok.value}', expected read/write/execute/delete",
                perm_tok.line, perm_tok.col,
            )
        self.expect(TokenKind.LPAREN)
        resource = self._parse_resource()
        self.expect(TokenKind.RPAREN)
        return Capability(permission=perm_tok.value, resource=resource, line=tok.line)

    def parse_deny(self) -> Deny:
        tok = self.expect(TokenKind.KEYWORD, "deny")
        self.expect(TokenKind.COLON)
        # action can be an IDENT or a keyword like 'write', 'delete', etc.
        action_tok = self.advance()
        if action_tok.kind not in (TokenKind.IDENT, TokenKind.KEYWORD):
            raise ParseError(
                f"expected action identifier, got '{action_tok.value}'",
                action_tok.line, action_tok.col,
            )
        self.expect(TokenKind.LPAREN)
        target = self._parse_resource()
        # Handle optional second param: deny: delegate(write, user.credentials)
        extra = ""
        if self.at(TokenKind.COMMA):
            self.advance()
            extra_parts: list[str] = []
            while not self.at(TokenKind.RPAREN) and not self.at(TokenKind.EOF):
                extra_parts.append(self.advance().value)
            extra = " ".join(extra_parts)
        self.expect(TokenKind.RPAREN)
        full_target = target + (f", {extra}" if extra else "")
        return Deny(action=action_tok.value, target=full_target, line=tok.line)

    def parse_temporal(self) -> Temporal:
        tok = self.expect(TokenKind.KEYWORD, "temporal")
        self.expect(TokenKind.COLON)
        name_tok = self.advance()
        if name_tok.kind not in (TokenKind.IDENT, TokenKind.KEYWORD):
            raise ParseError(
                f"expected constraint name, got '{name_tok.value}'",
                name_tok.line, name_tok.col,
            )
        self.expect(TokenKind.LPAREN)
        params = self._collect_until_rparen()
        self.expect(TokenKind.RPAREN)
        return Temporal(name=name_tok.value, params=params, line=tok.line)

    def parse_compose(self) -> Compose:
        tok = self.expect(TokenKind.KEYWORD, "compose")
        self.expect(TokenKind.COLON)
        target_tok = self.expect(TokenKind.IDENT)
        self.expect(TokenKind.KEYWORD, "with")
        self.expect(TokenKind.LBRACE)

        stmts: list[ComposeStmt] = []
        while not self.at(TokenKind.RBRACE) and not self.at(TokenKind.EOF):
            stmts.append(self._parse_compose_stmt())

        self.expect(TokenKind.RBRACE)
        return Compose(target_agent=target_tok.value, statements=stmts, line=tok.line)

    def _parse_compose_stmt(self) -> ComposeStmt:
        tok = self.peek()
        if tok.value in ("channel", "trust"):
            kind = tok.value
            self.advance()
            self.expect(TokenKind.COLON)
            # Collect value with optional parens
            parts: list[str] = []
            while not self._at_compose_boundary():
                parts.append(self.advance().value)
            return ComposeStmt(kind=kind, value=" ".join(parts), line=tok.line)
        if tok.value == "deny":
            self.advance()
            self.expect(TokenKind.COLON)
            action_tok = self.advance()
            self.expect(TokenKind.LPAREN)
            target = self._collect_until_rparen()
            self.expect(TokenKind.RPAREN)
            return ComposeStmt(
                kind="deny",
                value=f"{action_tok.value}({target})",
                line=tok.line,
            )
        raise ParseError(
            f"unexpected compose statement '{tok.value}', "
            "expected channel, trust, or deny",
            tok.line, tok.col,
        )

    # --- Helpers ---

    def _parse_resource(self) -> str:
        """Parse: resource = ('*' | IDENT) ('.' ('*' | IDENT))*"""
        parts: list[str] = []
        tok = self.advance()
        if tok.kind == TokenKind.STAR:
            parts.append("*")
        elif tok.kind in (TokenKind.IDENT, TokenKind.KEYWORD):
            parts.append(tok.value)
        else:
            raise ParseError(
                f"expected resource identifier or '*', got '{tok.value}'",
                tok.line, tok.col,
            )
        while self.at(TokenKind.DOT):
            self.advance()
            next_tok = self.advance()
            if next_tok.kind == TokenKind.STAR:
                parts.append("*")
            elif next_tok.kind in (TokenKind.IDENT, TokenKind.KEYWORD):
                parts.append(next_tok.value)
            else:
                raise ParseError(
                    f"expected identifier or '*' after '.', got '{next_tok.value}'",
                    next_tok.line, next_tok.col,
                )
        return ".".join(parts)

    def _collect_until_rparen(self) -> str:
        parts: list[str] = []
        depth = 1
        while depth > 0 and not self.at(TokenKind.EOF):
            if self.at(TokenKind.LPAREN):
                depth += 1
            elif self.at(TokenKind.RPAREN):
                depth -= 1
                if depth == 0:
                    break
            parts.append(self.advance().value)
        return " ".join(parts)

    def _at_statement_boundary(self) -> bool:
        tok = self.peek()
        if tok.kind == TokenKind.EOF:
            return True
        if tok.kind == TokenKind.RBRACE:
            return True
        if tok.kind == TokenKind.KEYWORD and tok.value in (
            "invariant", "capability", "deny", "temporal", "compose",
        ):
            return True
        return False

    def _at_compose_boundary(self) -> bool:
        tok = self.peek()
        if tok.kind == TokenKind.EOF:
            return True
        if tok.kind == TokenKind.RBRACE:
            return True
        if tok.kind == TokenKind.KEYWORD and tok.value in ("channel", "trust", "deny"):
            return True
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_file(path: Path) -> Spec:
    """Parse an .asl file and return the AST."""
    source = path.read_text(encoding="utf-8")
    tokens = tokenize(source)
    parser = Parser(tokens, source=str(path))
    return parser.parse_spec()


def parse_string(source: str, name: str = "<string>") -> Spec:
    """Parse an ASL string and return the AST."""
    tokens = tokenize(source)
    parser = Parser(tokens, source=name)
    return parser.parse_spec()
