"""
Helpers for defining rules. A rule has:

  id, title, category      identify it
  severity                 baseline signal level: 'info' | 'low' | 'medium' | 'high'
  description              what the pattern is / why it is worth a look
  why_only_signal          honest caveat: legitimate uses / what this cannot tell
  check(ctx) -> [ {line, severity, detail, function, access}, ... ]   (one file at a time)

To add a rule: build one with pattern_rule / function_rule (or write your own check())
and append it to the lists in pattern_rules.py / function_rules.py.
"""
import re
from dataclasses import dataclass
from typing import Any, Callable

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def max_severity(a, b):
    return b if SEVERITY_ORDER[b] > SEVERITY_ORDER[a] else a


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str
    description: str
    why_only_signal: str
    check: Callable[[Any], list]


def pattern_rule(*, id, title, category, severity, pattern, description, why_only_signal,
                 classify=None, skip=None):
    """Rule that matches a regex against the file's code (comments removed, strings masked).

    classify(match=, ctx=, line=, fn=, window=) -> dict with optional severity/detail/access
    skip(match, ctx) -> True to ignore a match
    """
    regex = re.compile(pattern, re.ASCII) if isinstance(pattern, str) else pattern

    def check(ctx):
        hits = []
        seen_lines = set()
        for m in regex.finditer(ctx.code):
            if m.end() == m.start():
                continue
            if skip and skip(m, ctx):
                continue
            line = ctx.line_of(m.start())
            if line in seen_lines:          # one hit per line per rule
                continue
            seen_lines.add(line)
            fn = ctx.function_at(line)
            cls = {}
            if classify:
                cls = classify(match=m, ctx=ctx, line=line, fn=fn,
                               window=ctx.code[m.start():m.start() + 200]) or {}
            hits.append({
                "line": line,
                "severity": cls.get("severity") or severity,
                "detail": cls.get("detail"),
                "function": fn.name if fn else None,
                "access": cls.get("access"),
            })
        return hits

    return Rule(id, title, category, severity, description, why_only_signal, check)


def function_rule(*, id, title, category, severity, description, why_only_signal, select):
    """Rule that inspects each function that has a body.
    select(fn, ctx) returns None (no signal) or a dict with optional severity/detail/access."""

    def check(ctx):
        hits = []
        for fn in ctx.functions:
            if not fn.has_body:     # interface / abstract declarations carry no behavior
                continue
            r = select(fn, ctx)
            if not r:
                continue
            hits.append({
                "line": fn.line,
                "severity": r.get("severity") or severity,
                "detail": r.get("detail"),
                "function": fn.name,
                "access": r.get("access"),
            })
        return hits

    return Rule(id, title, category, severity, description, why_only_signal, check)
