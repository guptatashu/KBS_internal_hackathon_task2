"""
Rule registry. To add a rule: define it (see rule_kit.py) and add it to PATTERN_RULES or
FUNCTION_RULES. Order here is only the tie-breaker when findings have equal severity.
"""
from .pattern_rules import PATTERN_RULES
from .function_rules import FUNCTION_RULES

RULES = tuple(PATTERN_RULES + FUNCTION_RULES)
