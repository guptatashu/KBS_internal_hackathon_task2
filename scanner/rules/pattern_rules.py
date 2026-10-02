import re

from .rule_kit import pattern_rule
from ..function_parser import analyze_access


def _in_fn(fn):
    return f" (in function {fn.name}())" if fn else ""


def _classify_tx_origin(*, ctx, line, fn, **_):
    l = ctx.masked_lines[line - 1] if 0 <= line - 1 < len(ctx.masked_lines) else ""
    if re.search(r"tx\s*\.\s*origin\s*[!=]=\s*msg\s*\.\s*sender|msg\s*\.\s*sender\s*[!=]=\s*tx\s*\.\s*origin", l):
        return {"severity": "low",
                "detail": f'compared with msg.sender, an "externally-owned accounts only" style check{_in_fn(fn)}'}
    if re.search(r"[!=]=", l) or re.search(r"\b(require|assert|if)\b", l):
        return {"severity": "high", "detail": f"used in a comparison/check, possibly for authorization{_in_fn(fn)}"}
    return {"severity": "medium", "detail": f"referenced outside an obvious comparison{_in_fn(fn)}"}


tx_origin = pattern_rule(
    id="tx-origin",
    title="Use of tx.origin",
    category="authorization",
    severity="medium",
    pattern=r"\btx\s*\.\s*origin\b",
    description=(
        "tx.origin is the externally-owned account that started the whole transaction, not the immediate caller. "
        "When it is used to decide who is authorized, a malicious contract that a user is tricked into calling "
        "can act with that user's authority (phishing-style attack)."
    ),
    why_only_signal=(
        "tx.origin is sometimes used harmlessly, for example `tx.origin == msg.sender` to require that the caller "
        "is a plain wallet, or for logging. The signal level reflects how it is used on that line; only a review "
        "of the surrounding logic can tell whether it guards anything important."
    ),
    classify=_classify_tx_origin,
)


def _classify_selfdestruct(*, fn, **_):
    if not fn:
        return {"severity": "high",
                "detail": "found outside a normal function body (e.g. inline assembly or unusual layout)"}
    access = analyze_access(fn)
    return {
        "severity": "high" if access["level"] in ("none-detected", "caller-scoped") else "medium",
        "detail": f"in function {fn.name}(): {access['detail']}",
        "access": access["level"],
    }


selfdestruct = pattern_rule(
    id="selfdestruct",
    title="selfdestruct call",
    category="destructive-capability",
    severity="high",
    pattern=r"\b(selfdestruct|suicide)\s*\(",
    description=(
        "selfdestruct ends a contract's execution permanently and sends its entire ETH balance to a chosen address. "
        "On current Ethereum rules (after EIP-6780) it only erases the contract's code when called in the same "
        "transaction that created it, but the balance transfer still happens."
    ),
    why_only_signal=(
        'It can be a deliberate, properly restricted "shut down and refund" feature, or only reachable by a trusted '
        "party. The level is lowered to medium when the enclosing function shows an access restriction; this scanner "
        "cannot confirm that the restriction is correct."
    ),
    classify=_classify_selfdestruct,
)


def _classify_delegatecall(*, ctx, fn, **_):
    proxy_note = ("; Etherscan marks this contract as a proxy, where delegatecall is expected "
                  "but the implementation target still matters") if ctx.meta.get("isProxy") else ""
    return {"severity": "high", "detail": f"delegatecall{_in_fn(fn)}{proxy_note}"}


def _is_function_declaration(m, ctx):
    """Python's `re` has no variable-width lookbehind, so we do the (?<!function\\s+) check by hand."""
    before = ctx.code[max(0, m.start() - 60):m.start()]
    return re.search(r"\bfunction\s+$", before) is not None


delegatecall = pattern_rule(
    id="delegatecall",
    title="delegatecall usage",
    category="code-execution",
    severity="high",
    pattern=r"\bdelegatecall\s*\(",
    skip=_is_function_declaration,
    description=(
        "delegatecall runs another contract's code using THIS contract's storage and balance. If the target address "
        "or calldata can be influenced by someone untrusted, that code can overwrite storage or move funds."
    ),
    why_only_signal=(
        "It is the core mechanism of upgradeable proxies and libraries, so it is expected in those designs. "
        "What matters is who controls the target and calldata, which a text pattern cannot determine."
    ),
    classify=_classify_delegatecall,
)


def _classify_low_level_call(*, window, fn, **_):
    if re.match(r"\.call\s*(?:\{[^}]*\bvalue\b|\.value)", window):
        return {"severity": "medium", "detail": f"forwards ETH via a low-level call{_in_fn(fn)}"}
    return {"severity": "low",
            "detail": f"low-level call without an ETH value; passes arbitrary calldata{_in_fn(fn)}"}


low_level_call = pattern_rule(
    id="low-level-call",
    title="Low-level external call (.call)",
    category="external-interaction",
    severity="low",
    pattern=r"\.call\s*(?:\{|\(|\.value\s*\()",
    description=(
        "A low-level .call hands control to another address and does not automatically revert on failure. "
        "When it forwards ETH, the receiver can run code before the caller's bookkeeping finishes (reentrancy), "
        "and an unchecked return value can hide a failed payment."
    ),
    why_only_signal=(
        "Low-level calls are the recommended way to send ETH in modern Solidity and are used correctly in countless "
        "contracts. This scanner does not check whether state is updated before the call, whether the result is "
        "checked, or whether a reentrancy guard exists."
    ),
    classify=_classify_low_level_call,
)

PATTERN_RULES = [tx_origin, selfdestruct, delegatecall, low_level_call]
