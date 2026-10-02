import re

from .rule_kit import function_rule
from ..function_parser import analyze_access, severity_for_access, sends_eth


def _is_state_changing(fn):
    return fn.mutability not in ("view", "pure")


# ---- owner / admin controlled ---------------------------------------------------
def _select_owner_controlled(fn, ctx):
    if not fn.is_callable:
        return None
    access = analyze_access(fn)
    if access["level"] != "modifier":
        return None
    return {"severity": "low", "detail": f"{fn.name}(): {access['detail']}", "access": access["level"]}


owner_controlled = function_rule(
    id="owner-controlled-functions",
    title="Owner/admin-controlled functions",
    category="centralization",
    severity="low",
    description=(
        "Some externally callable functions are restricted by a privileged-looking modifier such as onlyOwner or "
        "onlyRole. That means a specific address (or role holder) can change behavior or parameters that everyone "
        "else depends on."
    ),
    why_only_signal=(
        "Privileged roles are normal and often necessary (fee setters, emergency controls). The signal shows where "
        "trust in an admin exists, not that it is abused. This scanner does not read the modifier's body, resolve "
        "who the owner is, or know whether ownership is renounced, behind a multisig, or time-locked."
    ),
    select=_select_owner_controlled,
)

# ---- mint -----------------------------------------------------------------------
_MINT_NAME_RE = re.compile(r"mint", re.I)


def _select_mint(fn, ctx):
    if not fn.is_callable or not _is_state_changing(fn) or not _MINT_NAME_RE.search(fn.name):
        return None
    access = analyze_access(fn)
    return {"severity": severity_for_access(access), "detail": f"{fn.name}(): {access['detail']}",
            "access": access["level"]}


mint_function = function_rule(
    id="mint-function",
    title="Token minting function",
    category="supply-control",
    severity="medium",
    description=(
        "An externally callable function whose name suggests it creates new tokens. If someone can mint without "
        "limit, existing holders can be diluted and the token's value can be destroyed."
    ),
    why_only_signal=(
        "Minting is how many tokens are issued at all (sales, rewards, bridges). Severity here depends only on what "
        "the scanner can see: a function with no detected restriction is marked high, one behind a privileged "
        "modifier or caller check is medium. It cannot see supply caps, role assignments, or whether an "
        "unrestricted-looking function enforces limits in ways the heuristic misses."
    ),
    select=_select_mint,
)

# ---- pause ----------------------------------------------------------------------
_PAUSE_NAME_RE = re.compile(r"(?:un)?pause|emergencystop|circuitbreaker", re.I)
_PAUSE_MODIFIER_RE = re.compile(r"whenNotPaused|whenPaused|notPaused")


def _select_pause(fn, ctx):
    if not fn.is_callable:
        return None
    if _is_state_changing(fn) and _PAUSE_NAME_RE.search(fn.name):
        access = analyze_access(fn)
        return {"severity": severity_for_access(access), "detail": f"{fn.name}(): {access['detail']}",
                "access": access["level"]}
    if any(_PAUSE_MODIFIER_RE.fullmatch(m) for m in fn.modifiers):
        return {"severity": "low", "detail": f"{fn.name}() stops working while the contract is paused"}
    return None


pause_mechanism = function_rule(
    id="pause-mechanism",
    title="Pause / unpause mechanism",
    category="operational-control",
    severity="low",
    description=(
        "The contract can be paused. While paused, functions guarded by whenNotPaused (often transfers, deposits, "
        "or withdrawals) stop working, so whoever holds the pause power can freeze users."
    ),
    why_only_signal=(
        "Pause switches are a widely used safety feature that can limit damage during an incident. The signal only "
        "shows that the power exists and how restricted its entry point looks. It cannot tell who holds the power, "
        "whether it is time-limited, or whether funds stay withdrawable during a pause."
    ),
    select=_select_pause,
)

# ---- withdrawal -----------------------------------------------------------------
_WITHDRAW_NAME_RE = re.compile(r"withdraw|sweep|rescue|drain|payout|skim|recover", re.I)


def _select_withdrawal(fn, ctx):
    if not fn.is_callable or not _is_state_changing(fn):
        return None
    by_name = bool(_WITHDRAW_NAME_RE.search(fn.name))
    eth = sends_eth(fn.body)
    if not by_name and not eth:
        return None
    access = analyze_access(fn)
    why = "; ".join(x for x in [
        "name suggests a withdrawal" if by_name else None,
        f"sends ETH via {eth}" if eth else None,
    ] if x)
    return {"severity": severity_for_access(access), "detail": f"{fn.name}(): {why}; {access['detail']}",
            "access": access["level"]}


fund_withdrawal = function_rule(
    id="fund-withdrawal",
    title="Withdrawal / fund-moving functions",
    category="fund-flow",
    severity="medium",
    description=(
        "Externally callable functions that look like they move funds out of the contract: by name (withdraw, "
        "sweep, rescue, ...) or because the body sends ETH via .send, a one-argument .transfer, or "
        ".call{value: ...}. Who can call them, and how much they can take, determines who can reach the "
        "contract's funds."
    ),
    why_only_signal=(
        "Every contract that holds funds needs some way to pay out, and ordinary user withdrawals of their own "
        "balance look identical at this level. Standard ERC-20 transfer/transferFrom are deliberately not counted. "
        "The scanner sees names and a few access patterns; it does not verify amounts, recipients, accounting, or "
        "reentrancy safety."
    ),
    select=_select_withdrawal,
)

FUNCTION_RULES = [owner_controlled, mint_function, pause_mechanism, fund_withdrawal]
