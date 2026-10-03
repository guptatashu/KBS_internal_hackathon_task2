"""
Lightweight function extraction for Solidity. This is NOT a real parser: it finds
`function name(...) <header> { body }` using paren/brace matching on text in which
comments are already removed and string contents are masked.
"""
import re
from dataclasses import dataclass, field

HEADER_KEYWORDS = {"external", "public", "internal", "private", "view", "pure",
                   "payable", "virtual", "override", "returns"}

_FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", re.ASCII)


@dataclass
class Function:
    name: str
    line: int
    end_line: int
    visibility: str
    mutability: str
    is_callable: bool
    modifiers: list = field(default_factory=list)
    has_body: bool = False
    body: str = ""


def extract_functions(code, line_of):
    fns = []
    pos = 0
    n = len(code)
    while True:
        m = _FUNC_RE.search(code, pos)
        if not m:
            break

        # 1) skip the parameter list
        i = m.end()
        depth = 1
        while i < n and depth > 0:
            if code[i] == "(":
                depth += 1
            elif code[i] == ")":
                depth -= 1
            i += 1

        # 2) header tail (visibility, mutability, modifiers, returns) runs to '{' or ';'
        j = i
        pd = 0
        while j < n:
            c = code[j]
            if c == "(":
                pd += 1
            elif c == ")":
                pd -= 1
            elif pd == 0 and c in "{;":
                break
            j += 1
        tail = code[i:j]
        has_body = j < n and code[j] == "{"

        # 3) body by brace matching
        body_end = j
        if has_body:
            d = 0
            body_end = n
            for k in range(j, n):
                if code[k] == "{":
                    d += 1
                elif code[k] == "}":
                    d -= 1
                    if d == 0:
                        body_end = k
                        break

        vis = re.search(r"\b(external|public|internal|private)\b", tail)
        mut = re.search(r"\b(view|pure|payable)\b", tail)
        visibility = vis.group(1) if vis else "public"
        mutability = mut.group(1) if mut else "nonpayable"

        fns.append(Function(
            name=m.group(1)[:80],
            line=line_of(m.start()),
            end_line=line_of(body_end),
            visibility=visibility,
            mutability=mutability,
            is_callable=visibility in ("external", "public"),
            modifiers=parse_modifiers(tail),
            has_body=has_body,
            body=code[j + 1:body_end] if has_body else "",
        ))

        pos = max(body_end, m.start() + 1)  # Solidity has no nested function definitions
    return fns


_PAREN = r"\((?:[^()]|\([^()]*\))*\)"


def parse_modifiers(tail):
    t = re.sub(r"returns\s*" + _PAREN, " ", tail)
    t = re.sub(r"override\s*" + _PAREN, " ", t)
    mods = []
    for mm in re.finditer(r"([A-Za-z_$][\w$]*)\s*(?:" + _PAREN + ")?", t, re.ASCII):
        if mm.group(1) not in HEADER_KEYWORDS:
            mods.append(mm.group(1)[:80])
    return mods


# ---------------------------------------------------------------------------------
# Access-control heuristics. These look at NAMES and obvious checks only. They cannot
# know whether a modifier's body actually enforces anything.
# ---------------------------------------------------------------------------------

# Modifier names that look like privilege gates (onlyOwner, onlyRole, auth, adminOnly, ...)
ACCESS_MODIFIER_RE = re.compile(
    r"only\w*|\w*only|auth|requiresauth|restricted|"
    r"\w*(?:owner|admin|governor|governance|operator|minter|keeper)\w*",
    re.I | re.ASCII,
)

_CALLER = r"(?:msg\.sender|_msgSender\s*\(\s*\)|tx\.origin)"
# An explicit check of the caller against something (==, !=, role helpers, allowlist mapping)
INLINE_CHECK_RE = re.compile(
    "|".join([
        _CALLER + r"\s*[!=]=",
        r"[!=]=\s*" + _CALLER,
        r"\b(?:_checkOwner|_checkRole|hasRole|isOwner|isAdmin|isMinter|isAuthorized|_authorize\w*)\s*\(",
        r"\bonlyRole\b",
        r"\b(?:owners?|admins?|minters?|authorized\w*|operators?|governance)\s*\[\s*" + _CALLER + r"\s*\]",
    ]),
    re.ASCII,
)
# Funds/state keyed by the caller's own address, e.g. balances[msg.sender]
CALLER_SCOPED_RE = re.compile(r"\[\s*(?:msg\.sender|_msgSender\s*\(\s*\))\s*\]")


def analyze_access(fn):
    """Returns {"level": 'modifier'|'inline-check'|'caller-scoped'|'none-detected', "detail": str}"""
    mod = next((m for m in fn.modifiers if ACCESS_MODIFIER_RE.fullmatch(m)), None)
    if mod:
        return {"level": "modifier", "detail": f"restricted by modifier {mod}"}
    if INLINE_CHECK_RE.search(fn.body):
        return {"level": "inline-check", "detail": "body compares the caller against something"}
    if CALLER_SCOPED_RE.search(fn.body):
        return {"level": "caller-scoped",
                "detail": "operates on the caller's own entry (e.g. balances[msg.sender])"}
    return {"level": "none-detected", "detail": "no access restriction detected by this heuristic"}


def severity_for_access(access):
    """Signal level implied by how (un)restricted a sensitive function looks."""
    level = access["level"]
    if level == "none-detected":
        return "high"
    if level == "caller-scoped":
        return "low"
    return "medium"  # modifier / inline-check: a privileged party holds the power


# ---------------------------------------------------------------------------------
# ETH-sending detection inside a function body
# ---------------------------------------------------------------------------------
def _has_top_level_comma(text, start):
    d = 1
    i = start
    while i < len(text) and d > 0:
        c = text[i]
        if c in "([{":
            d += 1
        elif c in ")]}":
            d -= 1
        elif c == "," and d == 1:
            return True
        i += 1
    return False


def sends_eth(body):
    """'send' | 'transfer' | 'call-with-value' | None.
    One-argument .transfer() is ETH; ERC-20 transfer(to, amt) has two."""
    if re.search(r"\.send\s*\(", body):
        return "send"
    if re.search(r"\.call\s*(?:\{[^}]*\bvalue\b|\.value\s*\()", body):
        return "call-with-value"
    for m in re.finditer(r"\.transfer\s*\(", body):
        if not _has_top_level_comma(body, m.end()):
            return "transfer"
    return None
