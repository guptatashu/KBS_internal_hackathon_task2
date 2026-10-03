"""
Component 5, step 3: validate the model's answer BEFORE anything else sees it.

The model's JSON is itself derived from untrusted data, so it is treated as untrusted too:
 - only whitelisted keys are copied out (anything extra is dropped),
 - enums are checked, text is whitespace-collapsed, length-capped and made free of control/bidi characters,
 - claims are checked against what the model was actually shown: functions must exist in the provided source,
   finding evidence must point at real file/line locations, scanner rule ids must be real,
 - a finding with no verifiable evidence is discarded (that is the enforcement of "do not invent vulnerabilities").
Structural problems (not an object, missing keys, bad riskLevel) make the whole answer MALFORMED_RESPONSE (retryable).
Problems with individual items drop just those items and are reported in `dropped` / `warnings`.
"""
import re
from dataclasses import dataclass, field

from preprocessor.text_sanitizer import escape_unicode

SCHEMA_VERSION = "1.0"
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH")
CONFIDENCES = ("LOW", "MEDIUM", "HIGH")
MAX_ITEMS = 25
MAX_EVIDENCE = 5
REQUIRED_KEYS = ("contractPurpose", "riskLevel", "summary", "riskReasoning", "keyFunctions", "permissions",
                 "fundMovement", "externalCalls", "securityFindings", "interactionRisks", "recommendations",
                 "limitations")
LIST_KEYS = REQUIRED_KEYS[4:]
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")


@dataclass
class ValidationContext:
    function_names: set = field(default_factory=set)      # functions defined in the source the model was shown
    shown_lines: dict = field(default_factory=dict)       # path -> set of line numbers the model was shown
    known_rules: set = field(default_factory=set)         # scanner rule ids that were given to the model
    scanner_severity: dict = field(default_factory=dict)  # rule -> severity, for the consistency warning
    scanner_locations: set = field(default_factory=set)   # (file, line) pairs from scanner evidence


def _malformed(message):
    return {"ok": False, "error": {"code": "MALFORMED_RESPONSE", "message": message, "retryable": True}}


def _text(value, limit):
    if not isinstance(value, str):
        return None
    s = escape_unicode(re.sub(r"\s+", " ", value).strip())
    if not s:
        return None
    return s if len(s) <= limit else s[: limit - 1] + "\u2026"


def _enum(value, allowed):
    if isinstance(value, str) and value.strip().upper() in allowed:
        return value.strip().upper()
    return None


def _function_name(value, ctx):
    if not isinstance(value, str):
        return None
    name = value.split("(")[0].strip().split(".")[-1].strip()
    return name if _IDENT.fullmatch(name) and name in ctx.function_names else None


def _resolve_path(path, ctx):
    if path in ctx.shown_lines:
        return path
    matches = [p for p in ctx.shown_lines if p.endswith("/" + path)]   # model wrote only the file name
    return matches[0] if len(matches) == 1 else None


class _Report:
    def __init__(self):
        self.dropped = {}   # (section, reason) -> count
        self.warnings = []

    def drop(self, section, reason, n=1):
        self.dropped[(section, reason)] = self.dropped.get((section, reason), 0) + n

    def dropped_list(self):
        return [{"section": s, "reason": r, "count": c} for (s, r), c in self.dropped.items()]


def _items(obj, section, report):
    raw = obj[section]
    if len(raw) > MAX_ITEMS:
        report.drop(section, f"more than {MAX_ITEMS} items; extra items ignored", len(raw) - MAX_ITEMS)
    return raw[:MAX_ITEMS]


def _strings(raw, limit, max_items=MAX_ITEMS):
    out = []
    for v in raw if isinstance(raw, list) else []:
        t = _text(v, limit)
        if t:
            out.append(t)
        if len(out) == max_items:
            break
    return out


def _evidence(raw, ctx, report):
    out, bad = [], 0
    for e in raw[: MAX_EVIDENCE * 2] if isinstance(raw, list) else []:
        path = e.get("file") if isinstance(e, dict) else None
        line = e.get("line") if isinstance(e, dict) else None
        if isinstance(line, str) and line.strip().isdigit():
            line = int(line)
        if not isinstance(path, str) or isinstance(line, bool) or not isinstance(line, int):
            bad += 1
            continue
        canon = _resolve_path(path, ctx)
        in_view = canon is not None and line in ctx.shown_lines[canon]
        if not in_view and (path, line) in ctx.scanner_locations:
            canon, in_view = path, True            # scanner evidence is evidence too, even in files not shown
        shown = _text(canon, 300) if in_view else None
        if not shown:
            bad += 1
            continue
        entry = {"file": shown, "line": line}
        if entry in out:
            continue  # duplicate citation, not an error
        out.append(entry)
        if len(out) == MAX_EVIDENCE:
            break
    if bad:
        report.drop("securityFindings.evidence", "location does not exist in the provided source", bad)
    return out


def _key_functions(obj, ctx, report):
    out = []
    for it in _items(obj, "keyFunctions", report):
        d = it if isinstance(it, dict) else {}
        name, desc = _function_name(d.get("name"), ctx), _text(d.get("description"), 400)
        if not name or not desc:
            report.drop("keyFunctions", "function not defined in the provided source, or fields missing")
            continue
        out.append({"name": name, "visibility": _text(d.get("visibility"), 30) or "unknown", "description": desc})
    return out


def _permissions(obj, ctx, report):
    out = []
    for it in _items(obj, "permissions", report):
        d = it if isinstance(it, dict) else {}
        role, caps = _text(d.get("role"), 100), _strings(d.get("capabilities"), 300, 10)
        if not role or not caps:
            report.drop("permissions", "role or capabilities missing")
            continue
        names = [_function_name(n, ctx) for n in (d.get("functions") if isinstance(d.get("functions"), list) else [])]
        if any(n is None for n in names):
            report.drop("permissions.functions", "function not defined in the provided source",
                        sum(n is None for n in names))
        out.append({"role": role, "capabilities": caps, "functions": [n for n in dict.fromkeys(names) if n]})
    return out


def _fund_movement(obj, ctx, report):
    out = []
    for it in _items(obj, "fundMovement", report):
        d = it if isinstance(it, dict) else {}
        fn, mech, desc = _function_name(d.get("function"), ctx), _text(d.get("mechanism"), 100), _text(d.get("description"), 400)
        if not fn or not mech or not desc:
            report.drop("fundMovement", "function not defined in the provided source, or fields missing")
            continue
        out.append({"function": fn, "mechanism": mech,
                    "accessControl": _text(d.get("accessControl"), 200) or "not stated", "description": desc})
    return out


def _external_calls(obj, ctx, report):
    out = []
    for it in _items(obj, "externalCalls", report):
        d = it if isinstance(it, dict) else {}
        fn, kind, desc = _function_name(d.get("function"), ctx), _text(d.get("kind"), 60), _text(d.get("description"), 400)
        if not fn or not kind or not desc:
            report.drop("externalCalls", "function not defined in the provided source, or fields missing")
            continue
        out.append({"function": fn, "kind": kind, "target": _text(d.get("target"), 150) or "unspecified",
                    "description": desc})
    return out


def _findings(obj, ctx, report):
    out = []
    for it in _items(obj, "securityFindings", report):
        d = it if isinstance(it, dict) else {}
        title, sev, conf = _text(d.get("title"), 200), _enum(d.get("severity"), SEVERITIES), _enum(d.get("confidence"), CONFIDENCES)
        observed, potential = _text(d.get("observed"), 500), _text(d.get("potentialRisk"), 500)
        if not (title and sev and conf and observed and potential):
            report.drop("securityFindings", "required field missing or invalid enum value")
            continue
        rule = d.get("scannerRule")
        rule = rule.strip() if isinstance(rule, str) and rule.strip() and rule.strip().lower() != "null" else None
        if rule is not None and rule not in ctx.known_rules:
            report.drop("securityFindings.scannerRule", "unknown scanner rule id ignored")
            rule = None
        evidence = _evidence(d.get("evidence"), ctx, report)
        if not evidence and rule is None:
            report.drop("securityFindings", "no verifiable evidence (finding looks invented)")
            continue
        out.append({"title": title, "severity": sev, "observed": observed, "potentialRisk": potential,
                    "evidence": evidence, "scannerRule": rule, "confidence": conf})
    return out


def _interaction_risks(obj, report):
    out = []
    for it in _items(obj, "interactionRisks", report):
        d = it if isinstance(it, dict) else {}
        desc = _text(d.get("description"), 500)
        if not desc:
            report.drop("interactionRisks", "description missing")
            continue
        out.append({"description": desc, "dependsOn": _text(d.get("dependsOn"), 300) or "not stated"})
    return out


def validate_analysis(obj, ctx):
    """-> {"ok": True, "analysis", "warnings", "dropped", "scannerRulesNotReferenced"} or {"ok": False, "error"}"""
    if not isinstance(obj, dict):
        return _malformed("The model's answer was not a JSON object.")
    missing = [k for k in REQUIRED_KEYS if k not in obj]
    if missing:
        return _malformed(f"The model's answer is missing required field(s): {', '.join(missing)}.")
    risk = _enum(obj["riskLevel"], RISK_LEVELS)
    if risk is None:
        return _malformed("The model's riskLevel is not one of LOW, MEDIUM, HIGH.")
    purpose, summary, reasoning = _text(obj["contractPurpose"], 400), _text(obj["summary"], 1200), _text(obj["riskReasoning"], 1500)
    if not (purpose and summary and reasoning):
        return _malformed("The model's contractPurpose, summary or riskReasoning is missing or empty.")
    wrong = [k for k in LIST_KEYS if not isinstance(obj[k], list)]
    if wrong:
        return _malformed(f"These fields must be lists: {', '.join(wrong)}.")

    report = _Report()
    findings = _findings(obj, ctx, report)
    analysis = {
        "contractPurpose": purpose, "riskLevel": risk, "summary": summary, "riskReasoning": reasoning,
        "keyFunctions": _key_functions(obj, ctx, report),
        "permissions": _permissions(obj, ctx, report),
        "fundMovement": _fund_movement(obj, ctx, report),
        "externalCalls": _external_calls(obj, ctx, report),
        "securityFindings": findings,
        "interactionRisks": _interaction_risks(obj, report),
        "recommendations": _strings(obj["recommendations"], 300),
        "limitations": _strings(obj["limitations"], 300),
    }

    referenced = {f["scannerRule"] for f in findings if f["scannerRule"]}
    not_referenced = sorted(ctx.known_rules - referenced)
    high = sorted(r for r, s in ctx.scanner_severity.items() if s == "high")
    if risk == "LOW" and high:
        report.warnings.append("riskLevel is LOW although the scanner reported HIGH-severity signal(s): "
                               + ", ".join(high) + ". Review the scanner findings directly.")
    return {"ok": True, "analysis": analysis, "warnings": report.warnings, "dropped": report.dropped_list(),
            "scannerRulesNotReferenced": not_referenced}
