"""
Component 5: LLM Contract Analysis Engine.

    Component 3 payload + Component 4 result  ->  validated, structured analysis (or a structured error)

Never raises. Returns one of:
  {"ok": True,  "analysis": {...}, "meta": {...}}
  {"ok": False, "error": {"code", "message", "retryable", "retryAfterMs"?}}

The API key is read from the environment inside llm.config.create_provider and nowhere else. It is never part of a
return value; errors handed back to callers contain only code/message/retryable/retryAfterMs (no provider text).
The returned analysis is plain text derived from untrusted input: a frontend must render it as TEXT, never as HTML.
"""
import json
import re

from llm.client import complete_with_retry
from llm.config import create_provider, get_llm_config

from .prompt import SYSTEM_PROMPT, build_user_message, metadata_view, scanner_view
from .source_view import build_source_view
from .validate import SCHEMA_VERSION, ValidationContext, validate_analysis

MAX_FORMAT_ATTEMPTS = 2        # one extra try if the model returns empty / malformed output
MIN_SOURCE_BUDGET = 3000
PROMPT_OVERHEAD_CHARS = 1500
MAX_FIT_ROUNDS = 8
FIT_MARGIN_CHARS = 200

DISCLAIMER = ("AI-generated analysis based on the provided source and deterministic scanner signals. It can be wrong or "
              "incomplete, is not a security audit, and 'LOW' does not mean safe.")


def _fail(code, message, retryable=False):
    return {"ok": False, "error": {"code": code, "message": message, "retryable": retryable}}


def _public_error(err):
    """Only these fields may leave the backend. (Provider text and status codes stay server-side.)"""
    out = {"code": err.get("code", "PROVIDER_ERROR"), "message": err.get("message", "Analysis failed."),
           "retryable": bool(err.get("retryable"))}
    if err.get("retryAfterMs") is not None:
        out["retryAfterMs"] = err["retryAfterMs"]
    return {"ok": False, "error": out}


def _unwrap(value, key):
    if isinstance(value, dict) and value.get("ok") is True and key in value:
        return value[key]
    return value


def parse_model_json(text):
    """Model text -> dict, or None. Tolerates a markdown fence or a sentence around the JSON object."""
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text).strip()
    for candidate in (text, text[text.find("{"): text.rfind("}") + 1] if "{" in text else ""):
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        return data if isinstance(data, dict) else None
    return None


def prepare_request(c3, c4, config):
    """Build everything that would be sent to the LLM, without sending it. -> {"ok", "system", "user", "view", "ctx", ...}"""
    payload, result = _unwrap(c3, "payload"), _unwrap(c4, "result")
    files = ((payload or {}).get("original") or {}).get("files") if isinstance(payload, dict) else None
    if not isinstance(files, list) or not files:
        return _fail("INVALID_INPUT", "Expected a Component 3 payload containing original.files.")
    if not isinstance(result, dict) or not isinstance(result.get("findings"), list):
        return _fail("INVALID_INPUT", "Expected a Component 4 result containing a findings list.")

    meta_view, scan_view = metadata_view(payload), scanner_view(result)
    fixed = len(SYSTEM_PROMPT) + len(json.dumps(meta_view)) + len(json.dumps(scan_view)) + PROMPT_OVERHEAD_CHARS
    budget = config["maxPromptChars"] - fixed
    if budget < MIN_SOURCE_BUDGET:
        return _fail("PROMPT_TOO_LARGE", "The scanner output alone leaves too little room for source code. "
                                         "Raise LLM_MAX_PROMPT_CHARS.")
    # The estimate above ignores parts that are only known once the message is built (the per-file function index,
    # headers, JSON escaping). So measure the real message and shrink the source budget until the whole prompt fits.
    limit = config["maxPromptChars"]
    for _ in range(MAX_FIT_ROUNDS):
        view = build_source_view(payload, budget)
        if not view["files"]:
            return _fail("PROMPT_TOO_LARGE", "No source file fit into the prompt size limit (LLM_MAX_PROMPT_CHARS).")
        user, nonce = build_user_message(meta_view, scan_view, view)
        over = len(SYSTEM_PROMPT) + len(user) - limit
        if over <= 0:
            break
        budget -= over + FIT_MARGIN_CHARS
        if budget < MIN_SOURCE_BUDGET:
            return _fail("PROMPT_TOO_LARGE", "Too little room is left for source code after the scanner output and "
                                             "instructions. Raise LLM_MAX_PROMPT_CHARS.")
    else:
        return _fail("PROMPT_TOO_LARGE", "The prompt could not be made to fit LLM_MAX_PROMPT_CHARS. Raise it.")

    ctx = ValidationContext(
        function_names=set(view["functionNames"]),
        shown_lines={f["path"]: f["shownLines"] for f in view["files"]},
        known_rules={f["rule"] for f in scan_view["findings"]},
        scanner_severity={f["rule"]: f["severity"] for f in scan_view["findings"]},
        scanner_locations={(e["file"], e["line"]) for f in scan_view["findings"] for e in f["evidence"]},
    )
    return {"ok": True, "system": SYSTEM_PROMPT, "user": user, "nonce": nonce, "view": view, "ctx": ctx,
            "scannerFindingsProvided": len(scan_view["findings"])}


def _coverage(view):
    return {
        "filesSent": [f["path"] for f in view["files"]],
        "filesTruncated": [f["path"] for f in view["files"] if f["truncated"]],
        "filesOmitted": [o["path"] for o in view["omitted"]],
        "charsSent": view["charsSent"],
    }


def analyze_contract(c3, c4, *, env=None, provider=None):
    try:
        config = get_llm_config(env)
        prep = prepare_request(c3, c4, config)
        if not prep["ok"]:
            return prep

        if provider is None:
            made = create_provider(env)
            if not made["ok"]:
                return _public_error(made["error"])
            provider = made["provider"]

        last_error, usage = None, None
        for attempt in range(1, MAX_FORMAT_ATTEMPTS + 1):
            r = complete_with_retry(provider, config, prep["system"], prep["user"])
            if not r["ok"]:
                return _public_error(r["error"])           # transport/provider failure: already retried where sensible
            usage = r.get("usage")

            if not (r.get("text") or "").strip():
                last_error = _fail("EMPTY_RESPONSE", "The AI provider returned an empty answer.", True)["error"]
                continue
            parsed = parse_model_json(r["text"])
            if parsed is None:
                last_error = _fail("MALFORMED_RESPONSE", "The AI answer was not valid JSON.", True)["error"]
                continue
            checked = validate_analysis(parsed, prep["ctx"])
            if not checked["ok"]:
                last_error = checked["error"]
                continue

            view = prep["view"]
            warnings = list(checked["warnings"])
            if view["omitted"] or any(f["truncated"] for f in view["files"]):
                warnings.append("Not all source code fit into the prompt, so the analysis covers only part of the "
                                "contract (see meta.sourceCoverage).")
            return {"ok": True, "analysis": checked["analysis"], "meta": {
                "schemaVersion": SCHEMA_VERSION, "provider": provider.name, "model": provider.model, "usage": usage,
                "sourceCoverage": _coverage(view),
                "scannerFindingsProvided": prep["scannerFindingsProvided"],
                "scannerRulesNotReferenced": checked["scannerRulesNotReferenced"],
                "warnings": warnings, "dropped": checked["dropped"], "disclaimer": DISCLAIMER,
            }}
        return _public_error(last_error)
    except Exception as err:  # safety net: Component 5 must never crash the pipeline
        return _fail("ANALYSIS_ERROR", "The AI analysis failed unexpectedly.")
