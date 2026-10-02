"""
Web pipeline: runs the REAL components one stage at a time and yields a progress event after each real step.

    INGEST     Component 1 + 2   validate the address, fetch verified source from Etherscan
    INSPECT    Component 3       turn the fetched source into the payload the scanner and the AI use
    DETECT     Component 4       deterministic pattern scan
    INTERPRET  Component 5       AI analysis (optional)
    REPORT     (this module)     assemble the report the browser renders

Nothing here is simulated: a stage is reported as "running" immediately before its component is called and as
"done" / "failed" / "skipped" only from that component's actual result. Components are called exactly as
main.py calls them; none of them is modified.

Events (plain dicts, JSON-serialisable):
  {"type": "stage",  "stage": "INGEST", "status": "running" | "done" | "failed" | "skipped", "t": <epoch ms>,
                     "durationMs"?, "detail"?, "error"?}
  {"type": "report", "report": {...}}      the pipeline produced a report (the AI part may be failed/skipped)
  {"type": "fatal",  "error": {...}}       the pipeline could not produce a report; later stages never ran
The generator never raises.
"""
import copy
import hashlib
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from analyzer import analyze_contract
from fetch_verified_source import fetch_verified_source
from Input_basic import validate_address
from llm.config import create_provider
from preprocessor.preprocess_source import preprocess_source
from preprocessor.text_sanitizer import LINE_SPLIT, escape_unicode
from scan_cli import DEMO
from scanner.scan_source import scan_source

STAGES = ("INGEST", "INSPECT", "DETECT", "INTERPRET", "REPORT")
DEMO_RESPONSE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "demo_model_response.json"
_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
CONTEXT_BEFORE, CONTEXT_AFTER, MAX_CODE_CHARS = 1, 2, 240


def default_components():
    """The real components. Tests pass their own namespace to avoid the network."""
    return SimpleNamespace(validate_address=validate_address, fetch=fetch_verified_source,
                           preprocess=preprocess_source, scan=scan_source, analyze=analyze_contract,
                           create_provider=create_provider)


class _CannedProvider:
    """Demo mode only: stands in for the LLM by returning the recorded answer in tests/fixtures.
    The answer still goes through the real Component 5 prompt building and validation."""
    name, model = "demo fixture", "recorded answer (not a live model)"

    def __init__(self, text):
        self._text = text

    def complete(self, **_):
        return {"ok": True, "text": self._text, "finishReason": "stop", "usage": None}


def _demo_c2():
    return {"ok": True, "data": {
        "contractName": "Wallet", "compilerVersion": "v0.8.20 (demo sample)", "optimizationUsed": False, "runs": 0,
        "evmVersion": "default", "licenseType": "MIT", "isProxy": False, "implementationAddress": None,
        "sourceFormat": "single-file", "files": [{"path": "Wallet.sol", "content": DEMO}]}}


# ----------------------------------------------------------------------------------------------------------------
# event helpers
# ----------------------------------------------------------------------------------------------------------------
def _now_ms():
    return int(time.time() * 1000)


def _stage(stage, status, **extra):
    return {"type": "stage", "stage": stage, "status": status, "t": _now_ms(), **extra}


def _public_error(err, default_code="PIPELINE_ERROR"):
    """Only these fields ever reach the browser."""
    err = err if isinstance(err, dict) else {}
    out = {"code": str(err.get("code") or default_code)[:60],
           "message": str(err.get("message") or "The step failed.")[:300],
           "retryable": bool(err.get("retryable"))}
    if isinstance(err.get("retryAfterMs"), (int, float)):
        out["retryAfterMs"] = int(err["retryAfterMs"])
    return out


def _failed(stage, started, err):
    ms = int((time.monotonic() - started) * 1000)
    pub = _public_error(err)
    return [_stage(stage, "failed", durationMs=ms, error=pub), {"type": "fatal", "stage": stage, "error": pub}]


def _ms(started):
    return int((time.monotonic() - started) * 1000)


# ----------------------------------------------------------------------------------------------------------------
# the pipeline
# ----------------------------------------------------------------------------------------------------------------
def run_scan(address, *, include_ai=True, demo=False, components=None):
    try:
        yield from _run(address, include_ai, demo, components or default_components())
    except Exception:  # last-resort net: the stream must end with a clear event, never a stack trace
        yield {"type": "fatal", "error": {"code": "INTERNAL_ERROR", "retryable": False,
                                          "message": "Unexpected error while running the scan."}}


def _run(address, include_ai, demo, c):
    durations = {}
    started_all = time.monotonic()

    # ---- INGEST: Component 1 (validate) + Component 2 (Etherscan) -------------------------------------------
    t = time.monotonic()
    yield _stage("INGEST", "running")
    if demo:
        c2 = _demo_c2()
    else:
        if not c.validate_address(address or ""):
            yield from _failed("INGEST", t, {"code": "INVALID_ADDRESS",
                                            "message": "Address must be 0x followed by 40 hex characters."})
            return
        c2 = c.fetch(address)
    if not c2.get("ok"):
        yield from _failed("INGEST", t, c2.get("error"))
        return
    data = c2["data"]
    n_files = len(data.get("files") or [])
    durations["INGEST"] = _ms(t)
    detail = ("Built-in sample contract, no network request" if demo
              else f"{data.get('contractName') or 'Unnamed contract'}: {n_files} source file{'s' if n_files != 1 else ''} from Etherscan")
    yield _stage("INGEST", "done", durationMs=durations["INGEST"], detail=detail)

    # ---- INSPECT: Component 3 -------------------------------------------------------------------------------
    t = time.monotonic()
    yield _stage("INSPECT", "running")
    c3 = c.preprocess(c2)
    if not c3.get("ok"):
        yield from _failed("INSPECT", t, {"code": "EMPTY_SOURCE", "retryable": False,
                                          "message": "Etherscan reports this contract as verified, but returned no "
                                                     "readable Solidity source files, so there is nothing to scan."})
        return
    meta_files = c3["payload"]["meta"]["files"]
    libs = sum(1 for f in meta_files if f.get("isDependency"))
    chars = sum(len(f["content"]) for f in c3["payload"]["original"]["files"])
    durations["INSPECT"] = _ms(t)
    yield _stage("INSPECT", "done", durationMs=durations["INSPECT"],
                 detail=f"{len(meta_files)} file{'s' if len(meta_files) != 1 else ''} ({libs} library), {chars:,} characters")

    # ---- DETECT: Component 4 --------------------------------------------------------------------------------
    t = time.monotonic()
    yield _stage("DETECT", "running")
    c4 = c.scan(c3)
    if not c4.get("ok"):
        yield from _failed("DETECT", t, c4.get("error"))
        return
    summary = c4["result"]["summary"]
    durations["DETECT"] = _ms(t)
    yield _stage("DETECT", "done", durationMs=durations["DETECT"],
                 detail=f"{len(c4['result']['rules'])} rules run, {summary['totalFindings']} signal"
                        f"{'s' if summary['totalFindings'] != 1 else ''} ({summary['bySeverity']['high']} high)")

    # ---- INTERPRET: Component 5 (optional; its failure must not lose the scan results) -----------------------
    ai = {"status": "skipped", "reason": "AI analysis was turned off for this scan."}
    provider, skip_reason = None, None
    if demo:
        try:
            provider = _CannedProvider(DEMO_RESPONSE.read_text(encoding="utf-8"))
        except OSError:
            skip_reason = "The recorded demo answer (tests/fixtures/demo_model_response.json) was not found."
            ai = {"status": "unavailable", "reason": skip_reason}
    elif include_ai:
        made = c.create_provider()
        if made.get("ok"):
            provider = made["provider"]
        else:
            skip_reason = _public_error(made.get("error"))["message"]
            ai = {"status": "unavailable", "reason": skip_reason}

    if provider is None:
        yield _stage("INTERPRET", "skipped", detail=ai["reason"])
    else:
        t = time.monotonic()
        yield _stage("INTERPRET", "running", detail=f"{provider.name}")
        c5 = c.analyze(c3, c4, provider=provider)
        durations["INTERPRET"] = _ms(t)
        if c5.get("ok"):
            ai = {"status": "ok", "analysis": c5["analysis"], "meta": c5["meta"], "demo": bool(demo)}
            yield _stage("INTERPRET", "done", durationMs=durations["INTERPRET"],
                         detail=f"{c5['meta'].get('provider')}: risk {c5['analysis']['riskLevel']}")
        else:
            pub = _public_error(c5.get("error"))
            ai = {"status": "failed", "error": pub}
            yield _stage("INTERPRET", "failed", durationMs=durations["INTERPRET"], error=pub)

    # ---- REPORT ---------------------------------------------------------------------------------------------
    t = time.monotonic()
    yield _stage("REPORT", "running")
    report = build_report(address, data, c3, c4["result"], ai, durations, demo)
    durations["REPORT"] = _ms(t)
    report["pipeline"]["durationsMs"] = dict(durations)
    report["pipeline"]["totalMs"] = _ms(started_all)
    yield _stage("REPORT", "done", durationMs=durations["REPORT"], detail="Report assembled")
    yield {"type": "report", "report": report}


# ----------------------------------------------------------------------------------------------------------------
# report assembly (what the browser receives)
# ----------------------------------------------------------------------------------------------------------------
def _clean_code(line):
    s = escape_unicode(line.replace("\t", "  ")).rstrip()
    return s if len(s) <= MAX_CODE_CHARS else s[:MAX_CODE_CHARS] + " ..."


def _context(files, path, line):
    """A few source lines around a cited line, so evidence can be shown as real code. [] if the file/line is unknown."""
    content = files.get(path)
    if content is None or not isinstance(line, int):
        return []
    lines = LINE_SPLIT.split(content)
    if not 1 <= line <= len(lines):
        return []
    lo, hi = max(1, line - CONTEXT_BEFORE), min(len(lines), line + CONTEXT_AFTER)
    out = [{"n": n, "text": _clean_code(lines[n - 1]), "hit": n == line} for n in range(lo, hi + 1)]
    while out and not out[-1]["hit"] and not out[-1]["text"].strip():   # no blank padding after the cited line
        out.pop()
    while out and not out[0]["hit"] and not out[0]["text"].strip():    # ...or before it
        out.pop(0)
    return out


def _short(value, limit):
    return value[:limit] if isinstance(value, str) else None


def build_report(address, data, c3, scan_result, ai, durations, demo):
    now = datetime.now(timezone.utc)
    files = {f["path"]: f["content"] for f in c3["payload"]["original"]["files"]}
    dep = {m["path"]: bool(m.get("isDependency")) for m in c3["payload"]["meta"]["files"]}

    scan = copy.deepcopy(scan_result)
    for finding in scan["findings"]:
        for ev in finding["evidence"]:
            ev["context"] = _context(files, ev["file"], ev["line"])

    ai = copy.deepcopy(ai)
    for finding in (ai.get("analysis") or {}).get("securityFindings", []):
        for ev in finding["evidence"]:
            ev["context"] = _context(files, ev["file"], ev["line"])

    impl = data.get("implementationAddress")
    stamp = now.isoformat(timespec="seconds")
    return {
        "mode": "demo" if demo else "live",
        "reportId": hashlib.sha256(f"{address}|{stamp}".encode()).hexdigest()[:10],
        "scannedAt": stamp,
        "address": None if demo else address,
        "chain": {"id": 1, "name": "Ethereum mainnet"},
        "contract": {
            "name": _short(data.get("contractName"), 100),
            "compilerVersion": _short(data.get("compilerVersion"), 80),
            "optimizationUsed": bool(data.get("optimizationUsed")),
            "runs": data.get("runs") if isinstance(data.get("runs"), int) else None,
            "evmVersion": _short(data.get("evmVersion"), 40),
            "licenseType": _short(data.get("licenseType"), 60),
            "sourceFormat": _short(data.get("sourceFormat"), 20),
            "isProxy": bool(data.get("isProxy")),
            "implementationAddress": impl if isinstance(impl, str) and _ADDRESS_RE.fullmatch(impl) else None,
            # Metadata only: the browser never receives the full source text.
            "files": [{"path": _short(p, 300), "isDependency": dep.get(p, False),
                       "lines": len(LINE_SPLIT.split(c)), "chars": len(c)} for p, c in files.items()],
        },
        "scan": scan,
        "ai": ai,
        "pipeline": {"stages": list(STAGES), "durationsMs": dict(durations)},
    }
