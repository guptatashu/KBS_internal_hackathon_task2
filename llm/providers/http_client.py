"""
Shared HTTP POST + failure classification for LLM providers (port of http.js).

Returns {"ok": True, "json": {...}} or
        {"ok": False, "error": {"code", "message", "retryable", "status"?, "retryAfterMs"?, "providerMessage"?}}.
Never raises. Secrets (API keys) are redacted from anything that could be shown or logged.

Named http_client.py (not http.py) so it can never shadow Python's standard-library `http` module.
"""
import json
import math
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests


def fail(code, message, retryable, **extra):
    return {"ok": False, "error": {"code": code, "message": message, "retryable": retryable, **extra}}


def redact(text, secrets=()):
    out = "" if text is None else str(text)
    for s in secrets:
        if s:
            out = out.replace(s, "[redacted]")
    return out


def parse_retry_after(header):
    """Retry-After is either a number of seconds or an HTTP date. Returns milliseconds or None."""
    if not header:
        return None
    try:
        secs = float(header)
        if math.isfinite(secs):
            return max(0, int(secs * 1000 + 0.5))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(header)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, int((when - datetime.now(timezone.utc)).total_seconds() * 1000))


def _do_post(url, headers, data, timeout_s):
    res = requests.post(url, headers=headers, data=data, timeout=timeout_s)
    try:
        return res.status_code, res.headers, res.content.decode("utf-8", errors="replace")
    finally:
        res.close()


def post_json(url, headers, body, timeout_ms, secrets=()):
    """
    POST `body` as JSON. `timeout_ms` is a HARD TOTAL deadline for connect + headers + reading the body
    (the JS version used an AbortController for this). requests only limits each individual socket wait,
    so a server that drips bytes slowly could otherwise hold us far past the limit. The request therefore runs
    in a worker thread and we stop waiting for it at the deadline; the abandoned thread ends on its own
    when requests' per-read timeout fires.
    """
    timeout_s = timeout_ms / 1000
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        status, headers_in, text = pool.submit(_do_post, url, headers, data, timeout_s).result(timeout=timeout_s)
        return interpret(status, headers_in, text, secrets)
    except (FutureTimeout, requests.Timeout):
        return fail("TIMEOUT", f"The AI provider did not answer within {round(timeout_s)}s.", True)
    except Exception:  # requests.RequestException and anything unexpected: this function never raises
        return fail("NETWORK_ERROR", "Could not reach the AI provider.", True)
    finally:
        pool.shutdown(wait=False)


def interpret(status, headers, text, secrets=()):
    try:
        data = json.loads(text) if text else None
    except ValueError:
        data = None  # handled below

    if 200 <= status < 300:
        # Must be a JSON object. ({} is allowed here; the provider adapter reports it as an empty response.)
        if not isinstance(data, dict):
            return fail("PROVIDER_ERROR", "The AI provider returned a body that is not valid JSON.", True, status=status)
        return {"ok": True, "json": data}

    provider_message = redact(_provider_message(data), secrets)[:200]

    if status == 429:
        return fail("RATE_LIMITED", "The AI provider rate limit was reached.", True, status=status,
                    providerMessage=provider_message, retryAfterMs=parse_retry_after(headers.get("retry-after")))
    if status in (401, 403) or (status == 400 and re.search(r"api[ _-]?key", provider_message, re.I)):
        return fail("AUTH_ERROR", "The AI provider rejected the server's API key (invalid, expired, or lacking access).",
                    False, status=status, providerMessage=provider_message)
    if status == 413:
        return fail("PROMPT_TOO_LARGE",
                    "The request was too large for the AI provider. Lower the source size budget in Component 3.",
                    False, status=status, providerMessage=provider_message)
    if status == 404:
        return fail("PROVIDER_ERROR", "The AI provider could not find the configured model. Check GEMINI_MODEL / GROQ_MODEL.",
                    False, status=status, providerMessage=provider_message)
    if status >= 500:
        return fail("PROVIDER_ERROR", f"The AI provider had a server error (HTTP {status}).", True,
                    status=status, providerMessage=provider_message)
    return fail("PROVIDER_ERROR", f"The AI provider rejected the request (HTTP {status}).", False,
                status=status, providerMessage=provider_message)


def _provider_message(data):
    """Error text from either {"error": "msg"}, {"error": {"message": "msg"}} or {"message": "msg"}."""
    if not isinstance(data, dict):
        return ""
    err = data.get("error")
    if isinstance(err, str):
        raw = err
    elif isinstance(err, dict):
        raw = err.get("message")
    else:
        raw = None
    return raw or data.get("message") or ""
