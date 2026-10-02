"""LLM settings and provider selection."""
import math
import os

from .providers.gemini import create_gemini_provider
from .providers.groq import create_groq_provider

# Model names rotate; these are defaults only. Override with GEMINI_MODEL / GROQ_MODEL.
DEFAULT_MODELS = {"gemini": "gemini-2.5-flash", "groq": "llama-3.3-70b-versatile"}


def _num(value, default):
    """A positive, finite number from an env string, otherwise the default."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    if math.isfinite(n) and n > 0:
        return int(n) if n == int(n) else n
    return default


def get_llm_config(env=None):
    env = os.environ if env is None else env
    return {
        "timeoutMs": _num(env.get("LLM_TIMEOUT_MS"), 60_000),
        "maxOutputTokens": _num(env.get("LLM_MAX_OUTPUT_TOKENS"), 8192),  # thinking models spend part of this on reasoning
        "maxAttempts": _num(env.get("LLM_MAX_ATTEMPTS"), 2),
        "maxRetryWaitMs": _num(env.get("LLM_MAX_RETRY_WAIT_MS"), 8_000),
        "maxPromptChars": _num(env.get("LLM_MAX_PROMPT_CHARS"), 150_000),
        "temperature": 0.1,  # low: we want consistent, conservative analysis
    }


def _fail(code, message):
    return {"ok": False, "error": {"code": code, "message": message, "retryable": False}}


def create_provider(env=None):
    """Pick a provider from the environment. Keys are read ONLY here."""
    env = os.environ if env is None else env
    chosen = (env.get("LLM_PROVIDER")
              or ("gemini" if env.get("GEMINI_API_KEY") else "groq" if env.get("GROQ_API_KEY") else "")).lower()

    if not chosen:
        return _fail("MISSING_API_KEY",
                     "No LLM provider is configured on the server (set GEMINI_API_KEY or GROQ_API_KEY).")

    if chosen in ("gemini", "groq"):
        api_key = env.get("GEMINI_API_KEY" if chosen == "gemini" else "GROQ_API_KEY")
        if not api_key:
            return _fail("MISSING_API_KEY", f'The server has no API key for the "{chosen}" provider.')
        model = env.get("GEMINI_MODEL" if chosen == "gemini" else "GROQ_MODEL") or DEFAULT_MODELS[chosen]
        make = create_gemini_provider if chosen == "gemini" else create_groq_provider
        return {"ok": True, "provider": make(api_key, model)}

    return _fail("UNKNOWN_PROVIDER", f'Unsupported LLM_PROVIDER "{chosen[:30]}". Use "gemini" or "groq".')
