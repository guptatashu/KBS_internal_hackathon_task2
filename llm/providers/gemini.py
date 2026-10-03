"""
Google Gemini adapter (generateContent). Port of gemini.js.

 - The API key travels in the x-goog-api-key HEADER, never in the URL, so it cannot leak into URL logs.
 - Instructions go in `systemInstruction`; the untrusted material goes in a separate user `contents` turn.
 - responseMimeType=application/json asks the API for JSON output; the caller still validates everything.
"""
from urllib.parse import quote

from .http_client import fail, post_json

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
_URI_SAFE = "!~*'()"  # same characters JS encodeURIComponent leaves alone
BLOCK_REASONS = frozenset({"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION", "OTHER"})


class GeminiProvider:
    name = "gemini"

    def __init__(self, api_key, model, base_url=BASE_URL):
        self._api_key = api_key
        self.model = model
        self._base_url = base_url

    def complete(self, system, user, timeout_ms, max_output_tokens, temperature):
        r = post_json(
            url=f"{self._base_url}/models/{quote(self.model, safe=_URI_SAFE)}:generateContent",
            headers={"Content-Type": "application/json", "x-goog-api-key": self._api_key},
            body={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {
                    "temperature": temperature,
                    "maxOutputTokens": max_output_tokens,
                    "responseMimeType": "application/json",
                },
            },
            timeout_ms=timeout_ms,
            secrets=[self._api_key],
        )
        if not r["ok"]:
            return r

        data = r["json"]
        feedback = data.get("promptFeedback")
        block_reason = feedback.get("blockReason") if isinstance(feedback, dict) else None
        if block_reason:
            return fail("BLOCKED_BY_PROVIDER", f"The AI provider blocked the request ({str(block_reason)[:40]}).", False)

        candidates = data.get("candidates")
        cand = candidates[0] if isinstance(candidates, list) and candidates else None
        if not isinstance(cand, dict):
            return fail("EMPTY_RESPONSE", "The AI provider returned no candidates.", True)

        finish = cand.get("finishReason")
        if isinstance(finish, str) and finish in BLOCK_REASONS:
            return fail("BLOCKED_BY_PROVIDER", f"The AI provider stopped the answer ({finish}).", False)
        if finish == "MAX_TOKENS":
            return fail("RESPONSE_TRUNCATED",
                        "The AI answer was cut off at the output token limit. Raise LLM_MAX_OUTPUT_TOKENS.", False)

        content = cand.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        parts = parts if isinstance(parts, list) else []
        # Skip "thought" parts: thinking-capable models may return their reasoning alongside the answer.
        text = "".join(p["text"] for p in parts
                       if isinstance(p, dict) and isinstance(p.get("text"), str) and not p.get("thought"))
        usage = data.get("usageMetadata") if isinstance(data.get("usageMetadata"), dict) else {}
        return {
            "ok": True,
            "text": text,
            "finishReason": finish or None,
            "usage": {"promptTokens": usage.get("promptTokenCount"), "outputTokens": usage.get("candidatesTokenCount")},
        }


def create_gemini_provider(api_key, model, base_url=BASE_URL):
    return GeminiProvider(api_key, model, base_url)
