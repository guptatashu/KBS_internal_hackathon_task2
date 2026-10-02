"""
Groq adapter (OpenAI-compatible chat completions). Port of groq.js.

 - Key in the Authorization header only.
 - System and user are separate chat messages.
 - response_format json_object asks for JSON (Groq requires the word "JSON" in the prompt; keep it there).
"""
import re

from .http_client import fail, post_json

BASE_URL = "https://api.groq.com/openai/v1"


class GroqProvider:
    name = "groq"

    def __init__(self, api_key, model, base_url=BASE_URL):
        self._api_key = api_key
        self.model = model
        self._base_url = base_url

    def complete(self, system, user, timeout_ms, max_output_tokens, temperature):
        r = post_json(
            url=f"{self._base_url}/chat/completions",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"},
            body={
                "model": self.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": temperature,
                "max_tokens": max_output_tokens,
                "response_format": {"type": "json_object"},
            },
            timeout_ms=timeout_ms,
            secrets=[self._api_key],
        )

        if not r["ok"]:
            # Groq rejects with 400 json_validate_failed when the model's JSON was invalid:
            # retryable, not a config error.
            err = r["error"]
            if err.get("status") == 400 and re.search(r"json_validate_failed", err.get("providerMessage") or "", re.I):
                return fail("MALFORMED_RESPONSE", "The model produced invalid JSON.", True)
            return r

        data = r["json"]
        choices = data.get("choices")
        choice = choices[0] if isinstance(choices, list) and choices else None
        if not isinstance(choice, dict):
            return fail("EMPTY_RESPONSE", "The AI provider returned no choices.", True)
        if choice.get("finish_reason") == "length":
            return fail("RESPONSE_TRUNCATED",
                        "The AI answer was cut off at the output token limit. Raise LLM_MAX_OUTPUT_TOKENS.", False)

        message = choice.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        text = content if isinstance(content, str) else ""
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return {
            "ok": True,
            "text": text,
            "finishReason": choice.get("finish_reason") or None,
            "usage": {"promptTokens": usage.get("prompt_tokens"), "outputTokens": usage.get("completion_tokens")},
        }


def create_groq_provider(api_key, model, base_url=BASE_URL):
    return GroqProvider(api_key, model, base_url)
