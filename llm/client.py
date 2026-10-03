"""
Retry wrapper around provider.complete(), using the retry settings from get_llm_config().
Never raises; returns the same {"ok": ...} shapes as the providers.
"""
import time

from .providers.http_client import fail


def complete_with_retry(provider, config, system, user, sleep=None):
    if len(system) + len(user) > config["maxPromptChars"]:
        return fail("PROMPT_TOO_LARGE",
                    f"The prompt is larger than the {config['maxPromptChars']}-character limit (LLM_MAX_PROMPT_CHARS).",
                    False)

    attempts = max(1, int(config["maxAttempts"]))
    result = None
    for attempt in range(1, attempts + 1):
        try:
            result = provider.complete(
                system=system, user=user,
                timeout_ms=config["timeoutMs"],
                max_output_tokens=config["maxOutputTokens"],
                temperature=config["temperature"],
            )
        except Exception as err:  # provider adapters should not raise, but never let one crash the pipeline
            return fail("PROVIDER_ERROR", "The AI provider call failed unexpectedly.", False)

        if result["ok"] or not result["error"]["retryable"] or attempt == attempts:
            return result

        # Honour the provider's Retry-After if it gave one, otherwise back off 1s, 2s, 4s...
        wait_ms = result["error"].get("retryAfterMs")
        if wait_ms is None:
            wait_ms = 1000 * 2 ** (attempt - 1)
        if wait_ms > config["maxRetryWaitMs"]:
            return result  # the provider wants a longer pause than we are willing to block for
        (sleep or time.sleep)(wait_ms / 1000)   # looked up at call time so tests can patch time.sleep
    return result
