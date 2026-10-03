"""Regression tests: raw exception text must never reach callers (it can contain keys or provider output)."""
import unittest
from unittest import mock

from llm.client import complete_with_retry
from fetch_verified_source import fetch_verified_source

CFG = {"maxPromptChars": 10_000, "maxAttempts": 1, "timeoutMs": 1000, "maxOutputTokens": 10,
       "temperature": 0.1, "maxRetryWaitMs": 0}


class ErrorHygiene(unittest.TestCase):
    def test_provider_exception_text_is_not_returned(self):
        provider = mock.Mock()
        provider.complete.side_effect = RuntimeError("boom key=SECRET-123")
        r = complete_with_retry(provider, CFG, "sys", "user")
        self.assertFalse(r["ok"])
        self.assertNotIn("SECRET-123", str(r))

    def test_fetch_safety_net_does_not_echo_the_exception(self):
        with mock.patch("fetch_verified_source._request_once", side_effect=RuntimeError("url?apikey=SECRET-123")):
            r = fetch_verified_source("0x" + "ab" * 20, api_key="SECRET-123")
        self.assertFalse(r["ok"])
        self.assertNotIn("SECRET-123", str(r))


if __name__ == "__main__":
    unittest.main()
