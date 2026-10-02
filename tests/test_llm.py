"""Run from the project root:  python -m unittest discover -v   (no network: requests.post is mocked)"""
import json
import time
import unittest
from unittest import mock

import requests

from llm.client import complete_with_retry
from llm.config import DEFAULT_MODELS, create_provider, get_llm_config
from llm.providers.gemini import create_gemini_provider
from llm.providers.groq import create_groq_provider
from llm.providers.http_client import interpret, parse_retry_after, post_json

KEY = "sk-secret-123"
CALL = dict(system="sys", user="usr", timeout_ms=5000, max_output_tokens=100, temperature=0.1)


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None, chunks=None):
        self.status_code = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        raw = body if isinstance(body, str) else json.dumps(body if body is not None else {})
        self._chunks = chunks if chunks is not None else [raw.encode("utf-8")]
        self.closed = False

    @property
    def content(self):
        return b"".join(self._chunks)

    def close(self):
        self.closed = True


def patched_post(resp=None, exc=None):
    return mock.patch("llm.providers.http_client.requests.post",
                      side_effect=exc, return_value=resp)


def gemini_ok(text='{"a":1}', **cand):
    return {"candidates": [{"content": {"parts": [{"text": text}]}, "finishReason": "STOP", **cand}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5}}


class HttpTests(unittest.TestCase):
    def test_success_and_empty_object_is_ok(self):
        self.assertEqual(interpret(200, {}, '{"x": 1}'), {"ok": True, "json": {"x": 1}})
        self.assertTrue(interpret(200, {}, "{}")["ok"])  # {} is valid JSON; the adapter reports it as empty

    def test_2xx_with_bad_body_is_retryable_provider_error(self):
        for body in ("", "not json", "[1, 2]", "null"):
            e = interpret(200, {}, body)["error"]
            self.assertEqual((e["code"], e["retryable"]), ("PROVIDER_ERROR", True), body)

    def test_status_classification(self):
        cases = [(401, "AUTH_ERROR", False), (403, "AUTH_ERROR", False), (413, "PROMPT_TOO_LARGE", False),
                 (404, "PROVIDER_ERROR", False), (500, "PROVIDER_ERROR", True), (503, "PROVIDER_ERROR", True),
                 (418, "PROVIDER_ERROR", False), (429, "RATE_LIMITED", True)]
        for status, code, retryable in cases:
            e = interpret(status, {}, "{}")["error"]
            self.assertEqual((e["code"], e["retryable"], e["status"]), (code, retryable, status))

    def test_400_api_key_is_auth_error_other_400_is_not(self):
        body = json.dumps({"error": {"message": "API key not valid. Please pass a valid API key."}})
        self.assertEqual(interpret(400, {}, body)["error"]["code"], "AUTH_ERROR")
        self.assertEqual(interpret(400, {}, '{"error": "bad field"}')["error"]["code"], "PROVIDER_ERROR")

    def test_provider_message_shapes_and_redaction(self):
        self.assertEqual(interpret(500, {}, '{"error": "plain"}')["error"]["providerMessage"], "plain")
        self.assertEqual(interpret(500, {}, '{"message": "top"}')["error"]["providerMessage"], "top")
        e = interpret(500, {}, json.dumps({"error": {"message": f"bad key {KEY} here"}}), [KEY])["error"]
        self.assertNotIn(KEY, e["providerMessage"])
        self.assertIn("[redacted]", e["providerMessage"])

    def test_retry_after(self):
        self.assertEqual(parse_retry_after("2"), 2000)
        self.assertEqual(parse_retry_after("0.5"), 500)
        self.assertIsNone(parse_retry_after(None))
        self.assertIsNone(parse_retry_after("garbage"))
        self.assertIsNone(parse_retry_after("nan"))
        self.assertEqual(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), 0)  # past date -> 0, not negative
        self.assertEqual(interpret(429, {"retry-after": "3"}, "{}")["error"]["retryAfterMs"], 3000)

    def test_post_json_failures_never_raise(self):
        with patched_post(exc=requests.Timeout()):
            self.assertEqual(post_json("u", {}, {}, 5000)["error"]["code"], "TIMEOUT")
        with patched_post(exc=requests.ConnectionError()):
            e = post_json("u", {}, {}, 5000)["error"]
            self.assertEqual((e["code"], e["retryable"]), ("NETWORK_ERROR", True))
        with patched_post(exc=RuntimeError("boom")):
            self.assertEqual(post_json("u", {}, {}, 5000)["error"]["code"], "NETWORK_ERROR")

    def test_hard_total_deadline_even_if_the_request_hangs(self):
        def hang(*a, **kw):
            time.sleep(0.6)  # simulates a server dripping bytes: requests itself would not time out
            return FakeResponse()
        t0 = time.monotonic()
        with mock.patch("llm.providers.http_client.requests.post", side_effect=hang):
            r = post_json("u", {}, {}, 150)
        self.assertEqual(r["error"]["code"], "TIMEOUT")
        self.assertLess(time.monotonic() - t0, 0.45)  # returned at the deadline, not after the hang

    def test_success_decodes_utf8_and_closes(self):
        resp = FakeResponse(body='{"t": "caf\u00e9"}')
        with patched_post(resp):
            self.assertEqual(post_json("u", {}, {}, 5000)["json"], {"t": "caf\u00e9"})
        self.assertTrue(resp.closed)


class GeminiTests(unittest.TestCase):
    def setUp(self):
        self.p = create_gemini_provider(KEY, "gemini-2.5-flash")

    def run_with(self, body, status=200):
        with patched_post(FakeResponse(status, body)) as post:
            return self.p.complete(**CALL), post

    def test_success_request_shape_and_thought_parts_skipped(self):
        body = {"candidates": [{"content": {"parts": [{"text": "thinking...", "thought": True}, {"text": '{"a":'},
                                                      {"text": "1}"}]}, "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5}}
        r, post = self.run_with(body)
        self.assertEqual(r, {"ok": True, "text": '{"a":1}', "finishReason": "STOP",
                             "usage": {"promptTokens": 10, "outputTokens": 5}})
        args, kw = post.call_args
        self.assertEqual(args[0], "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent")
        self.assertNotIn(KEY, args[0])                                   # key never in the URL
        self.assertEqual(kw["headers"]["x-goog-api-key"], KEY)           # ... only in the header
        sent = json.loads(kw["data"])
        self.assertEqual(sent["systemInstruction"]["parts"][0]["text"], "sys")
        self.assertEqual(sent["contents"], [{"role": "user", "parts": [{"text": "usr"}]}])
        self.assertEqual(sent["generationConfig"],
                         {"temperature": 0.1, "maxOutputTokens": 100, "responseMimeType": "application/json"})

    def test_blocked_truncated_and_empty(self):
        r, _ = self.run_with({"promptFeedback": {"blockReason": "SAFETY"}})
        self.assertEqual((r["error"]["code"], r["error"]["retryable"]), ("BLOCKED_BY_PROVIDER", False))
        r, _ = self.run_with(gemini_ok(finishReason="RECITATION"))
        self.assertEqual(r["error"]["code"], "BLOCKED_BY_PROVIDER")
        r, _ = self.run_with(gemini_ok(finishReason="MAX_TOKENS"))
        self.assertEqual((r["error"]["code"], r["error"]["retryable"]), ("RESPONSE_TRUNCATED", False))
        for body in ({}, {"candidates": []}, {"candidates": [None]}):
            r, _ = self.run_with(body)
            self.assertEqual((r["error"]["code"], r["error"]["retryable"]), ("EMPTY_RESPONSE", True), body)

    def test_http_errors_pass_through_and_key_is_redacted(self):
        r, _ = self.run_with({"error": {"message": f"nope {KEY}"}}, status=429)
        self.assertEqual(r["error"]["code"], "RATE_LIMITED")
        self.assertNotIn(KEY, json.dumps(r))


class GroqTests(unittest.TestCase):
    def setUp(self):
        self.p = create_groq_provider(KEY, "llama-3.3-70b-versatile")

    def run_with(self, body, status=200):
        with patched_post(FakeResponse(status, body)) as post:
            return self.p.complete(**CALL), post

    def test_success_and_request_shape(self):
        r, post = self.run_with({"choices": [{"message": {"content": '{"a":1}'}, "finish_reason": "stop"}],
                                 "usage": {"prompt_tokens": 7, "completion_tokens": 3}})
        self.assertEqual(r, {"ok": True, "text": '{"a":1}', "finishReason": "stop",
                             "usage": {"promptTokens": 7, "outputTokens": 3}})
        args, kw = post.call_args
        self.assertEqual(args[0], "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(kw["headers"]["Authorization"], f"Bearer {KEY}")
        sent = json.loads(kw["data"])
        self.assertEqual(sent["messages"], [{"role": "system", "content": "sys"}, {"role": "user", "content": "usr"}])
        self.assertEqual((sent["max_tokens"], sent["response_format"]), (100, {"type": "json_object"}))

    def test_error_paths(self):
        r, _ = self.run_with({"choices": [{"message": {"content": "x"}, "finish_reason": "length"}]})
        self.assertEqual(r["error"]["code"], "RESPONSE_TRUNCATED")
        r, _ = self.run_with({"choices": []})
        self.assertEqual((r["error"]["code"], r["error"]["retryable"]), ("EMPTY_RESPONSE", True))
        r, _ = self.run_with({"error": {"message": "json_validate_failed: bad"}}, status=400)
        self.assertEqual((r["error"]["code"], r["error"]["retryable"]), ("MALFORMED_RESPONSE", True))
        r, _ = self.run_with({"error": {"message": "invalid api key"}}, status=401)
        self.assertEqual(r["error"]["code"], "AUTH_ERROR")


class ConfigTests(unittest.TestCase):
    def test_defaults_and_overrides(self):
        c = get_llm_config({})
        self.assertEqual((c["timeoutMs"], c["maxOutputTokens"], c["maxAttempts"], c["maxRetryWaitMs"],
                          c["maxPromptChars"], c["temperature"]), (60000, 8192, 2, 8000, 150000, 0.1))
        self.assertEqual(get_llm_config({"LLM_TIMEOUT_MS": "1500"})["timeoutMs"], 1500)

    def test_invalid_numbers_fall_back_to_defaults(self):
        for bad in ("", "abc", "0", "-5", "nan", "inf"):
            self.assertEqual(get_llm_config({"LLM_MAX_ATTEMPTS": bad})["maxAttempts"], 2, bad)

    def test_provider_selection(self):
        self.assertEqual(create_provider({})["error"]["code"], "MISSING_API_KEY")
        g = create_provider({"GEMINI_API_KEY": "k"})["provider"]
        self.assertEqual((g.name, g.model), ("gemini", DEFAULT_MODELS["gemini"]))
        q = create_provider({"GROQ_API_KEY": "k", "GROQ_MODEL": "custom"})["provider"]
        self.assertEqual((q.name, q.model), ("groq", "custom"))
        both = {"GEMINI_API_KEY": "a", "GROQ_API_KEY": "b"}
        self.assertEqual(create_provider(both)["provider"].name, "gemini")                      # gemini wins by default
        self.assertEqual(create_provider({**both, "LLM_PROVIDER": "GROQ"})["provider"].name, "groq")  # case-insensitive
        self.assertEqual(create_provider({"LLM_PROVIDER": "groq", "GEMINI_API_KEY": "a"})["error"]["code"], "MISSING_API_KEY")
        e = create_provider({"LLM_PROVIDER": "x" * 80})["error"]
        self.assertEqual(e["code"], "UNKNOWN_PROVIDER")
        self.assertLess(len(e["message"]), 120)  # echoed provider name is truncated


class FakeProvider:
    name, model = "fake", "fake-1"

    def __init__(self, *results):
        self.results, self.calls = list(results), 0

    def complete(self, **kw):
        self.calls += 1
        return self.results.pop(0)


def err(code, retryable, **extra):
    return {"ok": False, "error": {"code": code, "message": code, "retryable": retryable, **extra}}


OK = {"ok": True, "text": "{}", "finishReason": "stop", "usage": {}}
CFG = get_llm_config({})


class RetryTests(unittest.TestCase):
    def test_retries_retryable_then_succeeds(self):
        p, sleeps = FakeProvider(err("TIMEOUT", True), OK), []
        self.assertTrue(complete_with_retry(p, CFG, "s", "u", sleep=sleeps.append)["ok"])
        self.assertEqual((p.calls, sleeps), (2, [1.0]))

    def test_non_retryable_is_not_retried(self):
        p = FakeProvider(err("AUTH_ERROR", False), OK)
        self.assertEqual(complete_with_retry(p, CFG, "s", "u", sleep=lambda s: None)["error"]["code"], "AUTH_ERROR")
        self.assertEqual(p.calls, 1)

    def test_honours_retry_after_and_gives_up_when_too_long(self):
        p, sleeps = FakeProvider(err("RATE_LIMITED", True, retryAfterMs=3000), OK), []
        self.assertTrue(complete_with_retry(p, CFG, "s", "u", sleep=sleeps.append)["ok"])
        self.assertEqual(sleeps, [3.0])
        p = FakeProvider(err("RATE_LIMITED", True, retryAfterMs=60_000), OK)
        r = complete_with_retry(p, CFG, "s", "u", sleep=lambda s: self.fail("should not sleep"))
        self.assertEqual((r["error"]["code"], p.calls), ("RATE_LIMITED", 1))

    def test_attempts_are_bounded(self):
        p = FakeProvider(*[err("TIMEOUT", True)] * 5)
        r = complete_with_retry(p, {**CFG, "maxAttempts": 3}, "s", "u", sleep=lambda s: None)
        self.assertEqual((r["error"]["code"], p.calls), ("TIMEOUT", 3))

    def test_prompt_too_large_never_calls_provider(self):
        p = FakeProvider(OK)
        r = complete_with_retry(p, {**CFG, "maxPromptChars": 10}, "s" * 6, "u" * 6)
        self.assertEqual((r["error"]["code"], p.calls), ("PROMPT_TOO_LARGE", 0))

    def test_provider_exception_becomes_error(self):
        class Boom:
            def complete(self, **kw): raise RuntimeError("x")
        self.assertEqual(complete_with_retry(Boom(), CFG, "s", "u")["error"]["code"], "PROVIDER_ERROR")


if __name__ == "__main__":
    unittest.main()
