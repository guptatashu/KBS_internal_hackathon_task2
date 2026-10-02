"""Web layer tests. Run from the project root:  python -m unittest discover -v   (no network, no API keys needed)"""
import json
import os
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import server
from Input_basic import validate_address
from preprocessor.preprocess_source import preprocess_source
from scanner.scan_source import scan_source
from webapp.pipeline import STAGES, default_components, run_scan

SECRET = "SECRET-KEY-must-never-reach-the-browser-123"

SRC = """pragma solidity ^0.8.20;
contract Token {
    address public owner = msg.sender;
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
}
"""


def c2_ok(name="Token"):
    return {"ok": True, "data": {
        "contractName": name, "compilerVersion": "v0.8.20+commit.a1b79de6", "optimizationUsed": True, "runs": 200,
        "evmVersion": "paris", "licenseType": "MIT", "isProxy": False, "implementationAddress": None,
        "sourceFormat": "single-file", "files": [{"path": "Token.sol", "content": SRC}]}}


FAKE_ANALYSIS = {
    "analysis": {"contractPurpose": "p", "riskLevel": "MEDIUM", "summary": "s", "riskReasoning": "r", "keyFunctions": [],
                 "permissions": [], "fundMovement": [], "externalCalls": [], "interactionRisks": [],
                 "recommendations": [], "limitations": [],
                 "securityFindings": [{"title": "t", "severity": "HIGH", "observed": "o", "potentialRisk": "p",
                                       "evidence": [{"file": "Token.sol", "line": 5}], "scannerRule": "mint-function",
                                       "confidence": "HIGH"}]},
    "meta": {"provider": "fake", "model": "fake-1", "warnings": [], "dropped": [], "scannerRulesNotReferenced": [],
             "scannerFindingsProvided": 1, "disclaimer": "d"}}


def components(fetch=None, analyze=None, provider_ok=True):
    return SimpleNamespace(
        validate_address=validate_address,
        fetch=fetch or mock.Mock(return_value=c2_ok()),
        preprocess=preprocess_source,
        scan=scan_source,
        analyze=analyze or mock.Mock(return_value={"ok": True, **FAKE_ANALYSIS}),
        create_provider=lambda: ({"ok": True, "provider": SimpleNamespace(name="fake", model="fake-1")} if provider_ok
                                 else {"ok": False, "error": {"code": "MISSING_API_KEY",
                                                              "message": "No LLM provider is configured on the server.",
                                                              "retryable": False}}))


ADDR = "0x" + "ab" * 20


def run(**kw):
    kw.setdefault("components", components())
    return list(run_scan(kw.pop("address", ADDR), **kw))


def stage_log(events):
    return [(e["stage"], e["status"]) for e in events if e["type"] == "stage"]


def parse_sse(raw):
    out = []
    for block in raw.split("\n\n"):
        lines = [l for l in block.split("\n") if l and not l.startswith(":")]
        if not lines:
            continue
        name = next(l[7:] for l in lines if l.startswith("event: "))
        data = json.loads(next(l[6:] for l in lines if l.startswith("data: ")))
        out.append((name, data))
    return out


class PipelineTests(unittest.TestCase):
    def test_full_run_reports_each_real_stage_in_order(self):
        ev = run()
        self.assertEqual(stage_log(ev), [(s, st) for s in STAGES for st in ("running", "done")])
        self.assertEqual(ev[-1]["type"], "report")
        r = ev[-1]["report"]
        self.assertEqual((r["mode"], r["address"], r["contract"]["name"]), ("live", ADDR, "Token"))
        self.assertEqual(r["ai"]["status"], "ok")
        self.assertEqual(r["scan"]["summary"]["rulesTriggered"][0], "mint-function")   # real scanner ran on the fake source

    def test_stage_events_carry_real_details_and_durations(self):
        done = {e["stage"]: e for e in run() if e["type"] == "stage" and e["status"] == "done"}
        self.assertIn("Token", done["INGEST"]["detail"])
        self.assertIn("1 file", done["INSPECT"]["detail"])
        self.assertIn("signal", done["DETECT"]["detail"])
        self.assertIn("MEDIUM", done["INTERPRET"]["detail"])
        self.assertTrue(all(isinstance(e["durationMs"], int) for e in done.values()))

    def test_ingest_failure_stops_the_pipeline_and_later_stages_never_start(self):
        comp = components(fetch=mock.Mock(return_value={"ok": False, "error": {
            "code": "NOT_VERIFIED", "message": "No verified source.", "retryable": False}}))
        ev = run(components=comp)
        self.assertEqual(stage_log(ev), [("INGEST", "running"), ("INGEST", "failed")])
        self.assertEqual(ev[-1]["type"], "fatal")
        self.assertEqual(ev[-1]["error"]["code"], "NOT_VERIFIED")
        self.assertFalse(any(e["type"] == "report" for e in ev))

    def test_invalid_address_never_reaches_etherscan(self):
        comp = components()
        ev = run(address="0x123", components=comp)
        comp.fetch.assert_not_called()
        self.assertEqual(ev[-1]["error"]["code"], "INVALID_ADDRESS")

    def test_missing_ai_key_skips_interpret_honestly_and_still_reports(self):
        ev = run(components=components(provider_ok=False))
        self.assertIn(("INTERPRET", "skipped"), stage_log(ev))
        self.assertNotIn(("INTERPRET", "done"), stage_log(ev))
        r = ev[-1]["report"]
        self.assertEqual(r["ai"]["status"], "unavailable")
        self.assertNotIn("analysis", r["ai"])

    def test_ai_can_be_turned_off_per_scan(self):
        comp = components()
        ev = run(include_ai=False, components=comp)
        comp.analyze.assert_not_called()
        self.assertEqual(ev[-1]["report"]["ai"]["status"], "skipped")

    def test_ai_failure_is_reported_but_scan_results_survive(self):
        bad = mock.Mock(return_value={"ok": False, "error": {
            "code": "RATE_LIMITED", "message": "Slow down.", "retryable": True, "retryAfterMs": 4000,
            "providerMessage": "leaky provider text", "status": 429}})
        ev = run(components=components(analyze=bad))
        self.assertIn(("INTERPRET", "failed"), stage_log(ev))
        self.assertIn(("REPORT", "done"), stage_log(ev))
        r = ev[-1]["report"]
        self.assertEqual(r["ai"]["status"], "failed")
        self.assertEqual(set(r["ai"]["error"]), {"code", "message", "retryable", "retryAfterMs"})   # nothing extra leaks
        self.assertGreater(r["scan"]["summary"]["totalFindings"], 0)

    def test_component_that_crashes_ends_with_fatal_not_an_exception(self):
        comp = components(fetch=mock.Mock(side_effect=RuntimeError("boom with /secret/path")))
        ev = run(components=comp)
        self.assertEqual(ev[-1]["type"], "fatal")
        self.assertEqual(ev[-1]["error"]["code"], "INTERNAL_ERROR")
        self.assertNotIn("secret", json.dumps(ev))

    def test_demo_mode_runs_real_c3_c4_c5_validation_on_the_recorded_answer(self):
        ev = list(run_scan(None, demo=True))     # default (real) components, no network
        r = ev[-1]["report"]
        self.assertEqual((r["mode"], r["address"], r["ai"]["status"]), ("demo", None, "ok"))
        self.assertTrue(r["ai"]["demo"])
        self.assertEqual(r["ai"]["analysis"]["riskLevel"], "HIGH")
        self.assertIn("recorded", r["ai"]["meta"]["model"])

    def test_evidence_carries_real_code_context_with_the_cited_line_marked(self):
        r = list(run_scan(None, demo=True))[-1]["report"]
        tx = next(f for f in r["scan"]["findings"] if f["rule"] == "tx-origin")
        ctx = tx["evidence"][0]["context"]
        hit = [c for c in ctx if c["hit"]]
        self.assertEqual(len(hit), 1)
        self.assertIn("tx.origin", hit[0]["text"])
        self.assertEqual(hit[0]["n"], tx["evidence"][0]["line"])
        ai_ev = r["ai"]["analysis"]["securityFindings"][0]["evidence"][0]
        self.assertTrue(any(c["hit"] for c in ai_ev["context"]))

    def test_report_never_contains_whole_source_files(self):
        r = run()[-1]["report"]
        for f in r["contract"]["files"]:
            self.assertEqual(set(f), {"path", "isDependency", "lines", "chars"})

        def keys(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    yield k
                    yield from keys(v)
            elif isinstance(node, list):
                for v in node:
                    yield from keys(v)
        self.assertNotIn("content", set(keys(r)))      # no file body anywhere in the report
        self.assertNotIn("combinedSource", set(keys(r)))

    def test_control_and_bidi_characters_in_displayed_code_are_made_visible(self):
        src = SRC.replace("function mint", "function mint\u202e")
        comp = components(fetch=mock.Mock(return_value={**c2_ok(), "data": {**c2_ok()["data"],
                                                                           "files": [{"path": "T.sol", "content": src}]}}))
        r = run(components=comp)[-1]["report"]
        blob = json.dumps(r, ensure_ascii=False)
        self.assertNotIn("\u202e", blob)

    def test_default_components_are_the_real_ones(self):
        from fetch_verified_source import fetch_verified_source
        self.assertIs(default_components().fetch, fetch_verified_source)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"GEMINI_API_KEY": SECRET, "ETHERSCAN_API_KEY": SECRET + "-etherscan"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def client(self, **kw):
        return server.create_app(components=kw.pop("components", components()), **kw).test_client()

    def test_index_is_served_with_a_strict_content_security_policy(self):
        r = self.client().get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", r.headers["Content-Security-Policy"].split("style-src")[0])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")

    def test_health_reports_configuration_but_never_a_key(self):
        r = self.client().get("/api/health")
        body = r.get_data(as_text=True)
        self.assertNotIn(SECRET, body)
        d = r.get_json()
        self.assertTrue(d["ai"]["configured"])
        self.assertEqual(d["ai"]["provider"], "gemini")
        self.assertTrue(d["etherscanConfigured"])

    def test_health_when_nothing_is_configured(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            d = self.client().get("/api/health").get_json()
        self.assertEqual(d["ai"], {"configured": False})
        self.assertFalse(d["etherscanConfigured"])

    def test_stream_emits_stage_events_then_the_report(self):
        r = self.client().get(f"/api/scan/stream?address={ADDR}")
        self.assertTrue(r.mimetype == "text/event-stream")
        events = parse_sse(r.get_data(as_text=True))
        names = [n for n, _ in events]
        self.assertEqual(names[-1], "report")
        self.assertEqual(names.count("stage"), 10)
        self.assertNotIn(SECRET, r.get_data(as_text=True))

    def test_stream_with_a_bad_address_ends_with_a_fatal_event(self):
        events = parse_sse(self.client().get("/api/scan/stream?address=nope").get_data(as_text=True))
        self.assertEqual(events[-1][0], "fatal")
        self.assertEqual(events[-1][1]["error"]["code"], "INVALID_ADDRESS")

    def test_demo_stream_needs_no_address_and_no_network(self):
        events = parse_sse(self.client(components=None).get("/api/scan/stream?demo=1").get_data(as_text=True))
        self.assertEqual(events[-1][0], "report")
        self.assertNotIn(SECRET, json.dumps(events))

    def test_ai_flag_zero_skips_the_ai_step(self):
        comp = components()
        self.client(components=comp).get(f"/api/scan/stream?address={ADDR}&ai=0").get_data()
        comp.analyze.assert_not_called()

    def test_second_scan_is_refused_while_the_server_is_at_capacity(self):
        gate, entered = threading.Event(), threading.Event()

        def slow_fetch(_):
            entered.set()
            gate.wait(5)
            return c2_ok()

        app = server.create_app(components=components(fetch=slow_fetch), max_concurrent=1)
        first = threading.Thread(target=lambda: app.test_client().get(f"/api/scan/stream?address={ADDR}").get_data())
        first.start()
        self.assertTrue(entered.wait(5))
        busy = parse_sse(app.test_client().get(f"/api/scan/stream?address={ADDR}").get_data(as_text=True))
        self.assertEqual(busy[-1][1]["error"]["code"], "SERVER_BUSY")
        gate.set()
        first.join(5)
        after = parse_sse(app.test_client().get(f"/api/scan/stream?address={ADDR}").get_data(as_text=True))
        self.assertEqual(after[-1][0], "report", "the slot must be released after the first scan finishes")

    def test_heartbeat_comments_keep_a_slow_stage_alive(self):
        def slow_fetch(_):
            time.sleep(0.35)
            return c2_ok()

        with mock.patch.object(server, "HEARTBEAT_SECONDS", 0.05):
            raw = self.client(components=components(fetch=slow_fetch)).get(f"/api/scan/stream?address={ADDR}").get_data(as_text=True)
        self.assertIn(": keep-alive", raw)
        self.assertEqual(parse_sse(raw)[-1][0], "report")

    def test_client_disconnect_stops_the_pipeline_before_the_next_stage(self):
        gate, entered = threading.Event(), threading.Event()
        comp = components(fetch=lambda _: (entered.set(), gate.wait(5), c2_ok())[2])
        comp.preprocess = mock.Mock(wraps=preprocess_source)
        resp = self.client(components=comp).get(f"/api/scan/stream?address={ADDR}")
        it = iter(resp.response)
        next(it)                       # "INGEST running"
        self.assertTrue(entered.wait(5))
        resp.response.close()          # the browser went away
        gate.set()
        time.sleep(0.3)
        comp.preprocess.assert_not_called()


if __name__ == "__main__":
    unittest.main()