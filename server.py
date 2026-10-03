"""
Chain-Mind web server: serves the report UI and streams the REAL pipeline's progress to it.

    python server.py                      ->  http://127.0.0.1:8000

Endpoints
  GET /                                   the UI
  GET /api/health                         which optional parts are configured (never returns a key)
  GET /api/scan/stream?address=0x...      Server-Sent Events: one "stage" event per real pipeline step, then
        [&ai=0]  [&demo=1]                "report" (or "fatal"). ai=0 skips the AI step; demo=1 uses the built-in sample.

All API keys stay in this process (read from the environment / .env by the existing components). The browser only
ever receives the assembled report. NOTE: this server spends your Etherscan / LLM quota on request, so it listens on
localhost by default. Do not expose it to the internet without adding authentication and rate limiting.
"""
import json
import os
import queue
import threading
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from flask import Flask, Response, jsonify, request, send_from_directory

from llm.config import create_provider
from webapp.pipeline import run_scan

STATIC_DIR = Path(__file__).parent / "webapp" / "static"
HEARTBEAT_SECONDS = 15
MAX_ADDRESS_CHARS = 100

# The UI loads only its own files (plus Google Fonts). Untrusted contract text is rendered with textContent.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def _sse(event_type, payload):
    return f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def create_app(components=None, max_concurrent=None):
    """`components` lets tests swap in fakes (no network). Production uses the real ones."""
    app = Flask(__name__, static_folder=None)
    slots = threading.BoundedSemaphore(max_concurrent or int(os.getenv("CHAINMIND_MAX_CONCURRENT", "2")))

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
        return resp

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC_DIR, name)

    @app.get("/api/health")
    def health():
        made = create_provider()
        ai = {"configured": bool(made.get("ok"))}
        if made.get("ok"):
            ai.update(provider=made["provider"].name, model=made["provider"].model)
        return jsonify({"ok": True, "ai": ai, "etherscanConfigured": bool(os.getenv("ETHERSCAN_API_KEY"))})

    @app.get("/api/scan/stream")
    def scan_stream():
        address = request.args.get("address", "").strip()[:MAX_ADDRESS_CHARS]
        include_ai = request.args.get("ai", "1") != "0"
        demo = request.args.get("demo") == "1"

        def generate():
            if not slots.acquire(blocking=False):
                yield _sse("fatal", {"type": "fatal", "error": {
                    "code": "SERVER_BUSY", "retryable": True,
                    "message": "The server is already running the maximum number of scans. Try again in a moment."}})
                return

            events, done, cancel = queue.Queue(), object(), threading.Event()

            def worker():
                try:
                    for ev in run_scan(address, include_ai=include_ai, demo=demo, components=components):
                        if cancel.is_set():   # the browser left; stop before starting the next (billable) stage
                            break
                        events.put(ev)
                finally:
                    events.put(done)
                    slots.release()

            threading.Thread(target=worker, daemon=True).start()
            try:
                while True:
                    try:
                        ev = events.get(timeout=HEARTBEAT_SECONDS)
                    except queue.Empty:
                        yield ": keep-alive\n\n"   # a long AI call must not look like a dead connection
                        continue
                    if ev is done:
                        return
                    yield _sse(ev["type"], ev)
            finally:
                cancel.set()

        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})

    return app


app = create_app()

if __name__ == "__main__":
    host = os.getenv("CHAINMIND_HOST", "127.0.0.1")
    port = int(os.getenv("CHAINMIND_PORT", "8000"))
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: listening on a non-local address. Anyone who can reach this port can spend your API quota.")
    print(f"Chain-Mind is running at http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)