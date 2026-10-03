
# Chain-Mind

**A smart-contract intelligence report for any verified Ethereum contract: paste an address, get a structured, evidence-backed summary of what the contract does, who controls it, and where funds can move.**

> **Honest status:** Chain-Mind is an AI-assisted hackathon prototype. Its deterministic scanner matches text patterns and its AI step can be wrong. **Neither is a replacement for a professional smart-contract audit**, and a `LOW` rating never means "safe".

---

## The problem

Before interacting with a contract, most people can't tell whether its owner can mint unlimited tokens, pause transfers, or drain the balance. The answers are in the Solidity source, but reading it takes expertise and time. Chain-Mind does a fast first-pass triage: it surfaces the powers and risky patterns in a contract and points at the exact lines, so a human knows where to look.

## What you get

For each scan, one report with:

1. **Overview**: address, contract name, compiler, proxy status, files
2. **Risk**: `LOW` / `MEDIUM` / `HIGH` with a short explanation
3. **Security signals**: severity, explanation, and the source lines as evidence
4. **Permissions**: owner/admin roles and privileged functions
5. **Fund movement**: functions that can transfer, mint or withdraw assets
6. **Key functions**: the important entry points, explained briefly
7. **AI assessment**: a plain-language interpretation, with its limitations

## Pipeline

Every step is a real component call. The UI shows a stage as running, done, failed or skipped only from that component's actual result, and nothing is simulated.

```
 address
    │
    ▼
 INGEST     validate address → fetch verified source from Etherscan        fetch_verified_source.py
    ▼
 INSPECT    normalise files, flag library code                             preprocessor/
    ▼
 DETECT     deterministic pattern scan → evidence-backed signals           scanner/
    ▼
 INTERPRET  LLM explains the code + signals, output validated    (optional) analyzer/ + llm/
    ▼
 REPORT     assemble the report the browser renders                        webapp/pipeline.py
```

The web server streams these stages to the browser as Server-Sent Events. If the AI step is unavailable or fails, the scan results are still returned. A failed AI step never loses the deterministic findings.

## Technologies

- **Python 3.10+**, Flask (web server, SSE), `requests`, `python-dotenv`
- **Etherscan API V2** for verified source (Ethereum mainnet, chain id 1)
- **Gemini or Groq** as the optional LLM (plain HTTPS, no SDK)
- **Vanilla JavaScript (ES modules) + CSS** frontend, with no build step and no framework
- Standard-library `unittest` for tests (no network or keys needed)

## How the deterministic scanner works

`scanner/` is a rule engine over source text. There is no LLM and no network, and the same input always gives the same output.

1. Comments are removed and string literals are masked, so a pattern mentioned only in a comment is not reported.
2. Solidity functions are located and their access control is classified: role modifier, inline caller check, caller-scoped, or none detected.
3. Eight rules run:

| Rule | Severity | Looks for |
|---|---|---|
| `tx-origin` | medium | any use of `tx.origin` (the harmless `== msg.sender` form is annotated as such) |
| `selfdestruct` | high | contract-destroying code |
| `delegatecall` | high | execution of external code in this contract's context |
| `low-level-call` | low | raw `.call{…}` / `.call(…)` external calls |
| `owner-controlled-functions` | low | functions gated to an owner/admin role |
| `mint-function` | medium | functions that create supply |
| `pause-mechanism` | low | pause/unpause or freeze controls |
| `fund-withdrawal` | medium | functions that move ETH/tokens out |

4. Each hit becomes a **signal** with file, line, snippet and an access-control note. There is deliberately no overall score or "vulnerable / safe" verdict.

## How the LLM component works

`analyzer/` + `llm/` turn the code and scanner signals into a structured analysis.

- **Separated prompt.** The system message holds only fixed instructions and the output schema. Contract code goes in the user message, inside a data block marked with a random per-request id, and is treated as untrusted, so instructions hidden in a contract (prompt injection) shouldn't be followed.
- **Grounded output.** The model must return one JSON object with a fixed schema.
- **Validated before use.** `analyzer/validate.py` keeps only whitelisted fields and checks enums. It verifies that named functions exist in the shown source and that evidence points at real file/line locations, and it **discards any finding it can't ground**. Empty, non-JSON or wrong-shape answers get one retry, then surface as a clear "AI analysis unavailable" state.
- **Resilient transport.** Timeouts, bounded retries with back-off, and Retry-After handling for rate limits. Large contracts are truncated to a prompt budget, and the report says when coverage is partial.
- **Contract source is sent to the chosen LLM provider only when the AI step runs.** Provider keys, raw provider errors and the API URLs never reach the browser.

## API setup

1. **Etherscan** (required): create a free key at <https://etherscan.io/apis>.
2. **LLM** (optional, but the INTERPRET stage and AI assessment need it): a key from [Google AI Studio](https://aistudio.google.com/) (Gemini) **or** [Groq](https://console.groq.com/). Set only one.

```bash
cp .env.example .env     # then edit .env
```

| Variable | Purpose | Default |
|---|---|---|
| `ETHERSCAN_API_KEY` | Source retrieval | required |
| `GEMINI_API_KEY` / `GROQ_API_KEY` | LLM provider (Gemini wins if both are set) | none |
| `LLM_PROVIDER` | Force `gemini` or `groq` | auto |
| `GEMINI_MODEL` / `GROQ_MODEL` | Model override | `gemini-2.5-flash` / `llama-3.3-70b-versatile` |
| `LLM_MAX_PROMPT_CHARS` | Prompt budget (try `24000` on Groq's free tier) | `150000` |
| `LLM_TIMEOUT_MS`, `LLM_MAX_ATTEMPTS`, … | Transport tuning | see `.env.example` |
| `CHAINMIND_HOST` / `CHAINMIND_PORT` | Server bind | `127.0.0.1` / `8000` |
| `CHAINMIND_MAX_CONCURRENT` | Simultaneous scans | `2` |

Keys are read from the environment on the server only. `.env` is git-ignored, so **never commit it**.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python server.py            # web UI → http://127.0.0.1:8000
```

Command-line alternatives:

```bash
python scan_cli.py --demo                    # offline scanner demo, no keys
python scan_cli.py 0x<address>               # live: Etherscan → scanner
python analyze_cli.py --demo --dry-run       # show the exact LLM prompt, no key, no API call
python main.py                               # interactive: scan, then optionally AI analysis
```

The stream endpoint also supports `?demo=1` (built-in sample plus a *recorded* AI answer, clearly labelled as a demo in the report) and `?ai=0` (skip the AI step).

### Tests

```bash
python -m unittest discover -v     # no network, no API keys
```

### Project layout

```
server.py                  Flask app: UI, /api/health, /api/scan/stream (SSE)
webapp/pipeline.py         runs the real components stage by stage, builds the report
webapp/static/             index.html, app.css, js/ (app, dom, highlight, report)
fetch_verified_source.py   Etherscan client (never raises; structured errors)
preprocessor/              source normalisation, comment stripping
scanner/                   rule engine + rules/
analyzer/                  prompt building, source view, response validation
llm/                       provider selection, retry wrapper, Gemini + Groq adapters
tests/                     unit and web-layer tests
```

## Limitations

- **Not an audit.** The scanner is text-pattern matching, with no compiler, AST, data-flow or inheritance resolution, so it can't prove that an access check actually enforces anything. Whole vulnerability classes (reentrancy ordering, arithmetic, oracle manipulation, economic attacks) are out of scope.
- **Absence of signals ≠ safety.** False positives and false negatives are both expected.
- **The AI can be wrong.** Validation removes ungrounded claims but can't verify its reasoning. Treat it as a reading aid.
- **Verified Solidity on Ethereum mainnet only.** Unverified contracts, Vyper, and other chains aren't supported. For proxies, the proxy's own source is analysed, and the implementation address is shown but not scanned.
- **Partial coverage on huge contracts**, because source is truncated to the prompt budget. This is flagged in the report.
- **Path-based library detection** (OpenZeppelin, solmate, …) is a heuristic.
- **Local tool, not a hosted service.** The server spends your Etherscan/LLM quota per request. It binds to localhost, and the concurrency cap is not authentication or rate limiting. Don't expose it publicly as-is.
- Scan history lives in the browser only; there is no database.

## Future improvements

- Parse with a real Solidity AST (e.g. Slither or solc output) instead of text patterns
- Follow proxies and scan the implementation contract
- More chains, plus bytecode-level analysis for unverified contracts
- Cross-check rules against known-vulnerable contract corpora to measure precision/recall
- Exportable PDF/Markdown reports and shareable report links
- Authentication and rate limiting for a hosted deployment

---

*Chain-Mind was built for a hackathon with AI assistance. Use it to decide where to look, not to decide whether to trust.*
# KBS_internal_hackathon_task2
e4e51b62c1f2c28062bb21ffcc958d8616922d5a
