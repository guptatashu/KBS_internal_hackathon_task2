"""
Test Component 5 without any frontend.

  python analyze_cli.py --demo --dry-run                 show the EXACT prompt that would be sent. No API call, no key.
  python analyze_cli.py --demo --response-file F.json    pretend F.json is the model's answer and run validation. No key.
  python analyze_cli.py --demo                           real LLM call on the built-in sample (needs GEMINI_API_KEY or GROQ_API_KEY)
  python analyze_cli.py 0xC02a...                        live: Components 2 -> 3 -> 4 -> 5
  add --json to print the raw result envelope ({"ok", "analysis", "meta"} / {"ok", "error"}) instead of the readable report
"""
import argparse
import json
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from analyzer import analyze_contract, prepare_request
from fetch_verified_source import fetch_verified_source
from llm.config import get_llm_config
from preprocessor.preprocess_source import preprocess_source
from report import print_analysis
from scan_cli import DEMO
from scanner.scan_source import scan_source


class _CannedProvider:
    """Stands in for the LLM: returns the contents of a file as the model's answer."""
    name, model = "canned", "response-file"

    def __init__(self, text):
        self._text = text

    def complete(self, **_):
        return {"ok": True, "text": self._text, "finishReason": "stop", "usage": None}


def main():
    ap = argparse.ArgumentParser(description="Run Component 5 (LLM contract analysis) from the command line.")
    ap.add_argument("address", nargs="?", help="0x contract address (live: needs ETHERSCAN_API_KEY)")
    ap.add_argument("--demo", action="store_true", help="use the built-in sample contract (offline)")
    ap.add_argument("--dry-run", action="store_true", help="print the prompt that would be sent, then stop")
    ap.add_argument("--response-file", metavar="FILE", help="skip the LLM; treat FILE as the model's reply")
    ap.add_argument("--json", action="store_true", help="print the raw result envelope as JSON")
    args = ap.parse_args()

    if args.demo:
        c3 = preprocess_source({"contractName": "Wallet", "compilerVersion": "v0.8.20",
                                "files": [{"path": "Wallet.sol", "content": DEMO}]})
    elif args.address and re.fullmatch(r"0x[a-fA-F0-9]{40}", args.address):
        c2 = fetch_verified_source(args.address)
        if not c2["ok"]:
            sys.exit(f"Component 2 ERROR: {c2['error']['message']}")
        c3 = preprocess_source(c2)
    else:
        ap.error("give a 0x address or --demo")
    if not c3["ok"]:
        sys.exit(f"Component 3 ERROR: {c3['error']['message']}")
    c4 = scan_source(c3)
    if not c4["ok"]:
        sys.exit(f"Component 4 ERROR: {c4['error']['message']}")

    if args.dry_run:
        prep = prepare_request(c3, c4, get_llm_config())
        if not prep["ok"]:
            sys.exit(f"ERROR: {prep['error']['message']}")
        bar = "=" * 30
        print(f"{bar} SYSTEM MESSAGE (instructions only) {bar}\n{prep['system']}\n")
        print(f"{bar} USER MESSAGE (data) {bar}\n{prep['user']}\n")
        print(f"[{len(prep['system'])} + {len(prep['user'])} characters; nothing was sent]")
        return

    provider = _CannedProvider(Path(args.response_file).read_text(encoding="utf-8")) if args.response_file else None
    result = analyze_contract(c3, c4, provider=provider)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif result["ok"]:
        print_analysis(result)
    else:
        print("ERROR:", result["error"]["code"], "-", result["error"]["message"],
              "(retryable)" if result["error"]["retryable"] else "")
    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
