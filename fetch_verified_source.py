"""
Component 2: Etherscan Verified Source Fetcher (Python version)

address -> Etherscan request -> verified source code OR a structured error.
This function never raises. It always returns one of:
  {"ok": True,  "data":  {...contract info and source...}}
  {"ok": False, "error": {"code": ..., "message": ..., "retryable": ...}}
"""
import json
import os
import re
import time

import requests

ETHERSCAN_URL = "https://api.etherscan.io/v2/api"  # Etherscan API V2
DEFAULT_CHAIN_ID = 1                                # 1 = Ethereum mainnet
REQUEST_TIMEOUT = 10                                # seconds
RATE_LIMIT_RETRY_DELAY = 1.2                        # seconds
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _fail(code, message, retryable=False):
    return {"ok": False, "error": {"code": code, "message": message, "retryable": retryable}}


def fetch_verified_source(address, chain_id=DEFAULT_CHAIN_ID, api_key=None):
    try:
        api_key = api_key or os.getenv("ETHERSCAN_API_KEY")
        if not api_key:
            return _fail("MISSING_API_KEY", "No Etherscan API key found. Put it in your .env file.")
        if not isinstance(address, str) or not ADDRESS_RE.fullmatch(address):
            return _fail("INVALID_ADDRESS", "Address must be 0x followed by 40 hex characters.")

        params = {
            "chainid": str(chain_id),
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        }

        attempt = _request_once(params)
        # One polite retry if we hit the rate limit
        if not attempt["ok"] and attempt["error"]["code"] == "RATE_LIMITED":
            time.sleep(RATE_LIMIT_RETRY_DELAY)
            attempt = _request_once(params)
        if not attempt["ok"]:
            return attempt

        return _interpret_response(attempt["json"])
    except Exception as err:  # safety net so the program never crashes
        return _fail("NETWORK_ERROR", "Unexpected error while contacting Etherscan. Try again.", True)


def _request_once(params):
    try:
        res = requests.get(ETHERSCAN_URL, params=params, timeout=REQUEST_TIMEOUT)
    except requests.Timeout:
        return _fail("TIMEOUT", "Etherscan did not respond in time. Try again.", True)
    except requests.RequestException:
        return _fail("NETWORK_ERROR", "Could not reach Etherscan. Check your internet and retry.", True)

    if res.status_code == 429:
        return _fail("RATE_LIMITED", "Etherscan rate limit reached. Wait a moment and retry.", True)
    if not res.ok:
        return _fail("HTTP_ERROR", f"Etherscan returned HTTP {res.status_code}.", res.status_code >= 500)

    try:
        return {"ok": True, "json": res.json()}
    except ValueError:
        return _fail("INVALID_RESPONSE", "Etherscan returned a response that is not valid JSON.")


def _interpret_response(data):
    if not isinstance(data, dict):
        return _fail("INVALID_RESPONSE", "Unexpected response shape from Etherscan.")

    # Etherscan reports failures as status "0" with a message in `result`
    if data.get("status") != "1":
        result = data.get("result")
        detail = result if isinstance(result, str) else data.get("message") or "Unknown error"
        if re.search(r"rate limit", detail, re.I):
            return _fail("RATE_LIMITED", "Etherscan rate limit reached. Wait a moment and retry.", True)
        if re.search(r"invalid api key|missing", detail, re.I):
            return _fail("INVALID_API_KEY", "Etherscan rejected the API key.")
        return _fail("API_ERROR", f"Etherscan error: {detail}")

    result = data.get("result")
    entry = result[0] if isinstance(result, list) and result else None
    if not isinstance(entry, dict) or not isinstance(entry.get("SourceCode"), str):
        return _fail("INVALID_RESPONSE", "Etherscan response is missing contract data.")

    # Unverified contracts come back with an empty SourceCode
    if entry["SourceCode"].strip() == "":
        return _fail("NOT_VERIFIED",
                     "This address has no verified source code on Etherscan "
                     "(it may be unverified or not a contract).")

    if re.match(r"vyper", entry.get("CompilerVersion") or "", re.I):
        return _fail("NOT_SOLIDITY", "This contract is verified, but it is Vyper, not Solidity.")

    try:
        fmt, files = parse_source_code(entry["SourceCode"])
    except Exception:
        return _fail("INVALID_RESPONSE", "Could not parse the contract's source code.")

    try:
        runs = int(entry.get("Runs") or 0)
    except ValueError:
        runs = 0

    return {
        "ok": True,
        "data": {
            "contractName": entry.get("ContractName"),
            "compilerVersion": entry.get("CompilerVersion"),
            "optimizationUsed": entry.get("OptimizationUsed") == "1",
            "runs": runs,
            "evmVersion": entry.get("EVMVersion"),
            "licenseType": entry.get("LicenseType"),
            "isProxy": entry.get("Proxy") == "1",
            "implementationAddress": entry.get("Implementation") or None,
            "sourceFormat": fmt,   # "single-file" or "multi-file"
            "files": files,        # [{"path": ..., "content": ...}]
            "combinedSource": "\n\n".join(f"// File: {f['path']}\n{f['content']}" for f in files),
        },
    }


def parse_source_code(raw):
    """Etherscan's SourceCode comes in 3 shapes: plain text, {{json}}, or {json}."""
    text = raw.strip()

    if text.startswith("{{") and text.endswith("}}"):
        obj = json.loads(text[1:-1])
        return "multi-file", _sources_to_files(obj.get("sources"))

    if text.startswith("{"):
        try:
            obj = json.loads(text)
            files = _sources_to_files(obj.get("sources") or obj)
            if files:
                return "multi-file", files
        except ValueError:
            pass  # not JSON after all, treat as plain source

    return "single-file", [{"path": "Contract.sol", "content": raw}]


def _sources_to_files(sources):
    return [
        {"path": path, "content": v["content"]}
        for path, v in (sources or {}).items()
        if isinstance(v, dict) and isinstance(v.get("content"), str)
    ]
