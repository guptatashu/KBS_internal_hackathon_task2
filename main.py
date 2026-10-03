"""Connects all components:  input -> validate -> Etherscan fetch -> preprocess -> scan -> (optional) AI analysis."""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")  # reads ETHERSCAN_API_KEY from the .env file

from Input_basic import get_address, validate_address         # Component 1
from fetch_verified_source import fetch_verified_source       # Component 2
from preprocessor.preprocess_source import preprocess_source  # Component 3
from scanner.scan_source import scan_source                   # Component 4
from llm.config import create_provider                        # LLM transport (key check only)
from analyzer import analyze_contract                          # Component 5
from report import print_analysis, print_scan_report


def main():
    while True:
        address = get_address()

        if not validate_address(address):
            print("Invalid address. Please try again.")
            continue

        print("Fetching source from Etherscan...")
        c2 = fetch_verified_source(address)
        if not c2["ok"]:
            print("Error:", c2["error"]["message"])
            continue  # let the user try another address

        data = c2["data"]
        print("\nContract: ", data["contractName"])
        print("Compiler: ", data["compilerVersion"])
        print("Format:   ", data["sourceFormat"])
        print("Proxy:    ", data["isProxy"])
        print("Files:    ", [f["path"] for f in data["files"]])
        if data["isProxy"]:
            print("Note:      this is a proxy; the real logic is at", data["implementationAddress"])

        c3 = preprocess_source(c2)
        if not c3["ok"]:
            print("Preprocess error:", c3["error"]["message"])
            continue

        c4 = scan_source(c3)
        if not c4["ok"]:
            print("Scan error:", c4["error"]["message"])
            continue

        print("\n=== Scan results ===")
        print_scan_report(c4["result"])

        # Component 5 (optional): only offered when an LLM key is configured. Sends the source + signals to that provider.
        if create_provider()["ok"]:
            if input("\nRun the AI analysis (sends the contract source to the LLM provider)? [y/N] ").strip().lower() == "y":
                print("Analyzing...")
                c5 = analyze_contract(c3, c4)
                if c5["ok"]:
                    print_analysis(c5)
                else:
                    print("AI analysis unavailable:", c5["error"]["message"])
        break


if __name__ == "__main__":
    main()
