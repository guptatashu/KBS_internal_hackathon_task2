"""
Usage:
  python scan_cli.py --demo                  offline sample contract
  python scan_cli.py 0xC02a...               live: Component 2 -> 3 -> 4
  add --json to print the full raw result instead of the readable summary
"""
import json
import re
import sys

from dotenv import load_dotenv

load_dotenv()

from fetch_verified_source import fetch_verified_source
from preprocessor.preprocess_source import preprocess_source
from scanner.scan_source import scan_source
from report import print_scan_report

DEMO = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Wallet {
    address public owner = msg.sender;

    // NOTE: tx.origin is mentioned in this comment only. It is not code and is not reported.

    receive() external payable {}

    function sweep(address payable to) external {
        require(tx.origin == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
'''


def main():
    args = sys.argv[1:]
    as_json = "--json" in args
    target = next((a for a in args if a != "--json"), None)

    if target == "--demo":
        c3 = preprocess_source({"contractName": "Wallet", "compilerVersion": "v0.8.20",
                                "files": [{"path": "Wallet.sol", "content": DEMO}]})
    elif target and re.fullmatch(r"0x[a-fA-F0-9]{40}", target):
        c2 = fetch_verified_source(target)
        if not c2["ok"]:
            print("Component 2 ERROR:", c2["error"])
            sys.exit(1)
        c3 = preprocess_source(c2)
    else:
        print("Usage: python scan_cli.py --demo | <0x address> [--json]")
        sys.exit(1)

    if not c3["ok"]:
        print("Component 3 ERROR:", c3["error"])
        sys.exit(1)
    c4 = scan_source(c3)
    if not c4["ok"]:
        print("Component 4 ERROR:", c4["error"])
        sys.exit(1)

    if as_json:
        print(json.dumps(c4["result"], indent=2))
    else:
        print_scan_report(c4["result"])


if __name__ == "__main__":
    main()
