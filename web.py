#!/usr/bin/env python3
"""HTML (web) entry point for Nemesis.

Usage:
    python web.py

Opens a local web UI in your browser. AUTHORIZED USE ONLY — only scan targets
you own or are permitted to test.
"""
from __future__ import annotations

import sys


def main() -> int:
    try:
        from webapp.server import main as run
    except ModuleNotFoundError as e:
        print(f"[!] Missing dependency: {e.name}")
        print("    pip install -r requirements.txt")
        return 1
    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
