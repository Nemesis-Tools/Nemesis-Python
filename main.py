#!/usr/bin/env python3
"""Nemesis — GUI entry point.

Usage:
    python main.py

AUTHORIZED USE ONLY. Only scan targets you own or are explicitly permitted to
test (bug bounty program scope, written authorization, etc.).
"""
from __future__ import annotations

import sys


def main() -> int:
    try:
        from gui.main_window import run_app
    except ModuleNotFoundError as e:
        print(f"[!] Missing dependency: {e.name}")
        print("    Install requirements first:  pip install -r requirements.txt")
        return 1
    run_app()
    return 0


if __name__ == "__main__":
    sys.exit(main())
