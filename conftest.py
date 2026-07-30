"""Pytest bootstrap: make the repository root importable.

pytest's default (prepend) import mode adds the directory of the top-most
conftest.py to sys.path, so placing this file at the repo root guarantees
`import core` / `import modules` work regardless of the invocation directory.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
