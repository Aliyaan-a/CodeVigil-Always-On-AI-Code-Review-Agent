#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════
  CodeVigil — Quick Demo
  Run this to see the tool in action instantly.
═══════════════════════════════════════════════════════════

Usage:
    python3 demo.py                    # Review the included sample code
    python3 demo.py path/to/file.py    # Review your own file
    python3 demo.py --scan path/to/dir # Scan entire directory
"""

import sys
import os
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.agents.orchestrator import Orchestrator
from src.schemas.config import CodeVigilConfig
from src.reporters.console_reporter import ConsoleReporter
from src.reporters.html_reporter import HTMLReporter
from src.reporters.markdown_reporter import MarkdownReporter
from src.reporters.json_reporter import JSONReporter

# ── Sample bad code (used if no file is provided) ─────────────

DEMO_CODE = '''
import os
import pickle
from os import *

API_KEY = "sk-1234567890abcdef1234567890abcdef"
password = "hardcoded_password_123"
DEBUG = True

def ProcessUserData(user_id, data=[], config={}, options=None, verbose=False, retry=3):
    """Process user data."""
    eval(data)
    os.system(f"echo {user_id}")
    loaded = pickle.loads(data)

    if loaded == None:
        for item in loaded:
            if item > 0:
                for sub in item:
                    if sub:
                        for x in sub:
                            if x > 10:
                                if x < 100:
                                    data += str(x)
    return loaded
    print("unreachable")

class bad_class:
    def __init__(self):
        return True

    def process(self):
        try:
            self._work()
        except:
            pass

    def _work(self):
        pass

settings = {"mode": "fast", "timeout": 30, "mode": "slow"}
list = [1, 2, 3]

import hashlib
weak_hash = hashlib.md5(b"data")
'''


def _safe_print(text: str = "") -> None:
    """Print that doesn't crash on Windows terminals with limited encoding."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


def main():
    _safe_print()
    _safe_print("  +=====================================================+")
    _safe_print("  |   CodeVigil -- AI Code Review Agent Demo         |")
    _safe_print("  +=====================================================+")
    _safe_print()

    # Parse arguments
    args = sys.argv[1:]
    scan_mode = False
    target = None

    if "--help" in args or "-h" in args:
        _safe_print(__doc__)
        return

    if "--scan" in args:
        scan_mode = True
        idx = args.index("--scan")
        if idx + 1 < len(args):
            target = args[idx + 1]
        else:
            _safe_print("  Error: --scan requires a directory path")
            return
    elif args:
        target = args[0]

    # Configure (LLM disabled — no API key needed)
    config = CodeVigilConfig()
    config.analyzers.llm.enabled = False

    orch = Orchestrator(config)

    if scan_mode and target:
        # -- Scan a directory -----------------------------------
        _safe_print(f"  Scanning directory: {target}")
        _safe_print(f"  {'─' * 50}")
        report = orch.scan_directory(target)

    elif target:
        # -- Review a specific file -----------------------------
        _safe_print(f"  Reviewing file: {target}")
        _safe_print(f"  {'─' * 50}")
        report = orch.review_file(target)

    else:
        # -- Demo mode: review built-in sample code -------------
        _safe_print("  No file specified -- running demo on sample bad code")
        _safe_print("  (Tip: python3 demo.py yourfile.py)")
        _safe_print(f"  {'-' * 50}")

        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, prefix="demo_"
        ) as f:
            f.write(DEMO_CODE)
            demo_path = f.name

        report = orch.review_file(demo_path)
        os.unlink(demo_path)

    # ── Display console report ────────────────────────────────
    reporter = ConsoleReporter(use_color=True)
    reporter.render(report)

    # -- Also generate HTML report ----------------------------
    html_path = "codevigil_report.html"
    HTMLReporter().render(report, output_path=html_path)
    _safe_print(f"  HTML report saved to: {html_path}")
    _safe_print(f"     Open it in your browser for a beautiful visual report!")
    _safe_print()

    # -- Quick stats ------------------------------------------
    if report.score:
        grade = report.score.grade
        if grade in ("A", "B"):
            verdict = "PASS - Great code quality!"
        elif grade == "C":
            verdict = "WARN - Decent, but room for improvement."
        else:
            verdict = "FAIL - Significant issues found."
        _safe_print(f"  Verdict: {verdict}")
        _safe_print()


if __name__ == "__main__":
    main()
