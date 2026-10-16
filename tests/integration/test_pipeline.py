"""Integration tests for the full orchestrator pipeline."""

from __future__ import annotations

import pytest
import tempfile
from pathlib import Path

from src.agents.orchestrator import Orchestrator
from src.schemas.config import CodeVigilConfig
from src.schemas.findings import Severity
from src.reporters.json_reporter import JSONReporter
from src.reporters.markdown_reporter import MarkdownReporter
from src.reporters.html_reporter import HTMLReporter
from src.reporters.sarif_reporter import SARIFReporter
from src.reporters.console_reporter import ConsoleReporter


SAMPLE_BAD_CODE = '''
import os
import pickle
from os import *

API_KEY = "sk-1234567890abcdef1234567890abcdef"
password = "hardcoded_password_123"

def processData(input, list, data=[], config={}):
    eval(input)
    os.system(f"echo {input}")
    result = pickle.loads(data)
    if result == None:
        for item in result:
            if item > 0:
                for sub in item:
                    if sub:
                        for x in sub:
                            if x > 10:
                                if x < 100:
                                    data += str(x)
    return result
    print("unreachable")

class bad_class:
    def __init__(self):
        return 42

    def BadMethod(self):
        pass
'''

SAMPLE_GOOD_CODE = '''"""A well-structured module."""

from __future__ import annotations

from typing import Optional


def calculate_total(items: list[float], tax_rate: float = 0.0) -> float:
    """Calculate the total price with tax.

    Args:
        items: List of item prices.
        tax_rate: Tax rate as a decimal (0.0 to 1.0).

    Returns:
        Total price including tax.
    """
    subtotal = sum(items)
    return subtotal * (1 + tax_rate)


class ShoppingCart:
    """A simple shopping cart."""

    def __init__(self, owner: str) -> None:
        """Initialize the cart.

        Args:
            owner: Name of the cart owner.
        """
        self._owner = owner
        self._items: list[float] = []

    def add_item(self, price: float) -> None:
        """Add an item to the cart.

        Args:
            price: Price of the item.
        """
        if price < 0:
            raise ValueError("Price cannot be negative")
        self._items.append(price)

    @property
    def total(self) -> float:
        """Get the cart total."""
        return calculate_total(self._items)
'''


@pytest.fixture
def bad_code_file(tmp_path):
    f = tmp_path / "bad_code.py"
    f.write_text(SAMPLE_BAD_CODE)
    return str(f)


@pytest.fixture
def good_code_file(tmp_path):
    f = tmp_path / "good_code.py"
    f.write_text(SAMPLE_GOOD_CODE)
    return str(f)


@pytest.fixture
def config():
    """Config with LLM disabled for testing."""
    cfg = CodeVigilConfig()
    cfg.analyzers.llm.enabled = False
    return cfg


class TestOrchestratorPipeline:
    def test_review_bad_file_finds_issues(self, bad_code_file, config):
        orch = Orchestrator(config)
        report = orch.review_file(bad_code_file)

        assert report.total_findings > 0
        assert report.score is not None
        assert report.score.overall < 100.0

        # Should find security issues
        categories = report.findings_by_category
        assert "security" in categories

        # Should find at least some of these
        rule_ids = {f.rule_id for fa in report.files_analyzed for f in fa.findings}
        # Hardcoded secrets
        assert rule_ids & {"SEC-001", "SEC-002"}, "Should detect hardcoded secrets"
        # Eval/exec/pickle
        assert rule_ids & {"SEC-020", "SEC-021"}, "Should detect insecure functions"
        # AST issues
        assert "AST-001" in rule_ids, "Should detect mutable defaults"

    def test_review_good_file_scores_well(self, good_code_file, config):
        orch = Orchestrator(config)
        report = orch.review_file(good_code_file)

        assert report.score is not None
        # Good code should score well (not necessarily perfect due to style checks)
        assert report.score.overall >= 70.0

        # Should have no critical/error security findings
        critical_security = [
            f for fa in report.files_analyzed for f in fa.findings
            if f.severity in (Severity.CRITICAL, Severity.ERROR)
            and f.category.value == "security"
        ]
        assert len(critical_security) == 0

    def test_scan_directory(self, tmp_path, config):
        # Create a small project
        (tmp_path / "module_a.py").write_text('"""Module A."""\n\ndef func_a() -> int:\n    """Return one."""\n    return 1\n')
        (tmp_path / "module_b.py").write_text('"""Module B."""\n\ndef func_b() -> int:\n    """Return two."""\n    return 2\n')
        (tmp_path / "README.md").write_text("# Project")  # Should be ignored

        orch = Orchestrator(config)
        report = orch.scan_directory(tmp_path)

        assert len(report.files_analyzed) == 2
        assert report.score is not None

    def test_report_contains_complexity_metrics(self, bad_code_file, config):
        orch = Orchestrator(config)
        report = orch.review_file(bad_code_file)

        all_metrics = []
        for fa in report.files_analyzed:
            all_metrics.extend(fa.complexity_metrics)

        assert len(all_metrics) > 0
        # processData should have high complexity
        proc_metrics = [m for m in all_metrics if m.function_name == "processData"]
        if proc_metrics:
            assert proc_metrics[0].cyclomatic_complexity > 5

    def test_analysis_duration_tracked(self, good_code_file, config):
        orch = Orchestrator(config)
        report = orch.review_file(good_code_file)
        assert report.analysis_duration_ms > 0
        for fa in report.files_analyzed:
            assert fa.analysis_duration_ms > 0


class TestReporters:
    @pytest.fixture
    def report(self, bad_code_file, config):
        orch = Orchestrator(config)
        return orch.review_file(bad_code_file)

    def test_json_reporter(self, report):
        reporter = JSONReporter()
        output = reporter.render(report)
        assert '"total_findings"' in output
        assert '"severity"' in output
        import json
        data = json.loads(output)
        assert "files_analyzed" in data

    def test_json_reporter_file_output(self, report, tmp_path):
        reporter = JSONReporter()
        out_path = str(tmp_path / "report.json")
        reporter.render(report, output_path=out_path)
        assert Path(out_path).exists()

    def test_markdown_reporter(self, report):
        reporter = MarkdownReporter()
        output = reporter.render(report)
        assert "# 🔍 CodeVigil Review" in output
        assert "Score:" in output

    def test_html_reporter(self, report):
        reporter = HTMLReporter()
        output = reporter.render(report)
        assert "<!DOCTYPE html>" in output
        assert "CodeVigil" in output

    def test_html_reporter_file_output(self, report, tmp_path):
        reporter = HTMLReporter()
        out_path = str(tmp_path / "report.html")
        reporter.render(report, output_path=out_path)
        assert Path(out_path).exists()
        content = Path(out_path).read_text()
        assert "<!DOCTYPE html>" in content

    def test_sarif_reporter(self, report):
        reporter = SARIFReporter()
        output = reporter.render(report)
        import json
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "CodeVigil"

    def test_console_reporter_no_crash(self, report):
        import io
        stream = io.StringIO()
        reporter = ConsoleReporter(stream=stream, use_color=False)
        reporter.render(report)
        output = stream.getvalue()
        assert "CodeVigil" in output
        assert len(output) > 100


class TestPluginIntegration:
    def test_plugins_contribute_findings(self, bad_code_file, config):
        orch = Orchestrator(config)
        report = orch.review_file(bad_code_file)

        analyzers = {f.source_analyzer for fa in report.files_analyzed for f in fa.findings}
        # Core analyzers should be present
        assert "ast_analyzer" in analyzers or "security_analyzer" in analyzers or "complexity" in analyzers

    def test_disabled_analyzer_skipped(self, bad_code_file):
        config = CodeVigilConfig()
        config.analyzers.ast.enabled = False
        config.analyzers.security.enabled = False
        config.analyzers.style.enabled = False
        config.analyzers.llm.enabled = False
        config.plugins = []

        orch = Orchestrator(config)
        report = orch.review_file(bad_code_file)
        # With everything disabled, should have no findings from core analyzers
        core_findings = [
            f for fa in report.files_analyzed for f in fa.findings
            if f.source_analyzer in ("ast_analyzer", "security_analyzer", "style_analyzer", "complexity")
        ]
        assert len(core_findings) == 0
