#!/usr/bin/env python3
"""
Standalone test runner for CodeVigil.
Uses only stdlib unittest — no pytest required.

Usage: python3 run_tests.py
"""

import sys
import os
import unittest
import io
import json
import tempfile
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.complexity import analyze_complexity, compute_cyclomatic_complexity
from src.analyzers.security_analyzer import SecurityAnalyzer
from src.analyzers.style_analyzer import StyleAnalyzer
from src.parsers.ast_utils import parse_source, count_nesting_depth, extract_code_snippet
from src.parsers.diff_parser import DiffParser, ChangeType
from src.parsers.file_parser import detect_language, read_source_file
from src.schemas.findings import (
    Finding, Severity, Category, Location, Suggestion,
    ReviewScore, ReviewReport, FileAnalysis, ComplexityMetrics,
)
from src.schemas.config import CodeVigilConfig
from src.agents.aggregator import FindingAggregator
from src.agents.scorer import Scorer
from src.agents.orchestrator import Orchestrator
from src.reporters.json_reporter import JSONReporter
from src.reporters.markdown_reporter import MarkdownReporter
from src.reporters.html_reporter import HTMLReporter
from src.reporters.sarif_reporter import SARIFReporter
from src.reporters.console_reporter import ConsoleReporter


# ═══════════════════════════════════════════════════════════════════
# AST Analyzer Tests
# ═══════════════════════════════════════════════════════════════════

class TestASTAnalyzer(unittest.TestCase):

    def test_mutable_default_list(self):
        code = 'def bad(items=[]):\n    items.append(1)\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-001" for f in findings))

    def test_mutable_default_dict(self):
        code = 'def bad(config={}):\n    return config\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-001" for f in findings))

    def test_immutable_default_not_flagged(self):
        code = 'def good(count=0, name="x", flag=True):\n    pass\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertFalse(any(f.rule_id == "AST-001" for f in findings))

    def test_bare_except(self):
        code = 'try:\n    x()\nexcept:\n    pass\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-002" for f in findings))

    def test_specific_except_ok(self):
        code = 'try:\n    x()\nexcept ValueError:\n    pass\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertFalse(any(f.rule_id == "AST-002" for f in findings))

    def test_unreachable_code(self):
        code = 'def f():\n    return 42\n    x = 10\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-003" for f in findings))

    def test_shadowed_builtin(self):
        code = 'list = [1, 2, 3]\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-004" for f in findings))

    def test_star_import(self):
        code = 'from os import *\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-006" for f in findings))

    def test_empty_except_pass(self):
        code = 'try:\n    x()\nexcept Exception:\n    pass\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-009" for f in findings))

    def test_return_in_init(self):
        code = 'class C:\n    def __init__(self):\n        return 42\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-010" for f in findings))

    def test_comparison_to_none(self):
        code = 'def f(x):\n    if x == None:\n        return True\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-012" for f in findings))

    def test_duplicate_dict_keys(self):
        code = 'd = {"a": 1, "b": 2, "a": 3}\n'
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-013" for f in findings))

    def test_syntax_error(self):
        code = "def func( :"
        findings = ASTAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "AST-000" for f in findings))


# ═══════════════════════════════════════════════════════════════════
# Complexity Tests
# ═══════════════════════════════════════════════════════════════════

class TestComplexity(unittest.TestCase):

    def test_simple_function(self):
        code = 'def simple():\n    return 42\n'
        metrics, findings = analyze_complexity(code, "test.py")
        self.assertEqual(len(metrics), 1)
        self.assertEqual(metrics[0].cyclomatic_complexity, 1)
        self.assertEqual(len(findings), 0)

    def test_branching_increases_cc(self):
        code = 'def f(x):\n    if x > 0:\n        return 1\n    elif x < 0:\n        return -1\n    return 0\n'
        metrics, _ = analyze_complexity(code, "test.py")
        self.assertGreaterEqual(metrics[0].cyclomatic_complexity, 3)

    def test_high_complexity_flagged(self):
        code = 'def f(a,b,c,d):\n'
        code += '    if a:\n        if b:\n            if c:\n                if d:\n'
        code += '                    if a and b:\n                        if c or d:\n'
        code += '                            return 1\n    return 0\n'
        _, findings = analyze_complexity(code, "test.py", max_cyclomatic=3)
        self.assertTrue(any(f.rule_id == "CX-001" for f in findings))

    def test_long_function_flagged(self):
        body = "\n".join(f"    x{i} = {i}" for i in range(55))
        code = f"def long_func():\n{body}\n    return x0\n"
        _, findings = analyze_complexity(code, "test.py", max_function_length=50)
        self.assertTrue(any(f.rule_id == "CX-003" for f in findings))

    def test_too_many_params(self):
        code = 'def f(a, b, c, d, e, f, g):\n    pass\n'
        _, findings = analyze_complexity(code, "test.py", max_params=5)
        self.assertTrue(any(f.rule_id == "CX-004" for f in findings))


# ═══════════════════════════════════════════════════════════════════
# Security Analyzer Tests
# ═══════════════════════════════════════════════════════════════════

class TestSecurityAnalyzer(unittest.TestCase):

    def test_hardcoded_api_key(self):
        code = 'API_KEY = "sk-abc123def456ghi789jkl012"\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-001" for f in findings))

    def test_hardcoded_password(self):
        code = 'password = "super_secret_password_123"\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-002" for f in findings))

    def test_eval_detected(self):
        code = 'result = eval(user_input)\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-021" for f in findings))

    def test_exec_detected(self):
        code = 'exec(code_string)\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-022" for f in findings))

    def test_pickle_loads(self):
        code = 'import pickle\ndata = pickle.loads(untrusted)\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-020" for f in findings))

    def test_os_system(self):
        code = 'import os\nos.system(f"echo {x}")\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-011" for f in findings))

    def test_subprocess_shell_true(self):
        code = 'import subprocess\nsubprocess.run(cmd, shell=True)\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-011" for f in findings))

    def test_weak_hash_md5(self):
        code = 'import hashlib\nh = hashlib.md5(data)\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-023" for f in findings))

    def test_debug_mode(self):
        code = 'DEBUG = True\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-025" for f in findings))

    def test_ssl_verify_false(self):
        code = 'requests.get(url, verify=False)\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "SEC-026" for f in findings))

    def test_clean_code_no_critical_security(self):
        code = 'import os\nimport hashlib\n\ndef get_key():\n    return os.environ.get("KEY", "")\n\ndef h(d):\n    return hashlib.sha256(d.encode()).hexdigest()\n'
        findings = SecurityAnalyzer(code, "test.py").analyze()
        critical = [f for f in findings if f.severity in (Severity.ERROR, Severity.CRITICAL)]
        self.assertEqual(len(critical), 0)


# ═══════════════════════════════════════════════════════════════════
# Style Analyzer Tests
# ═══════════════════════════════════════════════════════════════════

class TestStyleAnalyzer(unittest.TestCase):

    def test_long_line(self):
        code = "x = " + "a" * 200 + "\n"
        findings = StyleAnalyzer(code, "test.py", max_line_length=120).analyze()
        self.assertTrue(any(f.rule_id == "STY-001" for f in findings))

    def test_non_snake_case_function(self):
        code = 'def BadName():\n    pass\n'
        findings = StyleAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "STY-003" for f in findings))

    def test_snake_case_ok(self):
        code = 'def good_name():\n    pass\n'
        findings = StyleAnalyzer(code, "test.py").analyze()
        self.assertFalse(any(f.rule_id == "STY-003" for f in findings))

    def test_non_pascal_class(self):
        code = 'class bad_class:\n    pass\n'
        findings = StyleAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "STY-004" for f in findings))

    def test_missing_module_docstring(self):
        code = 'x = 42\n'
        findings = StyleAnalyzer(code, "test.py", enforce_docstrings=True).analyze()
        self.assertTrue(any(f.rule_id == "STY-010" for f in findings))

    def test_missing_return_type(self):
        code = '"""Module."""\n\ndef func(x: int):\n    return x + 1\n'
        findings = StyleAnalyzer(code, "test.py", enforce_type_hints=True).analyze()
        self.assertTrue(any(f.rule_id == "STY-020" for f in findings))

    def test_todo_detected(self):
        code = '"""Module."""\n# TODO: fix this later\nx = 42\n'
        findings = StyleAnalyzer(code, "test.py").analyze()
        self.assertTrue(any(f.rule_id == "STY-040" for f in findings))


# ═══════════════════════════════════════════════════════════════════
# Parser Tests
# ═══════════════════════════════════════════════════════════════════

class TestParsers(unittest.TestCase):

    def test_parse_function(self):
        code = 'def hello(name: str) -> str:\n    """Greet."""\n    return f"Hello, {name}"\n'
        result = parse_source(code)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(len(result.functions), 1)
        self.assertEqual(result.functions[0].name, "hello")

    def test_parse_class(self):
        code = 'class MyClass(Base):\n    """A class."""\n    def method(self):\n        pass\n'
        result = parse_source(code)
        self.assertEqual(len(result.classes), 1)
        self.assertEqual(result.classes[0].name, "MyClass")

    def test_parse_syntax_error(self):
        result = parse_source("def broken(:")
        self.assertGreater(len(result.errors), 0)

    def test_detect_language(self):
        self.assertEqual(detect_language("main.py"), "python")
        self.assertEqual(detect_language("app.js"), "javascript")
        self.assertEqual(detect_language("data.xyz"), "unknown")

    def test_diff_parser(self):
        diff = """diff --git a/src/main.py b/src/main.py
index abc..def 100644
--- a/src/main.py
+++ b/src/main.py
@@ -10,6 +10,8 @@ def existing():
     pass

+def new_func():
+    return 42
+
 def another():
     pass
"""
        parser = DiffParser()
        result = parser.parse_diff_string(diff)
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].file_path, "src/main.py")
        self.assertEqual(result.files[0].change_type, ChangeType.MODIFIED)
        self.assertEqual(len(result.files[0].added_lines), 3)

    def test_diff_new_file(self):
        diff = """diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+def hello():
+    return 1
"""
        result = DiffParser().parse_diff_string(diff)
        self.assertEqual(result.files[0].change_type, ChangeType.ADDED)

    def test_empty_diff(self):
        result = DiffParser().parse_diff_string("")
        self.assertEqual(len(result.files), 0)

    def test_extract_snippet(self):
        code = "line1\nline2\nline3\nline4\nline5"
        snippet = extract_code_snippet(code, 3, context=1)
        self.assertIn("line2", snippet)
        self.assertIn("line3", snippet)
        self.assertIn("line4", snippet)


# ═══════════════════════════════════════════════════════════════════
# Schema Tests
# ═══════════════════════════════════════════════════════════════════

class TestSchemas(unittest.TestCase):

    def _make_finding(self, **kw):
        defaults = dict(
            rule_id="T-001", title="Test", description="Desc",
            severity=Severity.WARNING, category=Category.BUG,
            location=Location(file_path="test.py", start_line=10),
            source_analyzer="test",
        )
        defaults.update(kw)
        return Finding(**defaults)

    def test_fingerprint_deterministic(self):
        f1 = self._make_finding()
        f2 = self._make_finding()
        self.assertEqual(f1.fingerprint, f2.fingerprint)

    def test_fingerprint_varies(self):
        f1 = self._make_finding(location=Location(file_path="a.py", start_line=1))
        f2 = self._make_finding(location=Location(file_path="a.py", start_line=2))
        self.assertNotEqual(f1.fingerprint, f2.fingerprint)

    def test_severity_ordering(self):
        self.assertGreater(Severity.CRITICAL, Severity.ERROR)
        self.assertGreater(Severity.ERROR, Severity.WARNING)
        self.assertGreater(Severity.WARNING, Severity.INFO)

    def test_sarif_conversion(self):
        sarif = self._make_finding().to_sarif_result()
        self.assertEqual(sarif["ruleId"], "T-001")
        self.assertEqual(sarif["level"], "warning")

    def test_review_score_perfect(self):
        score = ReviewScore.compute(findings=[], total_lines=100)
        self.assertEqual(score.overall, 100.0)
        self.assertEqual(score.grade, "A")

    def test_review_score_degrades(self):
        findings = [Finding(
            rule_id="SEC-001", title="t", description="d",
            severity=Severity.CRITICAL, category=Category.SECURITY,
            location=Location(file_path="t.py", start_line=1),
            source_analyzer="t",
        )]
        score = ReviewScore.compute(findings=findings, total_lines=100)
        self.assertLess(score.overall, 100.0)

    def test_complexity_risk_levels(self):
        low = ComplexityMetrics("f", "t.py", 1, 3, 5, 10, 2, 1)
        med = ComplexityMetrics("f", "t.py", 1, 15, 12, 40, 3, 3)
        high = ComplexityMetrics("f", "t.py", 1, 25, 35, 100, 8, 6)
        self.assertEqual(low.risk_level, "low")
        self.assertEqual(med.risk_level, "medium")
        self.assertEqual(high.risk_level, "high")

    def test_report_json_serialization(self):
        fa = FileAnalysis(file_path="test.py", lines_total=50, findings=[self._make_finding()])
        report = ReviewReport(files_analyzed=[fa])
        json_str = report.to_json()
        data = json.loads(json_str)
        self.assertIn("files_analyzed", data)
        self.assertEqual(data["total_findings"], 1)

    def test_report_sarif_export(self):
        fa = FileAnalysis(file_path="test.py", lines_total=50, findings=[self._make_finding()])
        report = ReviewReport(files_analyzed=[fa])
        sarif = report.to_sarif()
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)


# ═══════════════════════════════════════════════════════════════════
# Aggregator Tests
# ═══════════════════════════════════════════════════════════════════

class TestAggregator(unittest.TestCase):

    def _make(self, line=1, severity=Severity.WARNING):
        return Finding(
            rule_id="T-001", title="T", description="D",
            severity=severity, category=Category.BUG,
            location=Location(file_path="test.py", start_line=line),
            source_analyzer="test",
        )

    def test_unique_findings(self):
        agg = FindingAggregator()
        self.assertTrue(agg.add(self._make(line=1)))
        self.assertTrue(agg.add(self._make(line=2)))
        self.assertEqual(agg.total_count, 2)

    def test_dedup_keeps_higher_severity(self):
        agg = FindingAggregator()
        agg.add(self._make(line=1, severity=Severity.WARNING))
        agg.add(self._make(line=1, severity=Severity.ERROR))
        self.assertEqual(agg.total_count, 1)
        self.assertEqual(agg.get_findings()[0].severity, Severity.ERROR)

    def test_filter_by_severity(self):
        agg = FindingAggregator()
        agg.add(self._make(line=1, severity=Severity.INFO))
        agg.add(self._make(line=2, severity=Severity.ERROR))
        agg.add(self._make(line=3, severity=Severity.CRITICAL))
        results = agg.get_findings(min_severity=Severity.ERROR)
        self.assertEqual(len(results), 2)

    def test_sorted_by_severity(self):
        agg = FindingAggregator()
        agg.add(self._make(line=1, severity=Severity.INFO))
        agg.add(self._make(line=2, severity=Severity.CRITICAL))
        results = agg.get_findings()
        self.assertEqual(results[0].severity, Severity.CRITICAL)

    def test_limit(self):
        agg = FindingAggregator()
        for i in range(10):
            agg.add(self._make(line=i))
        self.assertEqual(len(agg.get_findings(limit=3)), 3)


# ═══════════════════════════════════════════════════════════════════
# Full Pipeline Integration Tests
# ═══════════════════════════════════════════════════════════════════

SAMPLE_BAD = '''
import os
import pickle
from os import *

API_KEY = "sk-1234567890abcdef1234567890abcdef"
password = "hardcoded_password_123"
DEBUG = True

def ProcessUserData(user_id, data=[], config={}):
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
                                data += str(x)
    return loaded
    print("unreachable")

class bad_class:
    def __init__(self):
        return True
'''

SAMPLE_GOOD = '''"""A well-structured module."""

from __future__ import annotations
from typing import Optional


def add(a: int, b: int) -> int:
    """Add two numbers.

    Args:
        a: First number.
        b: Second number.

    Returns:
        Sum of a and b.
    """
    return a + b
'''


class TestPipeline(unittest.TestCase):

    def _config(self):
        cfg = CodeVigilConfig()
        cfg.analyzers.llm.enabled = False
        return cfg

    def test_bad_file_finds_issues(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_BAD)
            f.flush()
            orch = Orchestrator(self._config())
            report = orch.review_file(f.name)

        self.assertGreater(report.total_findings, 0)
        self.assertIsNotNone(report.score)
        self.assertLess(report.score.overall, 100.0)

        rules = {fi.rule_id for fa in report.files_analyzed for fi in fa.findings}
        # Should detect hardcoded secrets
        self.assertTrue(rules & {"SEC-001", "SEC-002"}, f"Expected secrets, got {rules}")
        # Should detect eval/pickle
        self.assertTrue(rules & {"SEC-020", "SEC-021"}, f"Expected insecure funcs, got {rules}")
        # Should detect mutable defaults
        self.assertIn("AST-001", rules)

        os.unlink(f.name)

    def test_good_file_scores_well(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_GOOD)
            f.flush()
            orch = Orchestrator(self._config())
            report = orch.review_file(f.name)

        self.assertIsNotNone(report.score)
        self.assertGreaterEqual(report.score.overall, 70.0)

        critical = [
            fi for fa in report.files_analyzed for fi in fa.findings
            if fi.severity in (Severity.CRITICAL, Severity.ERROR) and fi.category == Category.SECURITY
        ]
        self.assertEqual(len(critical), 0)

        os.unlink(f.name)

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text('"""A."""\ndef f() -> int:\n    """F."""\n    return 1\n')
            (Path(d) / "b.py").write_text('"""B."""\ndef g() -> int:\n    """G."""\n    return 2\n')
            (Path(d) / "README.md").write_text("# Proj")

            orch = Orchestrator(self._config())
            report = orch.scan_directory(d)

        self.assertEqual(len(report.files_analyzed), 2)
        self.assertIsNotNone(report.score)

    def test_complexity_metrics_present(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_BAD)
            f.flush()
            orch = Orchestrator(self._config())
            report = orch.review_file(f.name)

        all_metrics = [m for fa in report.files_analyzed for m in fa.complexity_metrics]
        self.assertGreater(len(all_metrics), 0)
        os.unlink(f.name)

    def test_analysis_duration_tracked(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_GOOD)
            f.flush()
            orch = Orchestrator(self._config())
            report = orch.review_file(f.name)

        self.assertGreater(report.analysis_duration_ms, 0)
        os.unlink(f.name)


# ═══════════════════════════════════════════════════════════════════
# Reporter Tests
# ═══════════════════════════════════════════════════════════════════

class TestReporters(unittest.TestCase):

    def _report(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_BAD)
            f.flush()
            cfg = CodeVigilConfig()
            cfg.analyzers.llm.enabled = False
            orch = Orchestrator(cfg)
            report = orch.review_file(f.name)
        os.unlink(f.name)
        return report

    def test_json_reporter(self):
        report = self._report()
        output = JSONReporter().render(report)
        data = json.loads(output)
        self.assertIn("files_analyzed", data)

    def test_json_file_output(self):
        report = self._report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            JSONReporter().render(report, output_path=f.name)
            self.assertTrue(Path(f.name).exists())
            os.unlink(f.name)

    def test_markdown_reporter(self):
        report = self._report()
        output = MarkdownReporter().render(report)
        self.assertIn("CodeVigil", output)
        self.assertIn("Score:", output)

    def test_html_reporter(self):
        report = self._report()
        output = HTMLReporter().render(report)
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("CodeVigil", output)

    def test_sarif_reporter(self):
        report = self._report()
        output = SARIFReporter().render(report)
        data = json.loads(output)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(data["runs"][0]["tool"]["driver"]["name"], "CodeVigil")

    def test_console_reporter(self):
        report = self._report()
        stream = io.StringIO()
        ConsoleReporter(stream=stream, use_color=False).render(report)
        output = stream.getvalue()
        self.assertIn("CodeVigil", output)
        self.assertGreater(len(output), 50)

    def test_disabled_analyzers(self):
        cfg = CodeVigilConfig()
        cfg.analyzers.ast.enabled = False
        cfg.analyzers.security.enabled = False
        cfg.analyzers.style.enabled = False
        cfg.analyzers.llm.enabled = False
        cfg.plugins = []  # disable plugins too

        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_BAD)
            f.flush()
            orch = Orchestrator(cfg)
            # Clear auto-discovered plugins
            orch.plugin_registry.teardown_all()
            report = orch.review_file(f.name)

        core = [
            fi for fa in report.files_analyzed for fi in fa.findings
            if fi.source_analyzer in ("ast_analyzer", "security_analyzer", "style_analyzer", "complexity")
        ]
        self.assertEqual(len(core), 0)
        os.unlink(f.name)


# ═══════════════════════════════════════════════════════════════════
# Config Tests
# ═══════════════════════════════════════════════════════════════════

class TestConfig(unittest.TestCase):

    def test_default_config(self):
        cfg = CodeVigilConfig()
        self.assertTrue(cfg.analyzers.ast.enabled)
        self.assertFalse(cfg.analyzers.llm.enabled)
        self.assertEqual(cfg.analyzers.ast.max_complexity, 10)

    def test_load_yaml_config(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("analyzers:\n  ast:\n    max_complexity: 20\n")
            f.flush()
            cfg = CodeVigilConfig.load(f.name)

        self.assertEqual(cfg.analyzers.ast.max_complexity, 20)
        os.unlink(f.name)

    def test_model_dump(self):
        cfg = CodeVigilConfig()
        d = cfg.model_dump()
        self.assertIn("analyzers", d)
        self.assertIn("plugins", d)


# ═══════════════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
