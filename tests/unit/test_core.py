"""Unit tests for parsers, schemas, aggregator, and scorer."""

from __future__ import annotations

from src.agents.aggregator import FindingAggregator
from src.agents.scorer import Scorer
from src.parsers.ast_utils import count_nesting_depth, extract_code_snippet, parse_source
from src.parsers.diff_parser import ChangeType, DiffParser
from src.parsers.file_parser import detect_language
from src.schemas.findings import (
    Category,
    ComplexityMetrics,
    FileAnalysis,
    Finding,
    Location,
    ReviewReport,
    ReviewScore,
    Severity,
)

# ═══════════════════════════════════════════════════════════════
# AST Utils Tests
# ═══════════════════════════════════════════════════════════════


class TestParseSource:
    def test_parse_simple_function(self):
        code = '''
def hello(name: str) -> str:
    """Greet someone."""
    return f"Hello, {name}"
'''
        result = parse_source(code)
        assert len(result.errors) == 0
        assert len(result.functions) == 1
        assert result.functions[0].name == "hello"
        assert result.functions[0].docstring == "Greet someone."
        assert result.functions[0].return_annotation == "str"

    def test_parse_class(self):
        code = '''
class MyClass(Base):
    """A class."""
    def method(self):
        pass
'''
        result = parse_source(code)
        assert len(result.classes) == 1
        assert result.classes[0].name == "MyClass"
        assert result.classes[0].bases == ["Base"]
        assert len(result.classes[0].methods) == 1

    def test_parse_imports(self):
        code = '''
import os
from pathlib import Path
from typing import Optional, List
'''
        result = parse_source(code)
        assert len(result.imports) == 3

    def test_parse_syntax_error(self):
        code = "def broken(:"
        result = parse_source(code)
        assert len(result.errors) > 0

    def test_parse_async_function(self):
        code = '''
async def fetch(url: str):
    pass
'''
        result = parse_source(code)
        assert len(result.functions) == 1
        assert result.functions[0].is_async is True

    def test_parse_decorated_function(self):
        code = '''
class MyClass:
    @staticmethod
    def static_method():
        pass

    @classmethod
    def class_method(cls):
        pass

    @property
    def prop(self):
        return self._val
'''
        result = parse_source(code)
        cls = result.classes[0]
        assert cls.methods[0].is_staticmethod is True
        assert cls.methods[1].is_classmethod is True
        assert cls.methods[2].is_property is True

    def test_nesting_depth(self):
        code = '''
def deep():
    if True:
        for x in range(10):
            while True:
                if x:
                    pass
'''
        result = parse_source(code)
        import ast
        for node in ast.walk(result.tree):
            if isinstance(node, ast.FunctionDef) and node.name == "deep":
                depth = count_nesting_depth(node)
                assert depth == 4
                break

    def test_extract_code_snippet(self):
        code = "line1\nline2\nline3\nline4\nline5\nline6\nline7"
        snippet = extract_code_snippet(code, 4, context=1)
        assert "line3" in snippet
        assert "line4" in snippet
        assert "line5" in snippet


# ═══════════════════════════════════════════════════════════════
# Diff Parser Tests
# ═══════════════════════════════════════════════════════════════


class TestDiffParser:
    SAMPLE_DIFF = """diff --git a/src/main.py b/src/main.py
index abc1234..def5678 100644
--- a/src/main.py
+++ b/src/main.py
@@ -10,6 +10,8 @@ def existing_func():
     pass

+def new_func():
+    return 42
+
 def another_func():
     pass
"""

    def test_parse_basic_diff(self):
        parser = DiffParser()
        result = parser.parse_diff_string(self.SAMPLE_DIFF)
        assert len(result.files) == 1
        assert result.files[0].file_path == "src/main.py"
        assert result.files[0].change_type == ChangeType.MODIFIED
        assert len(result.files[0].added_lines) == 3

    def test_parse_new_file(self):
        diff = """diff --git a/new_file.py b/new_file.py
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/new_file.py
@@ -0,0 +1,3 @@
+def hello():
+    return "world"
+
"""
        parser = DiffParser()
        result = parser.parse_diff_string(diff)
        assert result.files[0].change_type == ChangeType.ADDED
        assert len(result.files[0].added_lines) == 3

    def test_parse_deleted_file(self):
        diff = """diff --git a/old_file.py b/old_file.py
deleted file mode 100644
index abc1234..0000000
--- a/old_file.py
+++ /dev/null
@@ -1,3 +0,0 @@
-def goodbye():
-    return "gone"
-
"""
        parser = DiffParser()
        result = parser.parse_diff_string(diff)
        assert result.files[0].change_type == ChangeType.DELETED

    def test_python_file_filter(self):
        diff = """diff --git a/src/main.py b/src/main.py
--- a/src/main.py
+++ b/src/main.py
@@ -1 +1 @@
-old
+new
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1 @@
-old
+new
"""
        parser = DiffParser()
        result = parser.parse_diff_string(diff)
        python_files = result.get_python_files()
        assert len(python_files) == 1
        assert python_files[0].file_path == "src/main.py"

    def test_total_changes(self):
        parser = DiffParser()
        result = parser.parse_diff_string(self.SAMPLE_DIFF)
        assert result.total_additions == 3
        assert result.total_files_changed == 1

    def test_empty_diff(self):
        parser = DiffParser()
        result = parser.parse_diff_string("")
        assert len(result.files) == 0


# ═══════════════════════════════════════════════════════════════
# File Parser Tests
# ═══════════════════════════════════════════════════════════════


class TestFileParser:
    def test_detect_python(self):
        assert detect_language("main.py") == "python"

    def test_detect_javascript(self):
        assert detect_language("app.js") == "javascript"

    def test_detect_unknown(self):
        assert detect_language("data.xyz") == "unknown"

    def test_detect_with_path(self):
        assert detect_language("/home/user/project/src/module.py") == "python"


# ═══════════════════════════════════════════════════════════════
# Schema Tests
# ═══════════════════════════════════════════════════════════════


class TestFindingModel:
    def _make_finding(self, **kwargs) -> Finding:
        defaults = {
            "rule_id": "TEST-001",
            "title": "Test finding",
            "description": "A test finding",
            "severity": Severity.WARNING,
            "category": Category.BUG,
            "location": Location(file_path="test.py", start_line=10),
            "source_analyzer": "test",
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_finding_creation(self):
        f = self._make_finding()
        assert f.rule_id == "TEST-001"
        assert f.severity == Severity.WARNING

    def test_fingerprint_deterministic(self):
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_varies_by_location(self):
        f1 = self._make_finding(location=Location(file_path="a.py", start_line=1))
        f2 = self._make_finding(location=Location(file_path="a.py", start_line=2))
        assert f1.fingerprint != f2.fingerprint

    def test_sarif_conversion(self):
        f = self._make_finding()
        sarif = f.to_sarif_result()
        assert sarif["ruleId"] == "TEST-001"
        assert sarif["level"] == "warning"
        assert sarif["locations"][0]["physicalLocation"]["region"]["startLine"] == 10

    def test_severity_ordering(self):
        assert Severity.CRITICAL > Severity.ERROR
        assert Severity.ERROR > Severity.WARNING
        assert Severity.WARNING > Severity.INFO


class TestReviewScore:
    def test_perfect_score_no_findings(self):
        score = ReviewScore.compute(findings=[], total_lines=100)
        assert score.overall == 100.0
        assert score.grade == "A"

    def test_score_degrades_with_findings(self):
        findings = [
            Finding(
                rule_id="SEC-001",
                title="Security issue",
                description="Critical security problem",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                location=Location(file_path="test.py", start_line=1),
                source_analyzer="test",
            )
        ]
        score = ReviewScore.compute(findings=findings, total_lines=100)
        assert score.overall < 100.0
        assert score.security < 100.0

    def test_zero_lines_returns_perfect(self):
        score = ReviewScore.compute(findings=[], total_lines=0)
        assert score.overall == 100.0

    def test_grade_calculation(self):
        score = ReviewScore.compute(findings=[], total_lines=100)
        assert score.grade == "A"


class TestComplexityMetrics:
    def test_risk_level_low(self):
        m = ComplexityMetrics(
            function_name="simple",
            file_path="test.py",
            line_number=1,
            cyclomatic_complexity=3,
            cognitive_complexity=5,
            lines_of_code=10,
            parameter_count=2,
            nesting_depth=1,
        )
        assert m.risk_level == "low"

    def test_risk_level_medium(self):
        m = ComplexityMetrics(
            function_name="moderate",
            file_path="test.py",
            line_number=1,
            cyclomatic_complexity=15,
            cognitive_complexity=12,
            lines_of_code=40,
            parameter_count=3,
            nesting_depth=3,
        )
        assert m.risk_level == "medium"

    def test_risk_level_high(self):
        m = ComplexityMetrics(
            function_name="complex",
            file_path="test.py",
            line_number=1,
            cyclomatic_complexity=25,
            cognitive_complexity=35,
            lines_of_code=100,
            parameter_count=8,
            nesting_depth=6,
        )
        assert m.risk_level == "high"


class TestReviewReport:
    def test_report_aggregation(self):
        fa = FileAnalysis(
            file_path="test.py",
            lines_total=100,
            findings=[
                Finding(
                    rule_id="T-001", title="t", description="d",
                    severity=Severity.WARNING, category=Category.BUG,
                    location=Location(file_path="test.py", start_line=1),
                    source_analyzer="test",
                ),
                Finding(
                    rule_id="T-002", title="t", description="d",
                    severity=Severity.ERROR, category=Category.SECURITY,
                    location=Location(file_path="test.py", start_line=5),
                    source_analyzer="test",
                ),
            ],
        )
        report = ReviewReport(files_analyzed=[fa])
        assert report.total_findings == 2
        assert report.findings_by_severity["warning"] == 1
        assert report.findings_by_severity["error"] == 1
        assert report.findings_by_category["bug"] == 1

    def test_sarif_export(self):
        fa = FileAnalysis(
            file_path="test.py", lines_total=50,
            findings=[
                Finding(
                    rule_id="T-001", title="t", description="d",
                    severity=Severity.WARNING, category=Category.BUG,
                    location=Location(file_path="test.py", start_line=1),
                    source_analyzer="test",
                ),
            ],
        )
        report = ReviewReport(files_analyzed=[fa])
        sarif = report.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1


# ═══════════════════════════════════════════════════════════════
# Aggregator Tests
# ═══════════════════════════════════════════════════════════════


class TestFindingAggregator:
    def _make_finding(self, rule_id="T-001", line=1, severity=Severity.WARNING) -> Finding:
        return Finding(
            rule_id=rule_id, title="Test", description="Desc",
            severity=severity, category=Category.BUG,
            location=Location(file_path="test.py", start_line=line),
            source_analyzer="test",
        )

    def test_add_unique_findings(self):
        agg = FindingAggregator()
        assert agg.add(self._make_finding(line=1)) is True
        assert agg.add(self._make_finding(line=2)) is True
        assert agg.total_count == 2

    def test_deduplicate_same_location(self):
        agg = FindingAggregator()
        agg.add(self._make_finding(line=1, severity=Severity.WARNING))
        agg.add(self._make_finding(line=1, severity=Severity.ERROR))
        assert agg.total_count == 1
        # Should keep the higher severity
        findings = agg.get_findings()
        assert findings[0].severity == Severity.ERROR

    def test_filter_by_severity(self):
        agg = FindingAggregator()
        agg.add(self._make_finding(line=1, severity=Severity.INFO))
        agg.add(self._make_finding(line=2, severity=Severity.ERROR))
        agg.add(self._make_finding(line=3, severity=Severity.CRITICAL))

        results = agg.get_findings(min_severity=Severity.ERROR)
        assert len(results) == 2
        assert all(f.severity >= Severity.ERROR for f in results)

    def test_sorted_by_severity(self):
        agg = FindingAggregator()
        agg.add(self._make_finding(line=1, severity=Severity.INFO))
        agg.add(self._make_finding(line=2, severity=Severity.CRITICAL))
        agg.add(self._make_finding(line=3, severity=Severity.WARNING))

        results = agg.get_findings()
        assert results[0].severity == Severity.CRITICAL
        assert results[-1].severity == Severity.INFO

    def test_add_many(self):
        agg = FindingAggregator()
        findings = [self._make_finding(line=i) for i in range(5)]
        new, dedup = agg.add_many(findings)
        assert new == 5
        assert dedup == 0

    def test_limit(self):
        agg = FindingAggregator()
        for i in range(10):
            agg.add(self._make_finding(line=i))
        results = agg.get_findings(limit=3)
        assert len(results) == 3


# ═══════════════════════════════════════════════════════════════
# Scorer Tests
# ═══════════════════════════════════════════════════════════════


class TestScorer:
    def test_score_clean_file(self):
        scorer = Scorer()
        fa = FileAnalysis(file_path="clean.py", lines_total=100, findings=[])
        score = scorer.score_file(fa)
        assert score.grade == "A"
        assert score.overall == 100.0

    def test_score_report_multiple_files(self):
        scorer = Scorer()
        files = [
            FileAnalysis(file_path="a.py", lines_total=100, findings=[]),
            FileAnalysis(file_path="b.py", lines_total=200, findings=[]),
        ]
        score = scorer.score_report(files)
        assert score.grade == "A"

    def test_generate_summary(self):
        scorer = Scorer()
        score = ReviewScore(
            overall=85.0, security=90.0, maintainability=80.0,
            reliability=85.0, style=75.0, grade="B",
        )
        summary = scorer.generate_summary(score, 5)
        assert "B" in summary
        assert "85" in summary
        assert "5" in summary
