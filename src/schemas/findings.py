"""
Core data models for CodeVigil findings, reports, and analysis results.

Uses standard library dataclasses for zero-dependency operation.
All analyzer outputs conform to these models for unified aggregation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def numeric(self) -> int:
        return {"info": 1, "warning": 2, "error": 3, "critical": 4}[self.value]

    def __ge__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric >= other.numeric

    def __gt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric > other.numeric

    def __le__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric <= other.numeric

    def __lt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric < other.numeric


class Category(str, Enum):
    SECURITY = "security"
    BUG = "bug"
    PERFORMANCE = "performance"
    STYLE = "style"
    MAINTAINABILITY = "maintainability"
    COMPLEXITY = "complexity"
    DOCUMENTATION = "documentation"
    BEST_PRACTICE = "best_practice"
    TYPE_SAFETY = "type_safety"
    ERROR_HANDLING = "error_handling"


@dataclass
class Location:
    file_path: str
    start_line: int = 1
    end_line: int | None = None
    start_col: int | None = None
    end_col: int | None = None
    function_name: str | None = None
    class_name: str | None = None

    def __post_init__(self) -> None:
        if self.end_line is not None and self.end_line < self.start_line:
            self.end_line = self.start_line

    @property
    def span(self) -> int:
        end = self.end_line or self.start_line
        return end - self.start_line + 1

    def __str__(self) -> str:
        loc = f"{self.file_path}:{self.start_line}"
        if self.end_line and self.end_line != self.start_line:
            loc += f"-{self.end_line}"
        if self.function_name:
            loc += f" (in {self.function_name})"
        return loc


@dataclass
class Suggestion:
    description: str
    replacement_code: str | None = None
    diff: str | None = None
    confidence: float = 0.8


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    location: Location
    source_analyzer: str
    suggestion: Suggestion | None = None
    code_snippet: str | None = None
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        content = f"{self.rule_id}:{self.location.file_path}:{self.location.start_line}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_sarif_result(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self._sarif_level(),
            "message": {"text": self.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": self.location.file_path},
                    "region": {
                        "startLine": self.location.start_line,
                        "endLine": self.location.end_line or self.location.start_line,
                    },
                }
            }],
        }
        if self.suggestion and self.suggestion.replacement_code:
            result["fixes"] = [{
                "description": {"text": self.suggestion.description},
                "artifactChanges": [{
                    "artifactLocation": {"uri": self.location.file_path},
                    "replacements": [{
                        "deletedRegion": {
                            "startLine": self.location.start_line,
                            "endLine": self.location.end_line or self.location.start_line,
                        },
                        "insertedContent": {"text": self.suggestion.replacement_code},
                    }],
                }],
            }]
        return result

    def _sarif_level(self) -> str:
        return {Severity.INFO: "note", Severity.WARNING: "warning",
                Severity.ERROR: "error", Severity.CRITICAL: "error"}[self.severity]


@dataclass
class ComplexityMetrics:
    function_name: str
    file_path: str
    line_number: int
    cyclomatic_complexity: int
    cognitive_complexity: int
    lines_of_code: int
    parameter_count: int
    nesting_depth: int
    halstead_volume: float | None = None
    halstead_difficulty: float | None = None
    maintainability_index: float | None = None

    @property
    def risk_level(self) -> str:
        if self.cyclomatic_complexity > 20 or self.cognitive_complexity > 30:
            return "high"
        if self.cyclomatic_complexity > 10 or self.cognitive_complexity > 15:
            return "medium"
        return "low"


@dataclass
class FileAnalysis:
    file_path: str
    language: str = "python"
    lines_total: int = 0
    lines_changed: int = 0
    findings: list[Finding] = field(default_factory=list)
    complexity_metrics: list[ComplexityMetrics] = field(default_factory=list)
    analysis_duration_ms: float = 0.0

    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def max_complexity(self) -> int:
        if not self.complexity_metrics:
            return 0
        return max(m.cyclomatic_complexity for m in self.complexity_metrics)


@dataclass
class ReviewScore:
    overall: float
    security: float
    maintainability: float
    reliability: float
    style: float
    grade: str

    @classmethod
    def compute(cls, findings: list[Finding], total_lines: int,
                weights: dict[str, float] | None = None) -> ReviewScore:
        if total_lines == 0:
            return cls(overall=100.0, security=100.0, maintainability=100.0,
                       reliability=100.0, style=100.0, grade="A")

        default_weights = {
            "security": 3.0, "bug": 2.5, "performance": 1.5, "style": 0.5,
            "maintainability": 1.0, "complexity": 1.0, "documentation": 0.3,
            "best_practice": 0.8, "type_safety": 1.2, "error_handling": 2.0,
        }
        w = {**default_weights, **(weights or {})}
        sev_mult = {Severity.INFO: 0.5, Severity.WARNING: 1.0,
                    Severity.ERROR: 2.5, Severity.CRITICAL: 5.0}
        dim_pen: dict[str, float] = {"security": 0.0, "maintainability": 0.0,
                                      "reliability": 0.0, "style": 0.0}
        cat_dim = {
            Category.SECURITY: "security", Category.BUG: "reliability",
            Category.PERFORMANCE: "reliability", Category.STYLE: "style",
            Category.MAINTAINABILITY: "maintainability", Category.COMPLEXITY: "maintainability",
            Category.DOCUMENTATION: "style", Category.BEST_PRACTICE: "maintainability",
            Category.TYPE_SAFETY: "reliability", Category.ERROR_HANDLING: "reliability",
        }
        for f in findings:
            dim = cat_dim.get(f.category, "maintainability")
            penalty = w.get(f.category.value, 1.0) * sev_mult[f.severity] / max(total_lines / 100, 1)
            dim_pen[dim] += penalty

        def p2s(p: float) -> float:
            return max(0.0, min(100.0, 100.0 - p * 10))

        scores = {d: p2s(p) for d, p in dim_pen.items()}
        overall = scores["security"] * 0.35 + scores["reliability"] * 0.30 + scores["maintainability"] * 0.20 + scores["style"] * 0.15

        def grade(s: float) -> str:
            if s >= 90: return "A"
            if s >= 80: return "B"
            if s >= 70: return "C"
            if s >= 60: return "D"
            return "F"

        return cls(overall=round(overall, 1), security=round(scores["security"], 1),
                   maintainability=round(scores["maintainability"], 1),
                   reliability=round(scores["reliability"], 1),
                   style=round(scores["style"], 1), grade=grade(overall))


@dataclass
class ReviewReport:
    project_name: str = "unknown"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    files_analyzed: list[FileAnalysis] = field(default_factory=list)
    score: ReviewScore | None = None
    summary: str = ""
    configuration: dict[str, Any] = field(default_factory=dict)
    analysis_duration_ms: float = 0.0

    @property
    def total_findings(self) -> int:
        return sum(len(fa.findings) for fa in self.files_analyzed)

    @property
    def findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for fa in self.files_analyzed:
            for f in fa.findings:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def findings_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for fa in self.files_analyzed:
            for f in fa.findings:
                counts[f.category.value] = counts.get(f.category.value, 0) + 1
        return counts

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for fa in self.files_analyzed:
            findings.extend(fa.findings)
        return sorted(findings, key=lambda f: f.severity.numeric, reverse=True)

    def to_json(self, indent: int = 2) -> str:
        def _ser(obj: Any) -> Any:
            if isinstance(obj, datetime): return obj.isoformat()
            if isinstance(obj, Enum): return obj.value
            if hasattr(obj, "__dataclass_fields__"):
                d = {}
                for fn in obj.__dataclass_fields__:
                    d[fn] = _ser(getattr(obj, fn))
                for attr in dir(obj):
                    if not attr.startswith("_") and attr not in d:
                        prop = getattr(type(obj), attr, None)
                        if isinstance(prop, property):
                            try: d[attr] = _ser(getattr(obj, attr))
                            except Exception: pass
                return d
            if isinstance(obj, list): return [_ser(i) for i in obj]
            if isinstance(obj, dict): return {k: _ser(v) for k, v in obj.items()}
            return obj
        return json.dumps(_ser(self), indent=indent, default=str)

    def to_sarif(self) -> dict[str, Any]:
        rules, results = {}, []
        for fa in self.files_analyzed:
            for f in fa.findings:
                if f.rule_id not in rules:
                    rules[f.rule_id] = {
                        "id": f.rule_id, "name": f.title,
                        "shortDescription": {"text": f.title},
                        "fullDescription": {"text": f.description},
                        "defaultConfiguration": {"level": f._sarif_level()},
                    }
                results.append(f.to_sarif_result())
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "CodeVigil", "version": "0.1.0",
                      "informationUri": "https://github.com/Aliyaan-a/CodeVigil-Always-On-AI-Code-Review-Agent",
                      "rules": list(rules.values())}}, "results": results}],
        }
