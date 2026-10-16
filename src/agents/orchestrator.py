"""
Main orchestrator agent.

Coordinates the entire analysis pipeline: parsing → analysis →
aggregation → scoring → reporting. Manages the lifecycle of
all analyzers and plugins.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from src.schemas.config import CodeVigilConfig
from src.schemas.findings import (
    FileAnalysis,
    Finding,
    ReviewReport,
    Severity,
)
from src.parsers.file_parser import read_source_file, collect_files, SourceFile
from src.parsers.diff_parser import DiffParser, DiffResult
from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.complexity import analyze_complexity
from src.analyzers.security_analyzer import SecurityAnalyzer
from src.analyzers.style_analyzer import StyleAnalyzer
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.agents.aggregator import FindingAggregator
from src.agents.scorer import Scorer
from src.plugins.base import AnalysisContext
from src.plugins.registry import PluginRegistry


class Orchestrator:
    """
    Central controller for the CodeVigil analysis pipeline.

    Manages the flow:
    1. Parse input (files, diffs, directories)
    2. Run core analyzers (AST, complexity, security, style)
    3. Run plugins
    4. Optionally run LLM analysis
    5. Aggregate and deduplicate findings
    6. Score results
    7. Generate report
    """

    def __init__(self, config: Optional[CodeVigilConfig] = None):
        self.config = config or CodeVigilConfig.load()
        self.scorer = Scorer(self.config.scoring)
        self.plugin_registry = PluginRegistry()
        self._llm_analyzer: Optional[LLMAnalyzer] = None

        # Initialize plugins
        self.plugin_registry.discover_plugins()

    @property
    def llm_analyzer(self) -> LLMAnalyzer:
        if self._llm_analyzer is None:
            self._llm_analyzer = LLMAnalyzer(self.config.analyzers.llm)
        return self._llm_analyzer

    # ── Public API ──────────────────────────────────────────────

    def review_file(self, file_path: str | Path) -> ReviewReport:
        """Review a single source file."""
        start = time.perf_counter()
        source_file = read_source_file(file_path)
        file_analysis = self._analyze_source(source_file)

        report = ReviewReport(
            project_name=str(file_path),
            files_analyzed=[file_analysis],
        )
        report.score = self.scorer.score_report(report.files_analyzed)
        report.summary = self.scorer.generate_summary(
            report.score, report.total_findings
        )
        report.analysis_duration_ms = (time.perf_counter() - start) * 1000
        report.configuration = self.config.model_dump()
        return report

    def review_diff(
        self,
        ref: str = "HEAD~1",
        staged: bool = False,
        repo_path: Optional[str] = None,
    ) -> ReviewReport:
        """Review changes from a Git diff."""
        start = time.perf_counter()
        parser = DiffParser(repo_path)

        if staged:
            diff_result = parser.diff_from_ref(ref, staged=True)
        else:
            diff_result = parser.diff_from_ref(ref)

        report = self._review_diff_result(diff_result, repo_path)
        report.analysis_duration_ms = (time.perf_counter() - start) * 1000
        return report

    def scan_directory(self, directory: str | Path) -> ReviewReport:
        """Scan all matching files in a directory."""
        start = time.perf_counter()
        directory = Path(directory)

        source_files = collect_files(
            directory,
            extensions=self.config.file_extensions,
            ignore_patterns=self.config.ignore_patterns,
        )

        file_analyses = []
        for sf in source_files:
            analysis = self._analyze_source(sf)
            file_analyses.append(analysis)

        report = ReviewReport(
            project_name=str(directory),
            files_analyzed=file_analyses,
        )
        report.score = self.scorer.score_report(report.files_analyzed)
        report.summary = self.scorer.generate_summary(
            report.score, report.total_findings
        )
        report.analysis_duration_ms = (time.perf_counter() - start) * 1000
        report.configuration = self.config.model_dump()
        return report

    # ── Internal Pipeline ──────────────────────────────────────

    def _analyze_source(
        self,
        source_file: SourceFile,
        changed_lines: Optional[set[int]] = None,
    ) -> FileAnalysis:
        """Run the full analysis pipeline on a single source file."""
        file_start = time.perf_counter()
        aggregator = FindingAggregator()

        source = source_file.content
        file_path = source_file.path

        # 1. AST Analysis
        if self.config.analyzers.ast.enabled:
            ast_analyzer = ASTAnalyzer(source, file_path)
            ast_findings = ast_analyzer.analyze()
            aggregator.add_many(self._filter_by_changed_lines(ast_findings, changed_lines))

        # 2. Complexity Analysis
        if self.config.analyzers.ast.enabled:
            cfg = self.config.analyzers.ast
            complexity_metrics, complexity_findings = analyze_complexity(
                source,
                file_path,
                max_cyclomatic=cfg.max_complexity,
                max_cognitive=cfg.max_cognitive_complexity,
                max_function_length=cfg.max_function_length,
                max_params=cfg.max_parameter_count,
                max_nesting=cfg.max_nesting_depth,
            )
            aggregator.add_many(self._filter_by_changed_lines(complexity_findings, changed_lines))
        else:
            complexity_metrics = []

        # 3. Security Analysis
        if self.config.analyzers.security.enabled:
            security_analyzer = SecurityAnalyzer(source, file_path)
            sec_findings = security_analyzer.analyze()
            aggregator.add_many(self._filter_by_changed_lines(sec_findings, changed_lines))

        # 4. Style Analysis
        if self.config.analyzers.style.enabled:
            style_cfg = self.config.analyzers.style
            style_analyzer = StyleAnalyzer(
                source,
                file_path,
                max_line_length=style_cfg.max_line_length,
                enforce_docstrings=style_cfg.enforce_docstrings,
                enforce_type_hints=style_cfg.enforce_type_hints,
            )
            style_findings = style_analyzer.analyze()
            aggregator.add_many(self._filter_by_changed_lines(style_findings, changed_lines))

        # 5. Plugin Analysis
        context = AnalysisContext(
            source=source,
            file_path=file_path,
            language=source_file.language,
            config=self.config,
            changed_lines=changed_lines,
            prior_findings=aggregator.get_findings(),
        )
        plugin_findings = self.plugin_registry.run_all(
            context,
            filter_names=self.config.plugins,
        )
        aggregator.add_many(plugin_findings)

        # 6. LLM Analysis (optional)
        if self.config.analyzers.llm.enabled:
            llm_findings = self.llm_analyzer.analyze(source, file_path)
            aggregator.add_many(self._filter_by_changed_lines(llm_findings, changed_lines))

        # Build FileAnalysis
        severity_threshold = Severity(
            self.config.reporting.severity_threshold
        )
        filtered_findings = aggregator.get_findings(
            min_severity=severity_threshold,
            limit=self.config.reporting.max_findings,
        )

        return FileAnalysis(
            file_path=file_path,
            language=source_file.language,
            lines_total=source_file.line_count,
            lines_changed=len(changed_lines) if changed_lines else source_file.line_count,
            findings=filtered_findings,
            complexity_metrics=complexity_metrics,
            analysis_duration_ms=(time.perf_counter() - file_start) * 1000,
        )

    def _review_diff_result(
        self,
        diff: DiffResult,
        repo_path: Optional[str],
    ) -> ReviewReport:
        """Review files from a parsed diff result."""
        base = Path(repo_path) if repo_path else Path.cwd()
        file_analyses = []

        for file_diff in diff.get_python_files():
            full_path = base / file_diff.file_path
            if not full_path.exists():
                continue

            try:
                sf = read_source_file(full_path)
                analysis = self._analyze_source(sf, file_diff.changed_lines)
                file_analyses.append(analysis)
            except (FileNotFoundError, ValueError):
                continue

        report = ReviewReport(
            project_name=f"diff:{diff.base_ref}..{diff.head_ref}",
            files_analyzed=file_analyses,
        )
        report.score = self.scorer.score_report(report.files_analyzed)
        report.summary = self.scorer.generate_summary(
            report.score, report.total_findings
        )
        report.configuration = self.config.model_dump()
        return report

    @staticmethod
    def _filter_by_changed_lines(
        findings: list[Finding],
        changed_lines: Optional[set[int]],
    ) -> list[Finding]:
        """Filter findings to only those on changed lines."""
        if changed_lines is None:
            return findings

        filtered = []
        for f in findings:
            start = f.location.start_line
            end = f.location.end_line or start
            # Include if any line in the finding's range is in the changed set
            if any(line in changed_lines for line in range(start, end + 1)):
                filtered.append(f)
            # Always include critical security findings regardless of diff
            elif f.severity == Severity.CRITICAL and f.category.value == "security":
                filtered.append(f)
        return filtered
