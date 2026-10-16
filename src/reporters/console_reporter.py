"""
Rich-powered console reporter.

Produces beautiful terminal output with color-coded findings,
severity badges, score visualizations, and tables.
"""

from __future__ import annotations

import sys
from typing import TextIO

from src.schemas.findings import Finding, ReviewReport, Severity

# Severity → terminal color codes (ANSI)
SEVERITY_COLORS = {
    Severity.INFO: "\033[36m",       # cyan
    Severity.WARNING: "\033[33m",    # yellow
    Severity.ERROR: "\033[31m",      # red
    Severity.CRITICAL: "\033[1;31m", # bold red
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

SEVERITY_ICONS = {
    Severity.INFO: "ℹ",
    Severity.WARNING: "⚠",
    Severity.ERROR: "✗",
    Severity.CRITICAL: "🔴",
}


class ConsoleReporter:
    """Renders a ReviewReport to the terminal with colors and formatting."""

    def __init__(self, stream: TextIO | None = None, use_color: bool = True):
        self.stream = stream or sys.stdout
        self.use_color = use_color

    def render(self, report: ReviewReport) -> None:
        """Render the complete report to the console."""
        self._print_header(report)
        self._print_score(report)
        self._print_findings(report)
        self._print_footer(report)

    def _print_header(self, report: ReviewReport) -> None:
        self._write(f"\n{BOLD}{'═' * 60}{RESET}")
        self._write(f"{BOLD}  CodeVigil Review Report{RESET}")
        self._write(f"{DIM}  Project: {report.project_name}{RESET}")
        self._write(f"{DIM}  Files:   {len(report.files_analyzed)}{RESET}")
        self._write(f"{DIM}  Time:    {report.analysis_duration_ms:.0f}ms{RESET}")
        self._write(f"{BOLD}{'═' * 60}{RESET}\n")

    def _print_score(self, report: ReviewReport) -> None:
        if report.score is None:
            return

        score = report.score
        grade_color = {
            "A": "\033[32m", "B": "\033[32m",
            "C": "\033[33m", "D": "\033[31m", "F": "\033[1;31m",
        }.get(score.grade, RESET)

        self._write(f"  {BOLD}Grade: {grade_color}{score.grade}{RESET}  ({score.overall}/100)\n")

        # Score bars
        self._print_bar("Security", score.security)
        self._print_bar("Reliability", score.reliability)
        self._print_bar("Maintainability", score.maintainability)
        self._print_bar("Style", score.style)
        self._write("")

    def _print_bar(self, label: str, value: float) -> None:
        width = 30
        filled = int(value / 100 * width)
        empty = width - filled

        if value >= 80:
            color = "\033[32m"
        elif value >= 60:
            color = "\033[33m"
        else:
            color = "\033[31m"

        bar = f"{color}{'█' * filled}{DIM}{'░' * empty}{RESET}"
        self._write(f"  {label:<17s} {bar} {value:.0f}")

    def _print_findings(self, report: ReviewReport) -> None:
        findings = report.all_findings
        if not findings:
            self._write(f"  {BOLD}\033[32m✓ No issues found!{RESET}\n")
            return

        # Group by file
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.location.file_path, []).append(f)

        for file_path, file_findings in by_file.items():
            self._write(f"  {BOLD}{file_path}{RESET}")
            for f in file_findings:
                icon = SEVERITY_ICONS.get(f.severity, "•")
                color = SEVERITY_COLORS.get(f.severity, RESET)
                line = f.location.start_line

                self._write(
                    f"    {color}{icon} [{f.severity.value.upper():8s}]{RESET} "
                    f"L{line:<4d} {f.rule_id}: {f.title}"
                )
                if f.description and f.description != f.title:
                    desc = f.description[:120]
                    self._write(f"      {DIM}{desc}{RESET}")
                if f.suggestion:
                    self._write(f"      {DIM}💡 {f.suggestion.description[:100]}{RESET}")
            self._write("")

    def _print_footer(self, report: ReviewReport) -> None:
        counts = report.findings_by_severity
        parts = []
        for sev in [Severity.CRITICAL, Severity.ERROR, Severity.WARNING, Severity.INFO]:
            count = counts.get(sev.value, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(sev, RESET)
                parts.append(f"{color}{count} {sev.value}{RESET}")

        if parts:
            self._write(f"  {BOLD}Summary:{RESET} {', '.join(parts)}")
        self._write(f"{BOLD}{'═' * 60}{RESET}\n")

    def _write(self, text: str) -> None:
        if not self.use_color:
            # Strip ANSI codes
            import re
            text = re.sub(r"\033\[[0-9;]*m", "", text)
        try:
            self.stream.write(text + "\n")
        except UnicodeEncodeError:
            # Windows cp1252/cp437 can't handle emoji — fall back to ascii-safe version
            safe = text.encode("ascii", errors="replace").decode("ascii")
            self.stream.write(safe + "\n")
