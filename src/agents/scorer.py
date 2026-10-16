"""
Severity scoring engine.

Computes composite quality scores from findings and metrics,
adjusting weights based on configuration and context.
"""

from __future__ import annotations

from src.schemas.findings import Finding, ReviewScore, FileAnalysis
from src.schemas.config import ScoringConfig


class Scorer:
    """
    Computes composite quality scores from findings.

    Uses a weighted scoring model where different categories and
    severities contribute differently to the overall score.
    """

    def __init__(self, config: ScoringConfig | None = None):
        self.config = config or ScoringConfig()

    def score_file(self, file_analysis: FileAnalysis) -> ReviewScore:
        """Compute a ReviewScore for a single file."""
        total_lines = max(file_analysis.lines_total, 1)
        return ReviewScore.compute(
            findings=file_analysis.findings,
            total_lines=total_lines,
            weights=self.config.weights,
        )

    def score_report(self, file_analyses: list[FileAnalysis]) -> ReviewScore:
        """Compute an aggregate ReviewScore across all files."""
        all_findings: list[Finding] = []
        total_lines = 0
        for fa in file_analyses:
            all_findings.extend(fa.findings)
            total_lines += fa.lines_total

        return ReviewScore.compute(
            findings=all_findings,
            total_lines=max(total_lines, 1),
            weights=self.config.weights,
        )

    def generate_summary(self, score: ReviewScore, total_findings: int) -> str:
        """Generate a human-readable summary of the review score."""
        grade_descriptions = {
            "A": "Excellent code quality. Well-structured and maintainable.",
            "B": "Good code quality with minor issues to address.",
            "C": "Moderate code quality. Several issues should be addressed.",
            "D": "Below average quality. Significant issues need attention.",
            "F": "Poor code quality. Critical issues require immediate fixes.",
        }

        summary_parts = [
            f"Overall Grade: {score.grade} ({score.overall}/100)",
            grade_descriptions.get(score.grade, ""),
            "",
            f"  Security:        {score.security}/100",
            f"  Reliability:     {score.reliability}/100",
            f"  Maintainability: {score.maintainability}/100",
            f"  Style:           {score.style}/100",
            "",
            f"Total findings: {total_findings}",
        ]

        return "\n".join(summary_parts)
