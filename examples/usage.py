"""
Example: Using CodeVigil programmatically.

This shows how to use the Orchestrator directly from Python
for custom integrations, scripts, or IDE plugins.
"""

from src.agents.orchestrator import Orchestrator
from src.schemas.config import CodeVigilConfig
from src.reporters.json_reporter import JSONReporter
from src.reporters.markdown_reporter import MarkdownReporter
from src.reporters.html_reporter import HTMLReporter


def review_single_file():
    """Review a file with default settings."""
    config = CodeVigilConfig.load()
    orch = Orchestrator(config)
    report = orch.review_file("path/to/your/file.py")

    print(f"Grade: {report.score.grade} ({report.score.overall}/100)")
    print(f"Total findings: {report.total_findings}")

    for fa in report.files_analyzed:
        for finding in fa.findings:
            print(f"  [{finding.severity.value}] {finding.rule_id}: {finding.title}")
            if finding.suggestion:
                print(f"    Fix: {finding.suggestion.description}")


def review_with_custom_config():
    """Review with custom thresholds."""
    config = CodeVigilConfig()
    config.analyzers.ast.max_complexity = 8
    config.analyzers.style.max_line_length = 100
    config.analyzers.security.enabled = True
    config.analyzers.llm.enabled = False
    config.reporting.severity_threshold = "warning"

    orch = Orchestrator(config)
    report = orch.review_file("path/to/file.py")
    return report


def generate_all_report_formats():
    """Generate reports in all available formats."""
    config = CodeVigilConfig.load()
    orch = Orchestrator(config)
    report = orch.review_file("path/to/file.py")

    # JSON
    JSONReporter().render(report, output_path="report.json")

    # Markdown (great for PR comments)
    MarkdownReporter().render(report, output_path="report.md")

    # HTML (standalone page)
    HTMLReporter().render(report, output_path="report.html")

    print("Reports generated: report.json, report.md, report.html")


def scan_project():
    """Scan an entire project directory."""
    config = CodeVigilConfig.load("configs/strict.yaml")
    orch = Orchestrator(config)
    report = orch.scan_directory("./src")

    print(f"Scanned {len(report.files_analyzed)} files")
    print(f"Overall: {report.score.grade} ({report.score.overall}/100)")
    print(f"Findings: {report.total_findings}")
    print(f"Time: {report.analysis_duration_ms:.0f}ms")


if __name__ == "__main__":
    review_single_file()
