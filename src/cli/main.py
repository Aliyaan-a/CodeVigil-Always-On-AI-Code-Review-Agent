"""
CodeVigil CLI — command-line interface.

Usage:
    codevigil review <file>         Review a single file
    codevigil diff [ref]            Review a Git diff
    codevigil scan <directory>      Scan a directory
"""

from __future__ import annotations

import click

from src.agents.orchestrator import Orchestrator
from src.reporters.console_reporter import ConsoleReporter
from src.reporters.html_reporter import HTMLReporter
from src.reporters.json_reporter import JSONReporter
from src.reporters.markdown_reporter import MarkdownReporter
from src.reporters.sarif_reporter import SARIFReporter
from src.schemas.config import CodeVigilConfig

REPORTERS = {
    "console": ConsoleReporter,
    "json": JSONReporter,
    "md": MarkdownReporter,
    "markdown": MarkdownReporter,
    "html": HTMLReporter,
    "sarif": SARIFReporter,
}


@click.group()
@click.version_option(version="0.1.0", prog_name="CodeVigil")
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
@click.pass_context
def cli(ctx: click.Context, config: str | None) -> None:
    """🔍 CodeVigil — AI-Powered Code Review Agent"""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="console", type=click.Choice(list(REPORTERS.keys())))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--severity", "-s", default="info", type=click.Choice(["info", "warning", "error", "critical"]))
@click.pass_context
def review(ctx: click.Context, file_path: str, fmt: str, output: str | None, severity: str) -> None:
    """Review a single source file."""
    config = _load_config(ctx, severity=severity, fmt=fmt, output=output)
    orchestrator = Orchestrator(config)
    report = orchestrator.review_file(file_path)
    _output_report(report, fmt, output)


@cli.command()
@click.argument("ref", default="HEAD~1")
@click.option("--staged", is_flag=True, help="Review staged changes only")
@click.option("--format", "-f", "fmt", default="console", type=click.Choice(list(REPORTERS.keys())))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--severity", "-s", default="info", type=click.Choice(["info", "warning", "error", "critical"]))
@click.pass_context
def diff(ctx: click.Context, ref: str, staged: bool, fmt: str, output: str | None, severity: str) -> None:
    """Review changes from a Git diff."""
    config = _load_config(ctx, severity=severity, fmt=fmt, output=output)
    orchestrator = Orchestrator(config)
    report = orchestrator.review_diff(ref=ref, staged=staged)

    if report.total_findings == 0 and fmt == "console":
        click.echo("✅ No issues found in the diff!")
        return

    _output_report(report, fmt, output)


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="console", type=click.Choice(list(REPORTERS.keys())))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--severity", "-s", default="info", type=click.Choice(["info", "warning", "error", "critical"]))
@click.pass_context
def scan(ctx: click.Context, directory: str, fmt: str, output: str | None, severity: str) -> None:
    """Scan all Python files in a directory."""
    config = _load_config(ctx, severity=severity, fmt=fmt, output=output)
    orchestrator = Orchestrator(config)
    report = orchestrator.scan_directory(directory)
    _output_report(report, fmt, output)


# ── Helpers ────────────────────────────────────────────────────

def _load_config(
    ctx: click.Context,
    severity: str = "info",
    fmt: str = "console",
    output: str | None = None,
) -> CodeVigilConfig:
    """Load and patch configuration from CLI options."""
    config_path = ctx.obj.get("config_path")
    config = CodeVigilConfig.load(config_path)
    config.reporting.severity_threshold = severity
    config.reporting.format = fmt
    if output:
        config.reporting.output_file = output
    return config


def _output_report(report: any, fmt: str, output: str | None) -> None:
    """Dispatch the report to the appropriate reporter."""
    reporter_cls = REPORTERS.get(fmt, ConsoleReporter)

    if fmt == "console":
        reporter = reporter_cls()
        reporter.render(report)
    else:
        reporter = reporter_cls()
        result = reporter.render(report, output_path=output)
        if output:
            click.echo(f"📄 Report saved to: {output}")
        else:
            click.echo(result)


def main() -> None:
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
