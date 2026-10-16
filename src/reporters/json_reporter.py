"""JSON report output."""

from __future__ import annotations

from pathlib import Path

from src.schemas.findings import ReviewReport


class JSONReporter:
    """Renders a ReviewReport as formatted JSON."""

    def render(self, report: ReviewReport, output_path: str | None = None) -> str:
        json_str = report.to_json(indent=2)
        if output_path:
            Path(output_path).write_text(json_str, encoding="utf-8")
        return json_str
