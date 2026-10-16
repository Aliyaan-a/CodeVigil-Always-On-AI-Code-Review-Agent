"""SARIF 2.1.0 report output — for GitHub/GitLab Security tab integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from src.schemas.findings import ReviewReport


class SARIFReporter:
    """Renders a ReviewReport as SARIF 2.1.0 JSON."""

    def render(self, report: ReviewReport, output_path: Optional[str] = None) -> str:
        sarif = report.to_sarif()
        json_str = json.dumps(sarif, indent=2)
        if output_path:
            Path(output_path).write_text(json_str, encoding="utf-8")
        return json_str
