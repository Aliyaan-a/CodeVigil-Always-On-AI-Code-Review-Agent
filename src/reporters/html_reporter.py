"""HTML report output — standalone self-contained page."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Optional

from src.schemas.findings import ReviewReport, Severity


class HTMLReporter:
    """Renders a ReviewReport as a standalone HTML page."""

    def render(self, report: ReviewReport, output_path: Optional[str] = None) -> str:
        content = self._build_html(report)
        if output_path:
            Path(output_path).write_text(content, encoding="utf-8")
        return content

    def _build_html(self, report: ReviewReport) -> str:
        score = report.score
        score_html = ""
        if score:
            grade_color = {"A": "#22c55e", "B": "#22c55e", "C": "#eab308", "D": "#ef4444", "F": "#dc2626"}.get(score.grade, "#888")
            score_html = f"""
            <div class="score-card">
                <div class="grade" style="color:{grade_color}">{score.grade}</div>
                <div class="score-value">{score.overall}/100</div>
                <div class="score-bars">
                    {self._bar("Security", score.security)}
                    {self._bar("Reliability", score.reliability)}
                    {self._bar("Maintainability", score.maintainability)}
                    {self._bar("Style", score.style)}
                </div>
            </div>"""

        findings_html = ""
        for f in report.all_findings:
            sev = f.severity.value
            sev_class = f"severity-{sev}"
            snippet = ""
            if f.code_snippet:
                snippet = f'<pre class="code-snippet">{html.escape(f.code_snippet)}</pre>'
            suggestion = ""
            if f.suggestion:
                suggestion = f'<div class="suggestion">💡 {html.escape(f.suggestion.description)}</div>'

            findings_html += f"""
            <div class="finding {sev_class}">
                <div class="finding-header">
                    <span class="badge {sev_class}">{sev.upper()}</span>
                    <span class="rule-id">{html.escape(f.rule_id)}</span>
                    <span class="location">L{f.location.start_line}</span>
                    <span class="title">{html.escape(f.title)}</span>
                </div>
                <div class="description">{html.escape(f.description)}</div>
                {snippet}
                {suggestion}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeVigil Report — {html.escape(report.project_name)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;line-height:1.6}}
.container{{max-width:900px;margin:0 auto}}
h1{{font-size:1.8rem;margin-bottom:.5rem;color:#f8fafc}}
.meta{{color:#94a3b8;font-size:.9rem;margin-bottom:2rem}}
.score-card{{background:#1e293b;border-radius:12px;padding:1.5rem;margin-bottom:2rem;display:flex;align-items:center;gap:2rem}}
.grade{{font-size:4rem;font-weight:800;min-width:80px;text-align:center}}
.score-value{{font-size:1.2rem;color:#94a3b8;min-width:80px}}
.score-bars{{flex:1}}
.bar-row{{display:flex;align-items:center;margin:.3rem 0;gap:.5rem}}
.bar-label{{width:120px;font-size:.85rem;color:#94a3b8;text-align:right}}
.bar-track{{flex:1;height:8px;background:#334155;border-radius:4px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:4px;transition:width .6s ease}}
.bar-value{{width:40px;font-size:.85rem;text-align:right}}
.finding{{background:#1e293b;border-radius:8px;padding:1rem;margin-bottom:.75rem;border-left:4px solid}}
.severity-critical{{border-color:#dc2626}}.severity-error{{border-color:#ef4444}}.severity-warning{{border-color:#eab308}}.severity-info{{border-color:#06b6d4}}
.finding-header{{display:flex;gap:.5rem;align-items:center;margin-bottom:.5rem;flex-wrap:wrap}}
.badge{{padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700;color:#fff}}
.badge.severity-critical{{background:#dc2626}}.badge.severity-error{{background:#ef4444}}.badge.severity-warning{{background:#854d0e}}.badge.severity-info{{background:#0e7490}}
.rule-id{{color:#60a5fa;font-weight:600;font-size:.85rem}}
.location{{color:#94a3b8;font-size:.85rem}}
.title{{font-weight:600}}
.description{{color:#94a3b8;font-size:.9rem;margin-bottom:.5rem}}
.code-snippet{{background:#0f172a;padding:.75rem;border-radius:6px;font-size:.8rem;overflow-x:auto;color:#cbd5e1;white-space:pre;font-family:'JetBrains Mono',Consolas,monospace}}
.suggestion{{color:#4ade80;font-size:.85rem;margin-top:.5rem}}
footer{{text-align:center;color:#475569;font-size:.8rem;margin-top:2rem;padding-top:1rem;border-top:1px solid #1e293b}}
</style>
</head>
<body>
<div class="container">
<h1>🔍 CodeVigil Report</h1>
<div class="meta">
    {html.escape(report.project_name)} · {len(report.files_analyzed)} files · {report.analysis_duration_ms:.0f}ms
</div>
{score_html}
<h2 style="margin-bottom:1rem">Findings ({report.total_findings})</h2>
{findings_html if findings_html else '<p style="color:#4ade80">✅ No issues found!</p>'}
<footer>Generated by CodeVigil v0.1.0</footer>
</div>
</body>
</html>"""

    def _bar(self, label: str, value: float) -> str:
        if value >= 80:
            color = "#22c55e"
        elif value >= 60:
            color = "#eab308"
        else:
            color = "#ef4444"
        return f"""
        <div class="bar-row">
            <span class="bar-label">{label}</span>
            <div class="bar-track"><div class="bar-fill" style="width:{value}%;background:{color}"></div></div>
            <span class="bar-value">{value:.0f}</span>
        </div>"""
