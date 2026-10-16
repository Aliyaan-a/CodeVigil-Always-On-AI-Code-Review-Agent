"""
Built-in security scanner plugin.

Wraps the core SecurityAnalyzer as a drop-in plugin for the
plugin registry system.
"""

from __future__ import annotations

from src.analyzers.security_analyzer import SecurityAnalyzer
from src.plugins.base import AnalysisContext, BaseAnalyzerPlugin
from src.schemas.findings import Finding


class SecurityScannerPlugin(BaseAnalyzerPlugin):
    """Plugin wrapper around the core security analyzer."""

    name = "security_scanner"
    description = "OWASP-based security vulnerability scanner"
    version = "0.1.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        analyzer = SecurityAnalyzer(context.source, context.file_path)
        return analyzer.analyze()
