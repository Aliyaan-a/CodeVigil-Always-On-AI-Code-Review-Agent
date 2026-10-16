"""
Plugin system base classes and protocols.

Defines the contract that all analyzer plugins must implement,
along with lifecycle hooks and context objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from src.schemas.config import CodeVigilConfig
from src.schemas.findings import Finding


@dataclass
class AnalysisContext:
    """
    Context object passed to plugins during analysis.

    Contains all information a plugin needs: source code, file metadata,
    configuration, and results from prior analyzers.
    """

    source: str
    file_path: str
    language: str = "python"
    config: CodeVigilConfig | None = None
    changed_lines: set[int] | None = None
    prior_findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def lines(self) -> list[str]:
        return self.source.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def is_line_changed(self, line: int) -> bool:
        """Check if a specific line was in the diff (if diff info available)."""
        if self.changed_lines is None:
            return True  # No diff info → treat everything as changed
        return line in self.changed_lines


@runtime_checkable
class AnalyzerPlugin(Protocol):
    """
    Protocol defining the plugin interface.

    Any class implementing these attributes and methods can be
    used as an analyzer plugin without inheritance.
    """

    name: str
    description: str
    version: str

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Run the analysis and return findings."""
        ...


class BaseAnalyzerPlugin(ABC):
    """
    Abstract base class for analyzer plugins.

    Provides default implementations and lifecycle hooks.
    Plugins can inherit from this or just implement the Protocol.
    """

    name: str = "unnamed_plugin"
    description: str = ""
    version: str = "0.1.0"
    enabled: bool = True

    def __init__(self, config: dict[str, Any] | None = None):
        self.plugin_config = config or {}

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Run the analysis — must be implemented by subclasses."""
        ...

    def setup(self) -> None:
        """Called once when the plugin is loaded. Override for initialization."""

    def teardown(self) -> None:
        """Called when the plugin is unloaded. Override for cleanup."""

    def supports_language(self, language: str) -> bool:
        """Return True if this plugin supports the given language."""
        return language == "python"

    def __repr__(self) -> str:
        return f"<Plugin {self.name} v{self.version}>"
