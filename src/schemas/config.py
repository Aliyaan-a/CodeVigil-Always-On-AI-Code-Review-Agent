"""
Configuration schema and loading for CodeVigil.

Supports YAML config files with sensible defaults, environment variable
overrides, and per-project config via .codevigil.yaml.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class ASTAnalyzerConfig:
    enabled: bool = True
    max_complexity: int = 10
    max_cognitive_complexity: int = 15
    max_function_length: int = 50
    max_parameter_count: int = 5
    max_nesting_depth: int = 4
    max_return_statements: int = 5


@dataclass
class SecurityAnalyzerConfig:
    enabled: bool = True
    severity_threshold: str = "info"
    check_hardcoded_secrets: bool = True
    check_sql_injection: bool = True
    check_command_injection: bool = True
    check_path_traversal: bool = True
    check_insecure_deserialization: bool = True
    check_weak_crypto: bool = True
    secret_patterns_file: Optional[str] = None


@dataclass
class StyleAnalyzerConfig:
    enabled: bool = True
    max_line_length: int = 120
    enforce_docstrings: bool = True
    enforce_type_hints: bool = True
    naming_convention: str = "pep8"


@dataclass
class LLMAnalyzerConfig:
    enabled: bool = False
    provider: str = "openai"
    model: str = "gpt-4"
    temperature: float = 0.1
    max_tokens: int = 2000
    api_key_env: str = "OPENAI_API_KEY"
    system_prompt: Optional[str] = None
    retry_attempts: int = 3
    timeout_seconds: int = 30


@dataclass
class AnalyzersConfig:
    ast: ASTAnalyzerConfig = field(default_factory=ASTAnalyzerConfig)
    security: SecurityAnalyzerConfig = field(default_factory=SecurityAnalyzerConfig)
    style: StyleAnalyzerConfig = field(default_factory=StyleAnalyzerConfig)
    llm: LLMAnalyzerConfig = field(default_factory=LLMAnalyzerConfig)


@dataclass
class ScoringConfig:
    weights: dict[str, float] = field(default_factory=lambda: {
        "security": 3.0, "bug": 2.5, "performance": 1.5,
        "style": 0.5, "maintainability": 1.0,
    })


@dataclass
class ReportingConfig:
    format: str = "console"
    output_file: Optional[str] = None
    include_suggestions: bool = True
    include_metrics: bool = True
    include_code_snippets: bool = True
    severity_threshold: str = "info"
    max_findings: Optional[int] = None


@dataclass
class CodeVigilConfig:
    analyzers: AnalyzersConfig = field(default_factory=AnalyzersConfig)
    plugins: list[str] = field(default_factory=lambda: ["security_scanner", "performance_checker"])
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    ignore_patterns: list[str] = field(default_factory=lambda: [
        "*.pyc", "__pycache__", ".git", "node_modules", "venv", ".venv", "*.egg-info",
    ])
    file_extensions: list[str] = field(default_factory=lambda: [".py"])

    @classmethod
    def load(cls, config_path: Optional[str | Path] = None) -> CodeVigilConfig:
        config_data: dict[str, Any] = {}

        search_paths = [
            config_path,
            Path.cwd() / ".codevigil.yaml",
            Path.cwd() / ".codevigil.yml",
            Path.home() / ".codevigil.yaml",
        ]

        for path in search_paths:
            if path is not None:
                p = Path(path)
                if p.exists():
                    with open(p) as f:
                        loaded = yaml.safe_load(f)
                        if isinstance(loaded, dict):
                            config_data = loaded
                    break

        config_data = cls._apply_env_overrides(config_data)
        return cls._from_dict(config_data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> CodeVigilConfig:
        """Build config from a dictionary, using defaults for missing values."""
        config = cls()

        analyzers_data = data.get("analyzers", {})
        if "ast" in analyzers_data:
            for k, v in analyzers_data["ast"].items():
                if hasattr(config.analyzers.ast, k):
                    setattr(config.analyzers.ast, k, v)
        if "security" in analyzers_data:
            for k, v in analyzers_data["security"].items():
                if hasattr(config.analyzers.security, k):
                    setattr(config.analyzers.security, k, v)
        if "style" in analyzers_data:
            for k, v in analyzers_data["style"].items():
                if hasattr(config.analyzers.style, k):
                    setattr(config.analyzers.style, k, v)
        if "llm" in analyzers_data:
            for k, v in analyzers_data["llm"].items():
                if hasattr(config.analyzers.llm, k):
                    setattr(config.analyzers.llm, k, v)

        if "plugins" in data:
            config.plugins = data["plugins"]
        if "scoring" in data and "weights" in data["scoring"]:
            config.scoring.weights = data["scoring"]["weights"]
        if "reporting" in data:
            for k, v in data["reporting"].items():
                if hasattr(config.reporting, k):
                    setattr(config.reporting, k, v)
        if "ignore_patterns" in data:
            config.ignore_patterns = data["ignore_patterns"]
        if "file_extensions" in data:
            config.file_extensions = data["file_extensions"]

        return config

    def model_dump(self) -> dict[str, Any]:
        """Serialize config to dict."""
        from dataclasses import asdict
        return asdict(self)

    @staticmethod
    def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
        env_map = {
            "CODEVIGIL_LLM_PROVIDER": ("analyzers", "llm", "provider"),
            "CODEVIGIL_LLM_MODEL": ("analyzers", "llm", "model"),
            "CODEVIGIL_LLM_ENABLED": ("analyzers", "llm", "enabled"),
            "CODEVIGIL_FORMAT": ("reporting", "format"),
            "CODEVIGIL_SEVERITY": ("reporting", "severity_threshold"),
        }
        for env_var, path in env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                current = data
                for key in path[:-1]:
                    current = current.setdefault(key, {})
                final_key = path[-1]
                if value.lower() in ("true", "1", "yes"):
                    current[final_key] = True
                elif value.lower() in ("false", "0", "no"):
                    current[final_key] = False
                else:
                    current[final_key] = value
        return data
