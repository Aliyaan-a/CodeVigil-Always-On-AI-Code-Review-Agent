# 🔍 CodeVigil — AI-Powered Code Review Agent

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**CodeVigil** is a modular, plugin-extensible AI code review agent that combines static analysis, AST-based pattern detection, and LLM-powered reasoning to deliver deep, actionable code reviews.

It reads Git diffs, full files, or entire repositories and produces structured reports identifying bugs, security vulnerabilities, performance issues, code smells, and style violations — with suggested fixes.

---

## ✨ Key Features

- **Multi-Engine Analysis Pipeline**: Chains rule-based, AST-based, and LLM-powered analyzers in a configurable pipeline
- **Plugin Architecture**: Drop-in analyzer plugins with auto-discovery — extend without modifying core code
- **AST-Powered Pattern Detection**: Deep structural analysis beyond regex — catches anti-patterns, complexity issues, and unreachable code
- **Security Scanner**: Detects hardcoded secrets, SQL injection, command injection, path traversal, insecure deserialization, and more (OWASP Top 10 coverage)
- **Complexity Metrics**: Cyclomatic complexity, cognitive complexity, Halstead metrics, and maintainability index per function
- **Git-Native**: Operates on diffs, staged changes, commits, or branches — integrates into any Git workflow
- **Structured Reports**: JSON, Markdown, HTML, and SARIF output formats for CI/CD integration
- **Severity Scoring**: ML-inspired composite scoring system that prioritizes findings by impact
- **Diff-Aware Reviews**: Only flags issues in changed lines (with configurable context radius)
- **Configurable Rule Sets**: YAML-based configuration with per-project overrides

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI / API Entry                       │
├─────────────────────────────────────────────────────────────┤
│                     Orchestrator Agent                       │
│  ┌──────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐ │
│  │ Git Diff  │  │   AST     │  │  Rule     │  │   LLM     │ │
│  │ Parser    │  │  Analyzer │  │  Engine   │  │  Reasoner │ │
│  └────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘ │
│       │              │              │              │         │
│       ▼              ▼              ▼              ▼         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Finding Aggregator & Deduplicator        │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │              Severity Scorer & Ranker                  │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │              Report Generator (JSON/MD/HTML/SARIF)     │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                     Plugin Registry                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │ Security  │  │ Perf     │  │ DocStyle │  │  Custom... │  │
│  │ Plugin    │  │ Plugin   │  │ Plugin   │  │  Plugins   │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

```bash
# Clone & install
git clone https://github.com/Aliyaan-a/CodeVigil-Always-On-AI-Code-Review-Agent.git
cd CodeVigil-Always-On-AI-Code-Review-Agent
pip install -e ".[dev]"

# Review a file
codevigil review path/to/file.py

# Review a Git diff
codevigil diff HEAD~1

# Review staged changes
codevigil diff --staged

# Full repo scan
codevigil scan ./my_project --config configs/strict.yaml

# Output as SARIF for GitHub Actions
codevigil review path/to/file.py --format sarif --output results.sarif
```

---

## 📦 Installation

```bash
# From source (recommended for development)
git clone https://github.com/Aliyaan-a/CodeVigil-Always-On-AI-Code-Review-Agent.git
cd CodeVigil-Always-On-AI-Code-Review-Agent
pip install -e ".[dev]"

# Dependencies only
pip install -r requirements.txt
```

### Requirements

- Python 3.10+
- Git (for diff operations)

### Optional Dependencies

- `openai` or `anthropic` — for LLM-powered analysis
- `tiktoken` — for token counting with OpenAI models

---

## ⚙️ Configuration

Create a `.codevigil.yaml` in your project root:

```yaml
analyzers:
  ast:
    enabled: true
    max_complexity: 10
    max_function_length: 50
  security:
    enabled: true
    severity_threshold: medium
  style:
    enabled: true
    max_line_length: 120
  llm:
    enabled: false  # Enable for AI-powered reviews
    provider: openai
    model: gpt-4
    temperature: 0.1

plugins:
  - security_scanner
  - performance_checker
  - docstring_enforcer

reporting:
  format: markdown
  include_suggestions: true
  include_metrics: true
  severity_threshold: info

scoring:
  weights:
    security: 3.0
    bug: 2.5
    performance: 1.5
    style: 0.5
    maintainability: 1.0
```

---

## 🧩 Plugin System

Create custom analyzers by implementing the `AnalyzerPlugin` protocol:

```python
from codevigil.plugins import AnalyzerPlugin, Finding

class MyCustomAnalyzer(AnalyzerPlugin):
    name = "my_analyzer"
    description = "Checks for my custom rules"

    def analyze(self, context) -> list[Finding]:
        findings = []
        # Your analysis logic here
        return findings
```

Drop it into `src/plugins/` and it's auto-discovered. See `docs/plugins.md` for the full plugin API.

---

## 📊 Output Formats

| Format   | Use Case                        | Flag              |
|----------|----------------------------------|-------------------|
| JSON     | CI/CD pipelines, APIs           | `--format json`   |
| Markdown | Pull request comments           | `--format md`     |
| HTML     | Standalone review reports       | `--format html`   |
| SARIF    | GitHub Security tab integration | `--format sarif`  |
| Console  | Terminal output (default)       | `--format console`|

---

## 🧪 Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=src --cov-report=html

# Only unit tests
pytest tests/unit/

# Only integration tests
pytest tests/integration/
```

---

## 📁 Project Structure

```
codevigil/
├── src/
│   ├── analyzers/          # Core analysis engines
│   │   ├── ast_analyzer.py       # AST-based pattern detection
│   │   ├── complexity.py         # Cyclomatic & cognitive complexity
│   │   ├── security_analyzer.py  # OWASP vulnerability scanner
│   │   ├── style_analyzer.py     # Code style & convention checks
│   │   └── llm_analyzer.py       # LLM-powered reasoning engine
│   ├── agents/             # Orchestration & coordination
│   │   ├── orchestrator.py       # Main pipeline controller
│   │   ├── aggregator.py         # Finding dedup & merge
│   │   └── scorer.py             # Severity scoring engine
│   ├── parsers/            # Input parsing
│   │   ├── diff_parser.py        # Git diff parsing
│   │   ├── file_parser.py        # Source file reading
│   │   └── ast_utils.py          # AST helper utilities
│   ├── reporters/          # Output generation
│   │   ├── json_reporter.py
│   │   ├── markdown_reporter.py
│   │   ├── html_reporter.py
│   │   ├── sarif_reporter.py
│   │   └── console_reporter.py
│   ├── plugins/            # Plugin system
│   │   ├── registry.py           # Auto-discovery & loading
│   │   ├── base.py               # Plugin protocols & base classes
│   │   ├── security_scanner.py   # Built-in security plugin
│   │   ├── performance_checker.py
│   │   └── docstring_enforcer.py
│   ├── schemas/            # Data models
│   │   ├── findings.py           # Finding & report models
│   │   └── config.py             # Configuration schema
│   ├── utils/              # Shared utilities
│   │   ├── git.py                # Git operations
│   │   ├── hashing.py            # Content hashing for dedup
│   │   └── logging.py            # Structured logging
│   └── cli/                # CLI interface
│       └── main.py               # Click-based CLI
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── configs/                # Preset configurations
│   ├── default.yaml
│   ├── strict.yaml
│   └── minimal.yaml
├── docs/                   # Documentation
├── examples/               # Example usage & sample code
├── .github/workflows/      # CI/CD
├── pyproject.toml
├── requirements.txt
└── README.md
```

---
