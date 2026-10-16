"""
Code style and convention analyzer.

Checks naming conventions, docstring presence, type hint coverage,
line length, import ordering, and other PEP 8 / PEP 257 patterns.
"""

from __future__ import annotations

import ast
import re
from typing import Optional

from src.schemas.findings import Finding, Category, Severity, Location, Suggestion
from src.parsers.ast_utils import parse_source, extract_code_snippet


# PEP 8 naming patterns
SNAKE_CASE_RE = re.compile(r"^_?_?[a-z][a-z0-9_]*_?_?$")
UPPER_CASE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
PASCAL_CASE_RE = re.compile(r"^_?[A-Z][a-zA-Z0-9]*$")

# Common abbreviations that are acceptable as short names
ACCEPTABLE_SHORT_NAMES = {"i", "j", "k", "n", "x", "y", "z", "e", "f", "db", "id", "ok", "_"}


class StyleAnalyzer:
    """
    Code style and convention analyzer.

    Enforces PEP 8 naming, PEP 257 docstrings, type hint coverage,
    line length limits, and import organization.
    """

    def __init__(
        self,
        source: str,
        file_path: str,
        max_line_length: int = 120,
        enforce_docstrings: bool = True,
        enforce_type_hints: bool = True,
    ):
        self.source = source
        self.file_path = file_path
        self.lines = source.splitlines()
        self.max_line_length = max_line_length
        self.enforce_docstrings = enforce_docstrings
        self.enforce_type_hints = enforce_type_hints
        self.parsed = parse_source(source)
        self.findings: list[Finding] = []

    def analyze(self) -> list[Finding]:
        """Run all style checks."""
        if self.parsed.errors:
            return self.findings

        self._check_line_length()
        self._check_trailing_whitespace()
        self._check_function_naming()
        self._check_class_naming()
        self._check_constant_naming()
        self._check_variable_naming()
        self._check_docstrings()
        self._check_type_hints()
        self._check_import_order()
        self._check_blank_lines()
        self._check_todo_fixme()

        return self.findings

    def _check_line_length(self) -> None:
        """Flag lines exceeding the configured maximum length."""
        for i, line in enumerate(self.lines, start=1):
            length = len(line)
            if length > self.max_line_length:
                # Allow long URLs and comments with URLs
                if "http://" in line or "https://" in line:
                    continue
                # Allow long string literals
                stripped = line.strip()
                if stripped.startswith(('"""', "'''", '"', "'")):
                    continue

                self.findings.append(Finding(
                    rule_id="STY-001",
                    title=f"Line too long ({length} > {self.max_line_length})",
                    description=f"Line {i} is {length} characters, exceeding the {self.max_line_length} limit.",
                    severity=Severity.INFO,
                    category=Category.STYLE,
                    location=Location(file_path=self.file_path, start_line=i),
                    source_analyzer="style_analyzer",
                ))

    def _check_trailing_whitespace(self) -> None:
        """Flag trailing whitespace."""
        trailing_count = 0
        for i, line in enumerate(self.lines, start=1):
            if line != line.rstrip():
                trailing_count += 1

        if trailing_count > 0:
            self.findings.append(Finding(
                rule_id="STY-002",
                title=f"Trailing whitespace ({trailing_count} lines)",
                description=f"{trailing_count} lines contain trailing whitespace.",
                severity=Severity.INFO,
                category=Category.STYLE,
                location=Location(file_path=self.file_path, start_line=1),
                source_analyzer="style_analyzer",
                suggestion=Suggestion(
                    description="Configure your editor to strip trailing whitespace on save.",
                    confidence=1.0,
                ),
            ))

    def _check_function_naming(self) -> None:
        """Ensure functions use snake_case (PEP 8)."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            name = node.name
            # Skip dunder methods and private methods
            if name.startswith("__") and name.endswith("__"):
                continue

            if not SNAKE_CASE_RE.match(name):
                self.findings.append(Finding(
                    rule_id="STY-003",
                    title=f"Function name '{name}' not snake_case",
                    description=f"Function '{name}' at line {node.lineno} should use snake_case naming (PEP 8).",
                    severity=Severity.INFO,
                    category=Category.STYLE,
                    location=Location(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        function_name=name,
                    ),
                    source_analyzer="style_analyzer",
                ))

    def _check_class_naming(self) -> None:
        """Ensure classes use PascalCase (PEP 8)."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, ast.ClassDef):
                continue

            if not PASCAL_CASE_RE.match(node.name):
                self.findings.append(Finding(
                    rule_id="STY-004",
                    title=f"Class name '{node.name}' not PascalCase",
                    description=f"Class '{node.name}' at line {node.lineno} should use PascalCase naming (PEP 8).",
                    severity=Severity.INFO,
                    category=Category.STYLE,
                    location=Location(file_path=self.file_path, start_line=node.lineno),
                    source_analyzer="style_analyzer",
                ))

    def _check_constant_naming(self) -> None:
        """Check that module-level constants use UPPER_CASE."""
        for node in ast.iter_child_nodes(self.parsed.tree):
            if not isinstance(node, ast.Assign):
                continue

            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id
                if name.startswith("_"):
                    continue

                # Heuristic: if the value is a simple literal, it's likely a constant
                is_constant_value = isinstance(
                    node.value,
                    (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict),
                )
                if not is_constant_value:
                    continue

                # If it looks like it was intended as a constant (all caps or mixed)
                # but doesn't follow UPPER_CASE convention
                if name.isupper():
                    continue  # Already UPPER_CASE
                if SNAKE_CASE_RE.match(name):
                    continue  # Regular variable, fine

                # Only flag if it looks like a failed attempt at a constant
                # (e.g., MaxRetries instead of MAX_RETRIES)
                if PASCAL_CASE_RE.match(name) and isinstance(node.value, ast.Constant):
                    self.findings.append(Finding(
                        rule_id="STY-005",
                        title=f"Constant '{name}' should be UPPER_CASE",
                        description=(
                            f"Module-level constant '{name}' at line {node.lineno} "
                            f"appears to be a constant but doesn't use UPPER_CASE."
                        ),
                        severity=Severity.INFO,
                        category=Category.STYLE,
                        location=Location(file_path=self.file_path, start_line=node.lineno),
                        source_analyzer="style_analyzer",
                    ))

    def _check_variable_naming(self) -> None:
        """Check for overly short or cryptic variable names."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            name = target.id
                            if (
                                len(name) == 1
                                and name not in ACCEPTABLE_SHORT_NAMES
                                and not name.startswith("_")
                            ):
                                self.findings.append(Finding(
                                    rule_id="STY-006",
                                    title=f"Single-character variable name '{name}'",
                                    description=(
                                        f"Variable '{name}' at line {child.lineno} in "
                                        f"function '{node.name}' is too short. Use a "
                                        f"descriptive name."
                                    ),
                                    severity=Severity.INFO,
                                    category=Category.STYLE,
                                    location=Location(
                                        file_path=self.file_path,
                                        start_line=child.lineno,
                                        function_name=node.name,
                                    ),
                                    source_analyzer="style_analyzer",
                                ))

    def _check_docstrings(self) -> None:
        """Check for missing docstrings on public functions, classes, and modules."""
        if not self.enforce_docstrings:
            return

        # Module docstring
        if not ast.get_docstring(self.parsed.tree):
            self.findings.append(Finding(
                rule_id="STY-010",
                title="Missing module docstring",
                description=f"Module '{self.file_path}' lacks a docstring.",
                severity=Severity.INFO,
                category=Category.DOCUMENTATION,
                location=Location(file_path=self.file_path, start_line=1),
                source_analyzer="style_analyzer",
            ))

        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.ClassDef):
                if not ast.get_docstring(node) and not node.name.startswith("_"):
                    self.findings.append(Finding(
                        rule_id="STY-011",
                        title=f"Missing docstring for class '{node.name}'",
                        description=f"Public class '{node.name}' at line {node.lineno} lacks a docstring.",
                        severity=Severity.INFO,
                        category=Category.DOCUMENTATION,
                        location=Location(file_path=self.file_path, start_line=node.lineno),
                        source_analyzer="style_analyzer",
                    ))

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_") and not node.name.startswith("__"):
                    continue
                if not ast.get_docstring(node):
                    self.findings.append(Finding(
                        rule_id="STY-012",
                        title=f"Missing docstring for '{node.name}'",
                        description=f"Public function '{node.name}' at line {node.lineno} lacks a docstring.",
                        severity=Severity.INFO,
                        category=Category.DOCUMENTATION,
                        location=Location(
                            file_path=self.file_path,
                            start_line=node.lineno,
                            function_name=node.name,
                        ),
                        source_analyzer="style_analyzer",
                    ))

    def _check_type_hints(self) -> None:
        """Check for missing type annotations on function signatures."""
        if not self.enforce_type_hints:
            return

        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Skip private and dunder methods (except __init__)
            if node.name.startswith("_") and node.name != "__init__":
                continue

            # Check return annotation (skip __init__)
            if node.returns is None and node.name != "__init__":
                self.findings.append(Finding(
                    rule_id="STY-020",
                    title=f"Missing return type annotation for '{node.name}'",
                    description=(
                        f"Function '{node.name}' at line {node.lineno} "
                        f"is missing a return type annotation."
                    ),
                    severity=Severity.INFO,
                    category=Category.TYPE_SAFETY,
                    location=Location(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        function_name=node.name,
                    ),
                    source_analyzer="style_analyzer",
                ))

            # Check parameter annotations
            unannotated = []
            for arg in node.args.args:
                if arg.arg == "self" or arg.arg == "cls":
                    continue
                if arg.annotation is None:
                    unannotated.append(arg.arg)

            if unannotated:
                self.findings.append(Finding(
                    rule_id="STY-021",
                    title=f"Missing type hints in '{node.name}'",
                    description=(
                        f"Parameters {unannotated} in function '{node.name}' "
                        f"at line {node.lineno} lack type annotations."
                    ),
                    severity=Severity.INFO,
                    category=Category.TYPE_SAFETY,
                    location=Location(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        function_name=node.name,
                    ),
                    source_analyzer="style_analyzer",
                ))

    def _check_import_order(self) -> None:
        """Check that imports follow PEP 8 grouping: stdlib, third-party, local."""
        import_groups: list[tuple[int, str, int]] = []  # (line, module, group)

        for node in ast.iter_child_nodes(self.parsed.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    group = self._classify_import(alias.name)
                    import_groups.append((node.lineno, alias.name, group))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                group = self._classify_import(module)
                import_groups.append((node.lineno, module, group))

        # Check ordering: group numbers should be non-decreasing
        prev_group = -1
        for lineno, module, group in import_groups:
            if group < prev_group:
                self.findings.append(Finding(
                    rule_id="STY-030",
                    title="Import order violation",
                    description=(
                        f"Import '{module}' at line {lineno} is out of order. "
                        f"Follow PEP 8: stdlib → third-party → local."
                    ),
                    severity=Severity.INFO,
                    category=Category.STYLE,
                    location=Location(file_path=self.file_path, start_line=lineno),
                    source_analyzer="style_analyzer",
                    suggestion=Suggestion(
                        description="Use isort to automatically sort imports.",
                        confidence=0.9,
                    ),
                ))
                break
            prev_group = group

    def _check_blank_lines(self) -> None:
        """Check for excessive consecutive blank lines."""
        consecutive_blanks = 0
        for i, line in enumerate(self.lines, start=1):
            if line.strip() == "":
                consecutive_blanks += 1
            else:
                if consecutive_blanks > 2:
                    self.findings.append(Finding(
                        rule_id="STY-031",
                        title=f"Too many blank lines ({consecutive_blanks})",
                        description=f"{consecutive_blanks} consecutive blank lines before line {i}.",
                        severity=Severity.INFO,
                        category=Category.STYLE,
                        location=Location(file_path=self.file_path, start_line=i - consecutive_blanks),
                        source_analyzer="style_analyzer",
                    ))
                consecutive_blanks = 0

    def _check_todo_fixme(self) -> None:
        """Track TODO/FIXME/HACK/XXX comments for visibility."""
        pattern = re.compile(r"#\s*(TODO|FIXME|HACK|XXX|BUG)\b[:\s]*(.*)", re.IGNORECASE)
        for i, line in enumerate(self.lines, start=1):
            match = pattern.search(line)
            if match:
                tag = match.group(1).upper()
                msg = match.group(2).strip()
                self.findings.append(Finding(
                    rule_id="STY-040",
                    title=f"{tag} comment found",
                    description=f"{tag} at line {i}: {msg}" if msg else f"{tag} at line {i}",
                    severity=Severity.INFO,
                    category=Category.MAINTAINABILITY,
                    location=Location(file_path=self.file_path, start_line=i),
                    source_analyzer="style_analyzer",
                    tags=[tag.lower()],
                ))

    @staticmethod
    def _classify_import(module: str) -> int:
        """Classify import into group: 0=stdlib, 1=third-party, 2=local."""
        stdlib_top_level = {
            "abc", "ast", "asyncio", "base64", "collections", "concurrent",
            "contextlib", "copy", "csv", "dataclasses", "datetime", "decimal",
            "enum", "functools", "glob", "hashlib", "hmac", "html", "http",
            "importlib", "inspect", "io", "itertools", "json", "logging",
            "math", "multiprocessing", "operator", "os", "pathlib", "pickle",
            "platform", "pprint", "queue", "random", "re", "secrets",
            "shutil", "signal", "socket", "sqlite3", "statistics", "string",
            "struct", "subprocess", "sys", "tempfile", "textwrap", "threading",
            "time", "traceback", "typing", "unittest", "urllib", "uuid",
            "warnings", "xml", "zipfile",
        }
        top = module.split(".")[0]
        if top in stdlib_top_level or top.startswith("_"):
            return 0
        if top == "src" or module.startswith("."):
            return 2
        return 1
