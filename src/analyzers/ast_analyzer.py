"""
AST-based code pattern analyzer.

Detects anti-patterns, unreachable code, shadowed variables,
mutable default arguments, bare excepts, and other structural issues
that go beyond what regex-based linting can catch.
"""

from __future__ import annotations

import ast

from src.parsers.ast_utils import extract_code_snippet, parse_source
from src.schemas.findings import Category, Finding, Location, Severity, Suggestion


class ASTAnalyzer:
    """
    Structural code analyzer using Python's AST.

    Detects patterns that require understanding of code structure
    rather than just text matching.
    """

    def __init__(self, source: str, file_path: str):
        self.source = source
        self.file_path = file_path
        self.parsed = parse_source(source)
        self.findings: list[Finding] = []

    def analyze(self) -> list[Finding]:
        """Run all AST-based checks and return findings."""
        if self.parsed.errors:
            for err in self.parsed.errors:
                self.findings.append(Finding(
                    rule_id="AST-000",
                    title="Syntax error",
                    description=err,
                    severity=Severity.ERROR,
                    category=Category.BUG,
                    location=Location(file_path=self.file_path, start_line=1),
                    source_analyzer="ast_analyzer",
                ))
            return self.findings

        self._check_mutable_defaults()
        self._check_bare_excepts()
        self._check_unreachable_code()
        self._check_shadowed_builtins()
        self._check_unused_variables()
        self._check_star_imports()
        self._check_global_statements()
        self._check_assert_in_non_test()
        self._check_empty_except()
        self._check_return_in_init()
        self._check_nested_function_depth()
        self._check_comparison_to_none()
        self._check_duplicate_keys()

        return self.findings

    def _check_mutable_defaults(self) -> None:
        """Detect mutable default arguments (list, dict, set literals)."""
        mutable_types = (ast.List, ast.Dict, ast.Set)

        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for default in node.args.defaults + node.args.kw_defaults:
                if default is None:
                    continue
                if isinstance(default, mutable_types):
                    self.findings.append(Finding(
                        rule_id="AST-001",
                        title="Mutable default argument",
                        description=(
                            f"Function '{node.name}' uses a mutable default argument. "
                            f"Mutable defaults are shared across all calls and can lead "
                            f"to subtle bugs."
                        ),
                        severity=Severity.ERROR,
                        category=Category.BUG,
                        location=Location(
                            file_path=self.file_path,
                            start_line=node.lineno,
                            function_name=node.name,
                        ),
                        source_analyzer="ast_analyzer",
                        suggestion=Suggestion(
                            description="Use None as default and initialize inside the function body.",
                            replacement_code=f"def {node.name}(..., param=None):\n    if param is None:\n        param = {type(default).__name__.lower()}()",
                            confidence=0.95,
                        ),
                        code_snippet=extract_code_snippet(self.source, node.lineno),
                    ))

    def _check_bare_excepts(self) -> None:
        """Detect bare except clauses that catch all exceptions."""
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                self.findings.append(Finding(
                    rule_id="AST-002",
                    title="Bare except clause",
                    description=(
                        "Bare 'except:' catches all exceptions including SystemExit "
                        "and KeyboardInterrupt. Use 'except Exception:' instead."
                    ),
                    severity=Severity.WARNING,
                    category=Category.BUG,
                    location=Location(
                        file_path=self.file_path,
                        start_line=node.lineno,
                    ),
                    source_analyzer="ast_analyzer",
                    suggestion=Suggestion(
                        description="Replace with 'except Exception:' or a more specific exception type.",
                        confidence=0.9,
                    ),
                    code_snippet=extract_code_snippet(self.source, node.lineno),
                ))

    def _check_unreachable_code(self) -> None:
        """Detect code after return/raise/break/continue statements."""
        terminal = (ast.Return, ast.Raise, ast.Break, ast.Continue)

        for node in ast.walk(self.parsed.tree):
            body: list[ast.stmt] | None = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or isinstance(node, (ast.If, ast.For, ast.While, ast.With)) or isinstance(node, ast.ExceptHandler):
                body = node.body

            if body is None:
                continue

            for i, stmt in enumerate(body[:-1]):
                if isinstance(stmt, terminal) and i < len(body) - 1:
                    next_stmt = body[i + 1]
                    self.findings.append(Finding(
                        rule_id="AST-003",
                        title="Unreachable code",
                        description=(
                            f"Code at line {next_stmt.lineno} is unreachable — "
                            f"it follows a {type(stmt).__name__.lower()} statement."
                        ),
                        severity=Severity.WARNING,
                        category=Category.BUG,
                        location=Location(
                            file_path=self.file_path,
                            start_line=next_stmt.lineno,
                        ),
                        source_analyzer="ast_analyzer",
                        suggestion=Suggestion(
                            description="Remove the unreachable code or restructure the logic.",
                            confidence=0.95,
                        ),
                        code_snippet=extract_code_snippet(self.source, stmt.lineno, next_stmt.lineno),
                    ))

    def _check_shadowed_builtins(self) -> None:
        """Detect variable names that shadow Python builtins."""
        builtins_to_check = {
            "list", "dict", "set", "tuple", "str", "int", "float", "bool",
            "type", "id", "input", "print", "len", "range", "map", "filter",
            "sum", "min", "max", "abs", "open", "file", "object", "complex",
            "bytes", "format", "hash", "hex", "next", "iter", "zip", "sorted",
            "reversed",
        }

        for node in ast.walk(self.parsed.tree):
            targets: list[ast.Name] = []

            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        targets.append(t)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets.append(node.target)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    if arg.arg in builtins_to_check:
                        self.findings.append(Finding(
                            rule_id="AST-004",
                            title=f"Parameter shadows builtin '{arg.arg}'",
                            description=(
                                f"Parameter '{arg.arg}' in function '{node.name}' "
                                f"shadows the Python builtin '{arg.arg}'."
                            ),
                            severity=Severity.WARNING,
                            category=Category.BEST_PRACTICE,
                            location=Location(
                                file_path=self.file_path,
                                start_line=node.lineno,
                                function_name=node.name,
                            ),
                            source_analyzer="ast_analyzer",
                        ))

            for target in targets:
                if target.id in builtins_to_check:
                    self.findings.append(Finding(
                        rule_id="AST-004",
                        title=f"Variable shadows builtin '{target.id}'",
                        description=(
                            f"Variable '{target.id}' at line {target.lineno} "
                            f"shadows the Python builtin '{target.id}'."
                        ),
                        severity=Severity.WARNING,
                        category=Category.BEST_PRACTICE,
                        location=Location(
                            file_path=self.file_path,
                            start_line=target.lineno,
                        ),
                        source_analyzer="ast_analyzer",
                    ))

    def _check_unused_variables(self) -> None:
        """Detect variables that are assigned but never used within a function."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            assigned: dict[str, int] = {}
            used: set[str] = set()

            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name) and not target.id.startswith("_"):
                            assigned[target.id] = target.lineno
                elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    used.add(child.id)

            for var_name, lineno in assigned.items():
                if var_name not in used and var_name != "self":
                    self.findings.append(Finding(
                        rule_id="AST-005",
                        title=f"Potentially unused variable '{var_name}'",
                        description=(
                            f"Variable '{var_name}' is assigned at line {lineno} "
                            f"but appears unused in function '{node.name}'."
                        ),
                        severity=Severity.INFO,
                        category=Category.MAINTAINABILITY,
                        location=Location(
                            file_path=self.file_path,
                            start_line=lineno,
                            function_name=node.name,
                        ),
                        source_analyzer="ast_analyzer",
                    ))

    def _check_star_imports(self) -> None:
        """Flag wildcard imports."""
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        self.findings.append(Finding(
                            rule_id="AST-006",
                            title=f"Wildcard import from '{node.module}'",
                            description=(
                                f"Wildcard import 'from {node.module} import *' "
                                f"pollutes the namespace and makes it unclear which "
                                f"names are available."
                            ),
                            severity=Severity.WARNING,
                            category=Category.STYLE,
                            location=Location(file_path=self.file_path, start_line=node.lineno),
                            source_analyzer="ast_analyzer",
                            suggestion=Suggestion(
                                description="Import specific names instead of using *.",
                                confidence=0.9,
                            ),
                        ))

    def _check_global_statements(self) -> None:
        """Flag use of global statements."""
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.Global):
                self.findings.append(Finding(
                    rule_id="AST-007",
                    title="Global statement used",
                    description=(
                        f"'global' statement for {', '.join(node.names)} at line {node.lineno}. "
                        f"Global mutable state makes code harder to test and reason about."
                    ),
                    severity=Severity.WARNING,
                    category=Category.MAINTAINABILITY,
                    location=Location(file_path=self.file_path, start_line=node.lineno),
                    source_analyzer="ast_analyzer",
                ))

    def _check_assert_in_non_test(self) -> None:
        """Warn about assert statements in non-test code."""
        if "test" in self.file_path.lower():
            return

        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.Assert):
                self.findings.append(Finding(
                    rule_id="AST-008",
                    title="Assert in production code",
                    description=(
                        f"Assert statement at line {node.lineno} can be stripped "
                        f"with -O flag. Use proper error handling instead."
                    ),
                    severity=Severity.INFO,
                    category=Category.ERROR_HANDLING,
                    location=Location(file_path=self.file_path, start_line=node.lineno),
                    source_analyzer="ast_analyzer",
                    suggestion=Suggestion(
                        description="Replace with 'if not condition: raise ValueError(...)'.",
                        confidence=0.7,
                    ),
                ))

    def _check_empty_except(self) -> None:
        """Detect except blocks that only contain pass."""
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.ExceptHandler):
                if (len(node.body) == 1 and isinstance(node.body[0], ast.Pass)):
                    self.findings.append(Finding(
                        rule_id="AST-009",
                        title="Empty except block (silenced exception)",
                        description=(
                            f"Exception handler at line {node.lineno} silently swallows "
                            f"errors with 'pass'. This hides bugs."
                        ),
                        severity=Severity.ERROR,
                        category=Category.ERROR_HANDLING,
                        location=Location(file_path=self.file_path, start_line=node.lineno),
                        source_analyzer="ast_analyzer",
                        suggestion=Suggestion(
                            description="Log the exception or handle it appropriately.",
                            confidence=0.9,
                        ),
                        code_snippet=extract_code_snippet(self.source, node.lineno),
                    ))

    def _check_return_in_init(self) -> None:
        """Detect return with value in __init__."""
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        self.findings.append(Finding(
                            rule_id="AST-010",
                            title="Return with value in __init__",
                            description=(
                                f"__init__ should not return a value (line {child.lineno}). "
                                f"This will raise a TypeError at runtime."
                            ),
                            severity=Severity.ERROR,
                            category=Category.BUG,
                            location=Location(
                                file_path=self.file_path,
                                start_line=child.lineno,
                                function_name="__init__",
                            ),
                            source_analyzer="ast_analyzer",
                        ))

    def _check_nested_function_depth(self, max_depth: int = 3) -> None:
        """Detect deeply nested function definitions."""
        def _walk(node: ast.AST, depth: int) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if depth >= max_depth:
                        self.findings.append(Finding(
                            rule_id="AST-011",
                            title=f"Deeply nested function (depth {depth})",
                            description=(
                                f"Function '{child.name}' at line {child.lineno} "
                                f"is nested {depth} levels deep. This hurts readability."
                            ),
                            severity=Severity.WARNING,
                            category=Category.COMPLEXITY,
                            location=Location(
                                file_path=self.file_path,
                                start_line=child.lineno,
                                function_name=child.name,
                            ),
                            source_analyzer="ast_analyzer",
                        ))
                    _walk(child, depth + 1)
                else:
                    _walk(child, depth)

        _walk(self.parsed.tree, 0)

    def _check_comparison_to_none(self) -> None:
        """Flag == None instead of 'is None'."""
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.Compare):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comparator, ast.Constant) and comparator.value is None:
                        self.findings.append(Finding(
                            rule_id="AST-012",
                            title="Comparison to None with == instead of 'is'",
                            description=(
                                f"Use 'is None' / 'is not None' instead of '== None' / '!= None' "
                                f"at line {node.lineno}."
                            ),
                            severity=Severity.INFO,
                            category=Category.STYLE,
                            location=Location(file_path=self.file_path, start_line=node.lineno),
                            source_analyzer="ast_analyzer",
                            suggestion=Suggestion(
                                description="Replace '== None' with 'is None'.",
                                confidence=0.95,
                            ),
                        ))

    def _check_duplicate_keys(self) -> None:
        """Detect duplicate keys in dict literals."""
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.Dict):
                seen: dict[str, int] = {}
                for key in node.keys:
                    if key is None:
                        continue
                    try:
                        key_repr = ast.dump(key)
                    except Exception:
                        continue
                    if key_repr in seen:
                        self.findings.append(Finding(
                            rule_id="AST-013",
                            title="Duplicate dictionary key",
                            description=(
                                f"Dictionary at line {node.lineno} has duplicate keys. "
                                f"The later value will overwrite the earlier one."
                            ),
                            severity=Severity.ERROR,
                            category=Category.BUG,
                            location=Location(file_path=self.file_path, start_line=node.lineno),
                            source_analyzer="ast_analyzer",
                        ))
                    seen[key_repr] = node.lineno
