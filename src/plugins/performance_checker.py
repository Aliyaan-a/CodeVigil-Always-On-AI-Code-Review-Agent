"""
Performance anti-pattern detection plugin.

Flags common Python performance pitfalls: unnecessary list copies,
string concatenation in loops, repeated attribute lookups,
inefficient iteration patterns, and more.
"""

from __future__ import annotations

import ast

from src.parsers.ast_utils import extract_code_snippet, parse_source
from src.plugins.base import AnalysisContext, BaseAnalyzerPlugin
from src.schemas.findings import Category, Finding, Location, Severity, Suggestion


class PerformanceCheckerPlugin(BaseAnalyzerPlugin):
    """Detects common Python performance anti-patterns."""

    name = "performance_checker"
    description = "Detects performance anti-patterns and inefficiencies"
    version = "0.1.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        parsed = parse_source(context.source)
        if parsed.errors:
            return findings

        findings.extend(self._check_string_concat_in_loop(parsed.tree, context))
        findings.extend(self._check_list_comprehension_opportunities(parsed.tree, context))
        findings.extend(self._check_membership_on_list(parsed.tree, context))
        findings.extend(self._check_unnecessary_list_call(parsed.tree, context))
        findings.extend(self._check_repeated_dict_access(parsed.tree, context))
        findings.extend(self._check_global_import_in_function(parsed.tree, context))

        return findings

    def _check_string_concat_in_loop(
        self, tree: ast.Module, ctx: AnalysisContext
    ) -> list[Finding]:
        """Detect string concatenation with += inside loops."""
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.While)):
                continue
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.AugAssign)
                    and isinstance(child.op, ast.Add)
                    and isinstance(child.target, ast.Name)
                ):
                    # Heuristic: check if the variable is used as a string
                    # (we can't fully type-check, but += with str literal is a hint)
                    if isinstance(child.value, (ast.Constant, ast.JoinedStr)):
                        if isinstance(child.value, ast.Constant) and not isinstance(
                            child.value.value, str
                        ):
                            continue
                        findings.append(Finding(
                            rule_id="PERF-001",
                            title="String concatenation in loop",
                            description=(
                                f"String concatenation with += at line {child.lineno} "
                                f"inside a loop creates a new string object each iteration. "
                                f"Use str.join() or io.StringIO instead."
                            ),
                            severity=Severity.WARNING,
                            category=Category.PERFORMANCE,
                            location=Location(
                                file_path=ctx.file_path, start_line=child.lineno
                            ),
                            source_analyzer="performance_checker",
                            suggestion=Suggestion(
                                description="Collect parts in a list and join: ''.join(parts)",
                                confidence=0.7,
                            ),
                            code_snippet=extract_code_snippet(ctx.source, child.lineno),
                        ))
        return findings

    def _check_list_comprehension_opportunities(
        self, tree: ast.Module, ctx: AnalysisContext
    ) -> list[Finding]:
        """Detect for loops that could be list comprehensions."""
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.For):
                continue
            # Pattern: empty list → for loop → append
            body = node.body
            if len(body) == 1 and isinstance(body[0], ast.Expr):
                expr = body[0].value
                if (
                    isinstance(expr, ast.Call)
                    and isinstance(expr.func, ast.Attribute)
                    and expr.func.attr == "append"
                    and not node.orelse
                ):
                    findings.append(Finding(
                        rule_id="PERF-002",
                        title="Loop could be a list comprehension",
                        description=(
                            f"For-loop at line {node.lineno} appends to a list and "
                            f"could be rewritten as a list comprehension for clarity and performance."
                        ),
                        severity=Severity.INFO,
                        category=Category.PERFORMANCE,
                        location=Location(file_path=ctx.file_path, start_line=node.lineno),
                        source_analyzer="performance_checker",
                        suggestion=Suggestion(
                            description="Replace with: result = [transform(x) for x in iterable]",
                            confidence=0.6,
                        ),
                    ))
        return findings

    def _check_membership_on_list(
        self, tree: ast.Module, ctx: AnalysisContext
    ) -> list[Finding]:
        """Detect 'x in [...]' or 'x in list_var' that could use a set."""
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.In, ast.NotIn)) and isinstance(
                        comparator, ast.List
                    ):
                        if len(comparator.elts) >= 3:
                            findings.append(Finding(
                                rule_id="PERF-003",
                                title="Membership test on list literal",
                                description=(
                                    f"Membership test against a list literal at line {node.lineno}. "
                                    f"Use a set literal {{...}} for O(1) lookup instead of O(n)."
                                ),
                                severity=Severity.INFO,
                                category=Category.PERFORMANCE,
                                location=Location(
                                    file_path=ctx.file_path, start_line=node.lineno
                                ),
                                source_analyzer="performance_checker",
                                suggestion=Suggestion(
                                    description="Replace [...] with {...} for O(1) membership testing.",
                                    confidence=0.9,
                                ),
                            ))
        return findings

    def _check_unnecessary_list_call(
        self, tree: ast.Module, ctx: AnalysisContext
    ) -> list[Finding]:
        """Detect list() wrapping generators that don't need materializing."""
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == "list":
                if node.args and isinstance(node.args[0], ast.GeneratorExp):
                    # Check if the list() result is only iterated (not indexed)
                    # This is a simplified heuristic
                    findings.append(Finding(
                        rule_id="PERF-004",
                        title="Possibly unnecessary list() materialization",
                        description=(
                            f"list() wrapping a generator at line {node.lineno} may be "
                            f"unnecessary if the result is only iterated, not indexed."
                        ),
                        severity=Severity.INFO,
                        category=Category.PERFORMANCE,
                        location=Location(file_path=ctx.file_path, start_line=node.lineno),
                        source_analyzer="performance_checker",
                    ))
        return findings

    def _check_repeated_dict_access(
        self, tree: ast.Module, ctx: AnalysisContext
    ) -> list[Finding]:
        """Detect repeated dict[key] access that could use a local variable."""
        findings = []
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Count subscript accesses per (dict_name, key)
            accesses: dict[str, list[int]] = {}
            for node in ast.walk(func):
                if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                    try:
                        key_repr = ast.dump(node.slice)
                        access_key = f"{node.value.id}[{key_repr}]"
                        accesses.setdefault(access_key, []).append(node.lineno)
                    except Exception:
                        pass

            for access_key, lines in accesses.items():
                if len(lines) >= 3:
                    findings.append(Finding(
                        rule_id="PERF-005",
                        title=f"Repeated dict access: {access_key}",
                        description=(
                            f"'{access_key}' is accessed {len(lines)} times in function "
                            f"'{func.name}'. Store it in a local variable."
                        ),
                        severity=Severity.INFO,
                        category=Category.PERFORMANCE,
                        location=Location(
                            file_path=ctx.file_path,
                            start_line=lines[0],
                            function_name=func.name,
                        ),
                        source_analyzer="performance_checker",
                    ))
        return findings

    def _check_global_import_in_function(
        self, tree: ast.Module, ctx: AnalysisContext
    ) -> list[Finding]:
        """Flag imports inside functions (unless there's a good reason)."""
        findings = []
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(func):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    findings.append(Finding(
                        rule_id="PERF-006",
                        title="Import inside function",
                        description=(
                            f"Import statement inside function '{func.name}' at line "
                            f"{node.lineno}. This runs on every call. Move to module level "
                            f"unless needed for circular import avoidance."
                        ),
                        severity=Severity.INFO,
                        category=Category.PERFORMANCE,
                        location=Location(
                            file_path=ctx.file_path,
                            start_line=node.lineno,
                            function_name=func.name,
                        ),
                        source_analyzer="performance_checker",
                    ))
        return findings
