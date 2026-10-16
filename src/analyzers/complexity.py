"""
Complexity analysis engine.

Computes cyclomatic complexity, cognitive complexity, Halstead metrics,
and maintainability index for Python functions and methods.
"""

from __future__ import annotations

import ast
import math

from src.parsers.ast_utils import count_nesting_depth, parse_source, walk_functions
from src.schemas.findings import (
    Category,
    ComplexityMetrics,
    Finding,
    Location,
    Severity,
    Suggestion,
)


def compute_cyclomatic_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """
    Compute cyclomatic complexity (McCabe's metric).

    CC = 1 + number of decision points.
    Decision points: if, elif, for, while, except, with, and, or,
    assert, ternary (IfExp), comprehension filters.
    """
    complexity = 1

    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp)) or isinstance(child, (ast.For, ast.AsyncFor, ast.While)) or isinstance(child, ast.ExceptHandler) or isinstance(child, (ast.With, ast.AsyncWith)) or isinstance(child, ast.Assert):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            # Each 'and'/'or' adds a path
            complexity += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            complexity += 1
            complexity += len(child.ifs)

    return complexity


def compute_cognitive_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """
    Compute cognitive complexity (SonarSource metric).

    Unlike cyclomatic complexity, cognitive complexity penalizes
    deeply nested structures and rewards linear flow.

    Increments for:
    - Structural: if, elif, else, for, while, except, ternary
    - Nesting: +1 for each level of nesting
    - Fundamental: and, or, break, continue, goto-like patterns
    """

    def _walk(body: list[ast.stmt], nesting: int) -> int:
        total = 0
        for stmt in body:
            total += _process_node(stmt, nesting)
        return total

    def _process_node(node: ast.AST, nesting: int) -> int:
        score = 0

        if isinstance(node, ast.If):
            score += 1 + nesting  # structural + nesting increment
            score += _walk(node.body, nesting + 1)
            for item in node.orelse:
                if isinstance(item, ast.If):
                    # elif counts as +1 (no nesting increment)
                    score += 1
                    score += _walk(item.body, nesting + 1)
                    score += _walk(item.orelse, nesting + 1) if item.orelse else 0
                else:
                    # else counts as +1
                    score += 1
                    score += _process_node(item, nesting + 1)
            return score

        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            score += 1 + nesting
            score += _walk(node.body, nesting + 1)
            if node.orelse:
                score += 1
                score += _walk(node.orelse, nesting + 1)
            return score

        if isinstance(node, ast.Try):
            score += _walk(node.body, nesting)
            for handler in node.handlers:
                score += 1 + nesting
                score += _walk(handler.body, nesting + 1)
            if node.orelse:
                score += _walk(node.orelse, nesting)
            if node.finalbody:
                score += _walk(node.finalbody, nesting)
            return score

        if isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
            return score

        if isinstance(node, ast.IfExp):
            score += 1 + nesting
            return score

        if isinstance(node, (ast.Break, ast.Continue)):
            score += 1
            return score

        # Recurse into nested structures
        if isinstance(node, (ast.With, ast.AsyncWith)):
            score += 1 + nesting
            score += _walk(node.body, nesting + 1)
            return score

        # Recursion detection (calling function with same name)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name):
                # Simplified recursion check
                pass

        # Generic child walk for non-control-flow nodes
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                score += _process_node(child, nesting)

        return score

    return _walk(node.body, 0)


def compute_halstead_metrics(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[float | None, float | None]:
    """
    Compute Halstead volume and difficulty.

    Halstead metrics measure algorithmic complexity based on
    operators and operands in the code.
    """
    operators: set[str] = set()
    operands: set[str] = set()
    total_operators = 0
    total_operands = 0

    for child in ast.walk(node):
        if isinstance(child, ast.BinOp) or isinstance(child, ast.UnaryOp):
            op_name = type(child.op).__name__
            operators.add(op_name)
            total_operators += 1
        elif isinstance(child, ast.BoolOp):
            op_name = type(child.op).__name__
            operators.add(op_name)
            total_operators += len(child.values) - 1
        elif isinstance(child, ast.Compare):
            for op in child.ops:
                op_name = type(op).__name__
                operators.add(op_name)
                total_operators += 1
        elif isinstance(child, ast.Name):
            operands.add(child.id)
            total_operands += 1
        elif isinstance(child, ast.Constant):
            operands.add(str(child.value))
            total_operands += 1
        elif isinstance(child, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            operators.add("=")
            total_operators += 1
        elif isinstance(child, ast.Call):
            operators.add("()")
            total_operators += 1

    n1 = len(operators)  # distinct operators
    n2 = len(operands)   # distinct operands
    N1 = total_operators  # total operators
    N2 = total_operands   # total operands

    if n1 == 0 or n2 == 0 or N1 + N2 == 0:
        return None, None

    N = N1 + N2
    n = n1 + n2
    volume = N * math.log2(n) if n > 0 else 0
    difficulty = (n1 / 2) * (N2 / n2) if n2 > 0 else 0

    return round(volume, 2), round(difficulty, 2)


def compute_maintainability_index(
    halstead_volume: float | None,
    cyclomatic: int,
    loc: int,
) -> float | None:
    """
    Compute maintainability index (MI).

    MI = max(0, (171 - 5.2 * ln(HV) - 0.23 * CC - 16.2 * ln(LOC)) * 100 / 171)
    """
    if halstead_volume is None or halstead_volume <= 0 or loc <= 0:
        return None

    mi = 171 - 5.2 * math.log(halstead_volume) - 0.23 * cyclomatic - 16.2 * math.log(loc)
    mi = max(0, mi * 100 / 171)
    return round(mi, 2)


def analyze_complexity(
    source: str,
    file_path: str,
    max_cyclomatic: int = 10,
    max_cognitive: int = 15,
    max_function_length: int = 50,
    max_params: int = 5,
    max_nesting: int = 4,
) -> tuple[list[ComplexityMetrics], list[Finding]]:
    """
    Run full complexity analysis on a source file.

    Returns metrics for every function and findings for violations.
    """
    parsed = parse_source(source)
    if parsed.errors:
        return [], []

    metrics: list[ComplexityMetrics] = []
    findings: list[Finding] = []

    for func_node in walk_functions(parsed.tree):
        cc = compute_cyclomatic_complexity(func_node)
        cog = compute_cognitive_complexity(func_node)
        vol, diff = compute_halstead_metrics(func_node)
        nesting = count_nesting_depth(func_node)
        end_line = func_node.end_lineno or func_node.lineno
        loc = end_line - func_node.lineno + 1
        param_count = len(func_node.args.args) + len(func_node.args.kwonlyargs)
        mi = compute_maintainability_index(vol, cc, loc)

        m = ComplexityMetrics(
            function_name=func_node.name,
            file_path=file_path,
            line_number=func_node.lineno,
            cyclomatic_complexity=cc,
            cognitive_complexity=cog,
            lines_of_code=loc,
            parameter_count=param_count,
            nesting_depth=nesting,
            halstead_volume=vol,
            halstead_difficulty=diff,
            maintainability_index=mi,
        )
        metrics.append(m)

        # Generate findings for violations
        location = Location(
            file_path=file_path,
            start_line=func_node.lineno,
            end_line=end_line,
            function_name=func_node.name,
        )

        if cc > max_cyclomatic:
            findings.append(Finding(
                rule_id="CX-001",
                title=f"High cyclomatic complexity ({cc})",
                description=(
                    f"Function '{func_node.name}' has cyclomatic complexity of {cc}, "
                    f"exceeding threshold of {max_cyclomatic}. Consider breaking it "
                    f"into smaller functions."
                ),
                severity=Severity.WARNING if cc <= max_cyclomatic * 2 else Severity.ERROR,
                category=Category.COMPLEXITY,
                location=location,
                source_analyzer="complexity",
                suggestion=Suggestion(
                    description="Extract conditional branches into separate helper functions.",
                    confidence=0.7,
                ),
                metadata={"cyclomatic_complexity": cc, "threshold": max_cyclomatic},
            ))

        if cog > max_cognitive:
            findings.append(Finding(
                rule_id="CX-002",
                title=f"High cognitive complexity ({cog})",
                description=(
                    f"Function '{func_node.name}' has cognitive complexity of {cog}, "
                    f"exceeding threshold of {max_cognitive}. This function is hard "
                    f"to understand due to deeply nested control flow."
                ),
                severity=Severity.WARNING if cog <= max_cognitive * 2 else Severity.ERROR,
                category=Category.COMPLEXITY,
                location=location,
                source_analyzer="complexity",
                suggestion=Suggestion(
                    description="Reduce nesting by using early returns, guard clauses, or extracting logic.",
                    confidence=0.7,
                ),
                metadata={"cognitive_complexity": cog, "threshold": max_cognitive},
            ))

        if loc > max_function_length:
            findings.append(Finding(
                rule_id="CX-003",
                title=f"Function too long ({loc} lines)",
                description=(
                    f"Function '{func_node.name}' is {loc} lines long, "
                    f"exceeding the {max_function_length} line limit."
                ),
                severity=Severity.WARNING,
                category=Category.MAINTAINABILITY,
                location=location,
                source_analyzer="complexity",
                suggestion=Suggestion(
                    description="Break this function into smaller, focused helper functions.",
                    confidence=0.8,
                ),
            ))

        if param_count > max_params:
            findings.append(Finding(
                rule_id="CX-004",
                title=f"Too many parameters ({param_count})",
                description=(
                    f"Function '{func_node.name}' has {param_count} parameters, "
                    f"exceeding the {max_params} parameter limit. Consider using "
                    f"a configuration object or dataclass."
                ),
                severity=Severity.WARNING,
                category=Category.MAINTAINABILITY,
                location=location,
                source_analyzer="complexity",
                suggestion=Suggestion(
                    description="Group related parameters into a dataclass or TypedDict.",
                    confidence=0.7,
                ),
            ))

        if nesting > max_nesting:
            findings.append(Finding(
                rule_id="CX-005",
                title=f"Excessive nesting depth ({nesting})",
                description=(
                    f"Function '{func_node.name}' has nesting depth of {nesting}, "
                    f"exceeding threshold of {max_nesting}."
                ),
                severity=Severity.WARNING,
                category=Category.COMPLEXITY,
                location=location,
                source_analyzer="complexity",
                suggestion=Suggestion(
                    description="Use early returns and guard clauses to flatten control flow.",
                    confidence=0.8,
                ),
            ))

        if mi is not None and mi < 20:
            findings.append(Finding(
                rule_id="CX-006",
                title=f"Low maintainability index ({mi})",
                description=(
                    f"Function '{func_node.name}' has a maintainability index of {mi}, "
                    f"indicating it is difficult to maintain. Consider refactoring."
                ),
                severity=Severity.ERROR if mi < 10 else Severity.WARNING,
                category=Category.MAINTAINABILITY,
                location=location,
                source_analyzer="complexity",
                metadata={"maintainability_index": mi},
            ))

    return metrics, findings
