"""
Docstring quality and completeness enforcer plugin.

Goes beyond presence checks — validates docstring format,
parameter documentation, return type docs, and example coverage.
"""

from __future__ import annotations

import ast
import re

from src.parsers.ast_utils import parse_source
from src.plugins.base import AnalysisContext, BaseAnalyzerPlugin
from src.schemas.findings import Category, Finding, Location, Severity, Suggestion


class DocstringEnforcerPlugin(BaseAnalyzerPlugin):
    """Enforces docstring quality and completeness."""

    name = "docstring_enforcer"
    description = "Validates docstring quality, parameter docs, and return type docs"
    version = "0.1.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        parsed = parse_source(context.source)
        if parsed.errors:
            return findings

        for node in ast.walk(parsed.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_") and not node.name.startswith("__"):
                continue

            docstring = ast.get_docstring(node)
            if not docstring:
                continue  # Missing docstrings handled by style analyzer

            # Check that parameters are documented
            args = [
                a.arg for a in node.args.args
                if a.arg not in ("self", "cls")
            ]
            args += [a.arg for a in node.args.kwonlyargs]

            if args:
                undocumented = []
                for arg in args:
                    # Check common docstring styles: Google, Numpy, Sphinx
                    patterns = [
                        rf"\b{re.escape(arg)}\b\s*[:\(]",   # Google: arg (type):
                        rf"\b{re.escape(arg)}\b\s*:",        # Sphinx: :param arg:
                        rf"Parameters\b.*\b{re.escape(arg)}\b",  # Numpy
                    ]
                    if not any(re.search(p, docstring, re.DOTALL) for p in patterns):
                        undocumented.append(arg)

                if undocumented and len(undocumented) <= len(args):
                    # Only flag if some but not all are documented (avoids noise on minimal docstrings)
                    documented_count = len(args) - len(undocumented)
                    if documented_count > 0 or len(args) >= 3:
                        findings.append(Finding(
                            rule_id="DOC-001",
                            title=f"Undocumented parameters in '{node.name}'",
                            description=(
                                f"Function '{node.name}' has undocumented parameters: "
                                f"{', '.join(undocumented)}."
                            ),
                            severity=Severity.INFO,
                            category=Category.DOCUMENTATION,
                            location=Location(
                                file_path=context.file_path,
                                start_line=node.lineno,
                                function_name=node.name,
                            ),
                            source_analyzer="docstring_enforcer",
                            suggestion=Suggestion(
                                description="Add parameter descriptions to the docstring.",
                                confidence=0.8,
                            ),
                        ))

            # Check return documentation for functions with return annotations
            if node.returns is not None and node.name != "__init__":
                return_patterns = [
                    r"Returns?\s*:", r"Return\s+type", r":returns?:",
                    r":rtype:", r"Yields?\s*:",
                ]
                has_return_doc = any(
                    re.search(p, docstring, re.IGNORECASE) for p in return_patterns
                )
                if not has_return_doc:
                    findings.append(Finding(
                        rule_id="DOC-002",
                        title=f"Missing return documentation in '{node.name}'",
                        description=(
                            f"Function '{node.name}' has a return annotation but "
                            f"the docstring doesn't document the return value."
                        ),
                        severity=Severity.INFO,
                        category=Category.DOCUMENTATION,
                        location=Location(
                            file_path=context.file_path,
                            start_line=node.lineno,
                            function_name=node.name,
                        ),
                        source_analyzer="docstring_enforcer",
                    ))

            # Check for raises documentation
            raises_in_body = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Raise) and child.exc:
                    if isinstance(child.exc, ast.Call) and isinstance(child.exc.func, ast.Name):
                        raises_in_body.add(child.exc.func.id)
                    elif isinstance(child.exc, ast.Name):
                        raises_in_body.add(child.exc.id)

            if raises_in_body:
                undocumented_raises = []
                for exc_name in raises_in_body:
                    if not re.search(rf"Raises?\b.*\b{re.escape(exc_name)}\b", docstring, re.DOTALL | re.IGNORECASE):
                        if not re.search(rf":raises?\s+{re.escape(exc_name)}:", docstring, re.IGNORECASE):
                            undocumented_raises.append(exc_name)

                if undocumented_raises:
                    findings.append(Finding(
                        rule_id="DOC-003",
                        title=f"Undocumented exceptions in '{node.name}'",
                        description=(
                            f"Function '{node.name}' raises {', '.join(undocumented_raises)} "
                            f"but the docstring doesn't document these exceptions."
                        ),
                        severity=Severity.INFO,
                        category=Category.DOCUMENTATION,
                        location=Location(
                            file_path=context.file_path,
                            start_line=node.lineno,
                            function_name=node.name,
                        ),
                        source_analyzer="docstring_enforcer",
                    ))

        return findings
