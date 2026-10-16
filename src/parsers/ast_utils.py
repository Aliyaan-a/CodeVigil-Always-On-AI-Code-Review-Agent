"""
AST helper utilities for parsing and traversing Python source trees.

Provides high-level abstractions over the ast module for extracting
function signatures, class hierarchies, import graphs, and control flow.
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass, field
from typing import Iterator, Optional


@dataclass
class FunctionInfo:
    """Extracted metadata about a function or method."""

    name: str
    lineno: int
    end_lineno: int
    col_offset: int
    args: list[str]
    defaults_count: int
    decorators: list[str]
    return_annotation: Optional[str]
    is_async: bool
    is_method: bool
    is_staticmethod: bool
    is_classmethod: bool
    is_property: bool
    docstring: Optional[str]
    body_lines: int
    class_name: Optional[str] = None


@dataclass
class ClassInfo:
    """Extracted metadata about a class."""

    name: str
    lineno: int
    end_lineno: int
    bases: list[str]
    decorators: list[str]
    methods: list[FunctionInfo]
    docstring: Optional[str]


@dataclass
class ImportInfo:
    """Extracted import information."""

    module: str
    names: list[str]
    alias: Optional[str]
    lineno: int
    is_from_import: bool


@dataclass
class ParsedModule:
    """Complete parsed representation of a Python module."""

    source: str
    tree: ast.Module
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    global_variables: list[tuple[str, int]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def parse_source(source: str) -> ParsedModule:
    """Parse Python source code into a structured representation."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError as e:
        return ParsedModule(
            source=source,
            tree=ast.Module(body=[], type_ignores=[]),
            errors=[f"SyntaxError at line {e.lineno}: {e.msg}"],
        )

    module = ParsedModule(source=source, tree=tree)

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            module.functions.append(_extract_function(node, class_name=None))
        elif isinstance(node, ast.ClassDef):
            module.classes.append(_extract_class(node))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                module.imports.append(
                    ImportInfo(
                        module=alias.name,
                        names=[alias.name],
                        alias=alias.asname,
                        lineno=node.lineno,
                        is_from_import=False,
                    )
                )
        elif isinstance(node, ast.ImportFrom):
            module.imports.append(
                ImportInfo(
                    module=node.module or "",
                    names=[a.name for a in node.names],
                    alias=None,
                    lineno=node.lineno,
                    is_from_import=True,
                )
            )
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target in _get_assignment_targets(node):
                module.global_variables.append((target, node.lineno))

    return module


def _extract_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    class_name: Optional[str],
) -> FunctionInfo:
    """Extract function metadata from an AST node."""
    decorators = []
    is_static = False
    is_classmethod = False
    is_property = False

    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            decorators.append(dec.id)
            if dec.id == "staticmethod":
                is_static = True
            elif dec.id == "classmethod":
                is_classmethod = True
            elif dec.id == "property":
                is_property = True
        elif isinstance(dec, ast.Attribute):
            decorators.append(ast.dump(dec))

    args = [a.arg for a in node.args.args]
    is_method = class_name is not None and not is_static

    return_ann = None
    if node.returns:
        try:
            return_ann = ast.unparse(node.returns)
        except Exception:
            return_ann = "Unknown"

    docstring = ast.get_docstring(node)
    end_lineno = node.end_lineno or node.lineno
    body_lines = end_lineno - node.lineno

    return FunctionInfo(
        name=node.name,
        lineno=node.lineno,
        end_lineno=end_lineno,
        col_offset=node.col_offset,
        args=args,
        defaults_count=len(node.args.defaults) + len(node.args.kw_defaults),
        decorators=decorators,
        return_annotation=return_ann,
        is_async=isinstance(node, ast.AsyncFunctionDef),
        is_method=is_method,
        is_staticmethod=is_static,
        is_classmethod=is_classmethod,
        is_property=is_property,
        docstring=docstring,
        body_lines=body_lines,
        class_name=class_name,
    )


def _extract_class(node: ast.ClassDef) -> ClassInfo:
    """Extract class metadata from an AST node."""
    bases = []
    for base in node.bases:
        try:
            bases.append(ast.unparse(base))
        except Exception:
            bases.append("Unknown")

    decorators = []
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            decorators.append(dec.id)

    methods = []
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods.append(_extract_function(item, class_name=node.name))

    return ClassInfo(
        name=node.name,
        lineno=node.lineno,
        end_lineno=node.end_lineno or node.lineno,
        bases=bases,
        decorators=decorators,
        methods=methods,
        docstring=ast.get_docstring(node),
    )


def _get_assignment_targets(node: ast.Assign | ast.AnnAssign) -> list[str]:
    """Extract variable names from assignment nodes."""
    targets = []
    if isinstance(node, ast.AnnAssign):
        if isinstance(node.target, ast.Name):
            targets.append(node.target.id)
    else:
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        targets.append(elt.id)
    return targets


def walk_functions(tree: ast.Module) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Yield all function definitions in the tree, including nested ones."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def count_nesting_depth(node: ast.AST) -> int:
    """Calculate maximum nesting depth of control flow within a node."""
    nesting_types = (
        ast.If,
        ast.For,
        ast.While,
        ast.With,
        ast.Try,
        ast.ExceptHandler,
        ast.AsyncFor,
        ast.AsyncWith,
    )

    def _depth(n: ast.AST, current: int) -> int:
        max_d = current
        for child in ast.iter_child_nodes(n):
            if isinstance(child, nesting_types):
                max_d = max(max_d, _depth(child, current + 1))
            else:
                max_d = max(max_d, _depth(child, current))
        return max_d

    return _depth(node, 0)


def extract_code_snippet(source: str, start_line: int, end_line: Optional[int] = None, context: int = 2) -> str:
    """Extract a code snippet with surrounding context lines."""
    lines = source.splitlines()
    start = max(0, start_line - 1 - context)
    end = min(len(lines), (end_line or start_line) + context)
    snippet_lines = []
    for i in range(start, end):
        prefix = ">>> " if start_line - 1 <= i <= (end_line or start_line) - 1 else "    "
        snippet_lines.append(f"{prefix}{i + 1:4d} | {lines[i]}")
    return "\n".join(snippet_lines)
