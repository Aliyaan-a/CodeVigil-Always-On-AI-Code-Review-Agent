"""Unit tests for all core analyzers."""

from __future__ import annotations

from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.complexity import (
    analyze_complexity,
)
from src.analyzers.security_analyzer import SecurityAnalyzer
from src.analyzers.style_analyzer import StyleAnalyzer
from src.schemas.findings import Severity

# ═══════════════════════════════════════════════════════════════
# AST Analyzer Tests
# ═══════════════════════════════════════════════════════════════


class TestASTAnalyzer:
    def test_mutable_default_detected(self):
        code = '''
def bad_func(items=[]):
    items.append(1)
    return items
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "AST-001" in rule_ids

    def test_mutable_default_dict(self):
        code = '''
def bad_func(config={}):
    return config
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-001" for f in findings)

    def test_immutable_default_not_flagged(self):
        code = '''
def good_func(count=0, name="default", flag=True):
    pass
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert not any(f.rule_id == "AST-001" for f in findings)

    def test_bare_except_detected(self):
        code = '''
try:
    risky()
except:
    pass
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-002" for f in findings)

    def test_specific_except_not_flagged(self):
        code = '''
try:
    risky()
except ValueError:
    pass
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert not any(f.rule_id == "AST-002" for f in findings)

    def test_unreachable_code_after_return(self):
        code = '''
def func():
    return 42
    x = 10
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-003" for f in findings)

    def test_shadowed_builtin(self):
        code = '''
list = [1, 2, 3]
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-004" for f in findings)

    def test_star_import_flagged(self):
        code = '''
from os import *
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-006" for f in findings)

    def test_empty_except_pass(self):
        code = '''
try:
    risky()
except Exception:
    pass
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-009" for f in findings)

    def test_return_in_init(self):
        code = '''
class MyClass:
    def __init__(self):
        return 42
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-010" for f in findings)

    def test_comparison_to_none(self):
        code = '''
def func(x):
    if x == None:
        return True
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-012" for f in findings)

    def test_duplicate_dict_keys(self):
        code = '''
d = {"a": 1, "b": 2, "a": 3}
'''
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-013" for f in findings)

    def test_syntax_error_reported(self):
        code = "def func( :"
        findings = ASTAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "AST-000" for f in findings)


# ═══════════════════════════════════════════════════════════════
# Complexity Analyzer Tests
# ═══════════════════════════════════════════════════════════════


class TestComplexityAnalyzer:
    def test_simple_function_low_complexity(self):
        code = '''
def simple():
    return 42
'''
        metrics, findings = analyze_complexity(code, "test.py")
        assert len(metrics) == 1
        assert metrics[0].cyclomatic_complexity == 1
        assert len(findings) == 0

    def test_branching_increases_cc(self):
        code = '''
def branchy(x):
    if x > 0:
        return 1
    elif x < 0:
        return -1
    else:
        return 0
'''
        metrics, _ = analyze_complexity(code, "test.py")
        assert metrics[0].cyclomatic_complexity == 3  # 1 + if + elif

    def test_loop_increases_cc(self):
        code = '''
def loopy(items):
    total = 0
    for item in items:
        if item > 0:
            total += item
    return total
'''
        metrics, _ = analyze_complexity(code, "test.py")
        assert metrics[0].cyclomatic_complexity >= 3

    def test_high_complexity_flagged(self):
        code = '''
def complex_func(a, b, c, d, e, f):
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            return 1
                        elif a and b:
                            return 2
                        elif c or d:
                            return 3
                    return 4
                return 5
            return 6
        return 7
    return 8
'''
        _, findings = analyze_complexity(code, "test.py", max_cyclomatic=5)
        assert any(f.rule_id == "CX-001" for f in findings)

    def test_cognitive_complexity(self):
        code = '''
def nested(items):
    for item in items:
        if item > 0:
            for sub in item:
                if sub:
                    print(sub)
'''
        metrics, _ = analyze_complexity(code, "test.py")
        assert metrics[0].cognitive_complexity > 0

    def test_long_function_flagged(self):
        # 60 lines
        body = "\n".join(f"    x{i} = {i}" for i in range(55))
        code = f"def long_func():\n{body}\n    return x0\n"
        _, findings = analyze_complexity(code, "test.py", max_function_length=50)
        assert any(f.rule_id == "CX-003" for f in findings)

    def test_too_many_params(self):
        code = '''
def many_params(a, b, c, d, e, f, g):
    pass
'''
        _, findings = analyze_complexity(code, "test.py", max_params=5)
        assert any(f.rule_id == "CX-004" for f in findings)


# ═══════════════════════════════════════════════════════════════
# Security Analyzer Tests
# ═══════════════════════════════════════════════════════════════


class TestSecurityAnalyzer:
    def test_hardcoded_api_key(self):
        code = '''
API_KEY = "sk-abc123def456ghi789jkl012"
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_hardcoded_password(self):
        code = '''
password = "super_secret_password_123"
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-002" for f in findings)

    def test_eval_detected(self):
        code = '''
result = eval(user_input)
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-021" for f in findings)

    def test_exec_detected(self):
        code = '''
exec(code_string)
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-022" for f in findings)

    def test_pickle_loads(self):
        code = '''
import pickle
data = pickle.loads(untrusted_bytes)
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-020" for f in findings)

    def test_os_system(self):
        code = '''
import os
os.system(f"rm -rf {user_input}")
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-011" for f in findings)

    def test_subprocess_shell_true(self):
        code = '''
import subprocess
subprocess.run(cmd, shell=True)
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-011" for f in findings)

    def test_weak_hash_md5(self):
        code = '''
import hashlib
h = hashlib.md5(data)
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-023" for f in findings)

    def test_debug_mode(self):
        code = '''
DEBUG = True
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-025" for f in findings)

    def test_ssl_verify_false(self):
        code = '''
requests.get(url, verify=False)
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "SEC-026" for f in findings)

    def test_clean_code_no_security_issues(self):
        code = '''
import os
import hashlib

def get_api_key():
    return os.environ.get("API_KEY", "")

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()
'''
        findings = SecurityAnalyzer(code, "test.py").analyze()
        security_findings = [f for f in findings if f.severity in (Severity.ERROR, Severity.CRITICAL)]
        assert len(security_findings) == 0


# ═══════════════════════════════════════════════════════════════
# Style Analyzer Tests
# ═══════════════════════════════════════════════════════════════


class TestStyleAnalyzer:
    def test_long_line_detected(self):
        code = "x = " + "a" * 200 + "\n"
        findings = StyleAnalyzer(code, "test.py", max_line_length=120).analyze()
        assert any(f.rule_id == "STY-001" for f in findings)

    def test_non_snake_case_function(self):
        code = '''
def BadFunctionName():
    pass
'''
        findings = StyleAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "STY-003" for f in findings)

    def test_snake_case_function_ok(self):
        code = '''
def good_function_name():
    pass
'''
        findings = StyleAnalyzer(code, "test.py").analyze()
        assert not any(f.rule_id == "STY-003" for f in findings)

    def test_non_pascal_case_class(self):
        code = '''
class bad_class:
    pass
'''
        findings = StyleAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "STY-004" for f in findings)

    def test_missing_module_docstring(self):
        code = '''
x = 42
'''
        findings = StyleAnalyzer(code, "test.py", enforce_docstrings=True).analyze()
        assert any(f.rule_id == "STY-010" for f in findings)

    def test_missing_function_docstring(self):
        code = '''
"""Module doc."""

def public_func():
    pass
'''
        findings = StyleAnalyzer(code, "test.py", enforce_docstrings=True).analyze()
        assert any(f.rule_id == "STY-012" for f in findings)

    def test_missing_return_type_annotation(self):
        code = '''
"""Module."""

def func(x: int):
    return x + 1
'''
        findings = StyleAnalyzer(code, "test.py", enforce_type_hints=True).analyze()
        assert any(f.rule_id == "STY-020" for f in findings)

    def test_todo_detected(self):
        code = '''
"""Module."""
# TODO: fix this later
x = 42
'''
        findings = StyleAnalyzer(code, "test.py").analyze()
        assert any(f.rule_id == "STY-040" for f in findings)
