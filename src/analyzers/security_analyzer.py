"""
Security vulnerability analyzer.

Detects hardcoded secrets, injection vulnerabilities, insecure
deserialization, weak cryptography, and other OWASP Top 10 patterns
using both regex and AST-based detection.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

from src.schemas.findings import Finding, Category, Severity, Location, Suggestion
from src.parsers.ast_utils import parse_source, extract_code_snippet


@dataclass
class SecurityPattern:
    """A security rule definition."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    regex: Optional[re.Pattern] = None
    ast_check: Optional[str] = None
    suggestion: str = ""
    references: list[str] = field(default_factory=list)


# ── Secret Detection Patterns ──────────────────────────────────────

SECRET_PATTERNS = [
    SecurityPattern(
        rule_id="SEC-001",
        title="Hardcoded API key",
        description="Possible hardcoded API key detected. Store secrets in environment variables or a secrets manager.",
        severity=Severity.CRITICAL,
        regex=re.compile(
            r"""(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]""",
        ),
        suggestion="Use os.environ.get('API_KEY') or a secrets manager.",
        references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    ),
    SecurityPattern(
        rule_id="SEC-002",
        title="Hardcoded password",
        description="Possible hardcoded password or secret token detected.",
        severity=Severity.CRITICAL,
        regex=re.compile(
            r"""(?i)(?:password|passwd|pwd|secret|token|auth[_-]?token)\s*[=:]\s*['"][^'"]{6,}['"]""",
        ),
        suggestion="Use environment variables or a vault service for secrets.",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    SecurityPattern(
        rule_id="SEC-003",
        title="Hardcoded AWS credentials",
        description="AWS access key or secret key appears to be hardcoded.",
        severity=Severity.CRITICAL,
        regex=re.compile(
            r"""(?:AKIA[0-9A-Z]{16}|[Aa][Ww][Ss][_-]?[Ss]ecret[_-]?[Aa]ccess[_-]?[Kk]ey\s*[=:]\s*['"][^'"]+['"])""",
        ),
        suggestion="Use IAM roles, AWS SSO, or environment variables.",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
    ),
    SecurityPattern(
        rule_id="SEC-004",
        title="Private key in source",
        description="A private key or certificate appears to be embedded in source code.",
        severity=Severity.CRITICAL,
        regex=re.compile(r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"""),
        suggestion="Store keys in files outside the repository or use a key management service.",
    ),
]

# ── Injection Detection Patterns ───────────────────────────────────

INJECTION_PATTERNS = [
    SecurityPattern(
        rule_id="SEC-010",
        title="Potential SQL injection",
        description="String formatting is used to build SQL queries, which can lead to SQL injection.",
        severity=Severity.CRITICAL,
        regex=re.compile(
            r"""(?:execute|cursor\.execute|raw|rawsql)\s*\(\s*(?:f['"']|['"].*%s|['"].*\.format)""",
            re.IGNORECASE,
        ),
        suggestion="Use parameterized queries with placeholders.",
        references=["https://owasp.org/Top10/A03_2021-Injection/"],
    ),
    SecurityPattern(
        rule_id="SEC-011",
        title="Potential command injection",
        description="User input may flow into shell command execution.",
        severity=Severity.CRITICAL,
        ast_check="command_injection",
        suggestion="Use subprocess with a list of arguments instead of shell=True.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
    ),
    SecurityPattern(
        rule_id="SEC-012",
        title="Potential path traversal",
        description="User-controlled input used in file path operations without sanitization.",
        severity=Severity.ERROR,
        ast_check="path_traversal",
        suggestion="Validate and sanitize file paths. Use pathlib and resolve() to normalize.",
        references=["https://cwe.mitre.org/data/definitions/22.html"],
    ),
]

# ── Insecure Practices ─────────────────────────────────────────────

INSECURE_PATTERNS = [
    SecurityPattern(
        rule_id="SEC-020",
        title="Insecure deserialization (pickle)",
        description="Use of pickle.loads() or pickle.load() can execute arbitrary code.",
        severity=Severity.CRITICAL,
        ast_check="pickle_usage",
        suggestion="Use JSON or a safe serialization format instead.",
        references=["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"],
    ),
    SecurityPattern(
        rule_id="SEC-021",
        title="Use of eval()",
        description="eval() executes arbitrary code and is a major security risk.",
        severity=Severity.CRITICAL,
        ast_check="eval_usage",
        suggestion="Use ast.literal_eval() for safe evaluation of literals.",
    ),
    SecurityPattern(
        rule_id="SEC-022",
        title="Use of exec()",
        description="exec() executes arbitrary code strings.",
        severity=Severity.CRITICAL,
        ast_check="exec_usage",
        suggestion="Avoid exec() entirely. Use structured dispatch or importlib.",
    ),
    SecurityPattern(
        rule_id="SEC-023",
        title="Weak hash algorithm (MD5/SHA1)",
        description="MD5 and SHA1 are cryptographically broken for security purposes.",
        severity=Severity.ERROR,
        regex=re.compile(r"""(?:hashlib\.(?:md5|sha1)|\.(?:md5|sha1)\s*\()"""),
        suggestion="Use SHA-256 or SHA-3 for hashing.",
        references=["https://cwe.mitre.org/data/definitions/328.html"],
    ),
    SecurityPattern(
        rule_id="SEC-024",
        title="Insecure random number generation",
        description="random module is not suitable for security/cryptographic purposes.",
        severity=Severity.ERROR,
        ast_check="insecure_random",
        suggestion="Use secrets module or os.urandom() for security-sensitive randomness.",
    ),
    SecurityPattern(
        rule_id="SEC-025",
        title="Debug mode enabled",
        description="Debug mode appears to be enabled, which can expose sensitive information.",
        severity=Severity.ERROR,
        regex=re.compile(r"""(?:DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True)"""),
        suggestion="Ensure DEBUG is False in production configuration.",
    ),
    SecurityPattern(
        rule_id="SEC-026",
        title="HTTPS verification disabled",
        description="SSL/TLS certificate verification is disabled, allowing MITM attacks.",
        severity=Severity.CRITICAL,
        regex=re.compile(r"""verify\s*=\s*False"""),
        suggestion="Always verify SSL certificates. Use proper CA bundles.",
        references=["https://cwe.mitre.org/data/definitions/295.html"],
    ),
    SecurityPattern(
        rule_id="SEC-027",
        title="Hardcoded IP or localhost binding",
        description="Binding to 0.0.0.0 exposes the service to all network interfaces.",
        severity=Severity.WARNING,
        regex=re.compile(r"""(?:host\s*=\s*['"]0\.0\.0\.0['"]|\.run\(.*host\s*=\s*['"]0\.0\.0\.0['"])"""),
        suggestion="Bind to 127.0.0.1 for local-only or use a reverse proxy.",
    ),
]


class SecurityAnalyzer:
    """
    Security-focused code analyzer.

    Combines regex pattern matching with AST-based analysis
    for deeper vulnerability detection.
    """

    def __init__(self, source: str, file_path: str):
        self.source = source
        self.file_path = file_path
        self.lines = source.splitlines()
        self.parsed = parse_source(source)
        self.findings: list[Finding] = []

    def analyze(self) -> list[Finding]:
        """Run all security checks."""
        all_patterns = SECRET_PATTERNS + INJECTION_PATTERNS + INSECURE_PATTERNS

        # Regex-based checks
        for pattern in all_patterns:
            if pattern.regex:
                self._check_regex(pattern)

        # AST-based checks
        if not self.parsed.errors:
            self._check_command_injection()
            self._check_path_traversal()
            self._check_pickle_usage()
            self._check_eval_exec()
            self._check_insecure_random()
            self._check_yaml_load()
            self._check_tempfile_insecure()

        return self.findings

    def _check_regex(self, pattern: SecurityPattern) -> None:
        """Apply a regex pattern across all lines."""
        assert pattern.regex is not None
        for i, line in enumerate(self.lines, start=1):
            if pattern.regex.search(line):
                # Skip comments
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue

                self.findings.append(Finding(
                    rule_id=pattern.rule_id,
                    title=pattern.title,
                    description=pattern.description,
                    severity=pattern.severity,
                    category=Category.SECURITY,
                    location=Location(file_path=self.file_path, start_line=i),
                    source_analyzer="security_analyzer",
                    suggestion=Suggestion(
                        description=pattern.suggestion,
                        confidence=0.8,
                    ) if pattern.suggestion else None,
                    code_snippet=extract_code_snippet(self.source, i),
                    references=pattern.references,
                    tags=["security", "owasp"],
                ))

    def _check_command_injection(self) -> None:
        """Detect shell=True in subprocess calls and os.system usage."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._get_call_name(node)

            # os.system, os.popen
            if func_name in ("os.system", "os.popen"):
                self.findings.append(self._make_finding(
                    rule_id="SEC-011",
                    title=f"Command injection risk via {func_name}()",
                    description=f"{func_name}() executes commands via shell, enabling injection.",
                    severity=Severity.CRITICAL,
                    line=node.lineno,
                    suggestion="Use subprocess.run() with a list of arguments.",
                ))

            # subprocess with shell=True
            if func_name and "subprocess" in func_name:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.findings.append(self._make_finding(
                            rule_id="SEC-011",
                            title="subprocess called with shell=True",
                            description="shell=True passes command through the shell, enabling injection.",
                            severity=Severity.ERROR,
                            line=node.lineno,
                            suggestion="Pass command as a list and remove shell=True.",
                        ))

    def _check_path_traversal(self) -> None:
        """Detect file operations with potentially unsanitized paths."""
        dangerous_calls = {"open", "os.path.join"}

        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._get_call_name(node)
            if func_name not in dangerous_calls:
                continue

            # Check if any argument uses f-string or format with variable
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):  # f-string
                    self.findings.append(self._make_finding(
                        rule_id="SEC-012",
                        title="Potential path traversal via f-string in file path",
                        description="File path constructed with f-string may allow path traversal.",
                        severity=Severity.ERROR,
                        line=node.lineno,
                        suggestion="Validate path components and use pathlib.Path.resolve().",
                    ))

    def _check_pickle_usage(self) -> None:
        """Detect use of pickle for deserialization."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._get_call_name(node)
            if func_name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"):
                self.findings.append(self._make_finding(
                    rule_id="SEC-020",
                    title="Insecure deserialization with pickle",
                    description=f"{func_name}() can execute arbitrary code during deserialization.",
                    severity=Severity.CRITICAL,
                    line=node.lineno,
                    suggestion="Use JSON or a safe serialization format.",
                ))

    def _check_eval_exec(self) -> None:
        """Detect eval() and exec() usage."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._get_call_name(node)
            if func_name == "eval":
                self.findings.append(self._make_finding(
                    rule_id="SEC-021",
                    title="Use of eval()",
                    description="eval() executes arbitrary Python expressions.",
                    severity=Severity.CRITICAL,
                    line=node.lineno,
                    suggestion="Use ast.literal_eval() for safe evaluation.",
                ))
            elif func_name == "exec":
                self.findings.append(self._make_finding(
                    rule_id="SEC-022",
                    title="Use of exec()",
                    description="exec() executes arbitrary Python code.",
                    severity=Severity.CRITICAL,
                    line=node.lineno,
                    suggestion="Avoid exec(). Use structured dispatch patterns.",
                ))

    def _check_insecure_random(self) -> None:
        """Detect use of random module for security-sensitive operations."""
        # Check if random is imported
        random_imported = False
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "random":
                        random_imported = True
            elif isinstance(node, ast.ImportFrom) and node.module == "random":
                random_imported = True

        if not random_imported:
            return

        # Look for security-sensitive context
        security_keywords = {"token", "password", "secret", "key", "salt", "nonce", "otp"}
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name and func_name.startswith("random."):
                    # Check if used near security-sensitive variable names
                    parent_assign = self._find_parent_assign(node)
                    if parent_assign:
                        for target in parent_assign:
                            if any(kw in target.lower() for kw in security_keywords):
                                self.findings.append(self._make_finding(
                                    rule_id="SEC-024",
                                    title="Insecure random for security purpose",
                                    description=f"'{func_name}' used for '{target}' — not cryptographically secure.",
                                    severity=Severity.ERROR,
                                    line=node.lineno,
                                    suggestion="Use secrets.token_hex() or secrets.token_urlsafe().",
                                ))

    def _check_yaml_load(self) -> None:
        """Detect unsafe yaml.load() without Loader parameter."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._get_call_name(node)
            if func_name == "yaml.load":
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        has_safe_loader = True
                if not has_safe_loader and len(node.args) < 2:
                    self.findings.append(self._make_finding(
                        rule_id="SEC-028",
                        title="Unsafe YAML loading",
                        description="yaml.load() without SafeLoader can execute arbitrary code.",
                        severity=Severity.CRITICAL,
                        line=node.lineno,
                        suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                    ))

    def _check_tempfile_insecure(self) -> None:
        """Detect insecure temporary file creation."""
        for node in ast.walk(self.parsed.tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._get_call_name(node)
            if func_name in ("tempfile.mktemp",):
                self.findings.append(self._make_finding(
                    rule_id="SEC-029",
                    title="Insecure temporary file creation",
                    description="tempfile.mktemp() is vulnerable to race conditions.",
                    severity=Severity.ERROR,
                    line=node.lineno,
                    suggestion="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile().",
                ))

    # ── Helpers ──────────────────────────────────────────────────

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract the full dotted name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        return None

    def _find_parent_assign(self, node: ast.AST) -> Optional[list[str]]:
        """Try to find variable names this expression is assigned to."""
        # Simplified — walk up isn't easy with stdlib ast
        # Instead, scan for assignments containing this call
        for n in ast.walk(self.parsed.tree):
            if isinstance(n, ast.Assign):
                if any(self._contains_node(t, node) for t in [n.value]):
                    names = []
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            names.append(t.id)
                    return names
        return None

    @staticmethod
    def _contains_node(tree: ast.AST, target: ast.AST) -> bool:
        """Check if target node is anywhere in tree."""
        for node in ast.walk(tree):
            if node is target:
                return True
        return False

    def _make_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        line: int,
        suggestion: str = "",
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            category=Category.SECURITY,
            location=Location(file_path=self.file_path, start_line=line),
            source_analyzer="security_analyzer",
            suggestion=Suggestion(description=suggestion, confidence=0.8) if suggestion else None,
            code_snippet=extract_code_snippet(self.source, line),
            tags=["security"],
        )
