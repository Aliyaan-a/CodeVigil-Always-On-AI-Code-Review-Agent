"""
LLM-powered code analysis engine.

Uses large language models (OpenAI, Anthropic) to provide
deep semantic analysis, architectural feedback, and natural-language
explanations of complex issues that static analysis cannot catch.

This is an optional analyzer — it requires API credentials and
is disabled by default.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Optional, Protocol

from src.schemas.findings import Finding, Category, Severity, Location, Suggestion
from src.schemas.config import LLMAnalyzerConfig


# ── LLM Provider Protocol ──────────────────────────────────────────

class LLMProvider(Protocol):
    """Protocol for LLM API providers."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send a completion request and return the response text."""
        ...


class OpenAIProvider:
    """OpenAI API provider."""

    def __init__(self, model: str, api_key: str, temperature: float = 0.1, max_tokens: int = 2000):
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        try:
            import openai

            client = openai.OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return response.choices[0].message.content or ""
        except ImportError:
            raise RuntimeError("openai package not installed. Install with: pip install openai")
        except Exception as e:
            raise RuntimeError(f"OpenAI API call failed: {e}")


class AnthropicProvider:
    """Anthropic Claude API provider."""

    def __init__(self, model: str, api_key: str, temperature: float = 0.1, max_tokens: int = 2000):
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text
        except ImportError:
            raise RuntimeError("anthropic package not installed. Install with: pip install anthropic")
        except Exception as e:
            raise RuntimeError(f"Anthropic API call failed: {e}")


class MockProvider:
    """Mock provider for testing without API calls."""

    def __init__(self, response: str = ""):
        self._response = response

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if self._response:
            return self._response
        return json.dumps({
            "findings": [],
            "summary": "Mock analysis — no issues found.",
        })


# ── System Prompt ──────────────────────────────────────────────────

REVIEW_SYSTEM_PROMPT = """You are an expert Python code reviewer. Analyze the provided code and return a JSON object with your findings.

For each issue found, include:
- rule_id: A unique identifier (use "LLM-XXX" format, numbered sequentially)
- title: Short, clear title
- description: Detailed explanation of the issue and why it matters
- severity: One of "info", "warning", "error", "critical"
- category: One of "security", "bug", "performance", "style", "maintainability", "complexity", "documentation", "best_practice", "type_safety", "error_handling"
- line: The line number where the issue occurs (approximate is fine)
- suggestion: A concrete fix suggestion

Focus on:
1. Logical bugs and edge cases
2. Architectural concerns (tight coupling, SRP violations, abstraction leaks)
3. Concurrency issues (race conditions, deadlocks)
4. Resource management (unclosed handles, memory leaks)
5. Error handling gaps (missing exception handling, broad catches)
6. API design issues (confusing interfaces, inconsistent return types)
7. Performance anti-patterns (N+1 queries, unnecessary copies, inefficient algorithms)

Do NOT flag:
- Simple formatting issues (handled by other analyzers)
- Standard Python idioms even if unconventional
- Type hint completeness (handled by other analyzers)

Return ONLY a valid JSON object with this structure:
{
  "findings": [
    {
      "rule_id": "LLM-001",
      "title": "...",
      "description": "...",
      "severity": "warning",
      "category": "bug",
      "line": 42,
      "suggestion": "..."
    }
  ],
  "summary": "Brief overall assessment of code quality"
}"""


# ── LLM Analyzer ──────────────────────────────────────────────────

class LLMAnalyzer:
    """
    LLM-powered code analyzer for deep semantic analysis.

    Uses AI to detect issues that require understanding of intent,
    architecture, and domain logic beyond what static analysis provides.
    """

    def __init__(
        self,
        config: Optional[LLMAnalyzerConfig] = None,
        provider: Optional[LLMProvider] = None,
    ):
        self.config = config or LLMAnalyzerConfig()
        self._provider = provider

    @property
    def provider(self) -> LLMProvider:
        """Lazily initialize the LLM provider."""
        if self._provider is not None:
            return self._provider

        api_key = os.environ.get(self.config.api_key_env, "")
        if not api_key:
            raise RuntimeError(
                f"LLM API key not found. Set {self.config.api_key_env} environment variable."
            )

        if self.config.provider == "openai":
            self._provider = OpenAIProvider(
                model=self.config.model,
                api_key=api_key,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
        elif self.config.provider == "anthropic":
            self._provider = AnthropicProvider(
                model=self.config.model,
                api_key=api_key,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
        else:
            raise ValueError(f"Unknown LLM provider: {self.config.provider}")

        return self._provider

    def analyze(self, source: str, file_path: str) -> list[Finding]:
        """
        Analyze source code using an LLM.

        Sends the code to the configured LLM provider and parses
        the structured JSON response into Finding objects.
        """
        if not self.config.enabled:
            return []

        system_prompt = self.config.system_prompt or REVIEW_SYSTEM_PROMPT

        # Truncate very long files to stay within token limits
        lines = source.splitlines()
        if len(lines) > 500:
            source = "\n".join(lines[:500])
            source += f"\n\n# ... ({len(lines) - 500} more lines truncated)"

        user_prompt = f"Review this Python file ({file_path}):\n\n```python\n{source}\n```"

        # Retry logic
        last_error: Optional[Exception] = None
        for attempt in range(self.config.retry_attempts):
            try:
                response = self.provider.complete(system_prompt, user_prompt)
                return self._parse_response(response, file_path)
            except Exception as e:
                last_error = e
                if attempt < self.config.retry_attempts - 1:
                    continue

        # All retries failed
        return [Finding(
            rule_id="LLM-ERR",
            title="LLM analysis failed",
            description=f"LLM analysis failed after {self.config.retry_attempts} attempts: {last_error}",
            severity=Severity.INFO,
            category=Category.MAINTAINABILITY,
            location=Location(file_path=file_path, start_line=1),
            source_analyzer="llm_analyzer",
        )]

    def _parse_response(self, response: str, file_path: str) -> list[Finding]:
        """Parse LLM JSON response into Finding objects."""
        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try parsing the entire response as JSON
            json_str = response.strip()

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return [Finding(
                rule_id="LLM-ERR",
                title="Failed to parse LLM response",
                description="LLM returned non-JSON response. The model may need a better prompt.",
                severity=Severity.INFO,
                category=Category.MAINTAINABILITY,
                location=Location(file_path=file_path, start_line=1),
                source_analyzer="llm_analyzer",
            )]

        findings = []
        for item in data.get("findings", []):
            try:
                severity = Severity(item.get("severity", "info"))
                category = Category(item.get("category", "maintainability"))

                finding = Finding(
                    rule_id=item.get("rule_id", "LLM-000"),
                    title=item.get("title", "LLM Finding"),
                    description=item.get("description", ""),
                    severity=severity,
                    category=category,
                    location=Location(
                        file_path=file_path,
                        start_line=item.get("line", 1),
                    ),
                    source_analyzer="llm_analyzer",
                    suggestion=Suggestion(
                        description=item.get("suggestion", ""),
                        confidence=0.6,
                    ) if item.get("suggestion") else None,
                    tags=["llm-generated"],
                )
                findings.append(finding)
            except (ValueError, KeyError):
                continue

        return findings
