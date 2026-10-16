"""
Finding aggregator and deduplicator.

Merges findings from multiple analyzers, removes duplicates based
on content fingerprints, and handles overlapping detections.
"""

from __future__ import annotations

from typing import Optional

from src.schemas.findings import Finding, Severity


class FindingAggregator:
    """
    Aggregates and deduplicates findings from multiple analyzers.

    Uses content-based fingerprints to detect when multiple analyzers
    flag the same issue. When duplicates are found, keeps the finding
    with the highest severity and most detail.
    """

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._seen_fingerprints: dict[str, int] = {}

    def add(self, finding: Finding) -> bool:
        """
        Add a finding. Returns True if it was new, False if deduplicated.
        """
        fp = finding.fingerprint
        if fp in self._seen_fingerprints:
            idx = self._seen_fingerprints[fp]
            existing = self._findings[idx]
            # Keep the more severe / more detailed finding
            if self._should_replace(existing, finding):
                self._findings[idx] = finding
            return False

        self._seen_fingerprints[fp] = len(self._findings)
        self._findings.append(finding)
        return True

    def add_many(self, findings: list[Finding]) -> tuple[int, int]:
        """
        Add multiple findings. Returns (new_count, dedup_count).
        """
        new = 0
        dedup = 0
        for f in findings:
            if self.add(f):
                new += 1
            else:
                dedup += 1
        return new, dedup

    def get_findings(
        self,
        min_severity: Optional[Severity] = None,
        category: Optional[str] = None,
        source_analyzer: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[Finding]:
        """Get filtered and sorted findings."""
        results = self._findings

        if min_severity is not None:
            results = [f for f in results if f.severity >= min_severity]

        if category is not None:
            results = [f for f in results if f.category.value == category]

        if source_analyzer is not None:
            results = [f for f in results if f.source_analyzer == source_analyzer]

        # Sort by severity (descending), then by line number
        results = sorted(
            results,
            key=lambda f: (-f.severity.numeric, f.location.start_line),
        )

        if limit is not None:
            results = results[:limit]

        return results

    @property
    def total_count(self) -> int:
        return len(self._findings)

    @property
    def dedup_count(self) -> int:
        return self._dedup_total

    def _should_replace(self, existing: Finding, new: Finding) -> bool:
        """Determine if a new finding should replace an existing duplicate."""
        # Higher severity wins
        if new.severity > existing.severity:
            return True
        if new.severity < existing.severity:
            return False
        # More detailed description wins
        if len(new.description) > len(existing.description):
            return True
        # Has suggestion wins
        if new.suggestion is not None and existing.suggestion is None:
            return True
        return False

    _dedup_total: int = 0
