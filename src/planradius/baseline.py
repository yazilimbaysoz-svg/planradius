# planradius — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
"""Deterministic finding baselines for suppression with stale-entry detection.

Attribution: Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .rules import Finding

BASELINE_SCHEMA = 1
ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


class BaselineError(ValueError):
    """Raised when a baseline file does not conform to the schema."""


@dataclass(frozen=True)
class Baseline:
    """Immutable set of acknowledged finding fingerprints."""

    schema: int
    tool: str
    author: str
    fingerprints: frozenset[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "tool": self.tool,
            "author": self.author,
            "fingerprints": sorted(self.fingerprints),
        }


@dataclass(frozen=True)
class BaselineResult:
    """Partition of findings after baseline application."""

    active: tuple[Finding, ...]
    acknowledged: tuple[Finding, ...]
    stale: tuple[str, ...]


def create_baseline(findings: tuple[Finding, ...]) -> Baseline:
    """Create a reproducible baseline without timestamps or environment data."""
    return Baseline(
        schema=BASELINE_SCHEMA,
        tool="planradius",
        author=ATTRIBUTION,
        fingerprints=frozenset(finding.fingerprint for finding in findings),
    )


def parse_baseline(raw: Any) -> Baseline:
    """Validate a decoded baseline document strictly."""
    if not isinstance(raw, dict):
        raise BaselineError("baseline root must be a JSON object")
    if raw.get("schema") != BASELINE_SCHEMA:
        raise BaselineError(f"baseline schema must be {BASELINE_SCHEMA}")
    if raw.get("tool") != "planradius":
        raise BaselineError("baseline tool must be 'planradius'")
    fingerprints = raw.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(
        isinstance(item, str) and len(item) == 16 for item in fingerprints
    ):
        raise BaselineError("baseline fingerprints must be an array of 16-character strings")
    return Baseline(
        schema=BASELINE_SCHEMA,
        tool="planradius",
        author=str(raw.get("author") or ATTRIBUTION),
        fingerprints=frozenset(fingerprints),
    )


def load_baseline(text: str) -> Baseline:
    """Parse a baseline from JSON text."""
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise BaselineError(f"invalid baseline JSON: {exc}") from exc
    return parse_baseline(raw)


def apply_baseline(findings: tuple[Finding, ...], baseline: Baseline | None) -> BaselineResult:
    """Split findings into active/acknowledged and report stale entries."""
    if baseline is None:
        return BaselineResult(findings, (), ())
    acknowledged: list[Finding] = []
    active: list[Finding] = []
    current = {finding.fingerprint for finding in findings}
    for finding in findings:
        if finding.fingerprint in baseline.fingerprints:
            acknowledged.append(finding)
        else:
            active.append(finding)
    return BaselineResult(
        active=tuple(active),
        acknowledged=tuple(acknowledged),
        stale=tuple(sorted(baseline.fingerprints - current)),
    )
