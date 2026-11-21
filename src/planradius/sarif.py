# planradius — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
"""SARIF 2.1.0 serialization for CI annotation and code-scanning integration.

Attribution: Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .baseline import ATTRIBUTION
from .rules import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL_BY_SEVERITY = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _rule_descriptor(finding: Finding) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.title.replace(" ", "").replace(":", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.remediation},
        "helpUri": (
            finding.references[0]
            if finding.references
            else "https://github.com/yazilimbaysoz-svg/planradius"
        ),
        "properties": {"tags": ["security", finding.severity, "terraform", "opentofu"]},
    }
    return descriptor


def build_sarif(
    findings: tuple[Finding, ...],
    *,
    source: str,
    acknowledged_count: int = 0,
    stale_count: int = 0,
) -> dict[str, Any]:
    """Build a deterministic SARIF document from findings."""
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for finding in findings:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            rules.append(_rule_descriptor(finding))
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": LEVEL_BY_SEVERITY.get(finding.severity, "warning"),
                "message": {"text": f"{finding.detail} — {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": source, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [{"name": finding.resource, "kind": "resource"}],
                    }
                ],
                "partialFingerprints": {"planradius/fingerprint": finding.fingerprint},
                "properties": {
                    "severity": finding.severity,
                    "resource": finding.resource,
                    "attribution": ATTRIBUTION,
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "planradius",
                        "version": __version__,
                        "informationUri": "https://github.com/yazilimbaysoz-svg/planradius",
                        "organization": ATTRIBUTION,
                        "rules": rules,
                        "properties": {"attribution": ATTRIBUTION},
                    }
                },
                "results": results,
                "properties": {
                    "attribution": ATTRIBUTION,
                    "source": source,
                    "acknowledged_findings": acknowledged_count,
                    "stale_baseline_entries": stale_count,
                    "counts": {
                        level: sum(1 for item in findings if item.severity == level)
                        for level in ("critical", "high", "medium", "low")
                    },
                },
            }
        ],
    }
