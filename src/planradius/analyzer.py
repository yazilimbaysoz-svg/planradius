# planradius — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
"""Analysis orchestration: plan -> graph -> permissions -> deterministic findings.

Attribution: Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import __version__
from .baseline import ATTRIBUTION
from .graph import DependencyGraph, build_graph
from .iam import PermissionIndex, build_permission_index
from .model import Plan
from .rules import (
    SEVERITY_RANK,
    Finding,
    blast_radius_rules,
    data_exposure_rules,
    encryption_rules,
    escalation_rules,
    graph_rules,
    network_rules,
    plan_error_rules,
    policy_error_rules,
    replacement_rules,
    sort_findings,
    trust_policy_rules,
    wildcard_policy_rules,
)


@dataclass(frozen=True)
class Analysis:
    """Complete, reproducible result of analyzing one plan."""

    plan: Plan
    graph: DependencyGraph
    permissions: PermissionIndex
    findings: tuple[Finding, ...]

    def counts(self) -> dict[str, int]:
        return {
            level: sum(1 for finding in self.findings if finding.severity == level)
            for level in ("critical", "high", "medium", "low")
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": "planradius",
            "version": __version__,
            "attribution": ATTRIBUTION,
            "plan": {
                "format_version": self.plan.format_version,
                "terraform_version": self.plan.terraform_version,
                "resources": len(self.plan.resources),
                "changed_resources": len(self.plan.changed_resources),
                "dependency_edges": sum(
                    len(self.graph.dependencies_of(node)) for node in self.graph.nodes
                ),
            },
            "counts": self.counts(),
            "findings": [finding.as_dict() for finding in self.findings],
        }


def analyze(plan: Plan, *, max_blast_radius: int = 10) -> Analysis:
    """Evaluate every rule against a validated plan."""
    graph = build_graph(plan)
    permissions, policies = build_permission_index(plan)
    findings = [
        *wildcard_policy_rules(policies),
        *trust_policy_rules(policies),
        *escalation_rules(permissions),
        *network_rules(plan.resources),
        *data_exposure_rules(plan.resources),
        *encryption_rules(plan.resources),
        *replacement_rules(plan.resources, graph),
        *blast_radius_rules(plan.resources, graph, max_blast_radius),
        *graph_rules(graph),
        *policy_error_rules(policies),
        *plan_error_rules(plan.errors),
    ]
    return Analysis(plan, graph, permissions, sort_findings(findings))


def exceeds_threshold(findings: tuple[Finding, ...], fail_on: str) -> bool:
    """Return True when an active finding meets or beats the failure threshold."""
    if fail_on == "none":
        return False
    limit = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK.get(item.severity, 4) <= limit for item in findings)
