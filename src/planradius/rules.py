# planradius — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
"""Deterministic risk rules over a validated plan, graph, and permission index.

Attribution: Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterator

from .graph import DependencyGraph
from .iam import MatchedPath, ParsedPolicy, PermissionIndex
from .model import PlanResource

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


RULE_CATALOG: tuple[dict[str, str], ...] = (
    {
        "id": "PR-001",
        "title": "Wildcard action grant",
        "severity": "critical/high",
        "description": ("IAM statement grants a service-wide or account-wide action wildcard."),
    },
    {
        "id": "PR-002",
        "title": "Unrestricted role trust policy",
        "severity": "critical",
        "description": "A role trust policy accepts an unconstrained wildcard principal.",
    },
    {
        "id": "PR-003",
        "title": "Privilege escalation reachability",
        "severity": "critical/high",
        "description": "Aggregated principal permissions satisfy a documented escalation path.",
    },
    {
        "id": "PR-004",
        "title": "Public ingress",
        "severity": "high",
        "description": (
            "A changed security group exposes a management or unrestricted port globally."
        ),
    },
    {
        "id": "PR-005",
        "title": "Public data exposure",
        "severity": "high",
        "description": (
            "A data resource is publicly reachable or its access guardrails are disabled."
        ),
    },
    {
        "id": "PR-006",
        "title": "Encryption regression",
        "severity": "high",
        "description": "Encryption settings or KMS keys are removed from a planned resource.",
    },
    {
        "id": "PR-007",
        "title": "Stateful resource replacement",
        "severity": "high",
        "description": "A stateful resource is destroyed and recreated with downstream impact.",
    },
    {
        "id": "PR-008",
        "title": "Oversized dependency blast radius",
        "severity": "high/medium",
        "description": (
            "A changed resource affects more downstream resources than the configured limit."
        ),
    },
    {
        "id": "PR-009",
        "title": "Cyclic resource dependencies",
        "severity": "medium",
        "description": "The plan contains a dependency cycle with more than one resource.",
    },
    {
        "id": "PR-010",
        "title": "Unparseable policy document",
        "severity": "medium",
        "description": "A policy document cannot be decoded, so its grants cannot be assessed.",
    },
    {
        "id": "PR-011",
        "title": "Plan diagnostics errors",
        "severity": "high",
        "description": "The plan reports errors and is therefore an incomplete security artifact.",
    },
)


@dataclass(frozen=True)
class Finding:
    """A reproducible, attributable risk finding."""

    rule_id: str
    title: str
    severity: str
    resource: str
    detail: str
    remediation: str
    references: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(
            [self.rule_id, self.title, self.resource, self.detail],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "resource": self.resource,
            "detail": self.detail,
            "remediation": self.remediation,
            "references": list(self.references),
        }


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    resource: str,
    detail: str,
    remediation: str,
    references: tuple[str, ...] = (),
) -> Finding:
    return Finding(rule_id, title, severity, resource, detail, remediation, references)


def _walk_dicts(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk_dicts(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_dicts(item)


def _public_cidrs(value: Any) -> tuple[str, ...]:
    public = {"0.0.0.0/0", "::/0"}
    if isinstance(value, str):
        return (value,) if value in public else ()
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str) and item in public)
    return ()


def wildcard_policy_rules(policies: tuple[ParsedPolicy, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for policy in policies:
        for statement in policy.statements:
            if not statement.allows:
                continue
            for action in statement.actions:
                if not (action == "*" or action == "*:*" or action.endswith(":*")):
                    continue
                severity = "critical" if action in {"*", "*:*"} else "high"
                findings.append(
                    _finding(
                        "PR-001",
                        "Wildcard action grant",
                        severity,
                        policy.address,
                        f"Action {action!r} granted on "
                        f"{list(statement.resources) or ['<unscoped>']} to "
                        f"{list(statement.principals) or ['<identity policy: no Principal>']}",
                        "Replace the wildcard with the exact actions and resource ARNs required.",
                        ("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",),
                    )
                )
    return findings


def trust_policy_rules(policies: tuple[ParsedPolicy, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for policy in policies:
        if policy.policy_type != "aws_iam_role":
            continue
        for statement in policy.statements:
            if not statement.allows:
                continue
            wildcards = [
                principal
                for principal in statement.principals
                if principal == "*" or principal.upper() == "AWS:*"
            ]
            if not wildcards:
                continue
            findings.append(
                _finding(
                    "PR-002",
                    "Unrestricted role trust policy",
                    "critical",
                    policy.address,
                    f"Trust principal(s) {wildcards} can assume this role without constraint"
                    + (
                        "; conditions are present but not evaluated" if statement.conditions else ""
                    ),
                    "Bind the trust policy to explicit account, repository, or service principals.",
                    (
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html",
                    ),
                )
            )
    return findings


def escalation_rules(index: PermissionIndex) -> list[Finding]:
    """Emit one consolidated finding per principal with reachable escalation paths."""
    grouped: dict[str, list[MatchedPath]] = {}
    for matched in index.matched_paths():
        grouped.setdefault(matched.principal, []).append(matched)
    findings: list[Finding] = []
    for principal, matches in sorted(grouped.items()):
        identifiers = ", ".join(match.path.identifier for match in matches)
        summaries = "; ".join(
            f"{match.path.identifier}: {match.path.explanation}" for match in matches[:6]
        )
        if len(matches) > 6:
            summaries += f"; and {len(matches) - 6} further documented path(s)"
        scopes = sorted(
            {
                scope
                for match in matches
                for permission in match.permissions
                for scope in permission.scope
            }
        )
        unbounded = any(match.unscoped or match.principal in {"*", "aws:*"} for match in matches)
        conditional = any(
            permission.has_condition for match in matches for permission in match.permissions
        )
        severity = (
            "critical"
            if unbounded or any(match.path.severity == "critical" for match in matches)
            else "high"
        )
        findings.append(
            _finding(
                "PR-003",
                f"Privilege escalation reachability ({len(matches)} paths)",
                severity,
                matches[0].permissions[0].address,
                f"Principal {principal!r} can reach: {identifiers}. {summaries} "
                f"Resource scope: {scopes or ['<unscoped>']}"
                + ("; conditions present but not evaluated" if conditional else ""),
                "Remove the prerequisite grants or constrain them to explicit ARNs and conditions.",
                ("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",),
            )
        )
    return findings


def network_rules(plan_resources: tuple[PlanResource, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for resource in plan_resources:
        if not resource.changed:
            continue
        if not resource.type.startswith(("aws_security_group", "aws_vpc_security_group")):
            continue
        for block in _walk_dicts(resource.after):
            cidrs = _public_cidrs(block.get("cidr_blocks")) or _public_cidrs(
                block.get("cidr_block")
            )
            if not cidrs:
                continue
            low = block.get("from_port")
            high = block.get("to_port")
            if not isinstance(low, int) or not isinstance(high, int):
                low = high = None
            management = low is not None and any(
                low <= port <= high for port in (22, 3389, 2375, 6379, 27017)
            )
            all_ports = low is not None and low <= 0 and high >= 65535
            if not (management or all_ports or low is None):
                continue
            kind = "management/service port" if management else "unrestricted ingress"
            findings.append(
                _finding(
                    "PR-004",
                    f"Public {kind}",
                    "high",
                    resource.address,
                    f"CIDR(s) {list(cidrs)} reach ports {low}-{high} on {resource.type}",
                    "Restrict ingress to approved CIDRs and narrow the port range.",
                    ("https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",),
                )
            )
    return findings


def data_exposure_rules(plan_resources: tuple[PlanResource, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for resource in plan_resources:
        if not resource.changed:
            continue
        values = resource.after
        for key in ("publicly_accessible", "public", "public_network_access_enabled"):
            if values.get(key) is True:
                findings.append(
                    _finding(
                        "PR-005",
                        "Publicly reachable data resource",
                        "high",
                        resource.address,
                        f"{resource.type} sets {key}=true",
                        "Disable public network access or place the resource in a private subnet.",
                    )
                )
        acl = str(values.get("acl") or values.get("canned_acl") or "").lower()
        if acl in {"public-read", "public-read-write"}:
            findings.append(
                _finding(
                    "PR-005",
                    "Public object ACL",
                    "high",
                    resource.address,
                    f"{resource.type} sets acl={acl!r}",
                    "Use a private ACL and grant access through scoped IAM or presigned URLs.",
                )
            )
        block_keys = (
            "block_public_acls",
            "ignore_public_acls",
            "block_public_policy",
            "restrict_public_buckets",
        )
        if resource.type == "aws_s3_bucket_public_access_block" and all(
            values.get(key) is False for key in block_keys
        ):
            findings.append(
                _finding(
                    "PR-005",
                    "Public access block fully disabled",
                    "high",
                    resource.address,
                    f"All {len(block_keys)} S3 public-access guardrails are set to false",
                    "Enable all four S3 public access block settings unless explicitly justified.",
                )
            )
    return findings


def encryption_rules(plan_resources: tuple[PlanResource, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for resource in plan_resources:
        if not resource.changed:
            continue
        for key in ("encrypted", "storage_encrypted", "kms_key_id"):
            before = resource.before.get(key)
            after = resource.after.get(key)
            if before is True and after is False:
                findings.append(
                    _finding(
                        "PR-006",
                        "Encryption disabled",
                        "high",
                        resource.address,
                        f"{key} changed from true to false on {resource.type}",
                        "Restore encryption and rotate any data written while it was disabled.",
                    )
                )
            elif isinstance(before, str) and before and not after:
                findings.append(
                    _finding(
                        "PR-006",
                        "Encryption key detached",
                        "high",
                        resource.address,
                        f"{key} was removed from {resource.type}",
                        "Keep an explicit KMS key or provider-managed encryption configured.",
                    )
                )
        before_sse = "server_side_encryption_configuration" in resource.before
        after_sse = "server_side_encryption_configuration" in resource.after
        if before_sse and not after_sse:
            findings.append(
                _finding(
                    "PR-006",
                    "Server-side encryption configuration removed",
                    "high",
                    resource.address,
                    f"server_side_encryption_configuration removed from {resource.type}",
                    "Restore the server-side encryption block before applying.",
                )
            )
    return findings


def replacement_rules(
    plan_resources: tuple[PlanResource, ...], graph: DependencyGraph
) -> list[Finding]:
    findings: list[Finding] = []
    for resource in plan_resources:
        if not resource.stateful or not resource.replaced:
            continue
        affected = graph.blast_radius(resource.address)
        findings.append(
            _finding(
                "PR-007",
                "Stateful resource replacement",
                "high",
                resource.address,
                f"{resource.type} will be destroyed and recreated; "
                f"{len(affected)} downstream resource(s) affected"
                + (f": {', '.join(sorted(affected)[:5])}" if affected else ""),
                "Verify backups and a tested restore path, or change the attribute that "
                "forces replacement.",
            )
        )
    return findings


def blast_radius_rules(
    plan_resources: tuple[PlanResource, ...], graph: DependencyGraph, threshold: int
) -> list[Finding]:
    findings: list[Finding] = []
    for resource in plan_resources:
        if not resource.changed:
            continue
        affected = graph.blast_radius(resource.address)
        if len(affected) < threshold:
            continue
        findings.append(
            _finding(
                "PR-008",
                "Oversized dependency blast radius",
                "high" if len(affected) >= threshold * 2 else "medium",
                resource.address,
                f"Changing {resource.address} may affect {len(affected)} downstream resources: "
                + ", ".join(sorted(affected)[:8]),
                "Split the state or module so unrelated lifecycles are not coupled.",
            )
        )
    return findings


def graph_rules(graph: DependencyGraph) -> list[Finding]:
    return [
        _finding(
            "PR-009",
            "Cyclic resource dependencies",
            "medium",
            component[0],
            f"Dependency cycle detected across {len(component)} resources: "
            + ", ".join(component[:8]),
            "Break the implicit reference cycle; Terraform may be unable to order this plan.",
        )
        for component in graph.cycles()
    ]


def policy_error_rules(policies: tuple[ParsedPolicy, ...]) -> list[Finding]:
    return [
        _finding(
            "PR-010",
            "Unparseable policy document",
            "medium",
            policy.address,
            f"{policy.error}",
            "Emit a syntactically valid policy document; unknown grants cannot be risk-assessed.",
        )
        for policy in policies
        if policy.error
    ]


def plan_error_rules(errors: tuple[str, ...]) -> list[Finding]:
    return [
        _finding(
            "PR-011",
            "Plan contains diagnostics errors",
            "high",
            "<plan>",
            error,
            "Resolve the plan errors and regenerate the JSON plan before gating.",
        )
        for error in errors
    ]


def sort_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda item: (
                SEVERITY_RANK.get(item.severity, 4),
                item.rule_id,
                item.resource,
                item.fingerprint,
            ),
        )
    )
