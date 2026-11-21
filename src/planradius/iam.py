# planradius — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
"""IAM policy normalization, wildcard matching, and escalation reachability.

Attribution: Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .model import Plan, PlanResource

POLICY_FIELDS: dict[str, tuple[str, ...]] = {
    "aws_iam_policy": ("policy",),
    "aws_iam_role": ("assume_role_policy",),
    "aws_iam_role_policy": ("policy",),
    "aws_iam_group_policy": ("policy",),
    "aws_iam_user_policy": ("policy",),
    "aws_s3_bucket_policy": ("policy",),
    "aws_kms_key_policy": ("policy",),
    "aws_sqs_queue_policy": ("policy",),
    "aws_sns_topic_policy": ("policy",),
    "aws_ecr_repository_policy": ("policy",),
    "aws_vpc_endpoint_policy": ("policy",),
    "google_iam_policy": ("policy_data",),
}


@dataclass(frozen=True)
class EscalationPath:
    """A documented AWS privilege-escalation prerequisite set."""

    identifier: str
    name: str
    required_actions: tuple[str, ...]
    severity: str
    explanation: str


ESCALATION_PATHS: tuple[EscalationPath, ...] = (
    EscalationPath(
        "IAM-ESC-001",
        "Role pass-through into Lambda",
        ("iam:PassRole", "lambda:CreateFunction"),
        "critical",
        "A role can be passed to a new Lambda function and invoked as that role.",
    ),
    EscalationPath(
        "IAM-ESC-002",
        "Role pass-through into EC2",
        ("iam:PassRole", "ec2:RunInstances"),
        "critical",
        "A role can be attached to an instance profile and used by a new instance.",
    ),
    EscalationPath(
        "IAM-ESC-003",
        "Role pass-through into ECS",
        ("iam:PassRole", "ecs:CreateService"),
        "critical",
        "A task role can be attached to a new ECS service task definition.",
    ),
    EscalationPath(
        "IAM-ESC-004",
        "IAM policy mutation",
        ("iam:AttachRolePolicy",),
        "critical",
        "An existing managed policy can be attached to a controllable role.",
    ),
    EscalationPath(
        "IAM-ESC-005",
        "Inline policy injection",
        ("iam:PutRolePolicy",),
        "critical",
        "An inline policy can be written to a controllable role.",
    ),
    EscalationPath(
        "IAM-ESC-006",
        "Managed policy version rewrite",
        ("iam:CreatePolicyVersion",),
        "critical",
        "A new policy version can expand the effect of an existing managed policy.",
    ),
    EscalationPath(
        "IAM-ESC-007",
        "Default policy version rollback",
        ("iam:SetDefaultPolicyVersion",),
        "critical",
        "An older policy version can be selected as the effective version.",
    ),
    EscalationPath(
        "IAM-ESC-008",
        "Trust policy rewrite",
        ("iam:UpdateAssumeRolePolicy",),
        "critical",
        "A role trust policy can be changed to allow a different principal.",
    ),
    EscalationPath(
        "IAM-ESC-009",
        "Role assumption",
        ("sts:AssumeRole",),
        "high",
        "The principal can assume another role, potentially gaining broader access.",
    ),
    EscalationPath(
        "IAM-ESC-010",
        "Access key creation",
        ("iam:CreateAccessKey",),
        "high",
        "Long-lived credentials can be created for an existing IAM user.",
    ),
    EscalationPath(
        "IAM-ESC-011",
        "Lambda code injection",
        ("lambda:UpdateFunctionCode",),
        "critical",
        "Existing function code can be replaced with attacker-controlled logic.",
    ),
    EscalationPath(
        "IAM-ESC-012",
        "Secret retrieval",
        ("secretsmanager:GetSecretValue",),
        "high",
        "Stored secret material can be read by the principal.",
    ),
)


@dataclass(frozen=True)
class Statement:
    """One normalized policy statement."""

    address: str
    policy_type: str
    effect: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    principals: tuple[str, ...]
    conditions: tuple[str, ...]

    @property
    def allows(self) -> bool:
        return self.effect == "allow"


@dataclass(frozen=True)
class ParsedPolicy:
    """Policy extraction result, including explicit parse failures."""

    address: str
    policy_type: str
    statements: tuple[Statement, ...]
    error: str | None = None


@dataclass(frozen=True)
class Permission:
    """A granted action with its provenance."""

    action: str
    address: str
    scope: tuple[str, ...]
    has_condition: bool

    @property
    def unscoped(self) -> bool:
        return not self.scope or any(item == "*" for item in self.scope)


@dataclass(frozen=True)
class MatchedPath:
    """An escalation path reachable from an aggregated principal permission set."""

    path: EscalationPath
    permissions: tuple[Permission, ...]
    principal: str

    @property
    def unscoped(self) -> bool:
        return any(permission.unscoped for permission in self.permissions)


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _principals(value: Any) -> tuple[str, ...]:
    if value == "*":
        return ("*",)
    if isinstance(value, dict):
        result: list[str] = []
        for kind, members in value.items():
            for member in _string_tuple(members):
                result.append(f"{kind}:{member}")
        return tuple(sorted(result))
    if isinstance(value, list):
        return tuple(sorted({item for entry in value for item in _principals(entry)}))
    if isinstance(value, str):
        return (f"AWS:{value}",)
    return ()


def _condition_keys(value: Any) -> tuple[str, ...]:
    if not isinstance(value, dict):
        return ()
    keys: list[str] = []
    for operator, expression in value.items():
        if isinstance(expression, dict):
            keys.extend(f"{operator}:{name}" for name in expression if isinstance(name, str))
        else:
            keys.append(operator)
    return tuple(sorted(keys))


def _decode_document(value: Any) -> tuple[dict[str, Any], str | None]:
    if isinstance(value, dict):
        return value, None
    if not isinstance(value, str):
        return {}, "policy document is neither an object nor a JSON string"
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        return {}, f"policy document is not valid JSON: {exc}"
    if not isinstance(decoded, dict):
        return {}, "decoded policy document is not an object"
    return decoded, None


def parse_policy(resource: PlanResource) -> ParsedPolicy:
    """Extract policy statements from a single plan resource."""
    fields = POLICY_FIELDS.get(resource.type, ())
    documents: list[tuple[str, Any]] = [
        (field, resource.after[field]) for field in fields if field in resource.after
    ]
    if resource.type == "aws_iam_role":
        inline = resource.after.get("inline_policy")
        if isinstance(inline, list):
            for entry in inline:
                if isinstance(entry, dict) and isinstance(entry.get("policy"), (dict, str)):
                    documents.append(("inline_policy", entry["policy"]))
    if resource.type == "aws_lambda_permission":
        principal = _principals(resource.after.get("principal"))
        return ParsedPolicy(
            address=resource.address,
            policy_type="aws_lambda_permission",
            statements=(
                Statement(
                    address=resource.address,
                    policy_type="aws_lambda_permission",
                    effect="allow",
                    actions=tuple(
                        action.lower() for action in _string_tuple(resource.after.get("action"))
                    ),
                    not_actions=(),
                    resources=(str(resource.after.get("function_name") or "*"),),
                    principals=principal,
                    conditions=_condition_keys(resource.after.get("source_arn")),
                ),
            ),
        )
    if not documents:
        return ParsedPolicy(resource.address, resource.type or "unknown", ())

    statements: list[Statement] = []
    errors: list[str] = []
    for field, raw_document in documents:
        document, error = _decode_document(raw_document)
        if error:
            errors.append(f"{field}: {error}")
            continue
        raw_statements = document.get("Statement", [])
        if isinstance(raw_statements, dict):
            raw_statements = [raw_statements]
        if not isinstance(raw_statements, list):
            errors.append(f"{field}: Statement must be an object or array")
            continue
        for item in raw_statements:
            if not isinstance(item, dict):
                errors.append(f"{field}: statement entries must be objects")
                continue
            effect = str(item.get("Effect", "Allow")).lower()
            if effect not in {"allow", "deny"}:
                errors.append(f"{field}: unsupported Effect value")
                continue
            statements.append(
                Statement(
                    address=resource.address,
                    policy_type=resource.type,
                    effect=effect,
                    actions=tuple(action.lower() for action in _string_tuple(item.get("Action"))),
                    not_actions=tuple(
                        action.lower() for action in _string_tuple(item.get("NotAction"))
                    ),
                    resources=_string_tuple(item.get("Resource")),
                    principals=_principals(item.get("Principal")),
                    conditions=_condition_keys(item.get("Condition")),
                )
            )
    return ParsedPolicy(
        address=resource.address,
        policy_type=resource.type,
        statements=tuple(statements),
        error="; ".join(errors) or None,
    )


def action_matches(pattern: str, action: str) -> bool:
    """Match an IAM action pattern using only the * and ? wildcards."""
    expression = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern
    )
    return re.fullmatch(expression, action, flags=re.IGNORECASE) is not None


class PermissionIndex:
    """Principal-indexed permission reachability across all plan policies."""

    def __init__(self, policies: tuple[ParsedPolicy, ...]) -> None:
        grants: dict[str, list[Permission]] = {}
        denies: dict[str, set[str]] = {}
        for policy in policies:
            for statement in policy.statements:
                use_not_action = not statement.actions and bool(statement.not_actions)
                if not use_not_action:
                    patterns = statement.actions
                else:
                    patterns = tuple(
                        action
                        for action in ESCALATION_ACTIONS
                        if not any(
                            action_matches(excluded, action) for excluded in statement.not_actions
                        )
                    )
                for principal in statement.principals or ("*",):
                    key = principal.lower()
                    if statement.allows:
                        for action in patterns:
                            grants.setdefault(key, []).append(
                                Permission(
                                    action=action,
                                    address=statement.address,
                                    scope=statement.resources,
                                    has_condition=bool(statement.conditions),
                                )
                            )
                    else:
                        denies.setdefault(key, set()).update(patterns)
        self._grants = {
            key: tuple(sorted(value, key=lambda p: (p.action, p.address)))
            for key, value in grants.items()
        }
        self._denies = {key: frozenset(value) for key, value in denies.items()}
        self.principals = tuple(sorted(self._grants))

    def permits(self, principal: str, action: str) -> tuple[Permission, ...]:
        """Return grants for an action, honoring explicit deny patterns."""
        keys = {principal.lower(), "*"}
        denied = any(
            any(action_matches(pattern, action) for pattern in self._denies.get(key, ()))
            for key in keys
        )
        if denied:
            return ()
        return tuple(
            permission
            for key in keys
            for permission in self._grants.get(key, ())
            if action_matches(permission.action, action)
        )

    def matched_paths(self) -> tuple[MatchedPath, ...]:
        """Compute all reachable escalation paths across aggregated permissions."""
        results: list[MatchedPath] = []
        for principal in self.principals:
            for path in ESCALATION_PATHS:
                used: list[Permission] = []
                reachable = True
                for action in path.required_actions:
                    grants = self.permits(principal, action)
                    if not grants:
                        reachable = False
                        break
                    used.append(grants[0])
                if reachable:
                    results.append(
                        MatchedPath(
                            path=path,
                            permissions=tuple(
                                sorted(set(used), key=lambda p: (p.action, p.address))
                            ),
                            principal=principal,
                        )
                    )
        return tuple(sorted(results, key=lambda item: (item.path.identifier, item.principal)))


ESCALATION_ACTIONS: tuple[str, ...] = tuple(
    dict.fromkeys(action for path in ESCALATION_PATHS for action in path.required_actions)
)


def build_permission_index(plan: Plan) -> tuple[PermissionIndex, tuple[ParsedPolicy, ...]]:
    """Parse every policy-bearing resource in the plan and index its permissions."""
    policies = tuple(parse_policy(resource) for resource in plan.resources)
    return PermissionIndex(policies), policies
