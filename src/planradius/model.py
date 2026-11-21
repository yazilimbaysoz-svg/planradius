# planradius — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
"""Parse and validate Terraform/OpenTofu JSON plan documents.

Attribution: Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

MAX_RESOURCES = 200_000
MAX_DEPTH = 64
MAX_STRING_CHARS = 1_000_000
VALID_ACTIONS = frozenset({"no-op", "create", "update", "delete", "read", "forget", "open"})

_REFERENCE_RE = re.compile(
    r"\b((?:data\.)?[A-Za-z0-9_-]+\.[A-Za-z0-9_*.-]+(?:\[[^\]\n]+\])?"
    r"(?:\.[A-Za-z0-9_*.-]+(?:\[[^\]\n]+\])?)+)"
)


class PlanError(ValueError):
    """Raised when a plan document is structurally invalid or hostile."""


@dataclass(frozen=True)
class PlanResource:
    """A single resource entry from the plan's change array."""

    address: str
    mode: str
    type: str
    name: str
    provider: str
    actions: tuple[str, ...]
    before: dict[str, Any]
    after: dict[str, Any]
    after_unknown: frozenset[str]
    replace_paths: tuple[str, ...]
    dependencies: tuple[str, ...]
    expressions: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return any(action in {"create", "update", "delete"} for action in self.actions)

    @property
    def replaced(self) -> bool:
        return "delete" in self.actions and "create" in self.actions

    @property
    def stateful(self) -> bool:
        """Explicit inventory of resource families that persist user data."""
        stateful_prefixes = (
            "aws_db_",
            "aws_rds_",
            "aws_elasticache_",
            "aws_dynamodb_",
            "aws_ebs_",
            "aws_s3_bucket",
            "aws_efs_",
            "aws_fsx_",
            "aws_opensearch_",
            "aws_lambda_function",
            "google_sql_",
            "google_storage_bucket",
            "azurerm_mssql_",
            "azurerm_storage_account",
        )
        return self.type.startswith(stateful_prefixes)


@dataclass(frozen=True)
class Plan:
    """Validated, normalized view of a JSON plan."""

    format_version: str
    terraform_version: str
    resources: tuple[PlanResource, ...]
    errors: tuple[str, ...]

    @property
    def changed_resources(self) -> tuple[PlanResource, ...]:
        return tuple(resource for resource in self.resources if resource.changed)


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise PlanError(f"plan nesting exceeds maximum depth of {MAX_DEPTH}")
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            raise PlanError("plan contains a string longer than the supported limit")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PlanError("plan object keys must be strings")
            _check_depth(key, depth + 1)
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def _as_object(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PlanError(f"{field_name} must be an object or null")
    return value


def _as_string_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise PlanError(f"{field_name} must be an array")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise PlanError(f"{field_name} entries must be strings")
        result.append(item)
    return tuple(result)


def _collect_expression_tokens(value: Any, target: list[str]) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _collect_expression_tokens(item, target)
    elif isinstance(value, list):
        for item in value:
            _collect_expression_tokens(item, target)
    elif isinstance(value, str):
        for match in _REFERENCE_RE.finditer(value):
            target.append(match.group(1))


def _expression_strings(value: Any) -> tuple[str, ...]:
    found: list[str] = []
    _collect_expression_tokens(value, found)
    return tuple(dict.fromkeys(found))


def parse_plan_text(text: str) -> Plan:
    """Parse a JSON plan string, raising PlanError for invalid documents."""
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise PlanError(f"invalid JSON document: {exc}") from exc
    return parse_plan(raw)


def parse_plan(raw: Any) -> Plan:
    """Validate and normalize a decoded plan document."""
    if not isinstance(raw, dict):
        raise PlanError("plan root must be a JSON object")
    _check_depth(raw)
    changes = raw.get("resource_changes", [])
    if not isinstance(changes, list):
        raise PlanError("resource_changes must be an array")
    if len(changes) > MAX_RESOURCES:
        raise PlanError(f"plan exceeds maximum of {MAX_RESOURCES} resources")

    resources: list[PlanResource] = []
    seen: set[str] = set()
    for index, entry in enumerate(changes):
        if not isinstance(entry, dict):
            raise PlanError(f"resource_changes[{index}] must be an object")
        address = entry.get("address")
        if not isinstance(address, str) or not address:
            raise PlanError(f"resource_changes[{index}].address must be a non-empty string")
        if address in seen:
            raise PlanError(f"duplicate resource address in plan: {address}")
        seen.add(address)
        change = _as_object(entry.get("change"), f"resource_changes[{index}].change")
        actions = _as_string_tuple(change.get("actions"), "change.actions")
        if not actions:
            raise PlanError(f"{address}: change.actions must not be empty")
        invalid = sorted(set(actions) - VALID_ACTIONS)
        if invalid:
            raise PlanError(f"{address}: unsupported change action(s): {', '.join(invalid)}")
        before = _as_object(change.get("before"), "change.before")
        after = _as_object(change.get("after"), "change.after")
        unknown = _as_object(change.get("after_unknown"), "change.after_unknown")
        expressions = _expression_strings({"before": before, "after": after})
        config = entry.get("configuration")
        config_exprs: tuple[str, ...] = ()
        if isinstance(config, dict):
            depends_on = config.get("depends_on")
            config_exprs = _as_string_tuple(depends_on, "configuration.depends_on")
            expressions = tuple(dict.fromkeys([*expressions, *_expression_strings(config)]))
        resource = PlanResource(
            address=address,
            mode=str(entry.get("mode") or "managed"),
            type=str(entry.get("type") or ""),
            name=str(entry.get("name") or ""),
            provider=str(entry.get("provider") or ""),
            actions=actions,
            before=before,
            after=after,
            after_unknown=frozenset(unknown),
            replace_paths=_as_string_tuple(change.get("replace_paths"), "replace_paths"),
            dependencies=tuple(
                dict.fromkeys(
                    [*config_exprs, *_as_string_tuple(entry.get("dependencies"), "dependencies")]
                )
            ),
            expressions=expressions,
        )
        resources.append(resource)

    format_version = raw.get("format_version")
    terraform_version = raw.get("terraform_version")
    if format_version is not None and not isinstance(format_version, str):
        raise PlanError("format_version must be a string")
    if terraform_version is not None and not isinstance(terraform_version, str):
        raise PlanError("terraform_version must be a string")

    errors = _as_string_tuple(raw.get("diagnostics_errors"), "diagnostics_errors")
    return Plan(
        format_version=format_version or "unknown",
        terraform_version=terraform_version or "unknown",
        resources=tuple(resources),
        errors=errors,
    )
