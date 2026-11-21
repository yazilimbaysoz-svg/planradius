# planradius — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
"""Command-line interface for planradius.

Attribution: Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .analyzer import analyze, exceeds_threshold
from .baseline import (
    ATTRIBUTION,
    BaselineError,
    apply_baseline,
    create_baseline,
    load_baseline,
)
from .iam import build_permission_index
from .model import PlanError, parse_plan_text
from .render import render_explain, render_report, render_rules
from .rules import RULE_CATALOG
from .sarif import build_sarif

VERSION_TEXT = f"planradius {__version__} — {ATTRIBUTION}"
SEVERITIES = ("critical", "high", "medium", "low", "none")


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _write_text(path: str | None, text: str) -> None:
    if path:
        Path(path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="planradius",
        description=(
            "Deterministic Terraform/OpenTofu plan blast-radius and IAM escalation gate. "
            f"Built by {ATTRIBUTION}."
        ),
        epilog=(
            f"planradius {__version__} — Baysöz Labs <baysozlabs@proton.me>. "
            "Offline, stateless, and deterministic. No cloud credentials required."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=VERSION_TEXT)
    commands = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = commands.add_parser(
        "analyze",
        help="Analyze a Terraform/OpenTofu JSON plan",
        description=f"Analyze a plan JSON document. {ATTRIBUTION}",
        epilog=f"Attribution: {ATTRIBUTION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    analyze_cmd.add_argument("--plan", required=True, help="plan JSON path, or - for stdin")
    analyze_cmd.add_argument(
        "--format", choices=("table", "json", "sarif"), default="table", help="output format"
    )
    analyze_cmd.add_argument(
        "--fail-on", choices=SEVERITIES, default="high", help="minimum severity that fails the gate"
    )
    analyze_cmd.add_argument("--baseline", help="baseline JSON path for acknowledged findings")
    analyze_cmd.add_argument("--output", help="write output to a file instead of stdout")
    analyze_cmd.add_argument(
        "--max-blast-radius",
        type=int,
        default=10,
        help="downstream resource count that triggers PR-008 (default: 10)",
    )

    baseline_cmd = commands.add_parser(
        "baseline",
        help="Create a reproducible finding baseline",
        description=f"Create a finding fingerprint baseline. {ATTRIBUTION}",
        epilog=f"Attribution: {ATTRIBUTION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    baseline_cmd.add_argument("--plan", required=True, help="plan JSON path, or - for stdin")
    baseline_cmd.add_argument("--output", required=True, help="baseline JSON output path")
    baseline_cmd.add_argument("--max-blast-radius", type=int, default=10)

    explain_cmd = commands.add_parser(
        "explain",
        help="Explain blast radius and escalation reachability for one resource",
        description=f"Explain one resource in a plan. {ATTRIBUTION}",
        epilog=f"Attribution: {ATTRIBUTION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    explain_cmd.add_argument("--plan", required=True, help="plan JSON path, or - for stdin")
    explain_cmd.add_argument("--address", required=True, help="exact plan resource address")
    explain_cmd.add_argument("--format", choices=("table", "json"), default="table")
    explain_cmd.add_argument("--max-blast-radius", type=int, default=10)

    rules_cmd = commands.add_parser(
        "rules",
        help="List built-in rules",
        description=f"List built-in rules. {ATTRIBUTION}",
        epilog=f"Attribution: {ATTRIBUTION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    rules_cmd.add_argument("--format", choices=("table", "json"), default="table")
    return parser


def _validate_limit(value: int) -> None:
    if value < 1:
        raise ValueError("--max-blast-radius must be at least 1")


def _run_analyze(args: argparse.Namespace) -> int:
    _validate_limit(args.max_blast_radius)
    plan = parse_plan_text(_read_text(args.plan))
    analysis = analyze(plan, max_blast_radius=args.max_blast_radius)
    baseline = None
    if args.baseline:
        baseline = load_baseline(_read_text(args.baseline))
    result = apply_baseline(analysis.findings, baseline)

    if args.format == "table":
        text = render_report(analysis, result, args.plan)
    elif args.format == "sarif":
        text = _json(
            build_sarif(
                result.active,
                source=args.plan,
                acknowledged_count=len(result.acknowledged),
                stale_count=len(result.stale),
            )
        )
    else:
        payload = analysis.as_dict()
        payload["findings"] = [finding.as_dict() for finding in result.active]
        payload["acknowledged_findings"] = [finding.as_dict() for finding in result.acknowledged]
        payload["stale_baseline_entries"] = list(result.stale)
        text = _json(payload)
    _write_text(args.output, text)
    return 1 if exceeds_threshold(result.active, args.fail_on) else 0


def _run_baseline(args: argparse.Namespace) -> int:
    _validate_limit(args.max_blast_radius)
    plan = parse_plan_text(_read_text(args.plan))
    analysis = analyze(plan, max_blast_radius=args.max_blast_radius)
    baseline = create_baseline(analysis.findings)
    Path(args.output).write_text(_json(baseline.as_dict()), encoding="utf-8")
    sys.stdout.write(
        f"planradius {__version__}: wrote {len(baseline.fingerprints)} fingerprints "
        f"to {args.output} — {ATTRIBUTION}\n"
    )
    return 0


def _run_explain(args: argparse.Namespace) -> int:
    _validate_limit(args.max_blast_radius)
    plan = parse_plan_text(_read_text(args.plan))
    analysis = analyze(plan, max_blast_radius=args.max_blast_radius)
    resource = next((item for item in plan.resources if item.address == args.address), None)
    if resource is None:
        raise PlanError(f"resource address not found in plan: {args.address}")
    blast = tuple(sorted(analysis.graph.blast_radius(resource.address)))
    permissions, policies = build_permission_index(plan)
    principals = {
        principal.lower()
        for policy in policies
        if policy.address == resource.address
        for statement in policy.statements
        for principal in statement.principals
    }
    affected = {resource.address, *blast}
    paths = tuple(
        f"{match.path.identifier} {match.path.name} via principal {match.principal}"
        for match in permissions.matched_paths()
        if match.principal.lower() in principals
        or any(permission.address in affected for permission in match.permissions)
    )
    if args.format == "json":
        text = _json(
            {
                "tool": "planradius",
                "attribution": ATTRIBUTION,
                "address": resource.address,
                "type": resource.type,
                "actions": list(resource.actions),
                "dependencies": list(analysis.graph.dependencies_of(resource.address)),
                "dependents": list(analysis.graph.dependents_of(resource.address)),
                "blast_radius": list(blast),
                "escalation_paths": list(paths),
            }
        )
    else:
        text = render_explain(
            resource.address,
            {
                "type": resource.type,
                "actions": ", ".join(resource.actions),
                "dependencies": analysis.graph.dependencies_of(resource.address),
                "dependents": analysis.graph.dependents_of(resource.address),
            },
            blast,
            paths,
        )
    _write_text(None, text)
    return 0


def _run_rules(args: argparse.Namespace) -> int:
    if args.format == "json":
        _write_text(
            None,
            _json({"tool": "planradius", "attribution": ATTRIBUTION, "rules": list(RULE_CATALOG)}),
        )
    else:
        _write_text(None, render_rules())
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point with deterministic exit codes."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            return _run_analyze(args)
        if args.command == "baseline":
            return _run_baseline(args)
        if args.command == "explain":
            return _run_explain(args)
        return _run_rules(args)
    except (PlanError, BaselineError, ValueError, OSError) as exc:
        sys.stderr.write(f"planradius: error: {exc} — {ATTRIBUTION}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
