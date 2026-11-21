# planradius tests — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
# Attribution: Baysöz Labs <baysozlabs@proton.me>

from __future__ import annotations

import json

from planradius.analyzer import analyze, exceeds_threshold
from planradius.baseline import (
    ATTRIBUTION,
    BaselineError,
    apply_baseline,
    create_baseline,
    load_baseline,
)
from planradius.model import parse_plan
from planradius.rules import Finding, RULE_CATALOG
from planradius.sarif import build_sarif
from tests.conftest import make_plan, make_resource, policy_document

PROFILE = "Baysöz Labs <baysozlabs@proton.me>"


def rule_ids(findings: tuple[Finding, ...]) -> set[str]:
    return {finding.rule_id for finding in findings}


def test_all_rules_are_triggered_by_a_realistic_plan() -> None:
    wildcard = make_resource(
        "aws_iam_policy.wild",
        resource_type="aws_iam_policy",
        after={"policy": policy_document([{"Effect": "Allow", "Action": "*", "Resource": "*"}])},
    )
    trust = make_resource(
        "aws_iam_role.open",
        resource_type="aws_iam_role",
        after={
            "assume_role_policy": policy_document(
                [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Principal": {"AWS": "*"},
                    }
                ]
            )
        },
    )
    ingress = make_resource(
        "aws_security_group.ssh",
        resource_type="aws_security_group",
        after={"ingress": [{"from_port": 3389, "to_port": 3389, "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    database = make_resource(
        "aws_db_instance.main",
        resource_type="aws_db_instance",
        actions=["delete", "create"],
        before={"encrypted": True, "server_side_encryption_configuration": {"enabled": True}},
        after={"encrypted": False, "publicly_accessible": True},
    )
    cycle_a = make_resource("a.x", dependencies=["a.y"])
    cycle_b = make_resource("a.y", dependencies=["a.x"])
    broken = make_resource(
        "aws_iam_policy.broken",
        resource_type="aws_iam_policy",
        after={"policy": "{invalid"},
    )
    hub = make_resource("aws_vpc.hub", actions=["update"])
    fanout = [
        make_resource(f"aws_instance.fan{index}", dependencies=["aws_vpc.hub.id"])
        for index in range(11)
    ]
    plan = parse_plan(
        make_plan(
            [wildcard, trust, ingress, database, cycle_a, cycle_b, broken, hub, *fanout],
            errors=["unresolved variable in module.network"],
        )
    )
    findings = analyze(plan).findings
    assert rule_ids(findings) == {f"PR-{number:03d}" for number in range(1, 12)}
    assert all(finding.detail for finding in findings)
    assert PROFILE == ATTRIBUTION


def test_fingerprints_are_stable_and_unique_per_finding() -> None:
    finding = Finding(
        "PR-001",
        "Wildcard action grant",
        "critical",
        "aws_iam_policy.admin",
        "Action '*' granted on ['*']",
        "Narrow the policy.",
        ("https://example.invalid/rule",),
    )
    assert finding.fingerprint == Finding(**{**finding.__dict__}).fingerprint
    assert len(finding.fingerprint) == 16
    assert set(finding.as_dict()) >= {
        "fingerprint",
        "rule_id",
        "severity",
        "resource",
        "detail",
    }


def test_baseline_roundtrip_suppression_and_stale_entries() -> None:
    findings = (
        Finding("PR-001", "First", "critical", "a.b", "detail-1", "fix"),
        Finding("PR-002", "Second", "high", "c.d", "detail-2", "fix"),
    )
    baseline = create_baseline(findings)
    assert baseline.author == PROFILE
    restored = load_baseline(json.dumps(baseline.as_dict()))
    assert restored == baseline
    result = apply_baseline(findings, restored)
    assert result.active == ()
    assert result.acknowledged == findings
    assert result.stale == ()
    changed = (
        Finding("PR-001", "First", "critical", "a.b", "detail-1", "fix"),
        Finding("PR-002", "Second", "high", "c.d", "DIFFERENT", "fix"),
    )
    second = apply_baseline(changed, restored)
    assert second.active == (changed[1],)
    assert second.stale == (findings[1].fingerprint,)


def test_baseline_rejects_malformed_documents() -> None:
    for raw in (
        {},
        {"schema": 99, "tool": "planradius", "fingerprints": []},
        {"schema": 1, "tool": "other", "fingerprints": []},
        {"schema": 1, "tool": "planradius", "fingerprints": ["short"]},
    ):
        try:
            load_baseline(json.dumps(raw))
        except BaselineError:
            continue
        raise AssertionError(f"malformed baseline accepted: {raw}")


def test_sarif_is_well_formed_and_attributed() -> None:
    findings = (
        Finding("PR-001", "Wildcard", "critical", "a.b", "bad grant", "fix"),
        Finding("PR-009", "Cycle", "medium", "c.d", "cycle", "fix"),
    )
    document = build_sarif(findings, source="plan.json", acknowledged_count=3, stale_count=1)
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["PR-001", "PR-009"]
    assert [result["ruleId"] for result in run["results"]] == ["PR-001", "PR-009"]
    assert run["properties"]["attribution"] == PROFILE
    assert run["properties"]["acknowledged_findings"] == 3
    assert all(
        result["partialFingerprints"]["planradius/fingerprint"] == finding.fingerprint
        for result, finding in zip(run["results"], findings, strict=True)
    )
    assert json.loads(json.dumps(document)) == document


def test_severity_gate_thresholds() -> None:
    findings = (
        Finding("PR-001", "Critical", "critical", "a.b", "x", "y"),
        Finding("PR-009", "Medium", "medium", "c.d", "x", "y"),
    )
    assert exceeds_threshold(findings, "critical") is True
    assert exceeds_threshold(findings, "high") is True
    assert exceeds_threshold(findings, "medium") is True
    assert exceeds_threshold(findings, "low") is True
    assert exceeds_threshold(findings, "none") is False
    assert exceeds_threshold(findings[1:], "high") is False


def test_catalog_is_complete_and_attributed() -> None:
    identifiers = [rule["id"] for rule in RULE_CATALOG]
    assert identifiers == [f"PR-{number:03d}" for number in range(1, 12)]
    assert all(rule["description"] for rule in RULE_CATALOG)
