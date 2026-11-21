# planradius tests — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
# Attribution: Baysöz Labs <baysozlabs@proton.me>

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import make_plan, make_resource, run_cli, write_json

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


def test_version_and_help_advertise_attribution() -> None:
    version = run_cli("--version")
    assert version.returncode == 0
    assert ATTRIBUTION in version.stdout
    assert "planradius 1.0.0" in version.stdout
    for arguments in (("--help",), ("analyze", "--help"), ("rules", "--help")):
        result = run_cli(*arguments)
        assert result.returncode == 0
        assert ATTRIBUTION in result.stdout


def test_analyze_table_contains_findings_and_attribution(demo_plan_path: Path) -> None:
    result = run_cli("analyze", "--plan", str(demo_plan_path))
    assert result.returncode == 1
    assert ATTRIBUTION in result.stdout
    assert "PR-001" in result.stdout
    assert "PR-007" in result.stdout
    assert "fingerprint" in result.stdout


def test_analyze_json_and_sarif_formats(demo_plan_path: Path, tmp_path: Path) -> None:
    json_result = run_cli("analyze", "--plan", str(demo_plan_path), "--format", "json")
    assert json_result.returncode == 1
    payload = json.loads(json_result.stdout)
    assert payload["attribution"] == ATTRIBUTION
    assert payload["counts"]["critical"] >= 1
    assert all(item["fingerprint"] for item in payload["findings"])

    sarif_path = tmp_path / "findings.sarif"
    sarif_result = run_cli(
        "analyze",
        "--plan",
        str(demo_plan_path),
        "--format",
        "sarif",
        "--output",
        str(sarif_path),
    )
    assert sarif_result.returncode == 1
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["organization"] == ATTRIBUTION


def test_fail_on_thresholds_and_clean_plan(tmp_path: Path) -> None:
    clean = write_json(tmp_path / "clean.json", make_plan([make_resource("aws_vpc.main")]))
    assert run_cli("analyze", "--plan", str(clean)).returncode == 0
    demo = Path(__file__).resolve().parents[1] / "examples" / "plan.json"
    assert run_cli("analyze", "--plan", str(demo), "--fail-on", "none").returncode == 0
    assert run_cli("analyze", "--plan", str(demo), "--fail-on", "low").returncode == 1


def test_baseline_workflow_suppresses_gate(demo_plan_path: Path, tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    created = run_cli("baseline", "--plan", str(demo_plan_path), "--output", str(baseline_path))
    assert created.returncode == 0
    assert ATTRIBUTION in created.stdout
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert baseline["author"] == ATTRIBUTION
    assert baseline["fingerprints"]

    gated = run_cli(
        "analyze",
        "--plan",
        str(demo_plan_path),
        "--baseline",
        str(baseline_path),
        "--format",
        "json",
    )
    assert gated.returncode == 0
    payload = json.loads(gated.stdout)
    assert payload["findings"] == []
    assert len(payload["acknowledged_findings"]) == len(baseline["fingerprints"])
    assert payload["stale_baseline_entries"] == []


def test_explain_and_rules_commands(demo_plan_path: Path) -> None:
    explain = run_cli(
        "explain", "--plan", str(demo_plan_path), "--address", "aws_db_instance.primary"
    )
    assert explain.returncode == 0
    assert "blast radius" in explain.stdout
    assert ATTRIBUTION in explain.stdout
    json_explain = run_cli(
        "explain",
        "--plan",
        str(demo_plan_path),
        "--address",
        "aws_iam_role.deploy",
        "--format",
        "json",
    )
    assert json_explain.returncode == 0
    explanation = json.loads(json_explain.stdout)
    assert explanation["escalation_paths"]
    catalog = run_cli("rules", "--format", "json")
    assert catalog.returncode == 0
    assert len(json.loads(catalog.stdout)["rules"]) == 11


def test_stdin_and_missing_resource(tmp_path: Path) -> None:
    plan = write_json(tmp_path / "plan.json", make_plan([make_resource("a.b")]))
    stdin_result = run_cli("analyze", "--plan", "-", input_text=plan.read_text(encoding="utf-8"))
    assert stdin_result.returncode == 0
    missing = run_cli("explain", "--plan", str(plan), "--address", "does.not.exist")
    assert missing.returncode == 2
    assert ATTRIBUTION in missing.stderr


@pytest.mark.parametrize(
    "bad_input",
    [
        "{not json",
        json.dumps({"resource_changes": "bad"}),
        json.dumps(make_plan([make_resource("a.b", actions=["rm -rf /"])])),
        json.dumps(make_plan([make_resource("a.b"), make_resource("a.b")])),
    ],
)
def test_adversarial_inputs_fail_closed(bad_input: str, tmp_path: Path) -> None:
    path = write_json(tmp_path / "adversarial.json", bad_input)
    result = run_cli("analyze", "--plan", str(path))
    assert result.returncode == 2
    assert "error" in result.stderr
    assert ATTRIBUTION in result.stderr


def test_unicode_and_injection_payloads_are_never_executed(tmp_path: Path) -> None:
    hostile = "aws_instance.üñï-${jndi:ldap://example.invalid};$(id)"
    plan = write_json(
        tmp_path / "hostile.json",
        make_plan([make_resource(hostile, after={"payload": "<script>alert(1)</script>"})]),
    )
    result = run_cli("analyze", "--plan", str(plan), "--format", "json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["plan"]["resources"] == 1
    assert payload["findings"] == []


def test_invalid_blast_radius_limit_fails_closed(demo_plan_path: Path) -> None:
    result = run_cli("analyze", "--plan", str(demo_plan_path), "--max-blast-radius", "0")
    assert result.returncode == 2
    assert "at least 1" in result.stderr


def test_determinism_of_repeated_runs(demo_plan_path: Path) -> None:
    first = run_cli("analyze", "--plan", str(demo_plan_path), "--format", "json")
    second = run_cli("analyze", "--plan", str(demo_plan_path), "--format", "json")
    assert first.stdout == second.stdout
