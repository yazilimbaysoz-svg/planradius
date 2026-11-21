# planradius tests — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
# Attribution: Baysöz Labs <baysozlabs@proton.me>

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


def make_resource(
    address: str,
    *,
    resource_type: str = "aws_instance",
    actions: list[str] | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    dependencies: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "address": address,
        "mode": "managed",
        "type": resource_type,
        "name": address.split(".")[-1],
        "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
        "dependencies": dependencies or [],
        "change": {
            "actions": actions or ["update"],
            "before": before if before is not None else {},
            "after": after if after is not None else {},
        },
    }


def make_plan(
    resources: list[dict[str, Any]] | None = None,
    *,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "format_version": "1.2",
        "terraform_version": "1.10.5",
        "resource_changes": resources or [],
    }
    if errors:
        document["diagnostics_errors"] = errors
    return document


def policy_document(statements: list[dict[str, Any]]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def run_cli(*arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "planradius", *arguments],
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )


def write_json(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.fixture
def demo_plan_path() -> Path:
    root = Path(__file__).resolve().parents[1]
    return root / "examples" / "plan.json"
