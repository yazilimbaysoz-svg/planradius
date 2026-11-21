# planradius tests — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
# Attribution: Baysöz Labs <baysozlabs@proton.me>

from __future__ import annotations

import json

import pytest

from planradius.model import PlanError, parse_plan, parse_plan_text
from tests.conftest import make_plan, make_resource


def test_parse_plan_normalizes_changes() -> None:
    plan = parse_plan(
        make_plan(
            [
                make_resource(
                    "aws_s3_bucket.logs",
                    resource_type="aws_s3_bucket",
                    actions=["create"],
                    after={"acl": "private"},
                )
            ]
        )
    )
    assert plan.terraform_version == "1.10.5"
    assert len(plan.resources) == 1
    resource = plan.resources[0]
    assert resource.address == "aws_s3_bucket.logs"
    assert resource.actions == ("create",)
    assert resource.changed is True
    assert resource.replaced is False
    assert resource.stateful is True
    assert plan.changed_resources == plan.resources


def test_replacement_and_noop_flags() -> None:
    plan = parse_plan(
        make_plan(
            [
                make_resource(
                    "aws_db_instance.x",
                    resource_type="aws_db_instance",
                    actions=["delete", "create"],
                ),
                make_resource("aws_instance.y", actions=["no-op"]),
            ]
        )
    )
    assert plan.resources[0].replaced is True
    assert plan.resources[1].changed is False
    assert len(plan.changed_resources) == 1
    assert plan.resources[0].stateful is True


def test_reference_tokens_are_collected() -> None:
    plan = parse_plan(
        make_plan(
            [
                make_resource(
                    "aws_instance.app",
                    after={"endpoint": "${aws_db_instance.db.endpoint}"},
                )
            ]
        )
    )
    assert "aws_db_instance.db.endpoint" in plan.resources[0].expressions


def test_parse_plan_text_accepts_attribution_metadata() -> None:
    text = json.dumps(
        {
            "format_version": "1.2",
            "attribution": "Baysöz Labs <baysozlabs@proton.me>",
            "resource_changes": [],
        }
    )
    assert parse_plan_text(text).format_version == "1.2"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (None, "root must be a JSON object"),
        ({"resource_changes": {}}, "resource_changes must be an array"),
        (make_plan([make_resource("a.b", actions=["explode"])]), "unsupported change action"),
        (make_plan([make_resource("")]), "non-empty string"),
        (make_plan([make_resource("a.b"), make_resource("a.b")]), "duplicate resource address"),
        (
            make_plan([{"address": "a.b", "change": {"actions": ["create"], "before": []}}]),
            "change.before must be an object",
        ),
        (
            make_plan([{"address": "a.b", "change": {"actions": []}}]),
            "must not be empty",
        ),
    ],
)
def test_invalid_plans_are_rejected(document: object, message: str) -> None:
    with pytest.raises(PlanError, match=message):
        parse_plan(document)


def test_invalid_json_is_rejected() -> None:
    with pytest.raises(PlanError, match="invalid JSON document"):
        parse_plan_text("{not json")


def test_deeply_nested_plan_is_rejected() -> None:
    value: object = "leaf"
    for _ in range(70):
        value = {"nested": value}
    document = make_plan([make_resource("a.b", after={"payload": value})])
    with pytest.raises(PlanError, match="nesting exceeds"):
        parse_plan(document)


def test_oversized_string_is_rejected() -> None:
    document = make_plan([make_resource("a.b", after={"payload": "x" * 1_000_001})])
    with pytest.raises(PlanError, match="string longer"):
        parse_plan(document)


def test_hostile_unicode_and_injection_strings_are_data_only() -> None:
    address = 'aws_instance.ünïcøde-"><script>alert(1)</script>'
    plan = parse_plan(make_plan([make_resource(address, after={"payload": "$(rm -rf /)"})]))
    assert plan.resources[0].address == address
    assert plan.resources[0].after["payload"] == "$(rm -rf /)"


def test_non_string_object_keys_are_rejected() -> None:
    document = make_plan([make_resource("a.b", after={"payload": {1: "x"}})])
    with pytest.raises(PlanError, match="keys must be strings"):
        parse_plan(document)
