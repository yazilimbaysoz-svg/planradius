# planradius tests — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
# Attribution: Baysöz Labs <baysozlabs@proton.me>

from __future__ import annotations

import pytest

from planradius.iam import (
    ESCALATION_PATHS,
    PermissionIndex,
    action_matches,
    build_permission_index,
    parse_policy,
)
from planradius.model import parse_plan
from tests.conftest import make_plan, make_resource, policy_document


def as_plan_resource(document: dict[str, object]) -> object:
    return parse_plan(make_plan([document])).resources[0]


def policy_resource(
    address: str,
    document: str | dict[str, object],
    *,
    resource_type: str = "aws_iam_policy",
) -> dict[str, object]:
    return make_resource(address, resource_type=resource_type, after={"policy": document})


def test_action_matching_supports_only_iam_wildcards() -> None:
    assert action_matches("iam:*", "iam:PassRole")
    assert action_matches("s3:Get*", "s3:GetObject")
    assert action_matches("iam:Pass?ole", "iam:PassRole")
    assert not action_matches("s3:GetObject", "s3:PutObject")
    assert not action_matches("s3:*", "ec2:RunInstances")
    assert not action_matches("s3:[GR]et*", "s3:GetObject")


def test_parse_policy_extracts_statements_and_principals() -> None:
    document = policy_document(
        [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRole"],
                "Resource": "*",
                "Principal": {"AWS": ["arn:aws:iam::111122223333:role/ci"]},
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
            }
        ]
    )
    policy = parse_policy(
        as_plan_resource(
            make_resource(
                "aws_iam_role.ci",
                resource_type="aws_iam_role",
                after={"assume_role_policy": document},
            )
        )
    )
    assert policy.error is None
    assert len(policy.statements) == 1
    statement = policy.statements[0]
    assert statement.allows
    assert statement.principals == ("AWS:arn:aws:iam::111122223333:role/ci",)
    assert statement.conditions == ("StringEquals:aws:PrincipalOrgID",)


def test_parse_policy_reports_invalid_documents_without_guessing() -> None:
    policy = parse_policy(as_plan_resource(policy_resource("aws_iam_policy.broken", "{not json")))
    assert policy.error is not None
    assert "not valid JSON" in policy.error
    assert policy.statements == ()


def test_unsupported_effect_is_reported() -> None:
    policy = parse_policy(
        as_plan_resource(
            policy_resource(
                "aws_iam_policy.bad",
                policy_document([{"Effect": "Maybe", "Action": "*", "Resource": "*"}]),
            )
        )
    )
    assert policy.error is not None
    assert "unsupported Effect" in policy.error


def test_lambda_permission_is_normalized_as_grant() -> None:
    policy = parse_policy(
        as_plan_resource(
            make_resource(
                "aws_lambda_permission.public",
                resource_type="aws_lambda_permission",
                after={
                    "action": "lambda:InvokeFunction",
                    "principal": "*",
                    "function_name": "my-function",
                },
            )
        )
    )
    assert policy.statements[0].principals == ("*",)
    assert policy.statements[0].actions == ("lambda:invokefunction",)


def test_explicit_deny_suppresses_matched_path() -> None:
    grants = policy_resource(
        "aws_iam_policy.grant",
        policy_document(
            [
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole", "lambda:CreateFunction"],
                    "Resource": "*",
                }
            ]
        ),
    )
    denies = policy_resource(
        "aws_iam_policy.deny",
        policy_document([{"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}]),
    )
    plan = parse_plan(make_plan([grants, denies]))
    index, _ = build_permission_index(plan)
    identifiers = {match.path.identifier for match in index.matched_paths()}
    assert identifiers == set()


def test_cross_policy_escalation_aggregation() -> None:
    pass_role = policy_resource(
        "aws_iam_policy.pass",
        policy_document(
            [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::111122223333:role/task",
                }
            ]
        ),
    )
    create_function = policy_resource(
        "aws_iam_policy.create",
        policy_document(
            [
                {
                    "Effect": "Allow",
                    "Action": "lambda:CreateFunction",
                    "Resource": "arn:aws:lambda:eu-west-1:111122223333:function:*",
                }
            ]
        ),
    )
    plan = parse_plan(make_plan([pass_role, create_function]))
    index, _ = build_permission_index(plan)
    assert "IAM-ESC-001" in {match.path.identifier for match in index.matched_paths()}


def test_not_action_expands_to_escalation_catalog() -> None:
    document = policy_document(
        [
            {
                "Effect": "Allow",
                "NotAction": [
                    action for path in ESCALATION_PATHS for action in path.required_actions
                ],
                "Resource": "*",
            }
        ]
    )
    index, _ = build_permission_index(parse_plan(make_plan([policy_resource("a.b", document)])))
    assert index.matched_paths() == ()


@pytest.mark.parametrize(
    "principal_document",
    [
        {"AWS": "*"},
        "*",
        {"Service": "lambda.amazonaws.com"},
    ],
)
def test_principal_shapes_are_normalized(principal_document: object) -> None:
    document = policy_document(
        [{"Effect": "Allow", "Action": "*", "Principal": principal_document}]
    )
    policy = parse_policy(as_plan_resource(policy_resource("a.b", document)))
    assert policy.statements[0].principals
    assert all(isinstance(item, str) for item in policy.statements[0].principals)


def test_empty_index_has_no_paths() -> None:
    assert PermissionIndex(()).matched_paths() == ()
