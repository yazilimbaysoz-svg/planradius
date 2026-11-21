# planradius tests — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
# Attribution: Baysöz Labs <baysozlabs@proton.me>

from __future__ import annotations

from planradius.graph import build_graph
from planradius.model import parse_plan
from tests.conftest import make_plan, make_resource


def test_transitive_blast_radius() -> None:
    plan = parse_plan(
        make_plan(
            [
                make_resource("aws_vpc.main", actions=["update"]),
                make_resource("aws_subnet.a", dependencies=["aws_vpc.main.id"]),
                make_resource(
                    "aws_instance.web",
                    dependencies=["aws_subnet.a.id"],
                    after={"ref": "${aws_vpc.main.id}"},
                ),
                make_resource("aws_instance.isolated"),
            ]
        )
    )
    graph = build_graph(plan)
    assert graph.blast_radius("aws_vpc.main") == frozenset({"aws_subnet.a", "aws_instance.web"})
    assert graph.blast_radius("aws_subnet.a") == frozenset({"aws_instance.web"})
    assert graph.blast_radius("aws_instance.web") == frozenset()
    assert graph.blast_radius("does.not.exist") == frozenset()
    assert graph.dependents_of("aws_vpc.main") == ("aws_instance.web", "aws_subnet.a")
    assert graph.dependencies_of("aws_instance.web") == ("aws_subnet.a", "aws_vpc.main")


def test_indexed_addresses_resolve_to_base() -> None:
    plan = parse_plan(
        make_plan(
            [
                make_resource('aws_instance.web["a"]'),
                make_resource(
                    "aws_lb.app",
                    dependencies=['aws_instance.web["a"].id', "aws_instance.web[0].id"],
                ),
            ]
        )
    )
    graph = build_graph(plan)
    assert graph.dependencies_of("aws_lb.app") == ('aws_instance.web["a"]',)


def test_cycle_detection_uses_strongly_connected_components() -> None:
    plan = parse_plan(
        make_plan(
            [
                make_resource("a.one", dependencies=["a.two"]),
                make_resource("a.two", dependencies=["a.one"]),
                make_resource("a.three", dependencies=["a.three"]),
                make_resource("a.four", dependencies=["a.one"]),
            ]
        )
    )
    assert build_graph(plan).cycles() == (("a.one", "a.two"),)


def test_large_chain_does_not_recurse() -> None:
    resources = [
        make_resource(f"aws_instance.node{index}", dependencies=[f"aws_instance.node{index - 1}"])
        for index in range(2000)
    ]
    plan = parse_plan(make_plan(resources))
    graph = build_graph(plan)
    assert len(graph.blast_radius("aws_instance.node0")) == 1999
    assert graph.cycles() == ()
