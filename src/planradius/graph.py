# planradius — Copyright 2026 Baysöz Labs <baysozlabs@proton.me>
"""Deterministic dependency and blast-radius graph for a validated plan.

Attribution: Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from collections import deque

from .model import Plan, PlanResource


def _base_address(address: str) -> str:
    """Strip instance/index suffixes from a resource address."""
    result = address
    while result.endswith("]"):
        opening = result.rfind("[")
        if opening < 0:
            break
        result = result[:opening]
    return result


def _resolve_reference(reference: str, known: frozenset[str]) -> str | None:
    candidate = reference.strip().strip('"').strip("'")
    if candidate.startswith("${") and candidate.endswith("}"):
        candidate = candidate[2:-1]
    parts = candidate.split(".")
    for length in range(len(parts), 1, -1):
        prefix = ".".join(parts[:length])
        if prefix in known:
            return prefix
        base = _base_address(prefix)
        if base in known:
            return base
    return None


class DependencyGraph:
    """Directed graph: edge A -> B means "A depends on B"."""

    def __init__(self, resources: tuple[PlanResource, ...]) -> None:
        known = frozenset(resource.address for resource in resources)
        bases = frozenset(_base_address(address) for address in known)
        self._nodes = tuple(sorted(known))
        self._node_set = frozenset(known)
        edges: dict[str, tuple[str, ...]] = {}
        for resource in resources:
            targets: set[str] = set()
            for token in [*resource.dependencies, *resource.expressions]:
                resolved = _resolve_reference(token, known | bases)
                if resolved in known and resolved != resource.address:
                    targets.add(resolved)
            edges[resource.address] = tuple(sorted(targets))
        self._edges = edges
        self._reverse: dict[str, tuple[str, ...]] = {
            node: tuple(sorted(source for source, targets in edges.items() if node in targets))
            for node in self._nodes
        }

    @property
    def nodes(self) -> tuple[str, ...]:
        return self._nodes

    def dependencies_of(self, address: str) -> tuple[str, ...]:
        """Resources that the given address directly depends on."""
        return tuple(sorted(self._edges.get(address, ())))

    def dependents_of(self, address: str) -> tuple[str, ...]:
        """Resources that directly depend on the given address."""
        return self._reverse.get(address, ())

    def blast_radius(self, address: str) -> frozenset[str]:
        """All resources transitively affected when the given address changes."""
        if address not in self._node_set:
            return frozenset()
        seen: set[str] = set()
        queue = deque([address])
        while queue:
            current = queue.popleft()
            for dependent in self._reverse.get(current, ()):
                if dependent not in seen:
                    seen.add(dependent)
                    queue.append(dependent)
        seen.discard(address)
        return frozenset(seen)

    def cycles(self) -> tuple[tuple[str, ...], ...]:
        """Return strongly connected components with more than one node (iterative)."""
        index = 0
        indices: dict[str, int] = {}
        low: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        found: list[tuple[str, ...]] = []
        for root in self._nodes:
            if root in indices:
                continue
            work: list[tuple[str, int]] = [(root, 0)]
            while work:
                node, position = work[-1]
                if position == 0:
                    indices[node] = index
                    low[node] = index
                    index += 1
                    stack.append(node)
                    on_stack.add(node)
                neighbours = self._edges.get(node, ())
                if position < len(neighbours):
                    work[-1] = (node, position + 1)
                    neighbour = neighbours[position]
                    if neighbour not in indices:
                        work.append((neighbour, 0))
                    elif neighbour in on_stack:
                        low[node] = min(low[node], indices[neighbour])
                    continue
                work.pop()
                if low[node] == indices[node]:
                    component: list[str] = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.append(member)
                        if member == node:
                            break
                    if len(component) > 1:
                        found.append(tuple(sorted(component)))
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
        return tuple(sorted(found))


def build_graph(plan: Plan) -> DependencyGraph:
    """Build the dependency graph for a validated plan."""
    return DependencyGraph(plan.resources)
