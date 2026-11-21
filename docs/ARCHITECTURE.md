<!-- planradius architecture — Copyright 2026 Baysöz Labs <baysozlabs@proton.me> -->
<!-- Attribution: Baysöz Labs <baysozlabs@proton.me> -->

# Architecture — `planradius`

**Baysöz Labs <baysozlabs@proton.me>** — Version 1.0.0

## 1. System shape

```
                         ┌──────────────────────────┐
  terraform/tofu plan    │  model.py                │
  --json ──────────────> │  strict Plan validator   │
                         └────────────┬─────────────┘
                                      │ Plan (frozen dataclasses)
                    ┌─────────────────┼──────────────────┐
                    v                 v                  v
            graph.py           iam.py              rules.py
       dependency SCCs    policy normalization  11 deterministic rules
       reverse BFS        principal index       severity + fingerprints
                    └─────────────────┼──────────────────┘
                                      v
                              analyzer.py
                         (findings, counts, gate)
                                      │
                    ┌─────────────────┼──────────────────┐
                    v                 v                  v
              render.py          sarif.py           baseline.py
              table stdout       CI annotations      suppression/stale
```

`cli.py` is the only I/O boundary: it reads a plan file or stdin, invokes the
pure analysis core, and serializes results. `explain`, `rules`, `baseline`, and
`analyze` are four complete commands over the same core — no stubs.

## 2. Modules and contracts

| Module | Responsibility | Public surface |
| --- | --- | --- |
| `model.py` | Parse `resource_changes`, bound input size/depth, normalize actions, collect expression references | `parse_plan`, `parse_plan_text`, `Plan`, `PlanResource`, `PlanError` |
| `graph.py` | Build directed graph (A → B means A depends on B), compute reverse reachability and SCCs | `build_graph`, `DependencyGraph.blast_radius`, `dependencies_of`, `dependents_of`, `cycles` |
| `iam.py` | Decode JSON/string policy documents, normalize principals, index grants/denies per principal, match a curated escalation catalog | `build_permission_index`, `PermissionIndex.matched_paths`, `action_matches`, `parse_policy` |
| `rules.py` | Eleven rules producing attributable, hashed findings | `analyze` uses `sort_findings`, `Finding`, `RULE_CATALOG` |
| `baseline.py` | Create/validate fingerprint baselines; partition active/acknowledged/stale | `create_baseline`, `load_baseline`, `apply_baseline` |
| `sarif.py` | SARIF 2.1.0 with rule descriptors, logical resource locations, fingerprints | `build_sarif` |
| `render.py` | Deterministic, color-free terminal output | `render_report`, `render_explain`, `render_rules` |
| `analyzer.py` | Orchestration and `--fail-on` severity gate | `analyze`, `Analysis`, `exceeds_threshold` |
| `cli.py` | argparse CLI, exit codes, error handling | `main`, `build_parser` |

## 3. Algorithms

### 3.1 Strict parsing and hostile-input containment

- Root must be an object; `resource_changes` must be an array of objects.
- Maximum 200,000 resources, maximum nesting depth 64, maximum string length
  1,000,000 characters. Violations raise `PlanError` (exit code 2).
- Duplicate addresses, non-string keys, invalid action names, and non-object
  `before`/`after` are rejected. No evaluation, shell execution, import, or
  template rendering occurs on plan content.
- Reference tokens are extracted via a regular expression and treated purely
  as strings. `${...}`, JNDI-looking payloads, and script tags cannot execute.

### 3.2 Dependency graph and blast radius

- Known addresses (including indexed instances such as `aws_instance.web[0]`)
  form the node set. Dependencies come from `dependencies`, `configuration.depends_on`,
  and expression tokens in `before`/`after`.
- Tokens are resolved against the longest matching known prefix, falling back
  to the base address. Edges to non-existent nodes are discarded.
- `blast_radius(address)` is a reverse BFS over the dependency graph: every
  node that transitively depends on the changed resource. Self-loops are
  removed from the result.
- `cycles()` is an **iterative** Tarjan SCC implementation, so a 2,000-node
  chain does not hit Python's recursion limit.

### 3.3 IAM reachability

- Policy documents are read from a fixed inventory of policy-bearing resource
  types (`aws_iam_policy`, `aws_iam_role` trust policies, inline policies, S3,
  KMS, SQS, SNS, ECR, VPC endpoint policies, `aws_lambda_permission`).
- Statements normalize `Effect`, `Action`/`NotAction`, `Resource`, `Principal`,
  and condition keys. Invalid JSON becomes an explicit PR-010 finding rather
  than a guessed grant.
- `action_matches` implements IAM `*` / `?` semantics only (character classes
  are escaped, not interpreted) to avoid over-matching.
- Grants are aggregated **per principal across all policies in the plan**; this
  is what enables cross-resource escalation discovery (e.g. `iam:PassRole` in
  one policy plus `lambda:CreateFunction` in another).
- An explicit `Deny` matching a required action suppresses that path.
  Conditions are recorded but never simulated; findings state "not evaluated".
- The catalog contains 12 documented prerequisite sets (`IAM-ESC-001` …
  `IAM-ESC-012`). Findings are grouped by principal to keep CI output readable
  while listing every reachable path identifier.

### 3.4 Determinism

- All graph traversals iterate sorted node/edge sequences.
- Findings sort by severity rank, rule ID, resource, then fingerprint.
- Fingerprints are the first 16 hex characters of SHA-256 over canonical JSON
  of `(rule_id, title, resource, detail)`.
- Baselines and reports contain no timestamps, environment values, or random
  data. Repeated CLI runs are byte-identical (covered by tests).

## 4. Rule catalog

| Rule | Trigger | Severity |
| --- | --- | --- |
| PR-001 | Wildcard IAM action grant | critical / high |
| PR-002 | Wildcard principal in role trust policy | critical |
| PR-003 | Reachable documented privilege-escalation path | critical / high |
| PR-004 | Public ingress on management or all ports | high |
| PR-005 | Public data resource or disabled S3 guardrails | high |
| PR-006 | Encryption setting/key removed | high |
| PR-007 | Stateful resource replacement | high |
| PR-008 | Downstream blast radius over threshold | high / medium |
| PR-009 | Multi-node dependency cycle | medium |
| PR-010 | Unparseable policy document | medium |
| PR-011 | Plan diagnostics errors | high |

## 5. Interfaces and exit codes

- `analyze --plan FILE [--format table|json|sarif] [--fail-on LEVEL]
  [--baseline FILE] [--output FILE] [--max-blast-radius N]`
- `baseline --plan FILE --output FILE`
- `explain --plan FILE --address ADDRESS [--format table|json]`
- `rules [--format table|json]`
- `--version` and `--help` always include **Baysöz Labs <baysozlabs@proton.me>**.

Exit codes: `0` = no active finding at/above threshold, `1` = gate failed,
`2` = invalid input or usage. SARIF results contain only active findings;
acknowledged and stale counts live in run properties.

## 6. Performance and limits

Parsing is O(n) in plan size; graph construction is O(n × e) over extracted
references; reverse BFS is O(v + e); Tarjan is O(v + e). Memory is O(n + e).
Input caps prevent denial-of-service from malformed artifacts.

Known scope limits (documented, not hidden): conditions are not evaluated;
unknown values from `after_unknown` cannot be assessed; out-of-band resources
absent from the plan are invisible; the escalation catalog is AWS-oriented and
explicit rather than an exhaustive IAM simulator. See `SECURITY.md`.

## 7. Verification strategy

53 pytest tests cover model validation, graph reachability/cycles, IAM
wildcard/deny/aggregation semantics, all 11 rules, baseline round-trips, SARIF
shape, CLI formats/exit codes, determinism, and adversarial payloads. Gates:
`uv run pytest -q`, `ruff check --select E,F,W,S,B .`,
`semgrep --config p/default --error .`.

**Architecture owner: Baysöz Labs <baysozlabs@proton.me>**
