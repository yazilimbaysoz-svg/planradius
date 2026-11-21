<!-- planradius delivery plan — Copyright 2026 Baysöz Labs <baysozlabs@proton.me> -->
<!-- Attribution: Baysöz Labs <baysozlabs@proton.me> -->

# PLAN — `planradius` 1.0.0

**Owner:** Baysöz Labs <baysozlabs@proton.me>
**Division:** devops-platform
**Status:** shipped (all phases complete)

## Phase 0 — Selection (complete)

- [x] Audited `existing-repos.json`; confirmed no IaC-plan/graph product overlap.
- [x] Mined live `gh search repos` trend data; analyzed high-star supply-chain
      and graph-security ecosystem.
- [x] Attempted `gh search issues`; recorded API rate-limit and corroborated
      pain points with public 2026 guidance.
- [x] Selected a non-trivial, production-grade problem: deterministic plan-time
      blast-radius and IAM escalation analysis.

## Phase 1 — Core engine (complete)

- [x] Strict plan parser with input bounds and hostile-input containment.
- [x] Dependency graph with indexed-address resolution, reverse reachability,
      and iterative SCC cycle detection.
- [x] IAM policy normalization, wildcard semantics, per-principal aggregation,
      explicit deny suppression, and a 12-path escalation catalog.
- [x] Eleven rules covering privilege, network, data, encryption, replacement,
      blast radius, cycles, parse errors, and plan errors.

## Phase 2 — Enterprise surface (complete)

- [x] CLI: `analyze`, `baseline`, `explain`, `rules`; table/JSON/SARIF.
- [x] Deterministic fingerprint baselines with stale-entry detection.
- [x] SARIF 2.1.0 for GitHub code-scanning integration.
- [x] Docs: market research, architecture, security, changelog, README, plan.
- [x] MIT license, pyproject metadata, `.gitignore`, CI workflow.
- [x] Baysöz Labs attribution in every public file and in CLI version/help.

## Phase 3 — Quality gates (complete)

Command sequence executed from the repository root:

```bash
uv venv && uv pip install -e . && uv pip install pytest && \
uv run pytest -q && ruff check --select E,F,W,S,B . && \
semgrep --config p/default --error .
```

Result: **53 tests passed; ruff 0 findings; semgrep 0 findings (294 rules).**

## Phase 4 — Supreme Grand Jury Tribunal (complete)

See `docs/TRIBUNAL.md`: live CLI execution against adversarial plans, four
jurors (Correctness, Security, Operations, Attribution), unanimous **PASS**.

## Phase 5 — Release (complete)

- [x] Public repository `yazilimbaysoz-svg/planradius` with description/topics.
- [x] Showcase result JSON written to the designated workspace path only.

## Roadmap beyond 1.0 (not in this release)

- Optional GCP/Azure principal binding catalogs.
- Plan-to-plan diff mode for approvals (`--against baseline-plan.json`).
- SARIF suppression annotations generated from acknowledged fingerprints.

**Plan owner: Baysöz Labs <baysozlabs@proton.me>**
