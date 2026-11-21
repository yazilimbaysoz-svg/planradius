<!-- planradius changelog — Copyright 2026 Baysöz Labs <baysozlabs@proton.me> -->
<!-- Attribution: Baysöz Labs <baysozlabs@proton.me> -->

# CHANGELOG — `planradius`

All notable changes are documented here. Maintained by
**Baysöz Labs <baysozlabs@proton.me>**. This project adheres to semantic
versioning.

## [1.0.0] — 2026-11-21

### Added

- Strict, bounded Terraform/OpenTofu JSON plan parser with hostile-input
  rejection and attribution metadata support.
- Deterministic dependency graph: indexed-address resolution, transitive blast
  radius via reverse BFS, and iterative Tarjan cycle detection.
- IAM policy normalization, IAM `*` / `?` action matching, per-principal grant
  aggregation across policies, explicit deny suppression, and a 12-path
  privilege-escalation catalog.
- Eleven deterministic rules (PR-001 … PR-011) with SHA-256 fingerprints.
- Four complete CLI commands: `analyze`, `baseline`, `explain`, `rules`.
- Table, JSON, and SARIF 2.1.0 output; fingerprint baselines with stale-entry
  detection; `--fail-on` severity gating and deterministic exit codes.
- 53 pytest tests covering parsing, graphs, IAM semantics, rules, baselines,
  SARIF, CLI formats, determinism, and adversarial payloads.
- Enterprise documentation, MIT license, CI workflow, and Baysöz Labs
  attribution across every public file and CLI version/help output.

### Quality

- `pytest`: 53 passed.
- `ruff check --select E,F,W,S,B .`: 0 findings.
- `semgrep --config p/default --error .`: 0 findings.
- Supreme Grand Jury Tribunal: unanimous PASS (see `docs/TRIBUNAL.md`).

**Release owner: Baysöz Labs <baysozlabs@proton.me>**
