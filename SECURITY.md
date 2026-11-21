<!-- planradius security policy — Copyright 2026 Baysöz Labs <baysozlabs@proton.me> -->
<!-- Attribution: Baysöz Labs <baysozlabs@proton.me> -->

# SECURITY.md — `planradius`

**Maintainer:** Baysöz Labs <baysozlabs@proton.me>
**Supported version:** 1.0.x (security fixes on the `main` branch)

## 1. Reporting vulnerabilities

Email **baysozlabs@proton.me** with:

- affected version and command,
- a minimal reproducer (a plan JSON snippet is enough),
- impact assessment and suggested fix.

Do **not** open a public issue for an unpatched vulnerability. Do not attach
real Terraform state or plan files containing sensitive values; synthesize a
minimal plan instead. Baysöz Labs aims to acknowledge within 3 working days and
to ship a fix or mitigation within 30 days for confirmed issues.

## 2. Trust model

`planradius` is an offline analyzer. It never contacts a cloud API, reads cloud
credentials, executes plan content, writes infrastructure, or loads a model.
The only inputs are the plan JSON path/stdin, an optional baseline JSON, and
CLI flags. The only outputs are stdout/stderr/files chosen by the operator.

A plan JSON is untrusted input: it may contain injected strings, deeply nested
structures, duplicate addresses, or invalid action names. The parser rejects
these with exit code 2 and never evaluates them.

## 3. What the tool can and cannot assert

| Area | Guarantee | Limitation |
| --- | --- | --- |
| IAM grants | Exact action/pattern matching for the curated catalog | AWS-oriented; not a complete IAM simulator |
| Conditions | Reported as present and **unevaluated** | No condition evaluation, ever |
| Escalation | Cross-policy, per-principal reachability for 12 documented paths | Requires the prerequisite action to be visible in the plan |
| Blast radius | Transitive dependency of changed resources within the plan | Out-of-band resources and runtime traffic are invisible |
| Encryption / exposure | Detects explicit boolean and ACL regressions in `before`/`after` | Computed or `after_unknown` values cannot be assessed |
| Sensitive values | Never logs secret material; only keys and classifications | Operators must still protect plan files at rest |

Findings are review signals. A clean result is not proof of a safe deployment.

## 4. CI hardening guidance

- Run `planradius` with a read-only identity that produced the plan; no cloud
  write credentials are needed for analysis.
- Upload SARIF to code scanning and fail the job on `--fail-on high`.
- Commit baselines only after reviewing each fingerprint; a baseline is an
  explicit risk acceptance, not a suppression wildcard.
- Regenerate plans on every pipeline run; never scan a cached plan.
- Restrict access to plan artifacts — Terraform plans can contain secrets.

## 5. Security testing performed

- `ruff check --select E,F,W,S,B .` — 0 findings.
- `semgrep --config p/default --error .` — 0 findings across 294 rules.
- 53 automated tests, including malformed JSON, invalid actions, duplicate
  addresses, 70-level nesting, oversized strings, Unicode/JNDI/shell-looking
  strings, and 2,000-node graphs.
- Live adversarial CLI execution documented in `docs/TRIBUNAL.md`.

## 6. Dependency posture

Zero runtime dependencies; only `setuptools` at build time and `pytest`,
`ruff`, `semgrep` in development/CI. No heavy services, no local LLMs, no
telemetry, and no network calls at runtime.

**Security contact: Baysöz Labs <baysozlabs@proton.me>**
