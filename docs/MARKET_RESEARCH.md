<!-- planradius market research — Copyright 2026 Baysöz Labs <baysozlabs@proton.me> -->
<!-- Attribution: Baysöz Labs <baysozlabs@proton.me> -->

# Market Research — Why `planradius` Exists

**Author:** Baysöz Labs <baysozlabs@proton.me>
**Research date:** 2026-11-21
**Division:** devops-platform
**Verdict:** Build a deterministic, offline Terraform/OpenTofu **plan-time blast-radius
and IAM escalation reachability** gate. Project slug: `planradius`.

## 1. Method

1. Read `/home/runner/work/_temp/existing-repos.json` in full and classified every
   existing project by problem domain to eliminate redundancy.
2. Mined live GitHub trend signals with `gh search repos` (stars, descriptions,
   push recency) across `devops security supply-chain`, `topic:supply-chain`,
   `reproducible builds OCI`, and IaC plan analysis queries.
3. Attempted `gh search issues` for OIDC/workflow, SBOM/provenance, RBAC
   escalation, and plan-diff pain signals; the unauthenticated search API
   returned HTTP 403 rate-limit responses after the initial queries, so the
   issue signal was corroborated with current public engineering guidance via
   web research rather than fabricated. This limitation is recorded here rather
   than hidden.
4. Cross-checked the resulting gap against 2026 IaC/security publications and
   vendor documentation (see Sources).

## 2. Existing-portfolio deduplication

| Existing Baysöz Labs project | Domain | Overlap with proposed tool |
| --- | --- | --- |
| `atr-parity-gate` | AI-agent detection-rule conformance (ATR/Sigma) | None: different artifact type and semantics |
| `baysoz-actionlock` | GitHub Actions dependency lockfiles | None: CI action pins, not IaC plans |
| `baysoz-cardinalis` | Telemetry cardinality (HLL++, Prometheus/OTel) | None |
| `envpair`, `envlens`, `redos-lint`, `sec-audit-cli` | Config drift / regex DoS / CLI auditing | None |
| `baysoz-logmask` | Streaming PII/secret masking | None |
| `baysoz-polyglot-math-orchestrator` | Math optimization/routing | None |
| `baysoz-zero-trust-engine` | Crypto command shield, KVKK/GDPR redaction | Adjacent security brand, different function |
| `yazilimbaysoz-svg*` | Showcase infrastructure | Not a product |

**Conclusion:** no existing project touches infrastructure-as-code plan
semantics, dependency reachability, or IAM privilege graphs. `planradius` is
not a rename or variant of any prior deliverable.

## 3. Live GitHub trend evidence (`gh search repos`)

| Stars | Repository | What it proves |
| ---: | --- | --- |
| 1,579 | `guacsec/guac` | Security metadata **graphs** are a first-class, high-star approach; GUAC needs a graph database/service. |
| 1,457 | `openclarity/openclarity` | Cloud-native security orchestration is in demand, but platform-shaped and service-heavy. |
| 1,409 | `pypa/pip-audit` | Offline dependency auditing with deterministic CI output is a proven developer pattern. |
| 1,377 | `ossf/best-practices-badge` | Supply-chain posture/gating is mainstream. |
| 1,237 | `sigstore/rekor` | Transparency and provenance are foundational, not a plan-risk analyzer. |
| 1,129 | `cdxgen/cdxgen` | SBOM generation is commoditized; SBOM generation is **not** the gap. |
| 1,056 | `in-toto/in-toto` | Attestation semantics matter, but require signing infrastructure. |
| 725 | `theupdateframework/go-tuf` | Update integrity is mature; unrelated to IaC plan delta analysis. |
| 537 | `boostsecurityio/poutine` | Build-pipeline supply-chain scanning is an active 2024+ niche with real adoption. |

`gh search repos` for "reproducible builds OCI" and "terraform plan risk
analysis security stars:>100" returned no strong matches, which is itself a
market signal: there is no high-star, offline, plan-graph blast-radius tool.

## 4. Ecosystem pain points (2026)

Current practitioner guidance converges on four points:

- **Validation is not safety.** A structurally valid Terraform/OpenTofu plan
  can still widen IAM, publish a database, or replace a stateful resource.
- **The plan artifact is the right gate.** `terraform show -json` contains the
  resolved delta (`resource_changes[].change.actions`, `before`, `after`,
  `replace_paths`) that raw HCL linters cannot see through modules, `for_each`,
  and variables.
- **Graph fidelity beats string matching.** Vendor guidance explicitly rates
  graph-based scanning as higher fidelity and recommends plan-file scanning in
  CI before apply.
- **Blast radius is the missing number.** 2026 write-ups discuss blast radius
  mostly as an insurance question or a prompt for an LLM to rank by hand. That
  approach is nondeterministic, needs a model/services, and cannot produce a
  reproducible CI verdict.

Sources consulted:
- <https://techbytes.app/posts/iac-security-cheat-sheet-terraform-opentofu-2026>
- <https://scalr.com/learning-center/iac-security-for-terraform-and-opentofu>
- <https://devopsaitoolkit.com/blog/analyzing-terraform-plan-blast-radius-with-ai/>
- <https://stategraph.com/blog/terraform-blast-radius>
- <https://docs.aws.amazon.com/prescriptive-guidance/latest/terraform-aws-provider-best-practices/security.html>
- <https://safeguard.sh/resources/blog/how-snyk-iac-scans-a-terraform-plan-json-file-to-catch-drift-before-deployment>

## 5. Positioning

| Capability | HCL linters (Checkov/tfsec/Trivy) | Commercial plan scan | GUAC/rekor/in-toto | LLM plan reviewer | **planradius** |
| --- | --- | --- | --- | --- | --- |
| Resolved plan delta | partial | yes | no | yes | **yes** |
| Offline / zero services | yes | varies | no | no | **yes** |
| Dependency reachability | no | limited | provenance-only | heuristic | **deterministic BFS** |
| Cycle detection | no | limited | graph DB | no | **iterative Tarjan** |
| IAM escalation reachability | pattern-only | pattern-only | no | hallucination risk | **principal-indexed catalog** |
| Baseline + SARIF gate | varies | paid tiers | no | no | **included** |
| Reproducible verdict | yes | varies | yes | no | **yes** |

## 6. Why this stack

- **Python 3.13+**: typed standard library is sufficient; JSON parsing, graph
  algorithms, regex wildcard semantics, hashing, and argparse need no runtime
  packages. No heavy services, no local LLMs, no cloud SDKs.
- **uv**: reproducible isolated environments and one-command editable installs
  for both development and CI.
- **Deterministic outputs**: sorted node/edge iteration, SHA-256 finding
  fingerprints, no timestamps in reports or baselines. Identical input yields
  byte-identical output, which is a hard requirement for CI approvals.

## 7. Non-goals

Not an SBOM generator, not a drift detector, not a cloud posture manager, not
an HCL formatter, not a signing authority, and not an LLM wrapper. Those are
served by the high-star projects above; `planradius` deliberately composes with
them by consuming the plan JSON they already produce.

**Baysöz Labs <baysozlabs@proton.me>** — research complete, gap confirmed.
