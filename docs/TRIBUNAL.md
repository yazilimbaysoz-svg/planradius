<!-- planradius tribunal record — Copyright 2026 Baysöz Labs <baysozlabs@proton.me> -->
<!-- Attribution: Baysöz Labs <baysozlabs@proton.me> -->

# Supreme Grand Jury Tribunal — `planradius` 1.0.0

**Convened by:** Baysöz Labs <baysozlabs@proton.me>
**Date:** 2026-11-21
**Requirement:** unanimous PASS after all tests and security scans pass.

## Panel

| Juror | Mandate |
| --- | --- |
| Correctness | Real findings, deterministic output, correct graph and IAM semantics |
| Security | Hostile input containment, deny semantics, no guessed policy results |
| Operations | Exit codes, gate behavior, large-plan performance, live CLI utility |
| Attribution | Baysöz Labs attribution in every public file and every CLI/library surface |

## Procedure

The tribunal did not review source code in the abstract: it executed the built
CLI and library against real adversarial plans in an isolated temporary
workspace, including a 2,002-resource graph, explicit IAM deny statements,
malformed/oversized/deeply nested JSON, injection-shaped Unicode strings,
SARIF serialization, baseline suppression, and the public Python API.

## Live evidence

| Juror | Case | Verdict | Observed evidence |
| --- | --- | --- | --- |
| Correctness | Realistic plan rule coverage | PASS | `exit=1`, `counts={'critical': 4, 'high': 5, 'low': 0, 'medium': 0}`, rules PR-001…PR-007 |
| Correctness | SARIF shape + byte-identical determinism | PASS | identical repeated runs, 9 SARIF results matching 9 findings |
| Correctness | Cross-policy escalation + explicit deny | PASS | 1 escalation path without deny; 0 with matching `Deny` |
| Security | Hostile inputs fail closed | PASS | invalid JSON, duplicate address, invalid action, 70-level nesting, oversized string → all exit 2 |
| Security | Injection payloads remain inert data | PASS | JNDI/shell/script-shaped Unicode address accepted as data, 0 findings, no execution |
| Security | Unparseable policy reported, never guessed | PASS | PR-010 emitted; no fabricated grants |
| Operations | 2,000-node chain + cycle | PASS | 2,002 nodes analyzed in 0.79 s; PR-008 and PR-009 emitted without recursion failure |
| Operations | Baseline acknowledgment changes gate | PASS | 9 fingerprints stored; subsequent gated run exit 0 with 9 acknowledged findings |
| Operations | `explain` returns real graph/escalation data | PASS | 12 escalation paths and resolved dependencies for `aws_iam_role.deploy` |
| Attribution | All public files and CLI surfaces attributed | PASS | `--version`, `--help`, every public source/doc/config file; 0 unattributed files |
| Attribution | Public library API exports are live | PASS | `1.0.0 Baysöz Labs <baysozlabs@proton.me> 12 analyze` |

## Hallucination and stub check

- Every reported finding was produced by a named rule executing over parsed
  plan fields; no hardcoded finding text is emitted by the CLI.
- Every command (`analyze`, `baseline`, `explain`, `rules`) was executed live
  and returned real data; no `NotImplemented`, `TODO`, or placeholder output
  paths exist in the shipped package.
- Conditions are explicitly reported as unevaluated instead of being guessed.
- The escalation catalog is an explicit, documented inventory; unmatched
  actions produce no escalation finding.
- Gate state at tribunal time: 53/53 pytest tests passed; ruff 0 findings;
  semgrep 0 findings across 328 rules.

## Verdict

**Correctness: PASS. Security: PASS. Operations: PASS. Attribution: PASS.**

> **UNANIMOUS PASS — cleared for release.**
> Baysöz Labs <baysozlabs@proton.me>
