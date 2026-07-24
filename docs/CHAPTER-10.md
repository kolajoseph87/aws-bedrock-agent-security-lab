# Chapter 10 — Agent Red Teaming and Security Evaluations

## Goal

Chapter 10 proves that Northstar's Secure Coding Agent continues to enforce the controls from Chapters 0–9 when it receives adversarial input. It creates a repeatable security regression gate; it does not authorize attacks against production.

The central rule is:

> Test the agent like an attacker, but give the evaluator no production data, no production authority, and no path to turn a simulated exploit into a real side effect.

## What you are building

The chapter separates three responsibilities:

1. An independently approved, immutable attack corpus says what will be tested and what safe outcome is expected.
2. A disposable, isolated harness executes every approved case with synthetic data and intercepts all tool side effects.
3. An independent pipeline verifies the signed result bundle and blocks promotion when a critical case fails or security regresses.

The agent and evaluator cannot change expected answers, skip difficult cases, approve their own results, write to repositories, deploy, or use production identities.

## Threat coverage

The minimum corpus covers:

- Direct prompt injection
- Indirect injection from retrieved content
- RAG poisoning and provenance failure
- Tool-name, argument, resource, and approval manipulation
- Data exfiltration and output leakage
- Excessive agency and unauthorized side effects
- Cross-tenant and cross-repository access
- Signed work-order replay
- Runtime policy bypass
- Resource exhaustion
- Evaluator, oracle, corpus, or result tampering

Every fixture is harmless and synthetic. The expected outcome is deterministic denial with zero prohibited side effects.

## Do not average away critical failures

An aggregate pass rate can hide the most important result. A system that blocks 99 attacks but leaks one patient record is not 99% secure. Therefore, any critical leakage, cross-scope access, unauthorized action, replay, policy bypass, or evaluation-integrity failure blocks promotion regardless of the average score.

Probabilistic model behavior requires repeated runs and per-class thresholds. Flaky cases may be quarantined only through an independently approved, expiring exception. A model-based judge may assist scoring, but it cannot be the sole authority for identity, authorization, leakage, or side-effect decisions.

## Evaluation integrity

Bind every result to:

- Source commit
- Model identifier and version
- Runtime policy and Guardrail versions
- Tool catalog and worker image digest
- Attack corpus version and SHA-256 digest
- Evaluator image and harness digest
- Attested runner identity
- Unique run ID and anti-replay nonce

Store only sanitized case IDs, decisions, reason codes, hashes, metrics, and timestamps. Do not copy raw prompts, completions, retrieved chunks, source code, patches, credentials, PHI, or PII into evidence.

## AWS boundary

Amazon Bedrock model evaluation and Guardrail testing can support the program, but they do not replace deterministic authorization tests, side-effect interception, cross-tenant isolation checks, or independent promotion gates. Availability, Region support, quotas, IAM access, service lifecycle, and pricing must be verified from current AWS sources before live use.

The CloudFormation file is a guarded skeleton. `DeployChapter10SecurityEvaluations` defaults to `false`. It creates no resources unless deliberately enabled and reviewed. When enabled, it requires an evaluator image pinned by SHA-256 digest, approved VPC subnets and security groups, and a KMS key. It limits concurrency, explicitly denies dangerous permissions, and writes results to a retained S3 Object Lock bucket. Live testing must still prove that the selected subnets have only approved private endpoints and no unintended egress.

## Run the offline lab

```bash
python3 scripts/validate_security_evaluations.py \
  --manifest security-evaluations/security-evaluations.aws.json \
  --evidence evidence/lab-10-validation.json

python3 -m unittest discover -s tests -v
python3 -m compileall scripts tests python
```

Expected Chapter 10 validator result:

```text
17 Chapter 10 security-evaluation checks passed
```

Chapter 10 contributes 75 automated tests. When it is applied after the
corrected 397-test Chapters 0–9 baseline, the cumulative suite contains 472
tests.

Offline execution makes no AWS or Bedrock calls, invokes no model, writes no repository, deploys nothing, and uses no real patient or production data.

## Required live evidence before production

- VPC and egress-denial test from the evaluator
- Proof that production endpoints, roles, secrets, and data are unreachable
- Tool-side-effect interception test
- Corpus, runner, and result signature/attestation verification
- Source/model/policy/tool/corpus version binding
- Replay and substitution negative tests
- Full critical attack-class execution
- Repeated probabilistic-model runs and approved thresholds
- Promotion blocked on a seeded critical failure
- Sanitized evidence and retention verification
- Independent security and change-management approval

Passing this educational lab does not prove model robustness, HIPAA compliance, or production readiness.
