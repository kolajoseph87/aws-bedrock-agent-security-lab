# Amazon Bedrock Secure Coding Agent Security Lab

This cumulative lab teaches how Northstar Health Systems can build a secure coding assistant without exposing patient data or granting unsafe automation.

## Current coverage

- Chapter 0 — Safe foundation, workstation preflight, data boundary, cost guardrails, and guarded infrastructure
- Chapter 1 — Healthcare AppSec threat model, trust boundaries, abuse cases, mitigations, and testable security requirements
- Chapter 2 — Private VPC foundation, separated trust zones, Bedrock service endpoints, restricted egress, and network evidence
- Chapter 3 — Bedrock model allowlisting, inference governance, minimum-necessary context, privacy gates, and change control
- Chapter 4 — Separate workload identities, temporary credentials, restricted trust, KMS governance, and Secrets Manager controls
- Chapter 5 — Runtime PRE_INPUT, PRE_TOOL, and PRE_OUTPUT enforcement with exact tool authorization
- Chapter 6 — Secure RAG ingestion, tenant-aware retrieval, chunk inspection, citations, and deletion validation
- Chapter 7 — Isolated tool execution, immutable work orders, disposable patch workers, and verified artifacts
- Chapter 8 — Independent CI/CD release governance, software-supply-chain verification, signed artifacts, and safe deployment
- Chapter 9 — Privacy-safe runtime observability, correlated security events, anomaly detection, immutable evidence, and alerting
- Chapter 10 — Isolated agent red teaming, immutable attack corpora, adversarial regression tests, and independent promotion gates
- Chapter 11 — Independent kill switch, revocation, quarantine, forensic preservation, verified recovery, and incident exercises
- Chapter 12 — Separate agent identities, authenticated handoffs, bounded delegation, confused-deputy protection, and cascading-compromise containment
- Chapter 13 — Framework mapping, traceable control evidence, independent assurance, and fail-closed production-readiness gates
- Chapter 14 — Controlled capstone execution, end-to-end attack validation, evidence collection, teardown, and final assessment

## Scenario

Northstar Health Systems is a fictional healthcare organization. Its planned Amazon Bedrock Secure Coding Agent will review approved repositories, explain vulnerabilities, propose patches in isolation, and help CI/CD security gates. It must never retrieve real patient records, expose PHI/PII, use production secrets, approve its own changes, push to protected branches, or deploy to production without independent authorization.

All examples are synthetic. Passing this educational lab does not establish HIPAA compliance or production readiness.

## Run Chapter 0

```bash
cp config/lab.parameters.example.json config/lab.parameters.json
# Replace the owner placeholder, then run:
python3 scripts/preflight.py --config config/lab.parameters.json --offline
python3 -m unittest discover -s tests -v
```

## Run Chapter 1

```bash
python3 scripts/validate_threat_model.py \
  --manifest threat-model/threat-model.json \
  --evidence evidence/lab-1-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 2

```bash
python3 scripts/validate_network.py \
  --manifest network/landing-zone.aws.json \
  --evidence evidence/lab-2-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 3

```bash
python3 scripts/validate_model_governance.py \
  --manifest model-governance/model-governance.aws.json \
  --evidence evidence/lab-3-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 4

```bash
python3 scripts/validate_identity_security.py --manifest identity-security/identity-kms-secrets.aws.json --evidence evidence/lab-4-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 5

```bash
python3 scripts/validate_runtime_policy.py --manifest runtime-policy/runtime-policy.aws.json --evidence evidence/lab-5-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 6

```bash
python3 scripts/validate_secure_rag.py --manifest secure-rag/secure-rag.aws.json --evidence evidence/lab-6-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 7

```bash
python3 scripts/validate_tool_execution.py --manifest tool-execution/tool-execution.aws.json --evidence evidence/lab-7-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 8

```bash
python3 scripts/validate_release_governance.py --manifest release-governance/release-governance.aws.json --evidence evidence/lab-8-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 9

```bash
python3 scripts/validate_observability.py --manifest observability/observability.aws.json --evidence evidence/lab-9-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 10

```bash
python3 scripts/validate_security_evaluations.py --manifest security-evaluations/security-evaluations.aws.json --evidence evidence/lab-10-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 11

```bash
python3 scripts/validate_incident_response.py --manifest incident-response/incident-response.aws.json --evidence evidence/lab-11-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 12

```bash
python3 scripts/validate_multi_agent_security.py --manifest multi-agent-security/multi-agent-security.aws.json --evidence evidence/lab-12-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 13

```bash
python3 scripts/validate_compliance_assurance.py --manifest compliance-assurance/compliance-assurance.aws.json --evidence evidence/lab-13-validation.json
python3 -m unittest discover -s tests -v
```

## Run Chapter 14

```bash
python3 scripts/validate_capstone.py \
  --manifest capstone/capstone.aws.json \
  --evidence evidence/lab-14-validation.json
python3 -m unittest discover -s tests -v
```

## Safe deployment posture

The Chapter 0 CloudFormation template defaults `DeployLabFoundation` to `false`. With the default, it creates no resources. Review a change set before any future deployment, use an approved non-production AWS account, and never place credentials or sensitive data in parameters, tags, evidence, or Git.
