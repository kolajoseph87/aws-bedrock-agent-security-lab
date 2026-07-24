# Amazon Bedrock Secure Coding Agent Security Lab

This cumulative lab teaches how Northstar Health Systems can build a secure coding assistant without exposing patient data or granting unsafe automation.

## Current coverage

- Chapter 0 — Safe foundation, workstation preflight, data boundary, cost guardrails, and guarded infrastructure
- Chapter 1 — Healthcare AppSec threat model, trust boundaries, abuse cases, mitigations, and testable security requirements
- Chapter 2 — Private VPC foundation, separated trust zones, Bedrock service endpoints, restricted egress, and network evidence
- Chapter 3 — Bedrock model allowlisting, inference governance, minimum-necessary context, privacy gates, and change control
- Chapter 4 — Separate workload identities, temporary credentials, restricted trust, KMS governance, and Secrets Manager controls

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

No Python package installation is required. Offline mode makes no AWS API calls and creates no resources or cost.

## Safe deployment posture

The Chapter 0 CloudFormation template defaults `DeployLabFoundation` to `false`. With the default, it creates no resources. Review a change set before any future deployment, use an approved non-production AWS account, and never place credentials or sensitive data in parameters, tags, evidence, or Git.
