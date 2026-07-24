# Chapter 11 — Incident Response and Recovery

## Goal

Contain a compromised Secure Coding Agent without trusting the agent, losing evidence, or restoring the same weakness.

## Simple mental model

An agent incident is like a fire in an automated factory. First stop the machines. Then isolate the affected area, preserve trustworthy evidence, remove the cause, and restart one safe section at a time.

> Stop the agent first, preserve trustworthy evidence second, recover only after independent verification.

## What the kill switch must stop

The independent control plane blocks new model calls, RAG retrieval, tool requests, disposable workers, repository writes, releases, and deployments. If incident state cannot be read, these actions fail closed. Safe cancellation of in-flight work is required, and propagation must be measured within 60 seconds.

The agent cannot activate, clear, or bypass the kill switch. Recovery requires a new, signed authorization approved independently.

The offline command verifier uses a strict schema, a maximum 15-minute
authorization lifetime, two distinct approvers who are not the requester, and
a single-use nonce. Successful verification consumes the nonce immediately.

## Revoke more than credentials

Rotate secrets and deny or revoke temporary sessions, but also invalidate work orders, nonces, approvals, KMS grants, repository tokens, and pipeline authorizations. Otherwise an attacker can replay authority that was valid before containment.

## Quarantine the compromised layer

Responders can quarantine a model version, Guardrail or runtime policy, Knowledge Base source, tool definition, or worker image. Tenant/repository-scoped containment limits disruption; global containment remains available when the blast radius is unknown.

## Preserve evidence without copying sensitive bodies

Store sanitized events, hashes, timestamps, versions, decisions, identities, and reason codes in a separate security account. Use KMS encryption, CloudTrail digest validation, S3 Object Lock compliance mode, chain of custody, legal hold, and at least 400 days of retention.

Do not put raw prompts, completions, code, retrieved chunks, tool arguments, PHI, PII, credentials, secrets, or tokens into the evidence bundle.

The CloudFormation reference requires the ARN of an evidence bucket managed in
the separate security account. That bucket must already enforce KMS encryption,
S3 Object Lock compliance mode, legal hold, and CloudTrail digest validation.
The template does not claim to create or validate that cross-account archive.

## Recovery gates

Recovery requires:

1. Known-good model, policy, corpus, tool, image, source, and artifact versions.
2. Exact digest verification and a clean-room rebuild.
3. Verified credential rotation and rejection of old authorization artifacts.
4. Knowledge Base resynchronization plus negative retrieval tests.
5. The complete adversarial regression suite.
6. Independent recovery approval.
7. Canary release, enhanced monitoring, and immediate rollback readiness.

## Playbooks

The lab requires owned playbooks for prompt injection, data exposure, credential compromise, cross-tenant access, tool abuse, RAG poisoning, model/policy drift, supply-chain compromise, telemetry tampering, cost abuse, unauthorized deployment, and evaluator compromise.

Legal, Privacy, Security, Operations, and executive communications must know when they are engaged. Tabletop exercises and recovery drills turn documents into evidence.

## Run the offline lab

```bash
python3 scripts/validate_incident_response.py \
  --manifest incident-response/incident-response.aws.json \
  --evidence evidence/lab-11-validation.json
python3 -m unittest discover -s tests -v
```

The offline lab makes no AWS call, activates no kill switch, revokes no credential, and deploys nothing. Live proof must be collected separately in an approved non-production account.

The template stores incident and revocation state, but existing model, RAG,
tool, worker, repository, release, and deployment consumers must be integrated
to query that state before every protected action. Creating the tables alone
does not activate a kill switch or prove the 60-second propagation target.
