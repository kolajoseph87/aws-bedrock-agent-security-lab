# Chapter 9 — Runtime Observability, Detection, and Security Monitoring

## The lesson in very simple English

Security controls can fail, be bypassed, or be attacked. Chapter 9 creates a trustworthy trail showing who asked, which policy decided, what safe action was proposed, and whether anything unusual happened—without copying sensitive prompts, completions, code, retrieved chunks, tool arguments, secrets, PHI, or PII into the monitoring system.

> Observe every decision, expose no sensitive body, and alert when trusted behavior changes.

## Northstar healthcare AppSec scenario

Northstar’s Secure Coding Agent receives a synthetic request, retrieves approved guidance, proposes a patch, and requests a tool action. Every stage emits a sanitized, correlated event. Security monitoring detects cross-repository attempts, replayed work orders, policy drift, credential or PHI detector hits, repeated denials, unusual tools, release bypass, and missing telemetry. The agent cannot read, delete, suppress, or disable its own audit trail.

## Secure flow

1. Generate identity and scope from trusted runtime context—not prompt text.
2. Emit a versioned structured event for each security decision.
3. Allowlist fields and remove sensitive values before delivery.
4. Deliver to an independent security account with encryption, sequencing, retries, and a dead-letter path.
5. Correlate runtime, RAG, tool, worker, pipeline, and deployment events.
6. Detect abuse, leakage, replay, drift, cost anomalies, and telemetry gaps.
7. Route sanitized alerts to Security Operations with severity, owner, and runbook.
8. Preserve immutable evidence and require approval before tuning detections.

## Important boundaries

- Observability is not authorization and must never permit an action.
- CloudTrail records AWS API activity; it does not replace application-level security events.
- Bedrock model invocation logging can capture request and response bodies. It remains disabled for this healthcare scenario.
- GuardDuty findings do not prove the agent itself is safe.
- Security Lake centralizes supported security data; it does not automatically understand custom agent decisions without deliberate schema and correlation design.
- An alert is evidence of a condition—not permission for destructive automated response.

## Hands-on lab

```bash
python3 scripts/validate_observability.py \
  --manifest observability/observability.aws.json \
  --evidence evidence/lab-9-validation.json

python3 -m unittest discover -s tests -v
python3 -m compileall scripts tests python
```

The validator performs 14 checks. This corrected Chapter 9 update adds 77 tests. Applied to the published 320-test Chapter 8 baseline, the expected cumulative result is 397 tests.

## Common mistakes

- Logging complete prompts, completions, retrieved chunks, source, patches, or tool arguments.
- Trusting principal or tenant identity supplied by the prompt.
- Letting the agent disable, read, or delete its monitoring data.
- Treating CloudTrail alone as full agent observability.
- Losing audit events silently when telemetry is unavailable.
- Sending secrets or patient identifiers inside an alert.
- Using an unkeyed hash for low-entropy identifiers.
- Ignoring policy/model drift and missing telemetry.
- Tuning a noisy detection without approval and evidence.
- Automatically deleting resources or disabling identities from one unverified alert.

## Interview-ready explanation

> I design agent observability as an independent security control. Each runtime gate emits a schema-versioned, correlated event using server-derived identity and hashed scope. We allowlist fields and explicitly exclude prompts, completions, retrieved text, code, tool arguments, credentials, PHI, and PII. Delivery is encrypted, sequenced, retried, and fail-closed for protected actions. Detections cover injection, cross-tenant access, replay, unexpected tools, policy drift, leakage indicators, denial spikes, cost anomalies, release bypass, and telemetry gaps. The agent cannot read, delete, or disable its own audit trail, and destructive response always needs separately verified authorization.

## Live verification still required

Verify live CloudTrail organization trails, log-file validation, CloudWatch ingestion and alarms, EventBridge routes, security-account access, KMS separation, S3 Object Lock mode and retention, Security Lake and GuardDuty integrations, VPC Flow Logs, event latency and loss, dead-letter recovery, clock synchronization, responder destinations, runbooks, quotas, regional availability, lifecycle, and pricing in Northstar’s approved non-production AWS account.

## Official sources

- https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
- https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html
- https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html
- https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
