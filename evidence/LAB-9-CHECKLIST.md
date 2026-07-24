# Chapter 9 evidence checklist

- [ ] Validator reports all Chapter 9 checks passed.
- [ ] Full cumulative unit-test suite passes.
- [ ] Python compilation passes.
- [ ] Manifest and CloudFormation structure are reviewed.
- [ ] Evidence contains no prompt, completion, retrieved chunk, source, patch, tool argument, credential, PHI, or PII.
- [ ] Live CloudTrail delivery and log-file validation are tested.
- [ ] Live CloudWatch metric filters, alarms, and missing-data behavior are tested.
- [ ] Dead-letter recovery and bounded-buffer behavior are tested.
- [ ] Security-account access, KMS separation, Object Lock, and retention are verified.
- [ ] Security Lake, GuardDuty, EventBridge, and VPC Flow Log integrations are reviewed.
- [ ] Every detection has an owner, severity, runbook, and approved tuning process.
- [ ] Alert delivery and responder acknowledgement are exercised.
- [ ] Availability, quotas, lifecycle, regional support, and pricing are checked live.

Offline passing results are educational evidence only. They do not prove live monitoring, HIPAA compliance, or production readiness.
