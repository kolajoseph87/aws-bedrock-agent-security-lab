# Chapter 4 Evidence Checklist

Keep sanitized references, hashes, decisions, and test results—not PHI, PII, secret values, credentials, source bodies, prompts, or model responses.

- [ ] Identity inventory names a human owner for every role.
- [ ] People use federation and MFA; workloads use temporary role credentials.
- [ ] Bedrock API keys and long-lived AWS access keys are prohibited.
- [ ] Agent, isolated worker, and pipeline roles are separate.
- [ ] Trust policies use exact service principals and source conditions.
- [ ] Permissions boundaries and organization guardrails were reviewed.
- [ ] `iam:PassRole` is limited to exact roles and approved services.
- [ ] IAM Access Analyzer and policy simulation found no unintended access.
- [ ] The coding agent cannot read secrets, decrypt directly, write repositories, approve changes, or deploy.
- [ ] KMS administration and key use are separated.
- [ ] KMS encryption context contains only non-sensitive metadata.
- [ ] Secrets use exact ARNs, private access, monitoring, rotation, and emergency revocation tests.
- [ ] CloudFormation change set shows only intended non-production roles.
- [ ] Negative tests prove zero AWS calls and zero prohibited side effects.
- [ ] Live availability, quotas, access, lifecycle, pricing, IAM, KMS, and Secrets Manager behavior were checked before deployment.
- [ ] Residual risk has an owner and expiration date.
