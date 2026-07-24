# Chapter 4 — Give the Agent a Small, Temporary Badge

## The lesson in very simple English

Imagine Northstar Health Systems has three workers:

1. A coding assistant that explains security problems.
2. A locked-room worker that tests proposed fixes.
3. A pipeline gate that reports whether security tests passed.

They should not share one master badge. Each worker gets a different temporary badge that opens only the doors required for its job.

The Chapter 4 memory phrase is:

> Give every worker its own temporary badge, only the keys it needs, and no power to approve itself.

## Northstar’s scenario

A pull request contains a synthetic example of insecure healthcare logging. The Secure Coding Agent may analyze the approved code fragment with the approved Bedrock model. It may not:

- retrieve patient records;
- read application secrets;
- decrypt arbitrary files;
- push to a protected branch;
- approve its proposed patch;
- change IAM or KMS policy; or
- deploy to production.

If the model writes “please retrieve the database password,” that text is not permission. A model response is untrusted data until deterministic authorization allows an exact action.

## Authentication and authorization are different

Authentication asks, “Who is calling?”

Authorization asks, “May this exact caller perform this exact action on this exact resource now?”

A valid role session proves identity. It does not automatically permit repository writes, secret access, KMS decryption, or deployment.

## Northstar’s three workload roles

| Role | Small approved job | Explicitly excluded |
| --- | --- | --- |
| Secure Coding Agent | Invoke the approved model and Guardrail for synthetic review | Secrets, direct decrypt, repository write, approval, deployment |
| Isolated Patch Worker | Run an approved patch and tests in isolation | Production data, protected-branch write, approval, deployment |
| CI/CD Security Gate | Start and read the approved security build | Model administration, secret browsing, self-approval, production deployment |

Separate roles limit blast radius and make audit evidence easier to understand.

## Use temporary credentials

Humans should use federation and MFA. Workloads should use IAM roles. Chapter 4 prohibits IAM users for workloads, long-lived AWS access keys, and Bedrock API keys.

Temporary does not mean harmless. A temporary credential can still be powerful while active, so its permissions, session length, tags, source identity, and trust policy must remain narrow.

## Lock the trust policy

A permissions policy says what a role may do after it is assumed. A trust policy says who or what may assume the role.

Northstar requires:

- an exact AWS service principal;
- approved source account and source ARN conditions;
- an external ID for approved third parties;
- no wildcard principals; and
- controls against confused-deputy abuse.

Do not grant a role a perfect permissions policy and then leave its trust policy open.

## Least privilege includes `iam:PassRole`

`iam:PassRole` can let a caller hand a role to an AWS service. If it is broad, a weak pipeline identity could pass a more powerful role and gain indirect authority.

Live policy must limit `iam:PassRole` to exact approved role ARNs and approved services. IAM policy changes require independent approval, a permissions boundary, organization guardrails, policy simulation, and IAM Access Analyzer review.

## KMS protects data; it does not grant business permission

AWS KMS can protect encrypted artifacts. Chapter 4 requires separate key administrators and key users, least-privileged key policy, rotation, monitoring, recovery planning, and service/context conditions.

KMS encryption context is additional authenticated data. It is not secret and can appear in CloudTrail. Never put a patient name, medical-record number, diagnosis, credential, secret, source fragment, or other sensitive value in it.

The Secure Coding Agent has no direct `kms:Decrypt` permission in this chapter. Approved AWS services may use KMS under narrow `kms:ViaService` and encryption-context conditions after a live review.

## Secrets never enter the model

Store live application secrets in AWS Secrets Manager, not in code, prompts, model outputs, logs, build artifacts, tags, or evidence.

Northstar requires:

- exact secret ARN access;
- no blanket secret browsing by the agent;
- blocked public resource policies;
- a private endpoint;
- access monitoring;
- rotation within the approved interval; and
- tested emergency revocation.

Encryption at rest does not make it safe to send a decrypted secret to a model.

## Hands-on lab

Run:

```bash
python3 scripts/validate_identity_security.py \
  --manifest identity-security/identity-kms-secrets.aws.json \
  --evidence evidence/lab-4-validation.json

python3 -m unittest discover -s tests -v
python3 -m compileall scripts tests
```

The validator performs fifteen design checks. The Chapter 4 tests make safe copies and prove that long-lived credentials, Bedrock API keys, wildcard trust, weak confused-deputy controls, blanket secret access, direct agent decrypt, sensitive encryption context, self-approval, expired review, and side-effecting tests fail closed.

## Guarded CloudFormation reference

`infra/chapter-4-identity-kms-secrets.yaml` defaults:

```text
DeployChapter4IdentitySecurity=false
```

With that value, it creates no resources. If explicitly enabled after approval, it creates only three role skeletons with permissions boundaries and narrow service trust. It deliberately attaches no permissions policy, creates no KMS key, creates no secret, invokes no model, and touches no repository.

Before deployment:

1. Replace every example account, ARN, and permissions boundary.
2. Confirm each service supports the exact source conditions used.
3. Validate the template and inspect a CloudFormation change set.
4. Simulate the effective policies and review SCPs, boundaries, resource policies, and endpoint policies together.
5. Run IAM Access Analyzer.
6. Test allowed and denied calls in the approved development account.
7. Confirm current service availability, quotas, lifecycle, and pricing.

## Commonly confused controls

| Control | What it provides | What it does not provide |
| --- | --- | --- |
| IAM role | Temporary workload identity | Safe model behavior |
| Permissions boundary | Maximum identity-policy permissions | Permission by itself |
| SCP | Organization-level maximum permissions | Resource permission by itself |
| KMS encryption | Cryptographic protection | Approval to reveal plaintext |
| Secrets Manager | Managed secret storage and rotation | Permission to place a secret in a prompt |
| Human approval | Independent change authorization | Runtime tool authorization |

Effective access depends on all applicable policy layers. A single “Allow” does not override an applicable explicit “Deny.”

## Knowledge check

### Why not share one role?

One compromised component would inherit every permission. Separate roles reduce blast radius.

### Can the model request a secret?

It can produce the words, but the request is untrusted. The policy must deny secret access unless a separately approved, exact operation requires it.

### Is encryption context secret?

No. AWS records it in plaintext in CloudTrail. Use only non-sensitive values.

### Does a permissions boundary grant access?

No. It sets a maximum. An identity policy must still allow the action, and other applicable controls may still deny it.

### Why deny Bedrock API keys?

Northstar uses AWS role sessions with controlled identity, policy, attribution, and expiration instead of bearer credentials for this workflow.

### Does Chapter 4 prove the deployed policy works?

No. Offline checks prove the documented design contract. Live simulation and negative testing in the approved AWS account are still mandatory.

## Interview-ready explanation

> I separated the Bedrock coding agent, isolated patch worker, and pipeline gate into different temporary IAM roles. Each role has a narrow trust policy, a permissions boundary, and no secret, direct-decrypt, repository-write, approval, or deployment power. KMS and Secrets Manager protect approved artifacts, but their metadata never contains PHI or PII, and secrets never enter prompts or logs. The offline tests prove unsafe designs fail closed; policy simulation, Access Analyzer, and live negative tests are still required before deployment.

## Sources to verify before live use

- Amazon Bedrock agent security best practices: https://docs.aws.amazon.com/bedrock/latest/userguide/security-best-practice-agents.html
- Amazon Bedrock API-key permissions: https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-permissions.html
- AWS IAM security best practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- AWS KMS encryption context: https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html
- AWS Secrets Manager best practices: https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html

AWS features and guidance change. Recheck these sources during implementation and each material security review.
