# Chapter 7 — Secure Tool Execution: Let the Agent Ask, Not Act

## The lesson in very simple English

The coding agent may recommend a patch, but it must not receive a powerful shell or repository credential. A separate disposable worker receives one signed work order, checks it again, performs only the allowed commands in an isolated copy, and returns a sanitized artifact for human review.

> Let the agent request an action; let a separate, disposable worker perform only the exact approved action.

## Northstar healthcare AppSec scenario

The Secure Coding Agent finds synthetic patient information and a fake access-token marker in an unsafe logging example. It proposes removing sensitive logging. The runtime policy creates a short-lived work order for an isolated patch worker. The worker may edit only the approved training repository and run approved tests. It cannot reach production, push a branch, merge, deploy, retrieve secrets, or approve its own output.

## Secure flow

1. Bedrock returns a proposed action to Northstar's application.
2. `PRE_TOOL` validates identity, repository, base commit, operation, paths, arguments, approval, expiry, and policy version.
3. The application signs an immutable, single-use work order.
4. A separate worker verifies the signature and current repository state.
5. The worker starts in a fresh, disposable, non-privileged environment.
6. It checks out the exact immutable commit with no persistent credentials.
7. It runs only allowlisted, argument-safe commands with time, CPU, memory, process, file, and network limits.
8. It scans the diff and test output for PHI, PII, credentials, unsafe code, and scope expansion.
9. It returns a content-addressed patch and sanitized evidence.
10. An independent human reviews the result before any branch write, merge, release, or deployment.
11. The workspace and temporary authorization are destroyed.

## Important boundaries

- Bedrock action-group user confirmation is useful, but it is not exact tool authorization.
- Return control lets application code inspect proposed parameters before execution.
- A container or CodeBuild environment is not permission by itself. IAM, VPC rules, command policy, filesystem boundaries, artifact validation, and human approval remain separate.
- Repository files, build scripts, tests, package manifests, and compiler output are untrusted inputs.
- A successful test does not authorize a push, merge, release, or deployment.

## Hands-on lab

```bash
python3 scripts/validate_tool_execution.py \
  --manifest tool-execution/tool-execution.aws.json \
  --evidence evidence/lab-7-validation.json

python3 -m unittest discover -s tests -v
python3 -m compileall scripts tests python
```

The validator performs 18 checks. This corrected Chapter 7 update adds 61 tests. Applied to the published 198-test Chapter 6 baseline, the expected cumulative result is 259 tests.

## Common mistakes

- Giving the model a raw shell or AWS SDK.
- Trusting a tool name, path, branch, or repository supplied by the prompt.
- Using a mutable branch name instead of an exact commit.
- Running repository-controlled build commands without reviewing the approved command policy.
- Enabling privileged mode or a Docker socket.
- Leaving unrestricted network egress.
- Passing repository or cloud credentials into the worker.
- Treating user confirmation as the only authorization check.
- Streaming logs that may contain secrets or patient data.
- Letting the worker push, merge, deploy, or approve itself.
- Reusing a dirty workspace or replaying an old work order.

## Interview-ready explanation

> I separate reasoning from execution. Bedrock returns the proposed action to my application, where a fail-closed policy binds an exact principal, repository, immutable commit, operation, path set, arguments, approval, expiry, nonce, and policy version into a signed single-use work order. A fresh non-privileged worker revalidates that order, runs only allowlisted commands with no inbound access and restricted egress, scans the resulting diff and logs, and returns a hashed patch for independent review. The worker has no push, merge, deployment, secret, or self-approval authority.

## Live verification still required

Confirm the current CodeBuild compute image digest, service role, VPC ID, private subnets, endpoints, egress, quotas, timeout, concurrency, pricing, logging, artifact encryption, webhook settings, and source-credential behavior in Northstar's approved AWS account. Test denial and cleanup in the live non-production environment.

## Official sources

- https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html
- https://docs.aws.amazon.com/bedrock/latest/userguide/agents-userconfirmation.html
- https://docs.aws.amazon.com/codebuild/latest/userguide/vpc-support.html
- https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html
- https://docs.aws.amazon.com/config/latest/developerguide/codebuild-project-environment-privileged-check.html
