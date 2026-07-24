# Chapter 8 — Release Governance and Software Supply-Chain Security

## The lesson in very simple English

Chapter 7 produces a reviewed patch artifact. That still does not mean the patch is safe to ship. Chapter 8 makes an independent pipeline prove exactly what source entered the build, which tests ran, which dependencies were used, who built and approved it, and whether the released bytes are the same bytes that were signed.

> The agent may propose the patch; an independent pipeline must prove and approve what ships.

## Northstar healthcare AppSec scenario

The Secure Coding Agent proposes a fix for synthetic unsafe logging. A disposable worker returns a hashed patch. The release pipeline accepts only that exact patch and immutable source commit. It runs SAST, SCA, secret, IaC, malware, unit, and policy tests; produces an SBOM and provenance; signs the artifact; and pauses for independent approval. The agent cannot approve, merge, release, deploy, use production credentials, or change its own pipeline.

## Secure flow

1. Accept only the Chapter 7 content-addressed patch and exact source SHA.
2. Revalidate branch protection, reviewers, CODEOWNERS, current head SHA, and pipeline-file ownership.
3. Run every required security gate and fail closed if a gate is missing or unavailable.
4. Resolve only pinned dependencies from approved registries and verify integrity hashes.
5. Build in a non-privileged trusted builder with temporary credentials.
6. Create an SBOM and SLSA-style provenance bound to source, patch, builder, and build definition.
7. Sign the artifact digest and store it immutably with encryption and retention.
8. Obtain independent environment approval and a valid change ticket.
9. Promote the same verified digest; never rebuild between environments.
10. Use a canary or blue/green release with automatic rollback.

## Important boundaries

- Passing tests does not authorize deployment.
- An SBOM lists components; it does not prove they are safe.
- A signature proves which identity signed a digest; it does not prove the code is vulnerability-free.
- Provenance is valuable only when its builder identity and source bindings are independently verified.
- GitHub or CodePipeline branch protection does not replace IAM, artifact signing, environment approvals, or runtime monitoring.
- Guardrails do not secure the software supply chain.

## Hands-on lab

```bash
python3 scripts/validate_release_governance.py \
  --manifest release-governance/release-governance.aws.json \
  --evidence evidence/lab-8-validation.json

python3 -m unittest discover -s tests -v
python3 -m compileall scripts tests python
```

The validator performs 18 checks. This corrected Chapter 8 update adds 61 tests. Applied to the published 259-test Chapter 7 baseline, the expected cumulative result is 320 tests.

## Common mistakes

- Letting the agent merge or approve its own patch.
- Building a different commit from the one reviewers approved.
- Treating a green test result as deployment permission.
- Pulling mutable image tags or unpinned packages.
- Giving credentials to untrusted fork builds.
- Allowing a failed scanner to be skipped.
- Creating permanent or self-approved risk waivers.
- Rebuilding separately in test and production.
- Signing an artifact without verifying its provenance and SBOM.
- Deploying by filename or tag instead of immutable digest.
- Using the build role as the production deployment role.
- Writing source, patches, credentials, PHI, or PII into evidence.

## Interview-ready explanation

> I treat an agent-generated patch as untrusted input to an independent release pipeline. The pipeline revalidates the exact source and patch hashes, enforces branch protection and separation of duties, runs mandatory fail-closed security gates, pins and verifies dependencies, produces an SBOM and provenance, and signs the final artifact digest. A separate temporary deployment identity promotes that same digest after independent approval. Production uses a limited rollout and automatic rollback. The agent has no merge, release, deployment, credential, or self-approval authority.

## Live verification still required

Verify live repository rules, CODEOWNERS, OIDC trust, IAM boundaries, CodePipeline and CodeBuild configuration, build-image digest, registry allowlists, scanner versions and coverage, SBOM format, signing identity, KMS policy, immutable storage, retention, environment approvals, deployment strategy, rollback alarms, service quotas, regional availability, lifecycle, and pricing in Northstar's approved non-production AWS account.

## Official sources

- https://docs.aws.amazon.com/codepipeline/latest/userguide/security-iam.html
- https://docs.aws.amazon.com/codebuild/latest/userguide/security-best-practices.html
- https://docs.aws.amazon.com/signer/latest/developerguide/Welcome.html
- https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/build-a-ci-cd-pipeline-for-github-repositories-by-using-aws-codepipeline-and-github-webhooks.html
- https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- https://slsa.dev/spec/v1.2/provenance
