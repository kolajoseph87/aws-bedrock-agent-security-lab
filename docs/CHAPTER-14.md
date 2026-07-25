# Chapter 14 — Final Controlled Capstone

## Goal

Prove that Chapters 0–13 operate as one security system in an approved, isolated
non-production account. The capstone validates the deployment process, runs
harmless attacks, exercises containment and recovery, freezes evidence, removes
temporary resources, and produces technical and executive assessments.

> Validate the whole system under attack, preserve proof, remove temporary
> authority, and never confuse a successful lab with production authorization.

## Required sequence

1. Pin the clean source commit, manifests, model, policy, tools, dependencies,
   worker image, and artifact digests.
2. Verify all inherited tests and Chapter 13 assurance prerequisites.
3. Confirm the allowlisted non-production account, Region, synthetic dataset,
   budget, quotas, rollback target, kill switch, owners, and change ticket.
4. Obtain two independent human approvals and use a short-lived deployment
   session. The agent receives no deployment authority.
5. Review the CloudFormation change set before enabling any resource.
6. Run functional smoke tests, then the twelve harmless attack exercises.
7. Stop immediately for any critical mismatch, telemetry gap, containment
   failure, data exposure, or unauthorized side effect.
8. Exercise incident containment and clean-room recovery.
9. Freeze privacy-safe, content-addressed evidence in independent immutable
   storage.
10. Revoke temporary access, invalidate outstanding work, destroy ephemeral
    resources, reconcile inventory, and check for orphan cost.
11. Produce findings, limitations, remediation ownership, residual risk, and an
    executive summary for independent review.

Every approval must be bound to the exact non-production account, Region,
source commit, artifact digest, and change ticket. Approval records and phase
evidence must be current. Reusing an approval for another account, artifact, or
test run blocks the capstone.

## Pass condition

The strongest possible lab result is
`CONTROLLED_NONPRODUCTION_CAPSTONE_VALIDATED`. It is not a production approval,
HIPAA determination, certification, or permission to process real patient data.

## Safe local validation

```bash
python3 scripts/validate_capstone.py \
  --manifest capstone/capstone.aws.json \
  --evidence evidence/lab-14-validation.json
python3 -m unittest discover -s tests -v
python3 -m compileall scripts tests python
```

The validator performs no AWS calls and the infrastructure template creates
nothing while `DeployChapter14Capstone` remains `false`. The template is only
an immutable evidence-store skeleton; it does not deploy the complete capstone
architecture, execute attacks, validate CloudTrail digests, or prove teardown.
