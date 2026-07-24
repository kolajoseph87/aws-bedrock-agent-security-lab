# Chapter 3 — Govern the Bedrock Model Before Calling It

## The lesson in very simple English

Imagine Northstar hires a very smart temporary coding assistant. The assistant may be useful, but Northstar still needs to decide:

- Which assistant is approved?
- Which office may it work from?
- What job may it perform?
- What information may it see?
- How much time and money may it use?
- Who approves a replacement?

Amazon Bedrock gives Northstar access to foundation models. It does not make every model, request, setting, or dataset automatically appropriate for healthcare secure-development work.

The Chapter 3 memory phrase is:

> Use an approved model, in an approved Region, with the smallest safe input—and check before every call.

## Northstar’s scenario

A developer opens a pull request for a patient-portal API. The Secure Coding Agent should review a synthetic code sample and explain an insecure logging pattern. Before Northstar calls a Bedrock model, a deterministic gate checks:

1. The caller has the Secure Coding Agent identity.
2. The repository is on the approved training allowlist.
3. The request purpose is secure code review.
4. The exact model and Region are approved.
5. The model review has not expired.
6. The input contains no PHI, PII, credential, or production-code marker.
7. Token, request, timeout, and cost limits are safe.
8. The approved Guardrail is attached.

If any check fails—or the policy service has an error—the call stops before Bedrock.

## What model governance means

Model governance is the process for choosing, approving, using, monitoring, changing, and retiring models.

It answers questions such as:

- Is this model approved for this exact use case?
- Is its provider agreement acceptable?
- Is the model available in the approved AWS Region?
- Has AppSec tested its secure-coding behavior?
- Has Privacy reviewed the data flow?
- Has Legal reviewed applicable terms?
- Can Northstar detect an unapproved model change?
- Is there a safe rollback model?

It is not a one-time shopping decision. A model version, Region, provider term, feature, system prompt, Guardrail, or data source can materially change risk.

## Concepts people often confuse

| Control | What it does | What it does not do |
| --- | --- | --- |
| PrivateLink | Keeps the network route private | Decide whether the model or data is approved |
| IAM | Authorizes Bedrock API actions and resources | Inspect source code for PHI or secrets |
| Model allowlist | Defines approved model IDs, Regions, and uses | Guarantee correct or secure output |
| Bedrock Guardrails | Adds configurable input/output filtering | Replace deterministic PHI, PII, secret, and authorization checks |
| Runtime tool authorization | Decides whether an exact action may run | Approve the model itself |
| Human approval | Accepts a reviewed change or exception | Make unsafe data safe |

## Northstar’s approved-model record

Every approved entry must contain:

- Exact model identifier
- Provider
- Approved Region
- Approved tasks
- Business and security owner
- Risk-review reference
- Approval status
- Expiration date
- Evaluation evidence
- Rollback choice

The catalog is default-deny. If a model is missing from the catalog, it is not approved.

The reviewed lab example uses the exact in-Region model ID
`anthropic.claude-haiku-4-5-20251001-v1:0` in `us-east-1`. AWS currently
lists Claude Haiku 4.5 as active and supports in-Region use in `us-east-1`.
This is still only a training approval. Check the live AWS model lifecycle,
Region availability, account access, quota, and pricing before deployment.

This lab uses one illustrative model identifier. Model availability changes, so a real deployment must verify the current model ID, Region, license terms, and lifecycle state before use.

## Keep the inference surface small

Chapter 3 enables only the minimum educational path:

- Direct inference using the Converse operation
- Non-streaming requests
- Synthetic data
- Approved training repositories
- Conservative token and randomness limits

It does not approve:

- Streaming
- Batch inference
- Provisioned throughput
- Model customization
- Cross-Region inference
- Production repositories
- Real patient information

These features are not always bad. They are simply outside this chapter’s reviewed scope. New capability requires a new threat review and tests.

## Protect PHI, PII, credentials, and source code

Northstar uses several layers:

1. **Data minimization:** Send only the code lines and metadata needed for the finding.
2. **Deterministic input scan:** Reject known PHI, PII, credentials, and forbidden source classifications.
3. **Approved Guardrail:** Apply the reviewed Guardrail to the inference request.
4. **Deterministic output scan:** Inspect the proposed explanation or patch before release.
5. **Human review:** A qualified reviewer verifies the security finding and proposed change.

Guardrails are valuable defense in depth. They are not permission to send real PHI or production code into this lab.

## Logging rule

Amazon Bedrock model invocation logging can collect request data, response data, and metadata. That visibility can help investigations, but request and response bodies may contain sensitive code or healthcare information.

Chapter 3 therefore permits only sanitized security metadata, such as:

- Request ID
- Approved model alias
- Policy decision
- Repository classification
- Token counts
- Latency
- Error category
- Correlation ID

It forbids prompts, completions, code bodies, PHI, PII, credentials, and raw files in evidence. Later chapters will build the full audit and detection design.

## IAM rule

The educational IAM contract allows only:

```text
bedrock:Converse
```

It binds access to the reviewed model resource and approved Region, requires the Northstar use-case principal tag, and denies inference when the approved Guardrail identifier is missing.

IAM still does not authorize a repository write, branch merge, tool call, or deployment. Those require separate controls.

## Safe model changes

Before changing a model or version:

1. Update the inventory.
2. Review security, privacy, legal, cost, and availability.
3. Evaluate it in non-production with a fixed synthetic dataset.
4. Run secure-coding and security-regression tests.
5. Compare quality, unsafe-output, leakage, latency, and cost results.
6. Obtain independent approval.
7. Record a rollback model.
8. Promote the exact reviewed configuration.
9. Detect later drift.

A material change invalidates the old approval. “The new version looks similar” is not evidence.

## Hands-on lab

Run:

```bash
python3 scripts/validate_model_governance.py \
  --manifest model-governance/model-governance.aws.json \
  --evidence evidence/lab-3-validation.json

python3 -m unittest discover -s tests -v
```

The validator checks thirteen design requirements. The tests change safe copies of the manifest to prove the design fails closed.

The attacks include:

- Selecting an unapproved model
- Selecting the right model in the wrong Region
- Sending a synthetic PHI marker
- Sending a credential marker
- Exceeding token or cost limits
- Simulating a policy-service error
- Changing to an unreviewed model version
- Trying to capture a prompt in invocation logs

Every attack must stop before a model call and create zero prohibited side effects.

## CloudFormation reference

`infra/chapter-3-model-governance.yaml` is a guarded educational reference.

Its default is:

```text
DeployChapter3ModelGovernance=false
```

With the default, it creates no resources. If explicitly enabled after review, it creates only an IAM managed policy for the named development role. It does not deploy a Bedrock agent, model, Guardrail, log destination, repository, or patient datastore.

Before live use, confirm:

- The exact model exists in the selected Region.
- The ARN format matches the inference method.
- The named role already exists.
- The Guardrail ARN and numeric version are approved.
- A CloudFormation change set shows only expected changes.
- The policy works with organization SCPs, permission boundaries, and endpoint policies.

## Evidence to keep

- Approved-model inventory
- Evaluation dataset version and hash
- Evaluation and regression results
- Security, Privacy, Legal, and service-owner approvals
- IAM and Guardrail policy review
- CloudFormation change-set review
- Negative-test results proving zero model calls
- Drift and expiration status
- Rollback model decision

Never put raw prompts, completions, source files, PHI, PII, or credentials into the evidence package.

## Knowledge check

### 1. Does a private Bedrock endpoint approve a model?

No. It protects the network route. The model still needs governance and IAM approval.

### 2. Why use exact model identifiers?

They make the reviewed target clear and reduce silent changes through a vague alias.

### 3. Why disable cross-Region inference here?

Northstar has approved only one Region. Cross-Region profiles may route requests to additional Regions and require separate policy and data-residency review.

### 4. Why not log every prompt and response?

They can contain sensitive source code, credentials, PHI, or PII. Metadata is usually safer for this chapter.

### 5. Is a Guardrail enough to protect patient data?

No. Northstar also requires data minimization, deterministic scans, IAM, output checks, and human review.

### 6. What happens when the policy service is unavailable?

The request fails closed before Bedrock. Availability problems must not become permission.

## Team exercise

Choose a model your organization is considering for secure code review. Create a one-page approval record containing:

- Exact model and Region
- Approved task
- Prohibited data
- Owner and reviewers
- Evaluation dataset
- Security tests
- Logging decision
- Expiration date
- Rollback choice

Then explain why model approval does not authorize code changes or deployment.

## Interview-ready explanation

> I treat model selection as a governed security change. For Northstar’s Bedrock Secure Coding Agent, I use a default-deny model catalog with exact model IDs, approved Regions, owners, review expiration, and a fixed synthetic evaluation set. Before every invocation, deterministic checks validate identity, repository, purpose, data classification, Guardrail attachment, and token and cost limits. The request fails closed before Bedrock if anything is wrong. I also keep prompts and completions out of normal evidence because they can contain sensitive code or PHI. IAM model access remains separate from permission to change code or deploy.

## Important limitations

- Offline validation makes no Bedrock call.
- It does not prove that the illustrative model is currently available.
- It does not evaluate model quality or safety.
- It does not deploy the CloudFormation template.
- It does not establish HIPAA compliance or production readiness.
- Model behavior remains probabilistic and must be reviewed and retested.
