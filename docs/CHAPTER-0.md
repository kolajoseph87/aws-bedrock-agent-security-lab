# Chapter 0: Build the Safe Playground First

## What you will build

You will prepare a controlled, non-production foundation for Northstar Health Systems. You will not deploy a Bedrock model or agent. You will validate the workstation, identify the exact AWS account and Region, declare the data boundary, name an owner, plan cost alerts, review a guarded CloudFormation template, and run offline tests.

The simple lesson is:

> Check the playground before the robot enters it.

## The five-year-old explanation

Imagine a helpful robot that can read computer code. Northstar wants it to find unsafe code. Before giving it any code, we build a practice room. We make sure it is the right room, give the room an owner, decide how much it may cost, and put fake patient names in the toy files. Real patient information stays outside.

## Why Chapter 0 is security work

A coding agent can create risk before it writes a single line. A rushed setup can use the wrong AWS account, expose data in tags or logs, rely on long-lived access keys, enable expensive services, or accidentally mix a lab with production healthcare systems.

Chapter 0 prevents those mistakes early. It does not claim the future agent is secure.

## Northstar use case

The future agent may:

- Read explicitly approved synthetic training repositories.
- Identify common application-security weaknesses.
- Explain a vulnerability in simple language.
- Propose a patch inside an isolated worker.
- Run approved SAST, SCA, secret, IaC, and unit tests.
- Return a sanitized finding to the CI/CD pipeline.

The future agent may not:

- Read live patient records or real PHI/PII.
- Use production source code in this lab.
- Read production credentials or secrets.
- Push to a protected branch.
- Approve its own pull request.
- Disable a security gate.
- Change IAM permissions.
- Deploy directly to production.

Chapter 0 grants none of these future capabilities. It only records the intended boundary.

## Data rules

| Data | Chapter 0 rule |
|---|---|
| Synthetic source code | Allowed |
| Synthetic patient examples | Allowed and clearly labeled |
| Sanitized test findings | Allowed |
| Real PHI or PII | Forbidden |
| Production source code | Forbidden |
| Production secrets or credentials | Forbidden |
| Live patient records | Forbidden |

AWS service security features can help protect data, but configuration and customer controls still matter. Northstar must independently evaluate its HIPAA obligations, AWS agreements, eligible services, architecture, policies, and operating procedures. This training project is not a compliance certification.

## Prerequisites

- An approved non-production AWS account.
- Python 3.10 or newer, Git, and AWS CLI v2 for optional online checks.
- Permission to inspect caller identity and Region.
- A named AppSec or cloud-security owner.
- A team-approved monthly budget and notification route.
- Synthetic data only.

Check local tools:

```bash
python3 --version
git --version
aws --version
```

## Step 1: Create a local configuration

```bash
cp config/lab.parameters.example.json config/lab.parameters.json
```

Replace the owner placeholder. Replace `000000000000` with the approved 12-digit non-production AWS account ID. The preflight rejects common placeholder account IDs. Do not add access keys, session tokens, passwords, patient names, medical-record numbers, personal email addresses, or secrets.

Run the offline preflight:

```bash
python3 scripts/preflight.py \
  --config config/lab.parameters.json \
  --offline
```

Offline mode performs no AWS API calls. The example intentionally fails until its owner placeholder is replaced.

## Step 2: Use temporary AWS credentials and verify identity

Use your organization’s approved IAM Identity Center or role-assumption workflow. Do not create a long-lived IAM user access key for this lab.

```bash
aws sts get-caller-identity
aws configure get region
```

Stop if the account or Region is not the approved target. The preflight can perform the same comparison:

```bash
python3 scripts/preflight.py \
  --config config/lab.parameters.json \
  --evidence evidence/lab-0-preflight.json
```

The evidence contains only the last four account digits. Check records contain only the check name and PASS/FAIL status; they never copy AWS CLI output or full expected/actual account IDs. The evidence does not store an ARN, credential, or session token.

## Step 3: Confirm Bedrock availability without invoking a model

Model availability and features vary by Region and model. Access settings can also change. Review the current Bedrock model catalog and your organization’s approved-model list. Do not run inference in Chapter 0.

The planned model must later pass model governance, privacy, licensing, regional, cost, and security review. “Available in the console” does not mean “approved for healthcare source code.”

## Step 4: Plan cost controls

Set a recurring monthly AWS Budget scoped to the lab’s approved account and tags. Suggested alerts are 50%, 80%, and 100%, routed to a monitored team address. A budget alert is a warning, not a guaranteed hard stop. Budget actions can change permissions or resources and therefore require separate review and least privilege.

Do not enable a destructive automated action in Chapter 0.

## Step 5: Validate and preview CloudFormation

The template defaults to no resource creation:

```bash
aws cloudformation validate-template \
  --template-body file://infra/chapter-0-foundation.yaml
```

If your team later approves deployment, create a change set first and inspect every proposed resource. Do not execute it merely because validation passes. CloudFormation validation checks template structure; it does not prove that the architecture is secure.

The only guarded resource in Chapter 0 is an AWS Budget. `DeployLabFoundation=false` creates nothing.

## Step 6: Run automated tests

```bash
python3 -m unittest discover -s tests -v
```

The negative tests prove that preflight fails for a production environment, missing PHI denial, unsafe allowed data, unsafe tags, placeholder owner or account, invalid account/Region, missing Bedrock service declaration, evidence leakage, and invalid cost settings.

## Acceptance criteria

| Test | Expected result |
|---|---|
| Owner placeholder remains | Fail |
| Environment is `prod` | Fail |
| Real-PHI denial is missing | Fail |
| Tag suggests patient data | Fail |
| AWS account differs from approved config | Online check fails |
| Configured Region differs | Online check fails |
| CloudFormation guard remains false | No resource is created |
| Offline tests run | No AWS request, inference, agent action, or cost |
| Evidence is produced | No credential, ARN, full account ID, prompt, or PHI/PII |

## Evidence checklist

- [ ] Python, Git, and optional AWS CLI versions
- [ ] Approved account verified without committing the full ID
- [ ] Approved Region and model-availability review
- [ ] Named team owner
- [ ] Synthetic-only data declaration
- [ ] Offline preflight output
- [ ] Unit-test output
- [ ] CloudFormation validation result, if AWS CLI is available
- [ ] Reviewed change set before any approved deployment
- [ ] Budget amount, scope, and thresholds without personal contact details
- [ ] Cleanup owner and review date

## Safe cleanup

Offline Chapter 0 creates nothing, so it needs no cleanup. If an approved operator explicitly enabled the guarded budget, first identify the exact stack:

```bash
aws cloudformation describe-stacks --stack-name northstar-secure-coding-agent-ch0
```

Deletion is destructive. Confirm the stack contains only the approved Chapter 0 budget before requesting deletion through your organization’s change process.

## Common mistakes

- Treating an AWS Budget as a guaranteed spending cutoff.
- Assuming encryption automatically makes PHI use compliant.
- Putting ticket numbers, patient names, repository secrets, or personal email addresses in tags.
- Using a personal or production AWS account for training.
- Saving long-lived AWS keys in `.env`, source control, screenshots, or evidence.
- Assuming Bedrock model availability equals internal approval.
- Executing a CloudFormation change set without reviewing it.

## Knowledge check

1. Why is production source code forbidden in Chapter 0?
2. Does a passing template validation prove the infrastructure is secure?
3. Is an AWS Budget alert a hard cost limit?
4. Why does the evidence store only an account fingerprint?
5. What happens when `DeployLabFoundation` remains `false`?

### Answers

1. Chapter 0 has not yet established the identity, network, model, runtime, logging, and output controls needed to protect it.
2. No. Validation checks template structure, not complete security or compliance.
3. No. It warns the team; spending may continue unless an independently reviewed action intervenes.
4. It proves the operator checked the target while reducing exposure of account metadata.
5. The template creates no resource.

## Interview-ready explanation

> “I begin the Bedrock secure-coding-agent program with a fail-closed foundation. The preflight permits only dev or test, verifies the exact AWS account and Region, requires a named owner and cost boundary, declares real PHI, PII, production secrets, production code, and live patient records forbidden, and rejects sensitive tags. All tests run offline with synthetic data. The CloudFormation template defaults to zero resources, and any future change requires a reviewed change set. This is preparation, not a claim of HIPAA compliance or agent security.”

## Current AWS references

- Amazon Bedrock security and shared responsibility: https://docs.aws.amazon.com/bedrock/latest/userguide/security.html
- Amazon Bedrock data protection: https://docs.aws.amazon.com/bedrock/latest/userguide/data-protection.html
- Amazon Bedrock IAM: https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html
- Model availability and compatibility: https://docs.aws.amazon.com/bedrock/latest/userguide/models.html
- AWS Budgets best practices: https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-best-practices.html
- CloudFormation change-set best practice: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html

## Honest limitations

- Offline checks do not prove AWS permissions, Bedrock access, quotas, regional compatibility, or connectivity.
- Chapter 0 deploys no agent, Guardrail, Knowledge Base, model invocation, Lambda, CodeBuild worker, CI/CD pipeline, or runtime policy.
- Bedrock data-handling features do not remove Northstar’s responsibility to minimize, authorize, classify, log safely, and govern healthcare data.
- Synthetic examples do not prove controls work with every real application or attack.
- A successful Chapter 0 means the team is ready to begin threat modeling in Chapter 1. It does not mean the system is production-ready.
