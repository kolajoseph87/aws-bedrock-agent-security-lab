# Chapter 12 — Multi-Agent Security and Secure Orchestration

## Goal

Allow specialized agents to collaborate without allowing identity forgery, authority amplification, cross-scope data access, or one compromised agent to take over the workflow.

## Simple mental model

A multi-agent system is a hospital team. A nurse, pharmacist, surgeon, and billing clerk have different badges and duties. A note from one person does not give another person every permission the sender has. The receiver checks who sent it, what exact task was delegated, which patient and record it concerns, when it expires, and whether the request is still authorized.

> Every agent gets its own identity, minimum authority, authenticated messages, and bounded delegation—trust never transfers automatically.

## Trust boundaries

Northstar separates the planner, retriever, policy evaluator, patch worker, reviewer, and release controller. Every agent uses a distinct workload identity. Agents do not share credentials or bypass the orchestrator with peer-to-peer calls.

The orchestrator is a policy enforcement point, not a super-agent. It authenticates both parties, validates the signed handoff envelope, checks revocation, and sends only the minimum recipient-specific context. The receiver independently authorizes the request again.

## Secure handoff envelope

Every message binds the sender, receiver, tenant, repository, task, operation, resource, capability, parent, correlation ID, issue and expiry time, single-use nonce, delegation depth, and payload digest. Unknown fields fail closed. A name written inside a prompt is never identity.

Messages expire within five minutes and cannot be replayed. Encryption protects transport; signatures and digests protect origin and integrity.

The offline verifier uses a separate signing key for every sender, verifies the
payload against its SHA-256 digest, restricts each sender-to-receiver path, and
requires the operation expected by the receiver. A child must be sent by its
parent's authenticated receiver; otherwise the handoff is denied as privilege
laundering.

## Delegation is attenuation

A child can receive less authority than its parent, never more. Scope cannot expand, expiry cannot extend, and the capability is bound to the intended recipient, operation, and resource. Every hop checks the revocation list.

The parent envelope and signature are independently verified before child
authority is considered. Revocation may target the message ID, nonce, or exact
operation/audience/resource capability.

The workflow permits at most three delegation levels, four children per agent, and twelve total handoffs. Cycles are rejected. These limits stop infinite agent conversations, cost explosions, and privilege laundering.

## Confused deputy protection

A privileged receiver must not use its authority merely because another agent asked. It checks that the caller is allowed to request this exact operation for this exact tenant, repository, commit, and path. Cross-tenant or cross-repository context is denied before retrieval or tool execution.

Retrieved text remains untrusted data. It cannot invent an agent, capability, approval, or new task.

## Cascading-compromise containment

Each agent has its own tool allowlist, network egress allowlist, rate limit, cost limit, and blast-radius boundary. A compromised agent is quarantined, its capabilities and downstream delegations are revoked, and Chapter 11's kill switch can stop the workflow. Partial failures never fall back to a broader identity.

## Human authority remains separate

Agents may propose plans, retrievals, policies, and patches. They cannot approve themselves, merge, release, or deploy. Irreversible actions require independent human and pipeline authorization from Chapters 7 and 8.

## Run the offline lab

```bash
python3 scripts/validate_multi_agent_security.py \
  --manifest multi-agent-security/multi-agent-security.aws.json \
  --evidence evidence/lab-12-validation.json
python3 -m unittest discover -s tests -v
```

The lab sends no messages, invokes no model or AWS service, assumes no role, and changes no repository or deployment. The CloudFormation file is a disabled reference skeleton; live non-production integration tests are still required.

The reference declares all six agent roles plus a separate orchestrator role.
Agents can submit handoffs, but only the orchestrator role can consume the
shared queue. The FIFO dead-letter queue matches the FIFO source queue, TLS is
required, and every role trust policy binds the source AWS account. The
template still does not implement signing, receiver authorization, runtime
isolation, or revocation.

Amazon Bedrock Agents is now named Bedrock Agents Classic and AWS says it will
close to new customers on July 30, 2026. The lab therefore keeps the security
contract independent of the orchestration runtime: apply the same identity,
message, delegation, authorization, and containment rules to AgentCore or a
custom orchestrator. A supervisor/collaborator configuration alone does not
implement these controls.

## Safe exercises

Test forged senders, replay, confused-deputy requests, privilege amplification, delegation cycles, excessive fan-out, cross-tenant and cross-repository context, indirect instructions, self-approval, cascading compromise, and telemetry suppression. Every exercise uses synthetic fixtures and zero prohibited side effects.

## Current AWS references

- [Amazon Bedrock multi-agent collaboration](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-multi-agent-collaboration.html)
- [AWS confused-deputy prevention](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [Amazon SQS FIFO deduplication](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues-exactly-once-processing.html)
