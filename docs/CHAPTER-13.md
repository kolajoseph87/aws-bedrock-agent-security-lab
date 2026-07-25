# Chapter 13 — Compliance, assurance, and production readiness

## Goal

Turn the technical controls from Chapters 0–12 into an auditable assurance case without confusing documentation with proof.

> A control is not production-ready because it is documented; it must be mapped, implemented, tested, evidenced, owned, and independently approved.

## What the frameworks contribute

| Framework | Question it helps answer |
| --- | --- |
| OWASP Agentic AI | Which agent-specific failures must the design prevent? |
| NIST AI RMF | How will the organization govern, map, measure, and manage AI risk? |
| MITRE ATLAS | Which adversary behaviors should tests and detections cover? |
| HIPAA Security Rule | Which safeguards and risk-analysis duties may apply to electronic protected health information? |
| AWS Well-Architected | Is the cloud architecture securely and operationally designed? |

No framework replaces the others, and a crosswalk is not evidence that a control works.

## The assurance chain

Every control record must link:

`requirement → implementation → exact version → test → result → evidence digest → owner → independent approval → residual risk`

Missing, stale, conflicting, or substituted evidence blocks the gate. Screenshots and self-attestation may support context but are never sufficient alone.

The included manifest contains synthetic training records, not live compliance
evidence. A production gate must independently recompute evidence hashes,
verify collection identity and timestamps, confirm the exact source, model, and
policy versions, and reject duplicate control identifiers.

## Production-readiness decision

The final gate checks current inventory and data flows; threat model; privacy and legal review; model and vendor due diligence; identity, network, RAG, tool, release, monitoring, and incident controls; capacity and cost protections; support and on-call readiness; backup, rollback, kill switch, and recovery exercises.

The agent cannot approve itself, waive findings, accept residual risk, or authorize production. Two independent approvals and accountable executive acceptance are required for the exact assessed version. Control owners, independent reviewers, and the accountable executive must be different people.

## Continuous compliance

Assurance expires. Model, policy, prompt, tool, dependency, RAG source, data classification, identity, network, or architecture changes can invalidate earlier evidence. Control drift, stale evidence, incidents, new threats, and material changes trigger reassessment.

## Run the offline lab

```bash
python3 scripts/validate_compliance_assurance.py \
  --manifest compliance-assurance/compliance-assurance.aws.json \
  --evidence evidence/lab-13-validation.json
python3 -m unittest discover -s tests -v
python3 -m compileall scripts tests python
```

This performs no AWS audit, compliance certification, or production authorization. Use synthetic evidence only. Review the disabled CloudFormation reference in a change set before any approved non-production deployment.
