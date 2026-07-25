# Chapter 13 evidence checklist

Do not place prompts, completions, source code, patches, PHI, PII, credentials, secrets, or tokens in evidence.

- [ ] System inventory, owners, data flow, model, policy, tools, RAG sources, and environments are current.
- [ ] Controls map to OWASP Agentic AI, NIST AI RMF, MITRE ATLAS, applicable HIPAA safeguards, and AWS Well-Architected.
- [ ] Every control has an implementation owner, independent approver, test, cadence, result, evidence digest, and exact version scope.
- [ ] Evidence digests were recomputed from the collected artifacts and match the recorded SHA-256 values.
- [ ] Control IDs are unique and all evidence timestamps fall within the approved freshness window.
- [ ] Chapters 0–12 tests and validators pass against the exact source commit.
- [ ] Live validation occurred only in an approved isolated non-production account.
- [ ] Red-team, incident-response, kill-switch, rollback, backup, and recovery exercises passed.
- [ ] Critical findings are closed; high findings have independently approved, expiring remediation plans.
- [ ] Legal, privacy, vendor, architecture, operations, support, and security reviews are recorded.
- [ ] Two independent approvers and a separate accountable executive accepted the exact assessed version and residual risk.
- [ ] Evidence is privacy safe, content addressed, encrypted, immutable, access controlled, and retained under policy.
- [ ] Exceptions have owners, business justification, compensating controls, approval, and expiration.
- [ ] Material changes and stale evidence automatically reopen assessment.

Passing this checklist is educational evidence, not a certification, legal opinion, HIPAA determination, or production authorization.
