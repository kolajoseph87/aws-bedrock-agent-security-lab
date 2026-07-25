# Chapter 12 Evidence Checklist

- [ ] Distinct workload identity and minimum IAM role verified for every agent
- [ ] Only the orchestrator role can consume the encrypted handoff queue
- [ ] FIFO source and dead-letter queues match and insecure transport is denied
- [ ] Shared agent credentials and direct peer-to-peer bypass are prohibited
- [ ] Orchestrator and every receiver authorize each handoff independently
- [ ] Signed envelope binds sender, receiver, tenant, repository, task, operation, resource, parent, expiry, nonce, and digest
- [ ] Payload bytes reproduce the signed SHA-256 payload digest
- [ ] Every sender uses its own signing key and only approved handoff paths are accepted
- [ ] Requested operation matches the receiving agent's assigned responsibility
- [ ] Replay, expired messages, forged identity, unknown fields, and revoked capabilities fail closed
- [ ] Delegation cannot expand capability, scope, resource, audience, or expiry
- [ ] Parent signature is independently verified and child sender equals the parent receiver
- [ ] Revocation denies message IDs, nonces, and exact bound capabilities
- [ ] Maximum depth, fan-out, total handoffs, and cycle detection tested
- [ ] Confused-deputy and privilege-laundering tests produce zero side effects
- [ ] Tenant, repository, agent memory, and context isolation tested
- [ ] Retrieved content remains untrusted and cannot create authority
- [ ] Context forwarding excludes raw prompts, code, chunks, tool arguments, PHI, PII, credentials, secrets, and tokens
- [ ] Per-agent tools, network, cost, rate, and blast-radius limits verified
- [ ] Compromised-agent quarantine and downstream capability revocation tested
- [ ] Partial failure does not fall back to a broader identity
- [ ] Every handoff emits privacy-safe, tamper-evident correlation evidence
- [ ] Delegation anomaly, cross-scope, loop, and fan-out alerts tested
- [ ] Self-approval, merge, release, and deployment remain prohibited
- [ ] Twelve harmless multi-agent attacks pass in a non-production environment

Offline validation is design evidence only. Attach live, sanitized handoff and revocation proof from an approved non-production AWS account.
