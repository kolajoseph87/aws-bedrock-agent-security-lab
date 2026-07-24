# Chapter 11 Evidence Checklist

- [ ] Independent incident commander and two-person break-glass approval tested
- [ ] Signed response commands use strict schemas and expire within 15 minutes
- [ ] Two distinct approvers are verified and neither is the requester
- [ ] Successful command verification consumes the single-use nonce
- [ ] Kill switch blocks model, RAG, tool, worker, repository, release, and deployment paths
- [ ] Propagation measured at 60 seconds or less
- [ ] Missing incident-state service fails closed
- [ ] Unknown actions and malformed incident state fail closed
- [ ] STS sessions, work orders, nonces, approvals, secrets, KMS grants, repository tokens, and pipeline authority revoked
- [ ] Scoped and global containment tested
- [ ] Model, policy, knowledge source, tool, and worker-image quarantine tested
- [ ] Evidence copied to the independent security account with hashes and chain of custody
- [ ] CloudTrail digest validation and S3 Object Lock verified
- [ ] Evidence excludes prompts, completions, source, retrieved chunks, PHI, PII, credentials, and tokens
- [ ] Nested sensitive evidence fields are removed before preservation
- [ ] Separate-account archive proves KMS, Object Lock compliance mode, legal hold, and CloudTrail digest validation
- [ ] Known-good clean-room rebuild and exact artifact digest verified
- [ ] RAG resynchronization and post-delete negative retrieval test passed
- [ ] Full Chapter 10 adversarial regression passed
- [ ] Independent recovery approval, canary, enhanced monitoring, and rollback tested
- [ ] Recovery requires new authorization and revoked artifacts remain rejected
- [ ] Twelve incident playbooks table-topped with Legal, Privacy, Security, and Operations

Offline validation is design evidence only. Attach separate live, sanitized proof from an approved non-production account.
