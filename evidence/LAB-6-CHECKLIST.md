# Chapter 6 evidence checklist

- [ ] Approved immutable source version, owner, classification, and provenance hash
- [ ] Synthetic-only ingestion scan passed
- [ ] Poisoned documents quarantined with zero ingestion
- [ ] Exact Knowledge Base and role permissions reviewed
- [ ] Server-derived repository and tenant filters tested
- [ ] Cross-repository retrieval denied
- [ ] Retrieved chunks independently scanned
- [ ] Citations and source hashes revalidated
- [ ] Deleted content no longer retrievable after sync/direct deletion
- [ ] CloudTrail and CloudWatch evidence sanitized
- [ ] Live availability, quota, lifecycle, access, and pricing checked
- [ ] No prompts, chunks, PHI, PII, secrets, or source bodies in evidence

Offline artifacts are design evidence only. They do not prove live AWS enforcement, deletion, HIPAA compliance, or production readiness.
