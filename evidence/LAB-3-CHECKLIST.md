# Chapter 3 Evidence Checklist

- [ ] Model inventory has exact IDs, Region, owner, use, review, and expiry.
- [ ] Only synthetic data and non-production source are permitted.
- [ ] Caller identity, repository, and purpose are checked before invocation.
- [ ] The policy fails closed before a model call.
- [ ] IAM allows only the approved inference action and model resource.
- [ ] PHI, PII, and credentials are checked deterministically before and after the model.
- [ ] Prompt, completion, and request-body logging are disabled.
- [ ] Token, request, timeout, randomness, and cost limits are enforced.
- [ ] Model changes require evaluation, independent approval, and rollback.
- [ ] Negative tests make zero model calls and create zero side effects.
- [ ] Evidence contains decisions and identifiers, not code, prompts, PHI, PII, or secrets.

Passing this checklist is educational evidence, not HIPAA certification or production approval.
