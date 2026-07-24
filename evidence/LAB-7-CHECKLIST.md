# Chapter 7 evidence checklist

- [ ] Exact principal, repository, immutable commit, operation, paths, and arguments approved
- [ ] Signed, expiring, single-use work order and replay test
- [ ] Return-of-control parameters independently validated
- [ ] Separate worker role with no Bedrock, secret, push, merge, release, or deploy authority
- [ ] Fresh disposable workspace and post-job destruction verified
- [ ] Non-privileged worker with no Docker socket or inbound access
- [ ] Server-derived allowlisted commands and path containment tested
- [ ] CPU, memory, process, file, timeout, concurrency, and output limits tested
- [ ] Default-deny network egress and approved endpoint tests
- [ ] Immutable source and build image digests verified
- [ ] Diff, artifact, test output, and logs scanned before release
- [ ] Content-addressed patch and sanitized audit evidence
- [ ] Independent human review before repository write
- [ ] Live availability, quota, lifecycle, access, image, and pricing checks
- [ ] Cleanup and emergency revocation tested

Offline artifacts are design evidence only. They do not prove live AWS isolation, authorization, cleanup, HIPAA compliance, or production readiness.
