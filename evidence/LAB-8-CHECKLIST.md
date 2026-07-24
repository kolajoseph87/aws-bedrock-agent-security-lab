# Chapter 8 Evidence Checklist

- [ ] Exact Chapter 7 patch hash and immutable source SHA recorded
- [ ] Protected branch, CODEOWNERS, two reviewers, stale-approval dismissal, and head-SHA revalidation demonstrated
- [ ] Agent merge, approval, release, and deployment attempts denied
- [ ] SAST, SCA, secret, IaC, malware, unit, and policy gates demonstrated fail closed
- [ ] Dependency registry, version pin, lockfile, and integrity policy verified
- [ ] SBOM and provenance hashes recorded without source or sensitive bodies
- [ ] Trusted builder and build-definition identities verified
- [ ] Artifact digest signed and signature verified
- [ ] Artifact store encryption, immutability, and retention verified
- [ ] Build, pipeline, and production roles proven separate
- [ ] Temporary identity and environment approval demonstrated
- [ ] Canary or blue/green rollout and automatic rollback tested
- [ ] Twelve harmless negative tests produce zero deployments
- [ ] Live availability, quota, access, lifecycle, and pricing checked

Never place PHI, PII, credentials, source bodies, patch bodies, tokens, command output, or cloud credentials in evidence.
