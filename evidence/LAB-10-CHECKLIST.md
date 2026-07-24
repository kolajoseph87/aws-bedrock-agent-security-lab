# Lab 10 Evidence Checklist

- [ ] Chapter 10 validator reports 17 passing checks
- [ ] All cumulative unit tests pass
- [ ] Only synthetic, non-production fixtures are used
- [ ] Twelve required attack classes have unique case IDs and denial oracles
- [ ] Corpus version, digest, approval, and immutable location are verified
- [ ] Signed evaluation binding expires within five minutes and its nonce cannot be replayed
- [ ] Source, model, policy, tool, corpus, and evaluator versions match exactly
- [ ] Result schema, complete attack-class coverage, repeated runs, and per-class thresholds are verified
- [ ] Signed result-bundle digest is verified before promotion
- [ ] Evaluator uses approved private subnets, approved endpoints, and one concurrent job per repository
- [ ] Evaluator image is pinned by digest and the result archive uses S3 Object Lock compliance mode
- [ ] Evaluator image and harness signatures are verified
- [ ] Runner identity and source/model/policy/tool/corpus bindings are attested
- [ ] Network egress and production access are denied
- [ ] Repository writes, deployment, and real tool side effects are impossible
- [ ] Tool side effects are intercepted and recorded as zero
- [ ] Critical failure blocks promotion regardless of aggregate score
- [ ] Security regression blocks promotion
- [ ] Repeated runs and per-class thresholds cover probabilistic behavior
- [ ] Seeded corpus/result substitution and replay tests are denied
- [ ] Model-based scoring is not the sole authority
- [ ] Result bundle is signed, encrypted, immutable, and privacy-safe
- [ ] No prompts, completions, source, patches, PHI, PII, or credentials appear in evidence
- [ ] Independent security approval is current
- [ ] Live AWS availability, Region, quota, IAM, lifecycle, and pricing checks are retained

Generated `evidence/lab-10-validation.json` is local evidence and must remain excluded from Git.
