# Chapter 5 Evidence Checklist

## Offline proof

- [ ] 16 runtime-policy checks pass.
- [ ] 35 Chapter 5 tests pass.
- [ ] Python compilation passes.
- [ ] No generated evidence, caches, credentials, PHI, PII, production code, or secrets are packaged.
- [ ] CloudFormation defaults to `DeployChapter5RuntimePolicy=false`.

## Required live proof before deployment claims

- [ ] Current Bedrock and Lambda availability, access, quotas, lifecycle, and pricing verified.
- [ ] Temporary AWS identity and exact IAM conditions verified.
- [ ] Approved Guardrail ID enforced for model invocation.
- [ ] Action group returns control before tool execution.
- [ ] Policy artifact signature, digest, version, rollback, and independent approval verified.
- [ ] Policy timeout and error fail closed.
- [ ] Worker revalidates principal, resource, action, arguments hash, TTL, and replay protection.
- [ ] Write requires independent approval bound to the exact patch.
- [ ] Private networking and endpoint policies verified.
- [ ] Code signing and approved Lambda code artifact verified.
- [ ] Input denial produces zero Bedrock calls.
- [ ] Tool denial produces zero worker calls and zero target change.
- [ ] Output denial releases no PHI, PII, credential, source body, or false action claim.
- [ ] One trusted correlation ID joins policy, model, worker, and audit evidence.
- [ ] Evidence contains no full prompt, output, code body, patient identifier, token, header, or secret.
- [ ] Independent reviewer signs the results and expiration date.

Passing offline checks does not establish HIPAA compliance or production readiness.
