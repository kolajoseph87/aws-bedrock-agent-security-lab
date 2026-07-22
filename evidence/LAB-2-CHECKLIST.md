# Lab 2 Evidence Checklist

Use synthetic identifiers only. Never paste PHI, PII, credentials, prompts, source code, full account IDs, or secret values into evidence.

- [ ] Offline network validator passed.
- [ ] Full cumulative test suite passed.
- [ ] VPC and subnet CIDRs are approved and non-overlapping.
- [ ] Agent, worker, and interface-endpoint trust zones are separate.
- [ ] No subnet assigns public IP addresses.
- [ ] No Internet Gateway, NAT Gateway, or default Internet route exists in the lab design.
- [ ] Required Bedrock and supporting-service endpoints are approved for the selected Region.
- [ ] Interface endpoints have private DNS enabled.
- [ ] Endpoint policies and IAM policies use least privilege.
- [ ] Security groups contain no `0.0.0.0/0` or `::/0` rules.
- [ ] Direct worker Internet access is denied.
- [ ] Every denied negative test proves zero prohibited side effects.
- [ ] Live-environment flow logs and DNS logs have approved retention, redaction, and reader roles.
- [ ] Reviewer recorded CloudFormation validation and change-set results, if AWS tools were available.
- [ ] Reviewer recorded that private networking does not replace runtime authorization.

Reviewer: ____________________  Date: ____________________
