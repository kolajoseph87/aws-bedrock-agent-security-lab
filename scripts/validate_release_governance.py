#!/usr/bin/env python3
"""Offline validator for Chapter 8 release-governance controls."""
import argparse, datetime as dt, json
from pathlib import Path

ORDER=["PATCH_ARTIFACT","VERIFY_PROVENANCE","SECURITY_TESTS","BUILD","SIGN","INDEPENDENT_APPROVAL","RELEASE","DEPLOY"]
def validate(d,today=None):
 today=today or dt.date.today(); out=[]
 def add(n,ok,x): out.append({"name":n,"status":"PASS" if ok else "FAIL","detail":x})
 s=d.get("source_policy",{}); p=d.get("provenance",{}); g=d.get("security_gates",{}); dep=d.get("dependency_policy",{})
 a=d.get("artifact_policy",{}); deploy=d.get("deployment_policy",{}); h=d.get("healthcare_controls",{}); audit=d.get("audit",{}); aws=d.get("aws_controls",{}); review=d.get("review_and_evidence",{})
 add("synthetic non-production scope",d.get("environment")!="production" and d.get("data_classification")=="synthetic-only" and h.get("synthetic_data_only") is True and h.get("real_phi_allowed") is False and h.get("real_pii_allowed") is False and deploy.get("production_data_in_ci_allowed") is False,"CI uses synthetic data only.")
 add("complete release order",d.get("pipeline_order")==ORDER,"Provenance and gates precede release and deployment.")
 add("protected independently reviewed source",all(s.get(k) is True for k in ["protected_branch_required","codeowners_required","stale_approvals_dismissed","head_sha_revalidated","pipeline_changes_need_security_owner"]) and s.get("direct_push_allowed") is False and s.get("force_push_allowed") is False and s.get("agent_can_merge") is False and s.get("agent_can_approve") is False and s.get("required_reviewers",0)>=2,"Branch protection prevents agent self-promotion.")
 add("verifiable build provenance",all(p.get(k) is True for k in ["chapter7_patch_hash_required","immutable_source_sha_required","trusted_builder_identity_required","build_definition_hash_required","slsa_provenance_required","sbom_required","dependency_lockfile_required"]) and p.get("untrusted_fork_credentials_allowed") is False,"Every build is bound to source, builder, definition, SBOM, and patch.")
 add("mandatory fail-closed security gates",all(g.get(k) is True for k in ["sast_required","sca_required","secret_scan_required","iac_scan_required","malware_scan_required","unit_tests_required","policy_tests_required"]) and g.get("critical_findings_allowed")==0 and g.get("high_findings_allowed")==0 and g.get("fail_mode")=="closed","Required tests block on failure.")
 add("governed risk waivers",g.get("waivers_expire") is True and g.get("waivers_need_independent_risk_owner") is True,"Exceptions are independent and temporary.")
 add("hardened dependencies",all(dep.get(k) is True for k in ["allowlisted_registries_only","versions_pinned","integrity_hashes_required","new_dependency_review_required","license_policy_required","artifact_quarantine_required"]) and dep.get("mutable_tags_allowed") is False and dep.get("install_scripts_allowed") is False,"Dependencies are pinned, verified, reviewed, and quarantined.")
 add("signed immutable artifacts",all(a.get(k) is True for k in ["reproducible_build_check_required","customer_managed_kms_key_required","artifact_digest_required","cosign_signature_required","signature_verified_before_release","immutable_storage_required","retention_required"]),"Artifacts are reproducible, encrypted, signed, immutable, and retained.")
 add("same artifact promoted",a.get("promotion_by_digest_only") is True and a.get("rebuild_between_environments") is False,"The verified digest is promoted without rebuilding.")
 add("separated deployment authority",deploy.get("agent_can_release") is False and deploy.get("agent_can_deploy") is False and all(deploy.get(k) is True for k in ["pipeline_role_separate_from_build_role","production_role_separate","oidc_temporary_credentials_only","environment_approval_required","change_ticket_required"] ) and deploy.get("long_lived_cloud_credentials_allowed") is False,"Build and deployment identities are separate and temporary.")
 add("safe production rollout",deploy.get("canary_or_blue_green_required") is True and deploy.get("automatic_rollback_required") is True,"Production rollout is limited and reversible.")
 add("healthcare-safe evidence",h.get("logs_artifacts_sbom_provenance_scanned") is True and h.get("sensitive_bodies_in_evidence_allowed") is False,"Evidence is scanned and contains no sensitive bodies.")
 req={"correlation_id","repository_id","source_sha","patch_hash","builder_identity","build_definition_hash","sbom_hash","artifact_digest","signature_identity","approver_id","target_environment","decision","reason_code","timestamp"}
 forbidden={"source_body","patch_body","patient_identifier","access_token","secret_value","cloud_credential","command_output"}
 add("sanitized release audit",req.issubset(set(audit.get("required_fields",[]))) and forbidden.issubset(set(audit.get("forbidden_fields",[]))) and audit.get("append_only_destination_required") is True,"Audit records hashes and identities, not sensitive bodies.")
 add("AWS pipeline safeguards",all(aws.get(k) is True for k in ["codepipeline_v2_required","artifact_store_encrypted","cloudtrail_required","eventbridge_alerting_required","inspector_or_approved_scanner_required","signer_profile_required","live_availability_quota_access_lifecycle_pricing_check_required"]) and aws.get("codebuild_privileged_mode") is False,"AWS pipeline is encrypted, observable, non-privileged, and signed.")
 attacks=d.get("safe_attacks",[]); ids=[x.get("id") for x in attacks]
 add("safe attack contracts",len(attacks)>=12 and len(ids)==len(set(ids)) and None not in ids and all(x.get("stop_at") in ORDER and x.get("deployments")==0 and x.get("prohibited_side_effects")==0 for x in attacks),"Attacks stop with no deployment or prohibited effects.")
 try: current=today<=dt.date.fromisoformat(review.get("review_expires",""))
 except (TypeError,ValueError): current=False
 add("current independent review",bool(review.get("owner")) and current and review.get("independent_approval_required") is True and review.get("negative_tests_required") is True and review.get("live_signature_provenance_rollback_tests_required") is True and review.get("evidence_contains_sensitive_values") is False,"Review is current and live proof remains required.")
 limits=" ".join(d.get("limitations",[])).lower()
 add("honest offline limitations",len(d.get("limitations",[]))>=7 and "does not invoke aws" in limits and "does not build, sign, release, or deploy" in limits and "does not prove live iam" in limits and "does not prove hipaa compliance" in limits,"Offline checks are not represented as production proof.")
 add("exact chapter contract",d.get("chapter")==8,"Evidence is bound to Chapter 8.")
 return out
def main():
 p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--evidence",required=True); x=p.parse_args()
 checks=validate(json.loads(Path(x.manifest).read_text()))
 e={"chapter":8,"mode":"offline","aws_calls":0,"builds":0,"releases":0,"deployments":0,"resources_created":0,"prohibited_side_effects":0,"checks":checks}
 o=Path(x.evidence); o.parent.mkdir(parents=True,exist_ok=True); o.write_text(json.dumps(e,indent=2)+"\n")
 for c in checks: print(f'{c["status"]}: {c["name"]}')
 if any(c["status"]=="FAIL" for c in checks): raise SystemExit(1)
 print(f"{len(checks)} Chapter 8 release-governance checks passed")
if __name__=="__main__": main()
