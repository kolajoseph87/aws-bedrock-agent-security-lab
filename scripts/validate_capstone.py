#!/usr/bin/env python3
"""Deterministic offline validator for the Chapter 14 final capstone."""
import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path


def validate(d, today=None):
    today = today or dt.date.today()
    checks = []
    def add(name, ok, detail):
        checks.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    b=d.get("baseline",{}); s=d.get("scope",{}); a=d.get("authorization",{})
    x=d.get("execution",{}); r=d.get("attack_exercises",{}); e=d.get("evidence",{})
    q=d.get("assessment",{}); t=d.get("teardown",{})
    add("published baseline", b.get("source_commit")=="ce849d8" and b.get("published_test_count")==685 and b.get("chapters_required")==list(range(14)) and all(b.get(k) is True for k in ["all_inherited_tests_required","signed_same_digest_artifacts_required","no_unreviewed_local_changes"]), "Capstone is bound to published Chapters 0–13 and the 685-test baseline.")
    account_ids=s.get("approved_account_ids",[]); regions=s.get("approved_regions",[])
    exact_scope=(
        isinstance(account_ids,list) and len(account_ids)>=1
        and len(set(account_ids))==len(account_ids)
        and all(re.fullmatch(r"[0-9]{12}",v or "") for v in account_ids)
        and isinstance(regions,list) and len(regions)>=1
        and len(set(regions))==len(regions)
        and all(re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]",v or "") for v in regions)
    )
    add("controlled scope", exact_scope and all(s.get(k) is True for k in ["approved_account_allowlist_required","production_accounts_prohibited","approved_regions_only","synthetic_data_only","phi_pii_secrets_and_production_code_prohibited","public_access_prohibited","internet_egress_default_deny"]), "Only explicitly allowlisted non-production accounts, Regions, and synthetic data are allowed.")
    add("disabled deployment", a.get("deployment_disabled_by_default") is True and a.get("reviewed_change_set_required") is True, "Deployment requires an explicit reviewed change set.")
    binding=a.get("example_binding",{})
    binding_valid=(
        isinstance(binding,dict)
        and binding.get("account_id") in account_ids
        and binding.get("region") in regions
        and binding.get("source_commit")=="ce849d8"
        and re.fullmatch(r"sha256:[0-9a-f]{64}",binding.get("artifact_digest","")) is not None
        and isinstance(binding.get("change_ticket"),str) and bool(binding["change_ticket"])
        and isinstance(binding.get("session_ttl_minutes"),int)
        and not isinstance(binding.get("session_ttl_minutes"),bool)
        and 1<=binding["session_ttl_minutes"]<=60
        and binding.get("production_account") is False
        and binding.get("synthetic_data_only") is True
    )
    add("independent authorization", binding_valid and a.get("approvals_bound_to_example") is True and isinstance(a.get("approval_freshness_max_days"),int) and not isinstance(a.get("approval_freshness_max_days"),bool) and 1<=a["approval_freshness_max_days"]<=7 and all(a.get(k) is True for k in ["change_ticket_required","two_independent_approvals_required","short_lived_human_session_required","agent_cannot_deploy_approve_waive_or_accept_risk","account_region_commit_manifest_and_digest_binding_required"]), "Humans independently authorize an account, Region, commit, artifact, ticket, and short-lived session binding.")
    phases=["preflight","deploy","functional-smoke","attack-exercises","incident-drill","recovery","evidence-freeze","teardown","assessment"]
    add("ordered execution", x.get("ordered_phases")==phases and x.get("stop_on_first_critical_failure") is True, "Capstone phases are ordered and fail closed.")
    add("containment before attack", x.get("kill_switch_tested_before_attacks") is True and x.get("side_effects_intercepted_unless_explicitly_approved") is True, "Containment is proven before synthetic attacks.")
    add("bounded execution", all(x.get(k) is True for k in ["budgets_quotas_timeouts_and_concurrency_limits_required","rollback_target_and_teardown_plan_required","resource_inventory_and_owner_tags_required"]), "Cost, runtime, rollback, and ownership are bounded.")
    classes=r.get("classes_required",[])
    add("complete attack campaign", r.get("synthetic_and_harmless_only") is True and r.get("production_targets_prohibited") is True and len(classes)==12 and len(set(classes))==12, "Twelve distinct harmless end-to-end attacks are required.")
    add("deterministic attack oracles", all(r.get(k) is True for k in ["critical_control_failure_blocks_completion","expected_result_bound_before_execution","actual_result_and_evidence_digest_required"]), "Expected and actual outcomes are bound to evidence.")
    add("independent evidence", all(e.get(k) is True for k in ["independent_security_account_required","content_addressed_and_timestamped","source_model_policy_tool_artifact_and_config_versions_required","chain_of_custody_required","cloudtrail_integrity_validation_required","object_lock_compliance_mode_required"]), "Evidence has integrity, provenance, and independent custody.")
    add("privacy safe evidence", e.get("raw_prompts_code_phi_pii_secrets_tokens_and_tool_bodies_prohibited") is True and e.get("generated_evidence_excluded_from_git") is True, "Sensitive bodies and generated evidence stay out of source control.")
    add("evidence retention", isinstance(e.get("minimum_retention_days"),int) and not isinstance(e.get("minimum_retention_days"),bool) and e["minimum_retention_days"]>=400, "Capstone evidence retention is at least 400 days.")
    add("complete assessment", all(q.get(k) is True for k in ["technical_findings_required","control_effectiveness_and_limitations_required","residual_risk_and_remediation_owners_required","executive_summary_required","independent_security_privacy_and_business_review_required"]), "Technical and executive assessment outputs are required.")
    add("no assurance overclaim", q.get("open_critical_findings_allowed") is False and q.get("production_authorization_claimed") is False and q.get("compliance_certification_claimed") is False and q.get("maximum_outcome")=="CONTROLLED_NONPRODUCTION_CAPSTONE_VALIDATED", "The capstone cannot claim production authorization or certification.")
    add("verified teardown", all(t.get(k) is True for k in ["inventory_reconciled_before_and_after","temporary_access_and_grants_revoked","queues_jobs_sessions_and_work_orders_invalidated","ephemeral_resources_destroyed","retained_evidence_explicitly_allowlisted","orphan_resource_and_cost_checks_required","teardown_failure_blocks_completion"]), "Cleanup and revocation are part of the pass condition.")
    failures=d.get("safe_failures",[])
    required={"scope_substitution","source_substitution","agent_authority","missing_approval","sensitive_data","evidence_tampering","critical_regression","telemetry_failure","containment_failure","recovery_failure","teardown_failure","assurance_overclaim"}
    add("safe failure contracts", len(failures)==12 and {z.get("class") for z in failures}==required and len({z.get("id") for z in failures})==12 and all(z.get("expected")=="BLOCK" and z.get("aws_calls")==0 and z.get("side_effects")==0 for z in failures), "Twelve failure paths block without side effects.")
    review=d.get("review",{})
    try:
        expiry=dt.date.fromisoformat(review.get("review_expires",""))
        current=today<=expiry and (expiry-today).days<=90
    except (TypeError,ValueError):
        current=False
    add("current independent review", bool(review.get("owner")) and bool(review.get("independent_assessor")) and review.get("owner")!=review.get("independent_assessor") and current and review.get("evidence_contains_sensitive_values") is False, "Review is current, independent, and privacy safe.")
    limits=" ".join(d.get("limitations",[])).lower()
    add("honest limitations", len(d.get("limitations",[]))>=7 and "does not deploy or invoke aws" in limits and "not production authorization" in limits and "not hipaa compliance" in limits, "Offline scope and assurance limitations are explicit.")
    add("nonproduction only", d.get("environment")=="controlled-non-production", "The capstone is never a production deployment.")
    add("exact chapter contract", d.get("chapter")==14, "Evidence is bound to Chapter 14.")
    return checks


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",required=True)
    p.add_argument("--evidence",required=True)
    args=p.parse_args()
    raw=Path(args.manifest).read_bytes()
    checks=validate(json.loads(raw))
    result={"chapter":14,"mode":"offline","manifest_sha256":hashlib.sha256(raw).hexdigest(),"aws_calls":0,"deployments":0,"attacks_executed":0,"production_authorizations":0,"checks":checks}
    out=Path(args.evidence); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    for check in checks:
        print(f'{check["status"]}: {check["name"]}')
    if any(check["status"]=="FAIL" for check in checks):
        raise SystemExit(1)
    print(f"{len(checks)} Chapter 14 capstone checks passed")


if __name__=="__main__":
    main()
