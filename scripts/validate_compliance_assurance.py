#!/usr/bin/env python3
"""Deterministic offline validator for Chapter 13 compliance assurance."""
import argparse, datetime as dt, hashlib, json, re
from pathlib import Path

def validate(d, today=None):
    today=today or dt.date.today(); checks=[]
    def add(n,ok,detail): checks.append({"name":n,"status":"PASS" if ok else "FAIL","detail":detail})
    f=d.get("frameworks",{}); c=d.get("control_records",{}); e=d.get("evidence",{})
    a=d.get("assurance",{}); p=d.get("production_gate",{}); q=d.get("continuous_compliance",{})
    framework_names=["owasp_agentic_ai","nist_ai_rmf","mitre_atlas","hipaa_security_rule","aws_well_architected"]
    add("framework coverage", all(isinstance(f.get(x),dict) and isinstance(f[x].get("version"),str) and f[x]["version"] for x in framework_names), "Five assurance perspectives are explicitly versioned and mapped.")
    add("owasp agentic mapping", all(f.get("owasp_agentic_ai",{}).get(x) is True for x in ["version_pinned","control_mapping_required"]), "OWASP mappings are pinned and traceable.")
    add("nist ai rmf lifecycle", all(f.get("nist_ai_rmf",{}).get(x) is True for x in ["govern_map_measure_manage_covered","profiles_and_residual_risk_required"]), "Govern, Map, Measure, and Manage are covered.")
    add("threat informed assurance", all(f.get("mitre_atlas",{}).get(x) is True for x in ["threat_mapping_required","detection_and_mitigation_mapping_required"]), "ATLAS threats connect to detections and mitigations.")
    add("hipaa applicability", all(f.get("hipaa_security_rule",{}).get(x) is True for x in ["applicability_review_required","administrative_physical_technical_safeguards_reviewed","risk_analysis_required","minimum_necessary_required"]), "HIPAA applicability and safeguards require professional review.")
    add("aws architecture review", all(f.get("aws_well_architected",{}).get(x) is True for x in ["security_pillar_review_required","ai_lens_review_required"]), "AWS architecture review is required.")
    records=c.get("records",[])
    record_fields={"control_id","chapter","requirement","implementation","test","owner","independent_approver","evidence_sha256","source_commit","status","framework_refs"}
    records_valid=(
        isinstance(records,list)
        and len(records)==13
        and {x.get("chapter") for x in records if isinstance(x,dict)}==set(range(13))
        and len({x.get("control_id") for x in records if isinstance(x,dict)})==13
        and all(
            isinstance(x,dict)
            and set(x)==record_fields
            and all(isinstance(x.get(k),str) and x[k] for k in record_fields-{"chapter","framework_refs"})
            and isinstance(x.get("framework_refs"),list)
            and len(x["framework_refs"])>=2
            and x["owner"]!=x["independent_approver"]
            and re.fullmatch(r"sha256:[0-9a-f]{64}",x["evidence_sha256"]) is not None
            and x["source_commit"]=="00ccafc"
            and x["status"]=="SYNTHETIC_TRAINING_ONLY"
            for x in records
        )
    )
    add("traceable control records", all(c.get(x) is True for x in ["unique_control_ids","implementation_status_required","owner_and_approver_required","test_procedure_and_frequency_required","evidence_locator_and_digest_required","source_commit_model_policy_and_config_bound"]) and records_valid, "Every Chapter 0–12 control is uniquely identified, owned, mapped, synthetically evidenced, and bound to corrected commit 00ccafc.")
    add("time bound exceptions", all(c.get(x) is True for x in ["exceptions_have_owner_expiry_and_compensating_controls","expired_or_unapproved_exceptions_block_release"]), "Exceptions cannot silently become permanent.")
    add("trustworthy evidence", all(e.get(x) is True for x in ["machine_verifiable_preferred","tamper_evident_and_content_addressed","collection_identity_and_timestamp_required","chain_of_custody_required","retention_and_disposal_policy_required","independent_security_account_required"]), "Evidence has provenance, integrity, custody, and retention.")
    add("privacy safe evidence", e.get("raw_prompts_code_phi_pii_secrets_or_tokens_prohibited") is True and e.get("screenshots_alone_sufficient") is False and e.get("self_attestation_alone_sufficient") is False, "Evidence exposes no sensitive bodies and requires stronger proof than screenshots.")
    add("layered assurance", all(a.get(x) is True for x in ["design_review_required","automated_tests_required","live_nonproduction_validation_required","adversarial_testing_required","incident_recovery_drill_required","independent_assessor_required","sampling_scope_and_limitations_recorded"]), "Design, automation, live tests, attacks, recovery, and independent assessment are required.")
    add("finding governance", a.get("open_critical_findings_allowed") is False and a.get("open_high_findings_require_approved_time_bound_plan") is True, "Critical findings block and high findings require bounded remediation.")
    add("production readiness gate", all(p.get(x) is True for x in ["inventory_and_data_flow_current","threat_model_current","privacy_and_legal_review_required","model_and_vendor_due_diligence_required","identity_network_rag_tool_release_monitoring_ir_controls_verified","backup_rollback_kill_switch_and_support_ready","slo_capacity_cost_and_abuse_limits_verified","runbooks_training_and_oncall_required"]), "Technical and operational readiness are verified together.")
    add("independent risk decision", all(p.get(x) is True for x in ["change_ticket_and_two_independent_approvals_required","residual_risk_acceptance_by_accountable_executive_required","agent_cannot_approve_waive_or_accept_risk","fail_closed_on_missing_stale_or_conflicting_evidence"]), "Only accountable humans can authorize residual production risk.")
    add("continuous reassessment", all(q.get(x) is True for x in ["control_drift_detection_required","material_change_triggers_reassessment","model_policy_tool_data_dependency_or_architecture_change_material","continuous_monitoring_and_periodic_access_review_required","annual_risk_analysis_is_maximum_not_only_cadence"]) and 0<q.get("evidence_freshness_max_days",0)<=90, "Drift, material changes, and stale evidence trigger reassessment.")
    attacks=d.get("safe_failures",[]); required={"missing_evidence","stale_evidence","forged_evidence","self_approval","expired_exception","critical_finding","unmapped_control","scope_substitution","paper_compliance","sensitive_evidence","material_drift","agent_risk_acceptance"}
    add("safe assurance failures", len(attacks)>=12 and {x.get("class") for x in attacks}==required and len({x.get("id") for x in attacks})==len(attacks) and all(x.get("expected")=="BLOCK" and x.get("aws_calls")==0 and x.get("side_effects")==0 for x in attacks), "Twelve harmless assurance failures have deterministic blocking oracles.")
    r=d.get("review_and_evidence",{})
    try: exp=dt.date.fromisoformat(r.get("review_expires","")); current=today<=exp and (exp-today).days<=90
    except (TypeError,ValueError): current=False
    add("current accountable review", bool(r.get("owner")) and bool(r.get("accountable_executive")) and current and all(r.get(x) is True for x in ["independent_approval_required","legal_privacy_review_required"]) and r.get("evidence_contains_sensitive_values") is False, "Review is current, independent, accountable, and privacy safe.")
    limits=" ".join(d.get("limitations",[])).lower()
    add("honest assurance limits", len(d.get("limitations",[]))>=7 and "does not invoke aws" in limits and "does not audit a live aws account" in limits and "does not establish hipaa compliance" in limits, "The lab does not claim certification or live effectiveness.")
    add("non-production only", d.get("environment")=="non-production" and d.get("system",{}).get("production_use_authorized") is False, "The lab cannot authorize production.")
    add("exact chapter contract", d.get("chapter")==13, "Evidence is bound to Chapter 13.")
    return checks

def main():
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--evidence",required=True); x=p.parse_args()
    raw=Path(x.manifest).read_bytes(); checks=validate(json.loads(raw))
    result={"chapter":13,"mode":"offline","manifest_sha256":hashlib.sha256(raw).hexdigest(),"aws_calls":0,"audits_performed":0,"certifications_claimed":0,"production_authorizations":0,"checks":checks}
    out=Path(x.evidence); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2)+"\n")
    for q in checks: print(f'{q["status"]}: {q["name"]}')
    if any(q["status"]=="FAIL" for q in checks): raise SystemExit(1)
    print(f"{len(checks)} Chapter 13 compliance-assurance checks passed")
if __name__=="__main__": main()
