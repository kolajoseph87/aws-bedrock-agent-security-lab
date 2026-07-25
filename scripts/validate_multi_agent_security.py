#!/usr/bin/env python3
"""Deterministic offline validator for Chapter 12 multi-agent security."""
import argparse, datetime as dt, json
from pathlib import Path

def validate(d, today=None):
    today=today or dt.date.today(); checks=[]
    def add(n,ok,detail): checks.append({"name":n,"status":"PASS" if ok else "FAIL","detail":detail})
    a=d.get("architecture",{}); m=d.get("messages",{}); g=d.get("delegation",{})
    z=d.get("authorization",{}); c=d.get("context",{}); k=d.get("containment",{}); o=d.get("observability",{})
    add("separate agent identities", len(set(a.get("agents",[])))>=6 and a.get("unique_workload_identity_per_agent") is True and a.get("shared_agent_credentials_allowed") is False and a.get("separate_signing_key_per_agent_required") is True and a.get("approved_sender_receiver_paths_required") is True,
        "Every agent has a distinct workload identity and no shared credential.")
    add("orchestrated trust boundary", a.get("orchestrator_is_policy_enforcement_point") is True and a.get("peer_to_peer_bypass_allowed") is False,
        "All handoffs cross the orchestration policy boundary.")
    add("authenticated bounded messages", all(m.get(x) is True for x in ["strict_schema_required","sender_and_receiver_identity_required","mutual_authentication_required","signature_required","encryption_in_transit_required","issued_at_and_expiry_required","single_use_nonce_required","payload_digest_required"]) and 0<m.get("maximum_ttl_seconds",0)<=300,
        "Messages are authenticated, integrity protected, expiring, and replay resistant.")
    add("message context binding", all(m.get(x) is True for x in ["correlation_and_parent_ids_required","tenant_repository_and_task_scope_required","unknown_fields_denied","payload_digest_recalculation_required","receiver_operation_mapping_required"]) and m.get("prompt_claimed_identity_trusted") is False,
        "Identity and scope come from trusted control-plane context.")
    add("least authority delegation", all(g.get(x) is True for x in ["explicit_capability_required","capability_is_signed_and_single_use","cannot_delegate_more_authority_than_held","expiry_cannot_exceed_parent","scope_cannot_expand","audience_binding_required","operation_and_resource_binding_required","delegator_remains_accountable","revocation_checked_each_hop","parent_signature_verified_required","child_sender_must_equal_parent_receiver","message_nonce_and_capability_revocation_required"]),
        "Delegation can only narrow existing authority.")
    add("bounded delegation graph", 0<g.get("maximum_depth",0)<=3 and 0<g.get("maximum_fanout",0)<=4 and 0<g.get("maximum_total_handoffs",0)<=12 and g.get("cycle_detection_required") is True,
        "Depth, fan-out, handoffs, and cycles are bounded.")
    add("authorize every hop", all(z.get(x) is True for x in ["authorize_every_hop","server_derived_identity_and_scope","receiver_reauthorizes_locally","deny_by_default","fail_closed_if_policy_or_identity_unavailable","confused_deputy_context_binding_required"]),
        "Each receiver independently authorizes the exact handoff.")
    add("separation of duties", all(z.get(x) is True for x in ["separation_of_duties_required","self_approval_prohibited","agent_merge_release_or_deploy_prohibited"]) and a.get("human_is_required_for_irreversible_actions") is True,
        "Agents cannot approve themselves or perform irreversible release actions.")
    add("cross-scope isolation", z.get("cross_tenant_or_repository_access_prohibited") is True and c.get("memory_isolated_by_tenant_repository_and_agent") is True and c.get("context_labels_preserved_at_every_hop") is True,
        "Tenant, repository, and agent memory boundaries remain intact.")
    add("minimum safe context", c.get("minimum_necessary_fields_only") is True and c.get("raw_prompts_code_chunks_or_tool_arguments_forwarded") is False and c.get("phi_pii_credentials_secrets_or_tokens_forwarded") is False and c.get("recipient_specific_redaction_required") is True,
        "Only recipient-specific, sanitized context crosses agents.")
    add("untrusted content remains data", c.get("retrieved_content_is_untrusted_data") is True and c.get("provenance_and_content_hash_required") is True,
        "Retrieved content never becomes agent authority.")
    add("cascading compromise containment", all(k.get(x) is True for x in ["per_agent_rate_and_cost_limits","per_workflow_time_and_handoff_limits","tool_allowlist_per_agent","network_egress_allowlist_per_agent","blast_radius_isolated_per_agent","compromised_agent_quarantine_required","kill_switch_and_revocation_integrated","downstream_authority_revoked_on_compromise","partial_failure_cannot_fall_back_to_broader_agent"]),
        "A compromised agent cannot inherit or spread broader authority.")
    add("privacy-safe handoff audit", all(o.get(x) is True for x in ["every_handoff_audited","decision_and_reason_code_required","identity_scope_capability_and_versions_logged","tamper_evident_correlation_required"]) and o.get("message_body_logging_prohibited") is True,
        "Handoffs are reconstructable without sensitive message bodies.")
    add("multi-agent detections", all(o.get(x) is True for x in ["delegation_anomaly_detection_required","cross_scope_attempt_detection_required","loop_and_fanout_detection_required"]),
        "Monitoring detects scope abuse and orchestration anomalies.")
    attacks=d.get("safe_attacks",[]); ids=[x.get("id") for x in attacks]
    required={"forged_sender","message_replay","confused_deputy","privilege_laundering","delegation_cycle","excessive_fanout","cross_tenant_context","cross_repository_context","untrusted_content_instruction","self_approval","cascading_compromise","telemetry_suppression"}
    add("safe multi-agent attacks", len(attacks)>=12 and len(ids)==len(set(ids)) and {x.get("class") for x in attacks}==required and all(x.get("aws_calls")==0 and x.get("side_effects")==0 and x.get("expected") in {"DENY","QUARANTINE"} for x in attacks),
        "Twelve harmless attacks have deterministic denial or quarantine oracles.")
    r=d.get("review_and_evidence",{})
    try: exp=dt.date.fromisoformat(r.get("review_expires","")); current=today<=exp and (exp-today).days<=90
    except (TypeError,ValueError): current=False
    add("current independent review", bool(r.get("owner")) and current and r.get("independent_approval_required") is True and r.get("negative_tests_required") is True and r.get("live_nonproduction_handoff_tests_required") is True and r.get("evidence_contains_sensitive_values") is False,
        "The reviewed design is current and requires separate live proof.")
    limits=" ".join(d.get("limitations",[])).lower()
    add("honest offline limitations", len(d.get("limitations",[]))>=7 and "does not invoke aws" in limits and "does not create or run multiple agents" in limits and "does not prove hipaa compliance" in limits,
        "Offline design checks are not live multi-agent assurance.")
    add("non-production only", d.get("environment")=="non-production", "The lab cannot target production.")
    add("exact chapter contract", d.get("chapter")==12, "Evidence is bound to Chapter 12.")
    return checks

def main():
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--evidence",required=True); x=p.parse_args()
    checks=validate(json.loads(Path(x.manifest).read_text()))
    result={"chapter":12,"mode":"offline","aws_calls":0,"agent_messages_sent":0,"resources_created":0,"deployments":0,"prohibited_side_effects":0,"checks":checks}
    out=Path(x.evidence); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2)+"\n")
    for q in checks: print(f'{q["status"]}: {q["name"]}')
    if any(q["status"]=="FAIL" for q in checks): raise SystemExit(1)
    print(f"{len(checks)} Chapter 12 multi-agent security checks passed")
if __name__=="__main__": main()
