#!/usr/bin/env python3
"""Offline validator for Chapter 9 observability and detection controls."""
import argparse, datetime as dt, json
from pathlib import Path

ORDER=["EMIT","SANITIZE","DELIVER","CORRELATE","DETECT","ALERT","INVESTIGATE"]
def validate(d,today=None):
 today=today or dt.date.today(); out=[]
 def add(n,ok,x): out.append({"name":n,"status":"PASS" if ok else "FAIL","detail":x})
 t=d.get("telemetry_policy",{}); delivery=d.get("delivery_policy",{}); store=d.get("storage_policy",{})
 detect=d.get("detection_policy",{}); aws=d.get("aws_controls",{}); event=d.get("audit_event",{})
 alert=d.get("alerting",{}); review=d.get("review_and_evidence",{})
 add("synthetic non-production scope",d.get("environment")!="production" and d.get("data_classification")=="synthetic-only","Monitoring lab is synthetic and non-production.")
 add("complete monitoring order",d.get("event_flow")==ORDER,"Events are sanitized before delivery and detection.")
 add("structured attributable telemetry",all(t.get(k) is True for k in ["structured_events_required","schema_version_required","server_generated_identity_required","correlation_id_required","policy_version_required","decision_and_reason_required","tool_and_resource_hashes_required"]),"Events are attributable and correlatable.")
 raw=["raw_prompt_logging_allowed","raw_completion_logging_allowed","retrieved_chunk_logging_allowed","source_or_patch_body_logging_allowed","tool_argument_body_logging_allowed","credentials_or_tokens_logging_allowed"]
 add("minimum necessary telemetry",all(t.get(k) is False for k in raw),"Sensitive bodies are excluded.")
 add("fail-closed audit delivery",all(delivery.get(k) is True for k in ["fail_closed_for_security_audit_events","bounded_local_buffer_required","encrypted_dead_letter_queue_required","retry_with_backoff_required","sequence_and_deduplication_required","clock_synchronization_required","delivery_health_alarm_required"]) and delivery.get("agent_can_disable_telemetry") is False,"Security audit loss blocks protected actions.")
 add("isolated immutable storage",all(store.get(k) is True for k in ["separate_security_log_account_required","customer_managed_kms_key_required","append_only_immutable_archive_required","object_lock_required","least_privilege_read_roles_required"]) and store.get("retention_days",0)>=365 and all(store.get(k) is False for k in ["agent_log_read_access_allowed","agent_log_delete_access_allowed","cross_region_replication_allowed","public_access_allowed"]),"Security logs are isolated, encrypted, immutable, and retained.")
 needed=["runtime_denial_spike","prompt_injection_pattern","cross_tenant_or_repository_attempt","tool_authorization_failure","work_order_replay","unexpected_tool_or_resource","model_or_policy_version_drift","credential_or_phi_detector_hit","telemetry_gap_or_tamper","token_cost_and_latency_anomaly","release_or_deployment_bypass","severity_and_runbook_required","false_positive_tuning_requires_approval"]
 add("complete detection coverage",all(detect.get(k) is True for k in needed) and detect.get("automated_destructive_response_allowed") is False,"Detections cover abuse, drift, leakage, gaps, cost, and release bypass.")
 add("AWS telemetry safeguards",all(aws.get(k) is True for k in ["cloudtrail_organization_trail_required","cloudtrail_log_file_validation_required","cloudwatch_metric_filters_and_alarms_required","eventbridge_routing_required","security_lake_integration_review_required","guardduty_integration_review_required","vpc_flow_logs_required","kms_key_policy_separation_required","live_availability_quota_access_lifecycle_pricing_check_required"]) and aws.get("bedrock_invocation_logging_body_capture") is False,"AWS telemetry is comprehensive without invocation bodies.")
 req={"event_id","schema_version","timestamp","sequence_number","previous_event_hash","event_hash","correlation_id","principal_id","session_id_hash","tenant_id_hash","repository_id_hash","model_id","policy_version","stage","action","decision","reason_code","latency_ms","input_tokens","output_tokens"}
 forbidden={"raw_prompt","raw_completion","retrieved_chunk","source_body","patch_body","tool_arguments","patient_identifier","email_address","access_token","secret_value","cloud_credential"}
 add("sanitized event schema",req.issubset(set(event.get("required_fields",[]))) and forbidden.issubset(set(event.get("forbidden_fields",[]))) and all(event.get(k) is True for k in ["unknown_fields_rejected","sensitive_values_redacted_before_delivery","hashes_use_approved_keyed_method","event_integrity_chain_required","server_scope_hash_comparison_required"]),"Schema allowlists fields, binds server scope, verifies integrity, and rejects sensitive bodies.")
 add("actionable safe alerting",alert.get("independent_security_destination_required") is True and 0<alert.get("high_severity_ack_minutes",999)<=15 and alert.get("duplicate_suppression_required") is True and alert.get("alert_contains_sensitive_bodies") is False and alert.get("runbook_link_required") is True and alert.get("owner_required") is True,"Alerts are independent, timely, deduplicated, and sanitized.")
 attacks=d.get("safe_attacks",[]); ids=[x.get("id") for x in attacks]
 add("safe attack contracts",len(attacks)>=12 and len(ids)==len(set(ids)) and None not in ids and all(x.get("stop_at") in ORDER and x.get("aws_calls")==0 and x.get("prohibited_side_effects")==0 for x in attacks),"Offline attacks have no AWS calls or prohibited effects.")
 try: current=today<=dt.date.fromisoformat(review.get("review_expires",""))
 except (TypeError,ValueError): current=False
 add("current independent review",bool(review.get("owner")) and current and all(review.get(k) is True for k in ["independent_approval_required","negative_tests_required","live_detection_delivery_retention_tests_required"]) and review.get("evidence_contains_sensitive_values") is False,"Review is current and live proof remains required.")
 limits=" ".join(d.get("limitations",[])).lower()
 add("honest offline limitations",len(d.get("limitations",[]))>=7 and "does not invoke aws" in limits and "does not prove live cloudtrail" in limits and "does not prove hipaa compliance" in limits,"Offline checks are not production evidence.")
 add("exact chapter contract",d.get("chapter")==9,"Evidence is bound to Chapter 9.")
 return out
def main():
 p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--evidence",required=True); x=p.parse_args()
 checks=validate(json.loads(Path(x.manifest).read_text()))
 e={"chapter":9,"mode":"offline","aws_calls":0,"resources_created":0,"alerts_sent":0,"automated_responses":0,"prohibited_side_effects":0,"checks":checks}
 o=Path(x.evidence); o.parent.mkdir(parents=True,exist_ok=True); o.write_text(json.dumps(e,indent=2)+"\n")
 for c in checks: print(f'{c["status"]}: {c["name"]}')
 if any(c["status"]=="FAIL" for c in checks): raise SystemExit(1)
 print(f"{len(checks)} Chapter 9 observability checks passed")
if __name__=="__main__": main()
