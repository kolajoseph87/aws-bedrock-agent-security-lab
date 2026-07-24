#!/usr/bin/env python3
"""Offline validator for Chapter 7 tool-execution controls."""
import argparse, datetime as dt, json
from pathlib import Path

ORDER=["RETURN_CONTROL","PRE_TOOL","ISSUE_WORK_ORDER","VERIFY_WORK_ORDER","EXECUTE","VALIDATE_ARTIFACT","HUMAN_REVIEW","DESTROY"]

def validate(data, today=None):
    today=today or dt.date.today(); checks=[]
    def add(name,ok,detail): checks.append({"name":name,"status":"PASS" if ok else "FAIL","detail":detail})
    h=data.get("healthcare_controls",{}); a=data.get("authority",{}); w=data.get("work_order",{})
    iso=data.get("worker_isolation",{}); c=data.get("command_policy",{}); lim=data.get("resource_limits",{})
    art=data.get("artifact_policy",{}); aws=data.get("aws_controls",{}); audit=data.get("audit",{})
    review=data.get("review_and_evidence",{})
    add("synthetic non-production scope",data.get("environment")!="production" and data.get("data_classification")=="synthetic-only" and h.get("synthetic_data_only") is True and h.get("real_phi_allowed") is False and h.get("real_pii_allowed") is False and h.get("production_source_allowed") is False,"Only synthetic non-production inputs are allowed.")
    add("complete execution order",data.get("execution_order")==ORDER,"Execution is authorized, verified, validated, reviewed, and destroyed in order.")
    add("agent has no direct execution authority",a.get("agent_has_shell") is False and a.get("agent_has_aws_sdk_credentials") is False and a.get("agent_can_invoke_worker_directly") is False and a.get("return_control_required") is True,"The model proposes; trusted application code authorizes.")
    add("authorization independent and fail closed",a.get("user_confirmation_is_sufficient_authorization") is False and a.get("worker_revalidates_policy_decision") is True and a.get("fail_mode")=="closed","Confirmation is not substituted for policy enforcement.")
    work_keys=["signed","single_use","nonce_required","policy_version_required","argument_hash_required","principal_repository_commit_operation_paths_bound","immutable_commit_required","replay_cache_required"]
    add("immutable replay-resistant work order",all(w.get(k) is True for k in work_keys) and 0<w.get("maximum_ttl_seconds",0)<=300 and w.get("prompt_supplied_identity_or_scope_trusted") is False,"Work orders are signed, exact, short-lived, and single use.")
    iso_keys=["separate_role","fresh_disposable_workspace","destroy_after_job","approved_private_endpoints_only"]
    add("disposable private worker",all(iso.get(k) is True for k in iso_keys) and iso.get("inbound_network_allowed") is False and iso.get("default_network_egress")=="deny","Every job uses a disposable worker with no inbound or default egress.")
    add("non-privileged credential-free worker",iso.get("privileged_mode") is False and iso.get("docker_socket_mounted") is False and iso.get("persistent_repository_credentials") is False and iso.get("secrets_access_allowed") is False and iso.get("bedrock_invoke_allowed") is False and iso.get("production_access_allowed") is False,"Worker receives no reusable credentials or elevated authority.")
    add("deterministic command and path policy",c.get("server_derived_allowlist_required") is True and c.get("free_form_shell_allowed") is False and c.get("shell_metacharacters_allowed") is False and c.get("absolute_paths_allowed") is False and c.get("path_traversal_allowed") is False and c.get("symlink_escape_allowed") is False,"Commands and paths are parsed and allowlisted.")
    allowed=set(c.get("allowed_operations",[])); forbidden=set(c.get("forbidden_operations",[]))
    add("safe operation catalog",{"apply_patch","run_unit_tests","run_static_analysis","create_patch_artifact"}.issubset(allowed) and {"push","merge","release","deploy","modify_pipeline","read_secret","assume_role"}.issubset(forbidden) and not allowed.intersection(forbidden) and c.get("repository_build_scripts_trusted") is False and c.get("package_install_allowed") is False,"Repository code is untrusted and high-impact operations are forbidden.")
    add("bounded worker resources",0<lim.get("timeout_seconds",0)<=1800 and 0<lim.get("max_memory_mib",0)<=8192 and 0<lim.get("max_cpu_units",0)<=4096 and 0<lim.get("max_processes",0)<=256 and 0<lim.get("max_files_changed",0)<=50 and 0<lim.get("max_patch_bytes",0)<=1048576 and 0<lim.get("max_output_bytes",0)<=5242880 and lim.get("max_concurrent_jobs_per_repository")==1,"Time, compute, process, file, patch, output, and concurrency are bounded.")
    add("validated human-reviewed artifact",all(art.get(k) is True for k in ["diff_scope_revalidation_required","tests_and_static_analysis_required","malware_secret_phi_pii_unsafe_code_scan_required","content_addressed_patch_required","logs_sanitized_before_release","independent_human_review_before_repository_write"]) and art.get("streaming_worker_logs_allowed") is False and art.get("worker_can_approve_itself") is False,"Only scanned hashed artifacts reach independent review.")
    add("deterministic healthcare scanning",h.get("deterministic_input_diff_log_output_scans_required") is True,"Sensitive content is checked at every execution boundary.")
    add("AWS least-privilege execution controls",all(aws.get(k) is True for k in ["exact_codebuild_project_arn_required","immutable_build_image_digest_required","vpc_private_subnets_required","customer_managed_kms_key_required","cloudtrail_and_cloudwatch_required","live_availability_quota_access_image_lifecycle_pricing_check_required"]) and aws.get("security_group_has_ingress") is False and aws.get("codebuild_session_manager_debug_allowed") is False and aws.get("untrusted_webhooks_allowed") is False,"AWS worker configuration is private, immutable, encrypted, and observable.")
    req={"correlation_id","principal","repository_id","base_commit","operation","argument_hash","work_order_id","policy_version","worker_identity","image_digest","patch_hash","decision","reason_code","timestamp"}
    forbidden={"source_body","patch_body","command_output","patient_identifier","access_token","secret_value","repository_credential"}
    add("sanitized execution audit",req.issubset(set(audit.get("required_fields",[]))) and forbidden.issubset(set(audit.get("forbidden_fields",[]))) and audit.get("append_only_live_destination_required") is True,"Audit uses identifiers and hashes, not sensitive bodies.")
    attacks=data.get("safe_attacks",[]); ids=[x.get("id") for x in attacks]
    add("safe attack contracts",len(attacks)>=12 and len(ids)==len(set(ids)) and None not in ids and all(x.get("stop_at") in set(ORDER) and x.get("worker_calls") in {0,1} and x.get("prohibited_side_effects")==0 for x in attacks) and all(x.get("worker_calls")==0 for x in attacks if x.get("stop_at") in {"PRE_TOOL","VERIFY_WORK_ORDER"}),"Harmless attacks stop at a named boundary with zero prohibited effects.")
    try: current=today<=dt.date.fromisoformat(review.get("review_expires",""))
    except (TypeError,ValueError): current=False
    add("current independent review",bool(review.get("owner")) and current and review.get("independent_approval_required") is True and review.get("negative_tests_required") is True and review.get("live_worker_isolation_and_cleanup_tests_required") is True and review.get("evidence_contains_sensitive_values") is False,"Review is current and live proof remains required.")
    limits=" ".join(data.get("limitations",[])).lower()
    add("honest offline limitations",len(data.get("limitations",[]))>=7 and "does not invoke" in limits and "does not prove live iam" in limits and "does not prove that a live workspace is destroyed" in limits and "does not prove hipaa compliance" in limits,"Offline validation is not represented as live enforcement.")
    add("exact chapter contract",data.get("chapter")==7,"Evidence is bound to Chapter 7.")
    return checks

def main():
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--evidence",required=True); x=p.parse_args()
    checks=validate(json.loads(Path(x.manifest).read_text(encoding="utf-8")))
    evidence={"chapter":7,"mode":"offline","aws_calls":0,"bedrock_calls":0,"worker_calls":0,"repository_writes":0,"resources_created":0,"prohibited_side_effects":0,"checks":checks}
    out=Path(x.evidence); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    for check in checks: print(f'{check["status"]}: {check["name"]}')
    if any(check["status"]=="FAIL" for check in checks): raise SystemExit(1)
    print(f"{len(checks)} Chapter 7 tool-execution checks passed")
if __name__=="__main__": main()
