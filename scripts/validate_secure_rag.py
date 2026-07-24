#!/usr/bin/env python3
"""Offline validator for Chapter 6 secure RAG controls."""
import argparse, datetime as dt, json
from pathlib import Path

ORDER = ["PRE_QUERY", "RETRIEVE", "POST_RETRIEVAL", "GENERATE", "PRE_OUTPUT", "AUDIT"]

def validate(data, today=None):
    today = today or dt.date.today(); checks = []
    def add(name, ok, detail): checks.append({"name":name,"status":"PASS" if ok else "FAIL","detail":detail})
    h=data.get("healthcare_controls",{}); s=data.get("source_governance",{}); i=data.get("isolation",{})
    r=data.get("retrieval_policy",{}); l=data.get("lifecycle",{}); a=data.get("aws_controls",{})
    audit=data.get("audit",{}); review=data.get("review_and_evidence",{})
    add("synthetic non-production scope", data.get("environment")!="production" and data.get("data_classification")=="synthetic-only" and h.get("synthetic_data_only") is True and h.get("real_phi_allowed") is False and h.get("real_pii_allowed") is False and h.get("production_source_allowed") is False, "Only synthetic non-production content is permitted.")
    add("deterministic healthcare filtering", h.get("minimum_necessary_chunks_required") is True and h.get("deterministic_ingestion_scan_required") is True and h.get("deterministic_retrieval_scan_required") is True and h.get("guardrail_applies_to_retrieved_references") is False, "Retrieved references need independent deterministic inspection.")
    add("approved provenance-controlled ingestion", all(s.get(k) is True for k in ["approved_sources_only","immutable_source_version_required","malware_secret_phi_pii_scan_before_ingestion","prompt_injection_scan_before_ingestion","owner_and_classification_required","provenance_hash_required","quarantine_on_failure"]) and s.get("automatic_ingestion_from_pull_requests") is False, "Only scanned, owned, immutable approved sources may be ingested.")
    add("repository and tenant isolation", all(i.get(k) is True for k in ["knowledge_base_per_trust_domain","repository_and_tenant_metadata_required","server_derived_metadata_filters_required"]) and i.get("prompt_supplied_scope_trusted") is False and i.get("cross_repository_retrieval_allowed") is False and i.get("wildcard_knowledge_base_access_allowed") is False, "Scope is derived from trusted identity and bound to exact resources.")
    add("safe retrieval order", r.get("execution_order")==ORDER, "Query and retrieved chunks are checked before generation.")
    add("fail-closed bounded retrieval", r.get("fail_mode")=="closed" and 0<r.get("max_chunks",0)<=10 and 0<r.get("max_chunk_characters",0)<=8000 and 0.5<=r.get("minimum_relevance_score",0)<=1, "Retrieval is bounded and fails closed.")
    add("untrusted chunk handling", r.get("citations_required") is True and r.get("source_hash_revalidation_required") is True and r.get("retrieved_text_treated_as_untrusted_data") is True and r.get("instructions_in_retrieved_text_followed") is False, "Retrieved text is evidence, never authority.")
    add("grounded validated output", r.get("zero_results_prevents_unsupported_answer") is True and r.get("streaming_before_validation_allowed") is False, "Unsupported or unvalidated output is not released.")
    add("complete deletion lifecycle", l.get("deletion_policy")=="DELETE" and all(l.get(k) is True for k in ["source_deletion_requires_sync_or_direct_document_delete","post_delete_retrieval_test_required","stale_vector_detection_required","failed_ingestion_alert_required","rollback_to_approved_snapshot_required"]), "Deletion includes vector removal and a negative retrieval test.")
    add("AWS least-privilege defense in depth", all(a.get(k) is True for k in ["exact_knowledge_base_arn_required","separate_ingestion_and_retrieval_roles","customer_managed_kms_keys_required","s3_block_public_access_required","s3_versioning_required","private_endpoints_required","cloudtrail_and_cloudwatch_required","live_availability_quota_access_lifecycle_pricing_check_required"]) and a.get("cross_region_inference_allowed") is False, "AWS identities, storage, encryption, network, and monitoring are independently constrained.")
    req={"correlation_id","principal","repository_id","knowledge_base_id","query_hash","filter_hash","retrieved_chunk_ids","source_version_hashes","decision","reason_code","timestamp"}; forbidden={"full_query","retrieved_text","source_body","patient_identifier","access_token","secret_value"}
    add("sanitized retrieval audit", req.issubset(set(audit.get("required_fields",[]))) and forbidden.issubset(set(audit.get("forbidden_fields",[]))) and audit.get("append_only_live_destination_required") is True, "Audit stores hashes and identifiers, not sensitive bodies.")
    attacks=data.get("safe_attacks",[]); ids=[x.get("id") for x in attacks]
    add("safe attack contracts", len(attacks)>=10 and len(ids)==len(set(ids)) and None not in ids and all(x.get("stop_at") in set(ORDER) and x.get("model_calls") in {0,1} and x.get("prohibited_side_effects")==0 for x in attacks) and all(x.get("model_calls")==0 for x in attacks if x.get("expected")=="denied" and x.get("stop_at") in {"PRE_QUERY","POST_RETRIEVAL"}), "Harmless attacks stop at a named boundary with zero prohibited effects.")
    try: current=today<=dt.date.fromisoformat(review.get("review_expires",""))
    except (TypeError,ValueError): current=False
    add("current independent review", bool(review.get("owner")) and current and review.get("independent_approval_required") is True and review.get("negative_tests_required") is True and review.get("live_ingestion_and_retrieval_tests_required") is True and review.get("evidence_contains_sensitive_values") is False, "Review is current and live proof remains required.")
    text=json.dumps(data).lower()
    add("no sensitive values", not any('"'+k+'":' in text for k in ["patient_name","mrn","diagnosis","password","private_key","authorization_header"]), "Manifest contains no sensitive-value fields.")
    limits=" ".join(data.get("limitations",[])).lower()
    add("honest offline limitations", len(data.get("limitations",[]))>=7 and "does not create or query" in limits and "does not prove deletion" in limits and "does not prove hipaa compliance" in limits and "live iam" in limits, "Offline checks are not represented as live AWS or compliance proof.")
    add("exact chapter contract", data.get("chapter")==6, "Evidence is bound to Chapter 6.")
    return checks

def main():
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--evidence",required=True); x=p.parse_args()
    checks=validate(json.loads(Path(x.manifest).read_text(encoding="utf-8")))
    evidence={"chapter":6,"mode":"offline","aws_calls":0,"model_calls":0,"retrieval_calls":0,"resources_created":0,"prohibited_side_effects":0,"checks":checks}
    out=Path(x.evidence); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    for c in checks: print(f'{c["status"]}: {c["name"]}')
    if any(c["status"]=="FAIL" for c in checks): raise SystemExit(1)
    print(f"{len(checks)} Chapter 6 secure-RAG checks passed")
if __name__=="__main__": main()
