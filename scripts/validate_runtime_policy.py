#!/usr/bin/env python3
"""Offline validator for Chapter 5 AWS runtime policy controls."""
import argparse
import datetime as dt
import json
from pathlib import Path


EXPECTED_ORDER = ["PRE_INPUT", "BEDROCK_MODEL", "PRE_TOOL", "TOOL_WORKER", "PRE_OUTPUT", "AUDIT"]
EXPECTED_BOUNDARIES = {"PRE_INPUT", "PRE_TOOL", "PRE_OUTPUT"}
FORBIDDEN_KEYS = {"access_key", "secret_value", "password", "patient_name", "mrn", "diagnosis", "ssn", "private_key"}


def validate(data, today=None):
    today = today or dt.date.today()
    checks = []

    def check(name, condition, detail):
        checks.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})

    healthcare = data.get("healthcare_controls", {})
    source = data.get("policy_source", {})
    boundaries = data.get("boundaries", [])
    identity = data.get("identity_contract", {})
    policies = data.get("tool_policies", [])
    worker = data.get("worker_enforcement", {})
    audit = data.get("audit_contract", {})
    aws = data.get("aws_runtime_controls", {})
    review = data.get("review_and_evidence", {})

    check("non-production synthetic scope",
          data.get("environment") != "production" and data.get("data_classification") == "synthetic-only"
          and healthcare.get("synthetic_data_only") is True and healthcare.get("real_phi_allowed") is False
          and healthcare.get("real_pii_allowed") is False and healthcare.get("production_source_allowed") is False,
          "Only synthetic healthcare examples are allowed in non-production.")

    check("trusted versioned policy",
          source.get("approved_versioned_artifact") is True and source.get("mutable_latest_alias_allowed") is False
          and source.get("signature_verification_required") is True and source.get("rollback_version_pinned") is True
          and source.get("independent_approval_required") is True,
          "The runtime loads an approved, signed, pinned, independently reviewed policy.")

    check("safe execution order", data.get("execution_order") == EXPECTED_ORDER,
          "Input, tool, and output gates surround model and worker execution.")

    ids = [b.get("id") for b in boundaries]
    complete = (set(ids) == EXPECTED_BOUNDARIES and len(ids) == 3 and
                all(b.get("purpose") and b.get("required_checks") and b.get("timeout_ms", 0) > 0 for b in boundaries))
    check("three complete boundaries", complete, "PRE_INPUT, PRE_TOOL, and PRE_OUTPUT are uniquely defined.")

    closed = all(b.get("fail_mode") == "closed" for b in boundaries)
    zero = all(b.get("on_deny") and all(v == 0 for v in b.get("on_deny", {}).values()) for b in boundaries)
    check("fail closed with zero side effects", closed and zero,
          "Every boundary denies on failure without downstream calls, release, or prohibited effects.")

    privacy = (healthcare.get("minimum_necessary_context_required") is True
               and healthcare.get("deterministic_classification_before_guardrail") is True
               and healthcare.get("guardrail_required") is True
               and healthcare.get("guardrail_is_only_control") is False
               and healthcare.get("tool_parameters_scanned_independently") is True
               and healthcare.get("streaming_buffered_until_validation") is True
               and healthcare.get("full_prompts_or_outputs_logged") is False)
    check("layered healthcare data protection", privacy,
          "Deterministic checks surround Guardrails and validate tool parameters and buffered output.")

    identity_ok = (identity.get("aws_sigv4_and_temporary_role_session_required") is True
                   and identity.get("source_identity_required") is True
                   and identity.get("session_tags_required") is True
                   and identity.get("prompt_supplied_identity_trusted") is False
                   and identity.get("anonymous_allowed") is False
                   and identity.get("bedrock_api_keys_allowed") is False
                   and identity.get("delegated_identity_context_required") is True)
    check("trusted AWS identity context", identity_ok,
          "Authorization uses verified temporary AWS identity, not prompt claims or bearer API keys.")

    ids = [p.get("id") for p in policies]
    try:
        dates_ok = all(today <= dt.date.fromisoformat(p["review_expires"]) for p in policies)
    except (KeyError, TypeError, ValueError):
        dates_ok = False
    required = {"id", "principal", "tool", "actions", "resources", "argument_constraints",
                "human_approval_required", "review_expires", "evidence"}
    tool_ok = (len(policies) >= 3 and len(set(ids)) == len(ids) and None not in ids and dates_ok
               and all(required.issubset(p) and p["resources"] != ["*"] for p in policies))
    check("least-privileged current tool policies", tool_ok,
          "Tool policies bind principal, tool, action, resource, arguments, approval, evidence, and review.")

    writes = [p for p in policies if "write" in p.get("actions", [])]
    check("independent approval for writes", bool(writes) and all(p.get("human_approval_required") is True for p in writes),
          "Every write action requires independent human approval.")

    worker_ok = (worker.get("model_can_call_privileged_sdk_directly") is False
                 and worker.get("return_control_for_tool_authorization_required") is True
                 and worker.get("worker_revalidates_signed_decision") is True
                 and 0 < worker.get("decision_ttl_seconds_max", 0) <= 60
                 and worker.get("decision_bound_to_arguments_hash") is True
                 and worker.get("decision_bound_to_principal_and_resource") is True
                 and worker.get("replay_protection_required") is True
                 and worker.get("zero_side_effect_proof_required") is True)
    check("non-bypassable worker enforcement", worker_ok,
          "The model cannot bypass authorization; short-lived bound decisions are rechecked by the worker.")

    required_audit = {"correlation_id", "decision_id", "policy_version", "boundary", "principal",
                      "action", "resource", "decision", "reason_code", "timestamp", "latency_ms"}
    forbidden_audit = {"access_token", "authorization_header", "secret_value", "full_prompt",
                       "full_output", "patient_identifier", "source_body"}
    audit_ok = (audit.get("append_only_destination_required_for_live_use") is True
                and audit.get("synchronous_decision_record_required") is True
                and audit.get("correlation_id_generated_at_trusted_ingress") is True
                and required_audit.issubset(set(audit.get("required_fields", [])))
                and forbidden_audit.issubset(set(audit.get("forbidden_fields", [])))
                and len(audit.get("safe_reason_codes", [])) >= 10)
    check("sanitized correlated audit", audit_ok,
          "Decisions are reconstructable without prompts, code bodies, tokens, secrets, or patient identifiers.")

    aws_ok = all(aws.get(k) is True for k in [
        "bedrock_guardrail_attached", "bedrock_guardrail_identifier_iam_condition_required",
        "action_group_return_control_required", "lambda_resource_policy_exact_source_required",
        "lambda_reserved_concurrency_required", "lambda_code_signing_required",
        "private_endpoints_required", "cloudtrail_and_cloudwatch_required",
        "live_availability_quota_access_lifecycle_pricing_check_required"])
    check("AWS runtime defense in depth", aws_ok,
          "Bedrock, Lambda, network, logging, and live service checks are independently required.")

    attacks = data.get("safe_attacks", [])
    attack_ids = [a.get("id") for a in attacks]
    denied = [a for a in attacks if a.get("expected") == "denied"]
    attacks_ok = (len(attacks) >= 10 and len(set(attack_ids)) == len(attack_ids) and None not in attack_ids
                  and all(a.get("stop_at") in EXPECTED_BOUNDARIES | {"AUDIT"}
                          and a.get("model_calls") in {0, 1} and a.get("tool_calls") in {0, 1}
                          and a.get("prohibited_side_effects") == 0 for a in attacks)
                  and all(a.get("tool_calls") == 0 for a in denied)
                  and all(a.get("model_calls") == 0 for a in denied if a.get("stop_at") == "PRE_INPUT"))
    check("safe runtime attack contracts", attacks_ok,
          "Ten repeatable attacks stop at exact boundaries and denied actions have zero effects.")

    try:
        current = today <= dt.date.fromisoformat(review.get("review_expires", ""))
    except (TypeError, ValueError):
        current = False
    review_ok = (bool(review.get("owner")) and current and review.get("negative_tests_required") is True
                 and review.get("cloudformation_change_set_review_required") is True
                 and review.get("live_end_to_end_denial_tests_required") is True
                 and review.get("live_zero_side_effect_verification_required") is True
                 and review.get("evidence_contains_sensitive_values") is False)
    check("current review and live verification plan", review_ok,
          "Approval is current and offline evidence is not mistaken for live AWS proof.")

    lowered = json.dumps(data).lower()
    check("no sensitive value fields", not any(f'"{key}":' in lowered for key in FORBIDDEN_KEYS),
          "The manifest stores no credential value or healthcare identifier field.")

    limitations = " ".join(data.get("limitations", [])).lower()
    honest = (len(data.get("limitations", [])) >= 6 and "does not invoke amazon bedrock" in limitations
              and "does not call a repository" in limitations and "does not prove hipaa compliance" in limitations
              and "live iam" in limitations)
    check("honest offline limitations", honest,
          "The chapter separates offline design proof from live AWS and compliance evidence.")
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    checks = validate(data)
    evidence = {
        "chapter": 5, "mode": "offline", "aws_calls": 0, "model_calls": 0,
        "tool_calls": 0, "prohibited_side_effects": 0, "resources_created": 0,
        "checks": checks
    }
    out = Path(args.evidence)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    for item in checks:
        print(f'{item["status"]}: {item["name"]}')
    if any(item["status"] == "FAIL" for item in checks):
        raise SystemExit(1)
    print(f"{len(checks)} Chapter 5 runtime-policy checks passed")


if __name__ == "__main__":
    main()
