#!/usr/bin/env python3
"""Offline validator for Chapter 10 red-team and security evaluation controls."""
import argparse
import datetime as dt
import json
from pathlib import Path

ORDER = ["SELECT", "VALIDATE", "EXECUTE", "SCORE", "GATE", "REPORT"]


def validate(data, today=None):
    today = today or dt.date.today()
    checks = []

    def add(name, ok, detail):
        checks.append({"name": name, "status": "PASS" if ok else "FAIL",
                       "detail": detail})

    scope = data.get("scope", {})
    corpus = data.get("attack_corpus", {})
    harness = data.get("evaluation_harness", {})
    scoring = data.get("scoring_and_gates", {})
    integrity = data.get("integrity", {})
    aws = data.get("aws_controls", {})
    review = data.get("review_and_evidence", {})

    add("synthetic isolated scope",
        data.get("environment") == "non-production"
        and scope.get("synthetic_data_only") is True
        and all(scope.get(k) is False for k in [
            "production_endpoints_allowed", "production_credentials_allowed",
            "real_phi_or_pii_allowed", "repository_write_allowed",
            "deployment_allowed"]),
        "Evaluations cannot reach production data, credentials, or writes.")
    add("complete evaluation order", data.get("evaluation_flow") == ORDER,
        "Corpus selection, validation, execution, scoring, gating, and reporting are ordered.")
    required_classes = {
        "direct_prompt_injection", "indirect_prompt_injection", "rag_poisoning",
        "tool_manipulation", "data_exfiltration", "excessive_agency",
        "cross_tenant_access", "work_order_replay", "policy_bypass",
        "output_leakage", "resource_exhaustion", "evaluator_tampering"}
    add("complete adversarial coverage",
        required_classes.issubset(set(corpus.get("required_attack_classes", []))),
        "The corpus covers twelve material agent attack classes.")
    add("versioned immutable corpus",
        all(corpus.get(k) is True for k in [
            "version_required", "content_digest_required",
            "independent_approval_required", "immutable_storage_required",
            "case_schema_required", "expected_outcome_required",
            "duplicate_case_ids_rejected"]),
        "Every approved case is versioned, hashed, immutable, and has an oracle.")
    add("safe attack fixtures",
        all(corpus.get(k) is False for k in [
            "live_malware_allowed", "real_credentials_allowed",
            "real_patient_data_allowed", "destructive_payloads_allowed"]),
        "Fixtures contain no live malware, credentials, patient data, or destructive payloads.")
    add("isolated deterministic harness",
        all(harness.get(k) is True for k in [
            "fresh_ephemeral_environment_required", "deterministic_mode_required",
            "network_egress_denied_by_default", "server_derived_identity_required",
            "exact_tenant_and_repository_scope_required",
            "tool_side_effect_interception_required", "timeouts_and_quotas_required",
            "full_output_validation_required", "fail_closed_required",
            "private_subnets_required", "approved_private_endpoints_only",
            "single_concurrent_job_per_repository"]),
        "The evaluator is isolated, scoped, bounded, and fail-closed.")
    add("evaluator cannot self-authorize",
        all(harness.get(k) is False for k in [
            "agent_can_change_expected_results", "agent_can_select_only_passing_cases",
            "evaluator_can_approve_promotion", "model_judge_is_sole_authority"]),
        "Neither the target agent nor evaluator can rewrite truth or approve release.")
    add("critical failure gate",
        scoring.get("any_critical_failure_blocks_promotion") is True
        and scoring.get("data_leak_blocks_promotion") is True
        and scoring.get("cross_scope_access_blocks_promotion") is True
        and scoring.get("unauthorized_side_effect_blocks_promotion") is True
        and scoring.get("aggregate_score_cannot_override_critical_failure") is True,
        "No average score can hide a critical security failure.")
    add("regression and statistical controls",
        all(scoring.get(k) is True for k in [
            "approved_baseline_required", "per_class_thresholds_required",
            "security_regression_blocks_promotion", "flaky_case_quarantine_requires_approval",
            "false_negative_review_required", "repeat_runs_required_for_probabilistic_models"]),
        "Scores are compared to approved baselines with per-class thresholds.")
    add("independent promotion decision",
        scoring.get("independent_pipeline_gate_required") is True
        and scoring.get("human_review_required_for_critical_changes") is True
        and scoring.get("signed_result_bundle_required") is True,
        "A separate pipeline verifies results and approvals.")
    add("evaluation integrity",
        all(integrity.get(k) is True for k in [
            "pinned_evaluator_image_required", "signed_harness_required",
            "attested_runner_identity_required", "source_commit_binding_required",
            "model_policy_tool_and_corpus_versions_bound",
            "tamper_evident_results_required", "replay_protection_required",
            "separation_of_duties_required", "single_use_nonce_required",
            "signed_result_digest_required"])
        and integrity.get("maximum_authorization_ttl_seconds") == 300,
        "The runner, inputs, versions, and results are cryptographically attributable.")
    add("privacy-safe evidence",
        integrity.get("raw_prompts_or_completions_in_evidence") is False
        and integrity.get("phi_pii_credentials_or_source_in_evidence") is False
        and integrity.get("sanitized_reason_codes_required") is True,
        "Evidence proves outcomes without copying sensitive bodies.")
    add("AWS evaluation safeguards",
        all(aws.get(k) is True for k in [
            "temporary_role_credentials_required", "separate_evaluator_role_required",
            "kms_encrypted_results_required", "immutable_result_archive_required",
            "cloudtrail_and_cloudwatch_required",
            "vpc_configuration_required", "evaluator_image_digest_required",
            "object_lock_compliance_mode_required",
            "bedrock_model_evaluation_review_required",
            "bedrock_guardrail_automated_reasoning_review_required",
            "live_availability_quota_access_lifecycle_pricing_check_required"])
        and aws.get("bedrock_invocation_body_logging_allowed") is False,
        "AWS services support the evaluation without logging sensitive bodies.")
    attacks = data.get("safe_attacks", [])
    ids = [a.get("id") for a in attacks]
    add("safe executable attack contracts",
        len(attacks) >= 12 and len(ids) == len(set(ids)) and None not in ids
        and {a.get("class") for a in attacks} == required_classes
        and all(a.get("aws_calls") == 0
                and a.get("prohibited_side_effects") == 0
                and a.get("expected_decision") == "DENY" for a in attacks),
        "Each harmless attack has a unique ID and explicit denial oracle.")
    try:
        current = today <= dt.date.fromisoformat(review.get("review_expires", ""))
    except (TypeError, ValueError):
        current = False
    add("current independent review",
        bool(review.get("owner")) and current
        and (dt.date.fromisoformat(review["review_expires"]) - today).days <= 90
        and all(review.get(k) is True for k in [
            "independent_approval_required", "negative_tests_required",
            "live_isolation_and_gate_tests_required"])
        and review.get("evidence_contains_sensitive_values") is False,
        "Review is current and live proof remains required.")
    limits = " ".join(data.get("limitations", [])).lower()
    add("honest offline limitations",
        len(data.get("limitations", [])) >= 7
        and "does not invoke aws" in limits
        and "does not prove model robustness" in limits
        and "does not prove hipaa compliance" in limits,
        "Offline validation is not a live red-team or compliance result.")
    add("exact chapter contract", data.get("chapter") == 10,
        "Evidence is bound to Chapter 10.")
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    checks = validate(json.loads(Path(args.manifest).read_text()))
    evidence = {"chapter": 10, "mode": "offline", "aws_calls": 0,
                "resources_created": 0, "model_invocations": 0,
                "repository_writes": 0, "deployments": 0,
                "prohibited_side_effects": 0, "checks": checks}
    output = Path(args.evidence)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    for check in checks:
        print(f'{check["status"]}: {check["name"]}')
    if any(check["status"] == "FAIL" for check in checks):
        raise SystemExit(1)
    print(f"{len(checks)} Chapter 10 security-evaluation checks passed")


if __name__ == "__main__":
    main()
