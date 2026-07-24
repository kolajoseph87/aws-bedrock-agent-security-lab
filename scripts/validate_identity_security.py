#!/usr/bin/env python3
"""Offline validator for Chapter 4 identity, KMS, and secrets controls."""
import argparse
import datetime as dt
import json
from pathlib import Path


FORBIDDEN_KEYS = {
    "access_key", "secret_value", "password", "patient_name", "mrn",
    "diagnosis", "ssn", "private_key"
}


def validate(data):
    checks = []

    def check(name, condition, detail):
        checks.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})

    identity = data.get("identity_model", {})
    roles = data.get("roles", [])
    trust = data.get("trust_policy_controls", {})
    policies = data.get("iam_policy_controls", {})
    kms = data.get("kms_controls", {})
    secrets = data.get("secrets_controls", {})
    healthcare = data.get("healthcare_data_controls", {})
    boundaries = data.get("authorization_boundaries", {})
    review = data.get("review_and_evidence", {})

    check(
        "non-production synthetic scope",
        data.get("environment") != "production"
        and data.get("data_classification") == "synthetic-only"
        and healthcare.get("synthetic_data_only") is True
        and healthcare.get("real_phi_allowed") is False
        and healthcare.get("real_pii_allowed") is False
        and healthcare.get("production_source_allowed") is False,
        "Chapter 4 permits only synthetic healthcare examples in non-production.",
    )
    required_role_fields = {
        "name", "purpose", "trust_principal", "allowed_actions", "resource_scope",
        "may_read_secrets", "may_decrypt", "may_write_repository",
        "may_approve_pull_request", "may_deploy", "permissions_boundary_required"
    }
    names = [r.get("name") for r in roles]
    complete = (
        len(roles) >= 3
        and len(set(names)) == len(names)
        and all(required_role_fields.issubset(r) for r in roles)
        and all(r.get("purpose") and r.get("allowed_actions") for r in roles)
    )
    check("separate complete workload roles", complete, "Agent, worker, and pipeline duties use distinct owned roles.")

    temporary = (
        identity.get("default_deny") is True
        and identity.get("human_users_use_federation") is True
        and identity.get("workloads_use_iam_roles") is True
        and identity.get("temporary_credentials_only") is True
        and identity.get("iam_users_for_workloads_allowed") is False
        and identity.get("long_lived_access_keys_allowed") is False
        and identity.get("bedrock_api_keys_allowed") is False
        and identity.get("root_user_for_operations_allowed") is False
        and identity.get("mfa_required_for_privileged_humans") is True
        and 0 < identity.get("session_duration_minutes_max", 0) <= 60
    )
    check("temporary identity only", temporary, "Federated people and workload roles replace long-lived credentials and API keys.")

    tagged = (
        identity.get("source_identity_required") is True
        and set(identity.get("session_tags_required", [])) == {
            "northstar:environment", "northstar:application", "northstar:data-classification"
        }
    )
    check("session attribution", tagged, "Source identity and approved non-sensitive session tags support attribution.")

    exact_trust = (
        trust.get("service_principals_exact") is True
        and trust.get("wildcard_principals_allowed") is False
        and trust.get("external_id_required_for_third_parties") is True
        and trust.get("source_account_condition_required") is True
        and trust.get("source_arn_condition_required") is True
        and trust.get("confused_deputy_protection_required") is True
        and trust.get("role_chaining_for_privilege_escalation_allowed") is False
        and all(r.get("trust_principal", "").endswith(".amazonaws.com") for r in roles)
    )
    check("restricted trust policies", exact_trust, "Exact principals and source conditions reduce confused-deputy and role-assumption risk.")

    role_limits = (
        all(r.get("resource_scope") != "*" for r in roles)
        and all(r.get("permissions_boundary_required") is True for r in roles)
        and all(r.get("may_read_secrets") is False for r in roles)
        and all(r.get("may_decrypt") is False for r in roles)
        and all(r.get("may_write_repository") is False for r in roles)
        and all(r.get("may_approve_pull_request") is False for r in roles)
        and all(r.get("may_deploy") is False for r in roles)
    )
    check("least-authority role boundaries", role_limits, "No Chapter 4 role receives secret, decrypt, repository-write, approval, or deployment authority.")

    least_policy = (
        policies.get("wildcard_actions_allowed") is False
        and policies.get("wildcard_resources_allowed") is False
        and policies.get("customer_managed_least_privilege_policies") is True
        and policies.get("aws_managed_full_access_policies_allowed") is False
        and policies.get("permissions_boundaries_required") is True
        and policies.get("scp_guardrails_required_for_live_use") is True
        and policies.get("passrole_exact_resource_and_service_required") is True
        and policies.get("iam_policy_changes_require_independent_approval") is True
        and policies.get("access_analyzer_review_required") is True
        and policies.get("last_accessed_review_required") is True
    )
    check("least-privilege policy governance", least_policy, "Policies are narrow, bounded, reviewed, and monitored.")

    kms_safe = (
        kms.get("customer_managed_symmetric_key_required_for_sensitive_live_artifacts") is True
        and kms.get("separate_key_administration_and_usage") is True
        and kms.get("agent_role_direct_decrypt_allowed") is False
        and kms.get("key_rotation_required") is True
        and kms.get("key_policy_least_privilege") is True
        and kms.get("kms_via_service_condition_required") is True
        and kms.get("encryption_context_required") is True
        and kms.get("encryption_context_values_are_non_sensitive") is True
        and kms.get("phi_pii_or_secrets_in_encryption_context_allowed") is False
        and kms.get("key_deletion_waiting_period_days_min", 0) >= 30
        and kms.get("break_glass_recovery_documented") is True
        and kms.get("cloudtrail_monitoring_required") is True
    )
    check("safe KMS governance", kms_safe, "KMS administration, use, context, rotation, recovery, and monitoring are constrained.")

    secrets_safe = (
        secrets.get("secrets_manager_required_for_live_application_secrets") is True
        and secrets.get("hardcoded_secrets_allowed") is False
        and secrets.get("secrets_in_prompts_allowed") is False
        and secrets.get("secrets_in_model_outputs_allowed") is False
        and secrets.get("secrets_in_logs_or_evidence_allowed") is False
        and secrets.get("agent_blanket_secret_access_allowed") is False
        and secrets.get("exact_secret_arn_required") is True
        and secrets.get("resource_policy_block_public_access_required") is True
        and secrets.get("automatic_rotation_required") is True
        and 0 < secrets.get("rotation_days_max", 0) <= 30
        and secrets.get("private_endpoint_required") is True
        and secrets.get("secret_access_monitoring_required") is True
        and secrets.get("emergency_revocation_test_required") is True
    )
    check("safe secrets lifecycle", secrets_safe, "Secrets are narrowly retrieved, rotated, monitored, private, and excluded from AI content.")

    minimum = (
        healthcare.get("minimum_necessary_access_required") is True
        and healthcare.get("identifiers_in_role_names_tags_or_policy_metadata_allowed") is False
        and healthcare.get("sanitized_metadata_only") is True
    )
    check("healthcare metadata minimization", minimum, "Identity and evidence metadata contain no healthcare identifiers or payloads.")

    separated = (
        boundaries.get("model_output_is_authority") is False
        and boundaries.get("network_location_is_authority") is False
        and boundaries.get("encryption_is_authorization") is False
        and boundaries.get("runtime_tool_authorization_still_required") is True
        and boundaries.get("human_approval_for_repository_change_required") is True
        and boundaries.get("separation_of_duties_required") is True
        and boundaries.get("fail_closed_on_identity_or_policy_error") is True
    )
    check("authorization remains separate", separated, "Identity and encryption do not turn model output into permission.")

    try:
        review_current = dt.date.fromisoformat(review.get("review_expires", "")) > dt.date.today()
    except (TypeError, ValueError):
        review_current = False
    evidence_safe = (
        bool(review.get("owner"))
        and review_current
        and review.get("policy_simulation_required") is True
        and review.get("negative_tests_required") is True
        and review.get("cloudformation_change_set_review_required") is True
        and review.get("live_identity_kms_secret_access_test_required_before_deployment") is True
        and review.get("evidence_contains_values_or_payloads") is False
    )
    check("current review and live verification plan", evidence_safe, "Approval is current and offline evidence is not mistaken for live proof.")

    attacks = data.get("safe_attacks", [])
    safe_attacks = (
        len(attacks) >= 8
        and len({a.get("id") for a in attacks}) == len(attacks)
        and all(
            "denied" in a.get("expected", "")
            and a.get("aws_calls") == 0
            and a.get("prohibited_side_effects") == 0
            for a in attacks
        )
    )
    check("safe identity attack contracts", safe_attacks, "All attacks are offline denials with zero prohibited side effects.")

    lowered = json.dumps(data).lower()
    check("no sensitive fields", not any(f'"{key}"' in lowered for key in FORBIDDEN_KEYS), "The manifest stores no secret value or healthcare identifier field.")

    limitations = " ".join(data.get("limitations", [])).lower()
    honest = (
        len(data.get("limitations", [])) >= 6
        and "does not create, assume, or test an iam role" in limitations
        and "does not encrypt, decrypt, store, retrieve, rotate, or revoke" in limitations
        and "does not prove hipaa compliance" in limitations
        and "live policy simulation" in limitations
    )
    check("honest offline limitations", honest, "The validator clearly separates design checks from live AWS verification.")
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    data = json.loads(Path(args.manifest).read_text())
    checks = validate(data)
    evidence = {
        "chapter": 4,
        "mode": "offline",
        "aws_calls": 0,
        "roles_created_or_assumed": 0,
        "kms_operations": 0,
        "secret_operations": 0,
        "resources_created": 0,
        "checks": checks,
    }
    out = Path(args.evidence)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2) + "\n")
    for item in checks:
        print(f'{item["status"]}: {item["name"]}')
    if any(item["status"] == "FAIL" for item in checks):
        raise SystemExit(1)
    print(f"{len(checks)} Chapter 4 identity-security checks passed")


if __name__ == "__main__":
    main()
