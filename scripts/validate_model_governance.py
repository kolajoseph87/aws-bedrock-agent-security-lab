#!/usr/bin/env python3
"""Offline validator for Chapter 3's Amazon Bedrock model-governance contract."""
import argparse
import datetime as dt
import json
from pathlib import Path


FORBIDDEN_KEYS = {"access_key", "secret", "token", "password", "patient_name", "mrn", "diagnosis"}


def validate(data):
    checks = []

    def check(name, condition, detail):
        checks.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})

    catalog = data.get("model_catalog", {})
    models = catalog.get("approved_models", [])
    invocation = data.get("invocation_policy", {})
    limits = data.get("inference_limits", {})
    controls = data.get("data_controls", {})
    iam = data.get("iam_contract", {})
    changes = data.get("change_control", {})

    check(
        "non-production synthetic scope",
        data.get("environment") != "production"
        and data.get("data_classification") == "synthetic-only"
        and controls.get("synthetic_only") is True
        and controls.get("real_phi_allowed") is False
        and controls.get("real_pii_allowed") is False
        and controls.get("production_source_allowed") is False,
        "Chapter 3 permits only synthetic data and non-production source.",
    )
    required_fields = {"alias", "provider", "model_id", "region", "usage", "approval_status", "owner", "risk_review", "review_expires"}
    unique_ids = len({m.get("model_id") for m in models}) == len(models)
    complete_models = bool(models) and all(required_fields.issubset(m) and all(m.get(k) for k in required_fields) for m in models)
    check("complete approved model inventory", complete_models and unique_ids and catalog.get("default_deny") is True, "Every allowed model is unique, owned, reviewed, and default-deny.")

    regions = set(catalog.get("approved_regions", []))
    regional = bool(regions) and all(m.get("region") in regions for m in models)
    check("approved region binding", regional and catalog.get("cross_region_inference_allowed") is False, "Models stay in explicitly approved Regions.")

    versioned = all(":" in m.get("model_id", "") and "latest" not in m.get("model_id", "").lower() for m in models)
    check("versioned model identifiers", versioned and catalog.get("unversioned_model_aliases_allowed") is False, "Unversioned and latest-style aliases are forbidden.")

    reviews_valid = True
    for model in models:
        try:
            reviews_valid &= dt.date.fromisoformat(model["review_expires"]) > dt.date.today()
        except (KeyError, TypeError, ValueError):
            reviews_valid = False
    check("current model approvals", reviews_valid and all(m.get("approval_status") == "approved-for-synthetic-lab" for m in models), "Model approvals are explicit and unexpired.")

    invocation_required = (
        invocation.get("direct_model_invocation_only") is True
        and invocation.get("approved_api") == "Converse"
        and invocation.get("caller_identity_required") is True
        and invocation.get("repository_allowlist_required") is True
        and invocation.get("request_purpose_required") is True
        and invocation.get("policy_decision_before_invocation") is True
        and invocation.get("fail_closed_on_policy_error") is True
    )
    check("fail-closed invocation gate", invocation_required, "Identity, repository, purpose, and policy must pass before invocation.")

    disabled_features = all(
        invocation.get(key) is False
        for key in ("streaming_allowed", "batch_inference_allowed", "provisioned_throughput_allowed", "model_customization_allowed")
    )
    check("minimal inference surface", disabled_features, "Unneeded inference modes and customization are disabled in this chapter.")

    bounded = (
        0 <= limits.get("temperature_max", 99) <= 0.2
        and 0 < limits.get("top_p_max", 0) <= 0.9
        and 0 < limits.get("input_tokens_max", 0) <= 12000
        and 0 < limits.get("output_tokens_max", 0) <= 3000
        and 0 < limits.get("timeout_seconds_max", 0) <= 60
        and 0 < limits.get("requests_per_pr_max", 0) <= 10
        and 0 < limits.get("cost_limit_usd_per_pr", 0) <= 1.0
    )
    check("bounded inference settings", bounded, "Randomness, tokens, time, requests, and cost have conservative limits.")

    layered_data = all(
        controls.get(k) is True
        for k in ("minimum_necessary_context", "deterministic_input_scan", "bedrock_guardrail_required", "deterministic_output_scan", "sanitized_security_metadata_only")
    )
    no_body_logs = all(
        controls.get(k) is False
        for k in ("prompt_logging_allowed", "completion_logging_allowed", "invocation_logging_body_capture")
    )
    check("layered privacy controls", layered_data and no_body_logs and controls.get("credentials_allowed") is False, "Deterministic checks surround Guardrails and body logging is disabled.")

    least_iam = (
        iam.get("allowed_actions") == ["bedrock:Converse"]
        and iam.get("wildcard_action_allowed") is False
        and iam.get("wildcard_resource_allowed") is False
        and all(iam.get(k) is True for k in ("approved_model_resource_binding_required", "region_condition_required", "principal_tag_condition_required", "deny_unapproved_models_required"))
    )
    check("least-privilege IAM contract", least_iam, "Only Converse on approved model resources is allowed with identity and Region conditions.")

    change_keys = (
        "model_inventory_required",
        "security_privacy_legal_review_required",
        "non_production_evaluation_required",
        "fixed_synthetic_evaluation_set_required",
        "security_regression_tests_required",
        "independent_approval_required",
        "rollback_model_required",
        "material_change_invalidates_approval",
        "drift_detection_required",
    )
    check("controlled model changes", all(changes.get(k) is True for k in change_keys), "Every material model change must be evaluated, approved, reversible, and monitored.")

    attacks = data.get("safe_attacks", [])
    safe = (
        len(attacks) >= 8
        and len({a.get("id") for a in attacks}) == len(attacks)
        and all("denied" in a.get("expected", "") and a.get("model_calls") == 0 and a.get("prohibited_side_effects") == 0 for a in attacks)
    )
    check("safe pre-invocation attacks", safe, "Negative tests stop before model calls and create no prohibited side effects.")

    lowered = json.dumps(data).lower()
    check("no sensitive fields", not any(f'"{key}"' in lowered for key in FORBIDDEN_KEYS), "The manifest contains no credential or healthcare identifier fields.")
    limitations = " ".join(data.get("limitations", [])).lower()
    check(
        "honest capability claims",
        len(data.get("limitations", [])) >= 5
        and "does not call amazon bedrock" in limitations
        and "does not authorize repository changes" in limitations
        and "does not replace deterministic" in limitations,
        "The design separates model approval, tool authority, and deterministic privacy enforcement.",
    )
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    data = json.loads(Path(args.manifest).read_text())
    checks = validate(data)
    evidence = {"chapter": 3, "mode": "offline", "aws_calls": 0, "model_calls": 0, "resources_created": 0, "checks": checks}
    out = Path(args.evidence)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2) + "\n")
    for item in checks:
        print(f'{item["status"]}: {item["name"]}')
    if any(item["status"] == "FAIL" for item in checks):
        raise SystemExit(1)
    print(f"{len(checks)} Chapter 3 model-governance checks passed")


if __name__ == "__main__":
    main()
