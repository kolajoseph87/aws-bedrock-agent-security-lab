#!/usr/bin/env python3
"""Deterministic offline validator for Chapter 11 incident response."""
import argparse
import datetime as dt
import json
from pathlib import Path

ORDER = ["DETECT", "DECLARE", "CONTAIN", "PRESERVE", "ERADICATE", "RECOVER", "REVIEW"]

def validate(data, today=None):
    today = today or dt.date.today()
    checks = []
    def add(name, ok, detail):
        checks.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})
    auth = data.get("authority", {})
    kill = data.get("kill_switch", {})
    revoke = data.get("revocation", {})
    contain = data.get("containment", {})
    evidence = data.get("evidence", {})
    recovery = data.get("recovery", {})
    playbooks = data.get("playbooks", {})
    add("ordered response lifecycle", data.get("response_flow") == ORDER,
        "Detection through review follows a fixed incident lifecycle.")
    add("independent incident authority",
        all(auth.get(k) is True for k in ["server_derived_incident_identity_required",
            "independent_incident_commander_required", "break_glass_requires_two_people",
            "temporary_credentials_required", "session_recording_required",
            "strict_signed_command_schema_required", "distinct_approvers_required",
            "requester_cannot_approve", "single_use_nonce_required"])
        and all(auth.get(k) is False for k in ["agent_can_activate_or_clear_incident",
            "agent_can_disable_controls", "agent_can_delete_evidence", "agent_can_restore_service"])
        and auth.get("maximum_break_glass_ttl_seconds") <= 900,
        "The agent cannot command, erase, or recover its own incident.")
    add("complete kill switch",
        all(kill.get(k) is True for k in ["default_deny_required",
            "independent_control_plane_required", "deny_new_model_invocations",
            "deny_new_retrievals", "deny_new_tool_requests", "deny_worker_jobs",
            "deny_repository_writes", "deny_releases_and_deployments",
            "cancel_inflight_where_safe", "fail_closed_if_state_unavailable",
            "cannot_be_overridden_by_prompt", "unknown_actions_denied"])
        and 0 < kill.get("bounded_propagation_seconds", 0) <= 60,
        "A fail-closed control plane blocks every agent side-effect path.")
    add("complete authorization revocation", all(revoke.get(k) is True for k in [
        "sts_sessions_revoked_or_denied_required", "work_orders_revoked_required",
        "nonces_invalidated_required", "approvals_invalidated_required",
        "secrets_rotated_required", "kms_grants_retired_required",
        "repository_tokens_revoked_required", "pipeline_authorizations_revoked_required",
        "versioned_revocation_list_required", "replay_denied_after_recovery"]),
        "Credentials and previously valid authorization artifacts become unusable.")
    add("scoped and global containment", all(contain.get(k) is True for k in [
        "model_version_quarantine_required", "guardrail_and_policy_quarantine_required",
        "knowledge_base_source_quarantine_required", "tool_and_worker_image_quarantine_required",
        "tenant_and_repository_scoped_containment_required", "global_containment_available",
        "network_egress_isolation_required", "production_write_freeze_required",
        "blast_radius_assessment_required", "containment_must_not_destroy_evidence"]),
        "Responders can isolate one scope or the whole system without destroying proof.")
    add("immutable forensic evidence", all(evidence.get(k) is True for k in [
        "immutable_preservation_required", "separate_security_account_required",
        "kms_encryption_required", "s3_object_lock_compliance_mode_required",
        "cloudtrail_digest_validation_required", "chain_of_custody_required",
        "server_timestamp_required", "content_hash_required", "legal_hold_supported"])
        and evidence.get("minimum_retention_days", 0) >= 400,
        "Evidence is encrypted, attributable, immutable, and retained.")
    add("privacy-safe evidence",
        evidence.get("raw_prompts_completions_code_or_chunks_allowed") is False
        and evidence.get("phi_pii_credentials_or_tokens_allowed") is False
        and evidence.get("sanitized_reason_codes_required") is True
        and evidence.get("recursive_sensitive_field_removal_required") is True,
        "Forensics do not create another sensitive-data store.")
    add("verified recovery", all(recovery.get(k) is True for k in [
        "known_good_versions_required", "artifact_digest_verification_required",
        "clean_room_rebuild_required", "credential_rotation_verified_required",
        "rag_resync_and_negative_retrieval_test_required", "full_security_regression_required",
        "independent_recovery_approval_required", "staged_canary_required",
        "enhanced_monitoring_required", "rollback_ready_required",
        "recovery_point_and_time_objectives_required",
        "kill_switch_clear_requires_new_authorization"]),
        "Recovery uses known-good inputs, fresh authority, tests, and staged release.")
    required = {"prompt_injection","data_exposure","credential_compromise",
        "cross_tenant_access","tool_abuse","rag_poisoning","model_or_policy_drift",
        "supply_chain_compromise","telemetry_tampering","cost_or_resource_abuse",
        "unauthorized_deployment","evaluator_compromise"}
    add("complete incident playbooks", required.issubset(set(playbooks.get("required", [])))
        and all(playbooks.get(k) is True for k in ["owners_required","severity_matrix_required",
            "communications_plan_required","regulatory_and_legal_review_required",
            "tabletop_exercises_required","recovery_drills_required","lessons_learned_required",
            "control_updates_require_normal_change_governance"]),
        "Twelve agent incident classes have owned and rehearsed procedures.")
    exercises = data.get("safe_exercises", [])
    ids = [x.get("id") for x in exercises]
    add("safe exercise contracts", len(exercises) >= 12 and len(ids) == len(set(ids))
        and None not in ids and {x.get("class") for x in exercises} == required
        and all(x.get("aws_calls") == 0 and x.get("side_effects") == 0
                and x.get("expected") in {"CONTAIN","REVOKE","QUARANTINE","ROLLBACK","PRESERVE"}
                for x in exercises),
        "Exercises are harmless, unique, and have deterministic response oracles.")
    review = data.get("review_and_evidence", {})
    try:
        expiry = dt.date.fromisoformat(review.get("review_expires", ""))
        current = today <= expiry and (expiry - today).days <= 90
    except (TypeError, ValueError):
        current = False
    add("current independent review", bool(review.get("owner")) and current
        and all(review.get(k) is True for k in ["independent_approval_required",
            "negative_tests_required","live_kill_switch_and_recovery_drills_required"])
        and review.get("evidence_contains_sensitive_values") is False,
        "The design is current; live drills remain mandatory.")
    limits = " ".join(data.get("limitations", [])).lower()
    add("honest offline limitations", len(data.get("limitations", [])) >= 7
        and "does not invoke aws" in limits and "does not activate a kill switch" in limits
        and "does not prove hipaa compliance" in limits,
        "Offline checks are not live incident-response proof.")
    add("non-production only", data.get("environment") == "non-production",
        "The lab cannot target production.")
    add("exact chapter contract", data.get("chapter") == 11,
        "Evidence is bound to Chapter 11.")
    add("fail closed throughout",
        kill.get("default_deny_required") is True
        and kill.get("fail_closed_if_state_unavailable") is True
        and recovery.get("kill_switch_clear_requires_new_authorization") is True,
        "Missing state denies actions and recovery needs fresh authorization.")
    add("separation of duties",
        auth.get("independent_incident_commander_required") is True
        and auth.get("break_glass_requires_two_people") is True
        and recovery.get("independent_recovery_approval_required") is True,
        "No single agent or responder can contain and restore alone.")
    add("recovery resists recurrence",
        recovery.get("credential_rotation_verified_required") is True
        and recovery.get("full_security_regression_required") is True
        and revoke.get("replay_denied_after_recovery") is True,
        "Rotated authority and regression tests prevent immediate recurrence.")
    return checks

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    checks = validate(json.loads(Path(args.manifest).read_text()))
    result = {"chapter":11,"mode":"offline","aws_calls":0,"resources_created":0,
              "kill_switch_activations":0,"credentials_revoked":0,
              "deployments":0,"prohibited_side_effects":0,"checks":checks}
    out = Path(args.evidence)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    for check in checks:
        print(f'{check["status"]}: {check["name"]}')
    if any(c["status"] == "FAIL" for c in checks):
        raise SystemExit(1)
    print(f"{len(checks)} Chapter 11 incident-response checks passed")

if __name__ == "__main__":
    main()
