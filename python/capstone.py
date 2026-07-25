"""Fail-closed Chapter 14 capstone decision helpers."""
import datetime as dt
import re

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$")
PHASES = (
    "preflight", "deploy", "functional-smoke", "attack-exercises",
    "incident-drill", "recovery", "evidence-freeze", "teardown", "assessment",
)
ATTACK_CLASSES = {
    "direct_prompt_injection",
    "indirect_rag_injection",
    "cross_tenant_retrieval",
    "tool_argument_manipulation",
    "work_order_replay",
    "agent_message_forgery",
    "privilege_laundering",
    "sensitive_output",
    "release_digest_substitution",
    "telemetry_tampering",
    "kill_switch",
    "recovery_regression",
}


def _fresh(value, today, maximum_days=7):
    try:
        stamp = dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return False
    return 0 <= (today - stamp).days <= maximum_days


def execution_decision(
    phases,
    attacks,
    approvals,
    authorization,
    source_commit,
    today=None,
):
    """Return the strongest educational outcome; never authorize production."""
    today = today or dt.date.today()
    if not isinstance(source_commit, str) or not source_commit:
        return "BLOCK"
    if not isinstance(authorization, dict) or set(authorization) != {
        "account_id",
        "region",
        "artifact_digest",
        "change_ticket",
        "session_ttl_minutes",
        "production_account",
        "synthetic_data_only",
    }:
        return "BLOCK"
    if (
        not ACCOUNT_ID.fullmatch(authorization["account_id"])
        or not REGION.fullmatch(authorization["region"])
        or not SHA256.fullmatch(authorization["artifact_digest"])
        or not isinstance(authorization["change_ticket"], str)
        or not authorization["change_ticket"]
        or not isinstance(authorization["session_ttl_minutes"], int)
        or isinstance(authorization["session_ttl_minutes"], bool)
        or not 1 <= authorization["session_ttl_minutes"] <= 60
        or authorization["production_account"] is not False
        or authorization["synthetic_data_only"] is not True
    ):
        return "BLOCK"
    if not isinstance(phases, list) or [x.get("name") for x in phases if isinstance(x, dict)] != list(PHASES):
        return "BLOCK"
    phase_digests = set()
    for phase in phases:
        if set(phase) != {
            "name",
            "status",
            "source_commit",
            "evidence_digest",
            "collected_on",
        }:
            return "BLOCK"
        if phase["status"] != "PASS" or phase["source_commit"] != source_commit:
            return "BLOCK"
        if (
            not SHA256.fullmatch(phase["evidence_digest"])
            or phase["evidence_digest"] in phase_digests
            or not _fresh(phase["collected_on"], today)
        ):
            return "BLOCK"
        phase_digests.add(phase["evidence_digest"])
    if not isinstance(attacks, list) or len(attacks) != 12:
        return "BLOCK"
    attack_ids, attack_classes, attack_digests = set(), set(), set()
    for attack in attacks:
        if not isinstance(attack, dict) or set(attack) != {
            "id", "class", "expected", "actual", "critical", "side_effects",
            "source_commit", "evidence_digest", "collected_on",
        }:
            return "BLOCK"
        if (
            not attack["id"] or attack["id"] in attack_ids
            or attack["class"] not in ATTACK_CLASSES
            or attack["class"] in attack_classes
            or attack["actual"] != attack["expected"]
            or attack["expected"] != "BLOCK"
            or attack["critical"] is not True
            or attack["side_effects"] != 0
            or attack["source_commit"] != source_commit
            or not SHA256.fullmatch(attack["evidence_digest"])
            or attack["evidence_digest"] in attack_digests
            or not _fresh(attack["collected_on"], today)
        ):
            return "BLOCK"
        attack_ids.add(attack["id"])
        attack_classes.add(attack["class"])
        attack_digests.add(attack["evidence_digest"])
    if attack_classes != ATTACK_CLASSES:
        return "BLOCK"
    if not isinstance(approvals, list) or len(approvals) < 3:
        return "BLOCK"
    people, roles = set(), set()
    allowed_roles = {"security-assessor", "privacy-reviewer", "business-owner"}
    for approval in approvals:
        if not isinstance(approval, dict) or set(approval) != {
            "person", "role", "decision", "independent", "source_commit",
            "account_id", "region", "artifact_digest", "change_ticket",
            "approved_on",
        }:
            return "BLOCK"
        if (
            approval["decision"] != "APPROVE"
            or approval["independent"] is not True
            or approval["role"] not in allowed_roles
            or approval["source_commit"] != source_commit
            or approval["account_id"] != authorization["account_id"]
            or approval["region"] != authorization["region"]
            or approval["artifact_digest"] != authorization["artifact_digest"]
            or approval["change_ticket"] != authorization["change_ticket"]
            or not _fresh(approval["approved_on"], today)
            or not approval["person"]
            or approval["person"] in people
        ):
            return "BLOCK"
        people.add(approval["person"])
        roles.add(approval["role"])
    if roles != allowed_roles:
        return "BLOCK"
    return "CONTROLLED_NONPRODUCTION_CAPSTONE_VALIDATED"
