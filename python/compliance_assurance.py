"""Deterministic, fail-closed compliance-assurance teaching helpers."""
import datetime as dt
import re

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED_RECORD_FIELDS = {
    "control_id",
    "owner",
    "independent_approver",
    "test",
    "test_result",
    "evidence_digest",
    "collected_on",
    "source_commit",
    "model_version",
    "policy_version",
    "status",
}
APPROVAL_ROLES = {"security-reviewer", "privacy-reviewer", "risk-reviewer"}


def evidence_fresh(collected_on, today=None, maximum_days=90):
    today = today or dt.date.today()
    if not isinstance(maximum_days, int) or isinstance(maximum_days, bool):
        return False
    if not 1 <= maximum_days <= 90:
        return False
    try:
        stamp = dt.date.fromisoformat(collected_on)
    except (TypeError, ValueError):
        return False
    return 0 <= (today - stamp).days <= maximum_days


def production_decision(
    records,
    approvals,
    executive_acceptance,
    assessed_version,
    today=None,
    maximum_days=90,
):
    """Recommend only a controlled non-production pilot when every check passes."""
    today = today or dt.date.today()
    if not isinstance(assessed_version, str) or not assessed_version:
        return "BLOCK"
    if not isinstance(records, list) or not records:
        return "BLOCK"
    if not isinstance(approvals, list) or not approvals:
        return "BLOCK"
    if not isinstance(executive_acceptance, dict):
        return "BLOCK"

    control_ids = []
    owners = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != REQUIRED_RECORD_FIELDS:
            return "BLOCK"
        if record["status"] != "PASS" or record["test_result"] != "PASS":
            return "BLOCK"
        if record["source_commit"] != assessed_version:
            return "BLOCK"
        if not SHA256.fullmatch(record["evidence_digest"]):
            return "BLOCK"
        if not evidence_fresh(record["collected_on"], today, maximum_days):
            return "BLOCK"
        if not all(
            isinstance(record[field], str) and record[field]
            for field in REQUIRED_RECORD_FIELDS - {"status", "test_result"}
        ):
            return "BLOCK"
        if record["owner"] == record["independent_approver"]:
            return "BLOCK"
        control_ids.append(record["control_id"])
        owners.add(record["owner"])
    if len(control_ids) != len(set(control_ids)):
        return "BLOCK"

    people = set()
    for approval in approvals:
        if not isinstance(approval, dict):
            return "BLOCK"
        if set(approval) != {
            "person",
            "role",
            "decision",
            "independent",
            "assessed_version",
            "approved_on",
        }:
            return "BLOCK"
        if (
            approval["independent"] is not True
            or approval["decision"] != "APPROVE"
            or approval["role"] not in APPROVAL_ROLES
            or approval["assessed_version"] != assessed_version
            or not evidence_fresh(approval["approved_on"], today, maximum_days)
            or not isinstance(approval["person"], str)
            or not approval["person"]
            or approval["person"] in owners
        ):
            return "BLOCK"
        people.add(approval["person"])
    if len(people) < 2:
        return "BLOCK"

    if set(executive_acceptance) != {
        "person",
        "role",
        "decision",
        "assessed_version",
        "accepted_on",
    }:
        return "BLOCK"
    if (
        executive_acceptance["role"] != "accountable-executive"
        or executive_acceptance["decision"] != "ACCEPT"
        or executive_acceptance["assessed_version"] != assessed_version
        or not evidence_fresh(
            executive_acceptance["accepted_on"], today, maximum_days
        )
        or executive_acceptance["person"] in people
        or executive_acceptance["person"] in owners
    ):
        return "BLOCK"
    return "READY_FOR_CONTROLLED_NONPRODUCTION_PILOT"
