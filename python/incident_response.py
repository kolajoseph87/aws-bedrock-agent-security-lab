"""Pure, offline Chapter 11 incident-response decision helpers."""
import hashlib
import hmac
import json
import re

BLOCKED_WHEN_ACTIVE = {
    "model.invoke", "rag.retrieve", "tool.request", "worker.start",
    "repository.write", "release.promote", "deployment.start"
}
ALLOWED_WHEN_ACTIVE = {"evidence.read", "incident.status"}
COMMAND_FIELDS = {
    "incident_id", "nonce", "issued_at", "expires_at", "requested_by",
    "approved_by", "approvers", "action", "scope"
}
COMMAND_ACTIONS = {"ACTIVATE", "CONTAIN", "REVOKE", "CLEAR"}
SENSITIVE_KEYS = {
    "prompt", "completion", "code", "retrieved_chunk", "tool_arguments",
    "phi", "pii", "credential", "token", "secret"
}

def canonical_digest(value):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()

def sign_command(command, key):
    return hmac.new(key, canonical_digest(command).encode(), hashlib.sha256).hexdigest()

def verify_command(command, signature, key, now, used_nonces):
    if set(command) != COMMAND_FIELDS:
        return False, "COMMAND_SCHEMA_DENIED"
    if not hmac.compare_digest(sign_command(command, key), signature):
        return False, "BAD_SIGNATURE"
    if command["action"] not in COMMAND_ACTIONS:
        return False, "UNKNOWN_COMMAND"
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", command["nonce"] or ""):
        return False, "NONCE_INVALID"
    if command["issued_at"] > now or command["expires_at"] <= now:
        return False, "EXPIRED_OR_NOT_YET_VALID"
    if command["expires_at"] - command["issued_at"] > 900:
        return False, "TTL_TOO_LONG"
    if command["nonce"] in used_nonces:
        return False, "REPLAY"
    if command["approved_by"] == command["requested_by"]:
        return False, "SELF_APPROVAL"
    approvers = command["approvers"]
    if (not isinstance(approvers, list) or len(approvers) < 2
            or len(set(approvers)) != len(approvers)
            or command["requested_by"] in approvers
            or command["approved_by"] not in approvers):
        return False, "TWO_PERSON_RULE"
    if not command["incident_id"] or not command["scope"]:
        return False, "COMMAND_SCOPE_DENIED"
    used_nonces.add(command["nonce"])
    return True, "AUTHORIZED"

def authorize_action(action, incident_active, state_available=True):
    if state_available is not True or not isinstance(incident_active, bool):
        return False, "INCIDENT_STATE_UNAVAILABLE"
    if action not in BLOCKED_WHEN_ACTIVE | ALLOWED_WHEN_ACTIVE:
        return False, "UNKNOWN_ACTION_DENIED"
    if incident_active:
        if action in BLOCKED_WHEN_ACTIVE:
            return False, "KILL_SWITCH_ACTIVE"
        if action not in ALLOWED_WHEN_ACTIVE:
            return False, "UNKNOWN_ACTION_DENIED"
    return True, "ALLOWED"

def recovery_ready(record):
    required = {
        "known_good_digest_verified", "credentials_rotated",
        "rag_negative_test_passed", "security_regression_passed",
        "independent_approval", "canary_ready", "rollback_ready",
        "new_authorization"
    }
    if set(record) != required:
        return False, "RECOVERY_SCHEMA_DENIED"
    missing = sorted(k for k in required if record[k] is not True)
    return (not missing, "READY" if not missing else "MISSING:" + ",".join(missing))

def sanitize_evidence(event):
    if not isinstance(event, dict):
        raise ValueError("evidence must be an object")
    redacted = []

    def scrub(value, path=""):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                key_path = f"{path}.{key}" if path else key
                if key.lower() in SENSITIVE_KEYS:
                    redacted.append(key_path)
                else:
                    result[key] = scrub(item, key_path)
            return result
        if isinstance(value, list):
            return [scrub(item, f"{path}[{index}]")
                    for index, item in enumerate(value)]
        return value

    clean = scrub(event)
    clean["redacted_fields"] = sorted(redacted)
    clean["event_digest"] = canonical_digest(clean)
    return clean
