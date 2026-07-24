"""Deterministic, offline Chapter 5 teaching runner. It performs no external action."""
from dataclasses import dataclass, field
import re
import uuid


@dataclass
class RunResult:
    decision: str = "deny"
    reason: str = "POLICY_ERROR"
    stop_at: str = "PRE_INPUT"
    model_calls: int = 0
    tool_calls: int = 0
    prohibited_side_effects: int = 0
    response: str | None = None
    correlation_id: str = ""
    audit: list = field(default_factory=list)


class GovernedRunner:
    """Tiny proof model for ordering and zero-side-effect assertions."""

    def _event(self, result, boundary, decision, reason):
        result.audit.append({
            "correlation_id": result.correlation_id,
            "boundary": boundary,
            "decision": decision,
            "reason_code": reason
        })

    def run(self, prompt, principal="NorthstarSecureCodingAgentRole", tool=None,
            action=None, resource=None, path="src/example.py", approval_id=None,
            output="Sanitized secure-coding recommendation", policy_available=True):
        result = RunResult(correlation_id=str(uuid.uuid4()))
        text = prompt.lower()
        if not policy_available:
            result.reason = "POLICY_ERROR"
            self._event(result, "PRE_INPUT", "deny", result.reason)
            return result
        if any(x in text for x in ["ignore policy", "deploy production", "disable security"]):
            result.reason = "INPUT_INJECTION"
            self._event(result, "PRE_INPUT", "deny", result.reason)
            return result
        if any(x in text for x in ["synthetic-mrn-", "synthetic-patient-", "synthetic-ssn-"]):
            result.reason = "INPUT_SENSITIVE"
            self._event(result, "PRE_INPUT", "deny", result.reason)
            return result
        self._event(result, "PRE_INPUT", "allow", "INPUT_ALLOWED")
        result.model_calls = 1

        if tool:
            result.stop_at = "PRE_TOOL"
            if not policy_available:
                result.reason = "POLICY_TIMEOUT"
                self._event(result, "PRE_TOOL", "deny", result.reason)
                return result
            allowed_read = (principal == "NorthstarSecureCodingAgentRole"
                            and tool == "repository-reader" and action == "read"
                            and resource == "repo://training/secure-coding-agent")
            allowed_write = (principal == "NorthstarIsolatedPatchWorkerRole"
                             and tool == "patch-applier" and action == "write"
                             and resource == "workspace://training/isolated")
            if not (allowed_read or allowed_write):
                result.reason = "TOOL_NOT_ALLOWED"
                self._event(result, "PRE_TOOL", "deny", result.reason)
                return result
            if path.startswith("/") or ".." in path.split("/") or not path.startswith(("src/", "tests/")):
                result.reason = "ARGUMENT_NOT_ALLOWED"
                self._event(result, "PRE_TOOL", "deny", result.reason)
                return result
            if allowed_write and not approval_id:
                result.reason = "APPROVAL_REQUIRED"
                self._event(result, "PRE_TOOL", "deny", result.reason)
                return result
            self._event(result, "PRE_TOOL", "allow", "TOOL_ALLOWED")
            result.tool_calls = 1

        result.stop_at = "PRE_OUTPUT"
        if re.search(r"(training[_-]?secret|synthetic[_-]?token|synthetic-mrn-)", output, re.I):
            result.reason = "OUTPUT_SENSITIVE"
            self._event(result, "PRE_OUTPUT", "deny", result.reason)
            return result
        if re.search(r"\b(i|we)\s+(deployed|merged|pushed)\b", output, re.I):
            result.reason = "UNSUPPORTED_ACTION_CLAIM"
            self._event(result, "PRE_OUTPUT", "deny", result.reason)
            return result
        self._event(result, "PRE_OUTPUT", "allow", "OUTPUT_ALLOWED")
        result.stop_at = "AUDIT"
        result.decision = "allow"
        result.reason = "ALLOWED"
        result.response = output
        return result
