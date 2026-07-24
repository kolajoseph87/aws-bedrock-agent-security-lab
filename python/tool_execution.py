"""Deterministic offline tool-execution teaching model. Makes no external calls."""
import hashlib
import re
import time

ALLOWED = {"apply_patch", "run_unit_tests", "run_static_analysis", "create_patch_artifact"}
FORBIDDEN = {"push", "merge", "release", "deploy", "modify_pipeline", "read_secret", "assume_role"}
META = re.compile(r"[;&|`$><\n\r]")
SENSITIVE = re.compile(
    r"(access[_ -]?token|synthetic[- ]?mrn|patient diagnosis|private[_ -]?key|"
    r"aws_secret_access_key|authorization:\s*bearer|ssn\s*[:=])",
    re.I,
)
PROTECTED = (".github/workflows",)

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def _path_reason(path, symlink_paths=()):
    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
        return "PATH_ESCAPE"
    parts = path.split("/")
    if path.startswith("/") or ".." in parts or "." in parts or any(not part for part in parts):
        return "PATH_ESCAPE"
    if any(path == root or path.startswith(root + "/") for root in PROTECTED):
        return "PIPELINE_CHANGE_DENIED"
    if path in set(symlink_paths):
        return "SYMLINK_ESCAPE"
    return None

def authorize_request(operation, paths, arguments, base_commit, approved_commit, *,
                      principal, approved_principal, repository, approved_repository,
                      policy_version, approved_policy_version, symlink_paths=()):
    if operation not in ALLOWED or operation in FORBIDDEN:
        return {"allow": False, "reason": "OPERATION_DENIED"}
    if not principal or principal != approved_principal:
        return {"allow": False, "reason": "PRINCIPAL_MISMATCH"}
    if not repository or repository != approved_repository:
        return {"allow": False, "reason": "REPOSITORY_MISMATCH"}
    if not policy_version or policy_version != approved_policy_version:
        return {"allow": False, "reason": "POLICY_VERSION_MISMATCH"}
    if not base_commit or base_commit != approved_commit:
        return {"allow": False, "reason": "COMMIT_MISMATCH"}
    if not isinstance(paths, list) or not paths:
        return {"allow": False, "reason": "PATHS_REQUIRED"}
    for path in paths:
        reason = _path_reason(path, symlink_paths)
        if reason:
            return {"allow": False, "reason": reason}
    if not isinstance(arguments, list) or any(not isinstance(x, str) or META.search(x) for x in arguments):
        return {"allow": False, "reason": "UNSAFE_ARGUMENTS"}
    return {"allow": True, "reason": "REQUEST_APPROVED", "argument_hash": digest("\0".join(arguments))}

def verify_work_order(order, expected, used_nonces=None, now=None):
    used_nonces = used_nonces if used_nonces is not None else set()
    now = int(time.time()) if now is None else now
    required = {"id", "principal", "repository", "base_commit", "operation", "paths",
                "argument_hash", "policy_version", "nonce", "expires_at", "signature_valid"}
    if not required.issubset(order):
        return {"allow": False, "reason": "WORK_ORDER_INCOMPLETE"}
    if order["signature_valid"] is not True:
        return {"allow": False, "reason": "SIGNATURE_INVALID"}
    if not isinstance(order["expires_at"], int) or order["expires_at"] <= now or order["expires_at"] - now > 300:
        return {"allow": False, "reason": "WORK_ORDER_EXPIRED_OR_TOO_LONG"}
    if not isinstance(order["nonce"], str) or not order["nonce"]:
        return {"allow": False, "reason": "WORK_ORDER_INCOMPLETE"}
    if order["nonce"] in used_nonces:
        return {"allow": False, "reason": "REPLAY_DENIED"}
    for field in ("principal", "repository", "base_commit", "operation", "paths",
                  "argument_hash", "policy_version"):
        if field not in expected or order[field] != expected[field]:
            return {"allow": False, "reason": "WORK_ORDER_BINDING_MISMATCH"}
    used_nonces.add(order["nonce"])
    return {"allow": True, "reason": "WORK_ORDER_VERIFIED"}

def validate_artifact(changed_paths, patch, tests_passed, static_analysis_passed,
                      streaming_started=False, max_files=20, max_bytes=262144,
                      command_output="", max_output_bytes=1048576,
                      malware_found=False, unsafe_code_found=False,
                      symlink_paths=()):
    if streaming_started:
        return {"allow": False, "reason": "LOG_STREAMING_BEFORE_SCAN"}
    if (not isinstance(changed_paths, list) or len(changed_paths) > max_files
            or len(patch.encode()) > max_bytes
            or len(command_output.encode()) > max_output_bytes):
        return {"allow": False, "reason": "ARTIFACT_LIMIT_EXCEEDED"}
    for path in changed_paths:
        if _path_reason(path, symlink_paths):
            return {"allow": False, "reason": "DIFF_SCOPE_DENIED"}
    if malware_found:
        return {"allow": False, "reason": "MALWARE_DETECTED"}
    if unsafe_code_found:
        return {"allow": False, "reason": "UNSAFE_CODE_DETECTED"}
    if SENSITIVE.search(patch) or SENSITIVE.search(command_output):
        return {"allow": False, "reason": "SENSITIVE_ARTIFACT"}
    if not tests_passed or not static_analysis_passed:
        return {"allow": False, "reason": "VERIFICATION_FAILED"}
    return {"allow": True, "reason": "ARTIFACT_READY_FOR_HUMAN_REVIEW", "patch_hash": digest(patch)}
