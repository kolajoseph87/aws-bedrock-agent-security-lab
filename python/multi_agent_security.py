"""Pure offline helpers for authenticated, bounded multi-agent handoffs."""
import hashlib
import hmac
import json
import re

FIELDS = {
    "message_id", "parent_id", "correlation_id", "sender", "receiver",
    "tenant", "repository", "task", "operation", "resource", "capabilities",
    "delegation_depth", "issued_at", "expires_at", "nonce", "payload_digest"
}
AGENTS = {
    "planner", "retriever", "policy", "patch-worker", "reviewer",
    "release-controller"
}
OPS = {
    "plan.create", "rag.retrieve", "policy.evaluate", "patch.propose",
    "review.record", "release.request"
}
RECEIVER_OPERATION = {
    "planner": "plan.create", "retriever": "rag.retrieve",
    "policy": "policy.evaluate", "patch-worker": "patch.propose",
    "reviewer": "review.record", "release-controller": "release.request"
}
ALLOWED_HANDOFFS = {
    "planner": {"retriever", "policy"},
    "retriever": {"policy"},
    "policy": {"patch-worker"},
    "patch-worker": {"reviewer"},
    "reviewer": {"release-controller"},
    "release-controller": set(),
}
HEX64 = re.compile(r"[0-9a-f]{64}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{8,128}")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sign(message, key):
    return hmac.new(key, canonical(message), hashlib.sha256).hexdigest()


def capability(operation, receiver, resource):
    return f"{operation}|{receiver}|{resource}"


def verify_handoff(message, signature, keys, now, used_nonces, payload,
                   parent=None, parent_signature=None, revoked=frozenset()):
    if set(message) != FIELDS:
        return False, "MESSAGE_SCHEMA_DENIED"
    if message.get("sender") not in keys:
        return False, "IDENTITY_DENIED"
    if not hmac.compare_digest(sign(message, keys[message["sender"]]), signature):
        return False, "BAD_SIGNATURE"
    if (message["sender"] not in AGENTS or message["receiver"] not in AGENTS
            or message["sender"] == message["receiver"]):
        return False, "IDENTITY_DENIED"
    if parent:
        if (set(parent) != FIELDS or parent.get("sender") not in keys
                or parent_signature is None
                or not hmac.compare_digest(
                    sign(parent, keys[parent["sender"]]), parent_signature)):
            return False, "PARENT_AUTHENTICATION_DENIED"
        if message["sender"] != parent["receiver"]:
            return False, "PRIVILEGE_LAUNDERING_DENIED"
    if message["receiver"] not in ALLOWED_HANDOFFS[message["sender"]]:
        return False, "HANDOFF_PATH_DENIED"
    if (message["operation"] not in OPS
            or message["operation"] != RECEIVER_OPERATION[message["receiver"]]):
        return False, "OPERATION_DENIED"
    if not TOKEN.fullmatch(message.get("nonce") or ""):
        return False, "NONCE_DENIED"
    if message["nonce"] in used_nonces:
        return False, "REPLAY"
    capabilities = message.get("capabilities")
    if (not isinstance(capabilities, list) or not capabilities
            or len(capabilities) != len(set(capabilities))
            or capability(message["operation"], message["receiver"],
                          message["resource"]) not in capabilities):
        return False, "CAPABILITY_DENIED"
    if ({message["message_id"], message["nonce"]} | set(capabilities)) & set(revoked):
        return False, "REVOKED"
    if (not isinstance(message["issued_at"], int)
            or not isinstance(message["expires_at"], int)
            or not message["issued_at"] <= now < message["expires_at"]):
        return False, "EXPIRED_OR_NOT_YET_VALID"
    if message["expires_at"] - message["issued_at"] > 300:
        return False, "TTL_TOO_LONG"
    strings = [
        "message_id", "parent_id", "correlation_id", "tenant", "repository",
        "task", "resource"
    ]
    if not all(isinstance(message[x], str) and message[x] for x in strings):
        return False, "CONTEXT_DENIED"
    if not HEX64.fullmatch(message.get("payload_digest") or ""):
        return False, "PAYLOAD_DIGEST_DENIED"
    if digest(payload) != message["payload_digest"]:
        return False, "PAYLOAD_TAMPERED"
    if (not isinstance(message["delegation_depth"], int)
            or not 0 <= message["delegation_depth"] <= 3):
        return False, "DELEGATION_DEPTH_DENIED"
    if parent:
        if (message["parent_id"] != parent["message_id"]
                or message["correlation_id"] != parent["correlation_id"]):
            return False, "PARENT_BINDING_DENIED"
        for field in ["tenant", "repository", "task"]:
            if message[field] != parent[field]:
                return False, "SCOPE_EXPANSION_DENIED"
        if not set(capabilities).issubset(parent["capabilities"]):
            return False, "PRIVILEGE_AMPLIFICATION_DENIED"
        if (message["delegation_depth"] != parent["delegation_depth"] + 1
                or message["expires_at"] > parent["expires_at"]):
            return False, "DELEGATION_CHAIN_DENIED"
    used_nonces.add(message["nonce"])
    return True, "AUTHORIZED"


def graph_safe(edges, max_depth=3, max_fanout=4, max_handoffs=12):
    if len(edges) > max_handoffs:
        return False, "HANDOFF_LIMIT"
    graph = {}
    for sender, receiver in edges:
        graph.setdefault(sender, []).append(receiver)
    if any(len(receivers) > max_fanout for receivers in graph.values()):
        return False, "FANOUT_LIMIT"

    def walk(node, path, depth):
        if node in path or depth > max_depth:
            return False
        return all(walk(child, path + [node], depth + 1)
                   for child in graph.get(node, []))

    return ((True, "SAFE") if all(walk(node, [], 0) for node in graph)
            else (False, "CYCLE_OR_DEPTH"))


SENSITIVE = {
    "prompt", "completion", "code", "chunk", "tool_arguments", "phi", "pii",
    "secret", "token", "credential"
}


def sanitize_context(value):
    if not isinstance(value, dict):
        raise ValueError("context must be an object")
    removed = []

    def clean(item, path=""):
        if isinstance(item, dict):
            output = {}
            for key, child in item.items():
                child_path = f"{path}.{key}".strip(".")
                if key.lower() in SENSITIVE:
                    removed.append(child_path)
                else:
                    output[key] = clean(child, child_path)
            return output
        if isinstance(item, list):
            return [clean(child, f"{path}[{index}]")
                    for index, child in enumerate(item)]
        return item

    output = clean(value)
    output["redacted_fields"] = sorted(removed)
    return output
