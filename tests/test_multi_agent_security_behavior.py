import unittest
from python.multi_agent_security import *

KEYS = {agent: f"chapter-12-{agent}".encode() for agent in AGENTS}
PAYLOAD = {"decision": "synthetic"}


class BehaviorTests(unittest.TestCase):
    def msg(self, **changes):
        resource = "repo:commit:path"
        value = {
            "message_id": "message-0001", "parent_id": "root-message",
            "correlation_id": "correlation-0001", "sender": "planner",
            "receiver": "policy", "tenant": "synthetic-tenant",
            "repository": "approved/repo", "task": "task-0001",
            "operation": "policy.evaluate", "resource": resource,
            "capabilities": [capability("policy.evaluate", "policy", resource)],
            "delegation_depth": 0, "issued_at": 100, "expires_at": 200,
            "nonce": "nonce-0001", "payload_digest": digest(PAYLOAD)
        }
        value.update(changes)
        return value

    def check(self, message, payload=PAYLOAD, **kwargs):
        return verify_handoff(
            message, sign(message, KEYS[message["sender"]]), KEYS, 100, set(),
            payload, **kwargs)

    def test_valid(self):
        self.assertEqual(self.check(self.msg()), (True, "AUTHORIZED"))

    def test_bad_signature(self):
        self.assertEqual(verify_handoff(
            self.msg(), "bad", KEYS, 100, set(), PAYLOAD)[1], "BAD_SIGNATURE")

    def test_extra_field(self):
        self.assertEqual(self.check(self.msg(extra=True))[1], "MESSAGE_SCHEMA_DENIED")

    def test_unknown_sender(self):
        message = self.msg(sender="attacker")
        self.assertEqual(verify_handoff(
            message, "bad", KEYS, 100, set(), PAYLOAD)[1], "IDENTITY_DENIED")

    def test_self_handoff(self):
        self.assertEqual(self.check(self.msg(receiver="planner"))[1], "IDENTITY_DENIED")

    def test_disallowed_handoff_path(self):
        message = self.msg(sender="retriever", receiver="reviewer",
                           operation="review.record")
        message["capabilities"] = [
            capability("review.record", "reviewer", message["resource"])]
        self.assertEqual(self.check(message)[1], "HANDOFF_PATH_DENIED")

    def test_receiver_operation_mismatch(self):
        self.assertEqual(self.check(self.msg(operation="rag.retrieve"))[1],
                         "OPERATION_DENIED")

    def test_payload_tampering(self):
        self.assertEqual(self.check(self.msg(), payload={"decision": "changed"})[1],
                         "PAYLOAD_TAMPERED")

    def test_invalid_payload_digest(self):
        self.assertEqual(self.check(self.msg(payload_digest="bad"))[1],
                         "PAYLOAD_DIGEST_DENIED")

    def test_capability_not_bound_to_action(self):
        self.assertEqual(self.check(self.msg(capabilities=[
            capability("rag.retrieve", "retriever", "other")]))[1],
            "CAPABILITY_DENIED")

    def test_expired(self):
        message = self.msg()
        self.assertEqual(verify_handoff(
            message, sign(message, KEYS["planner"]), KEYS, 200, set(),
            PAYLOAD)[1], "EXPIRED_OR_NOT_YET_VALID")

    def test_long_ttl(self):
        self.assertEqual(self.check(self.msg(expires_at=500))[1], "TTL_TOO_LONG")

    def test_replay(self):
        message = self.msg()
        used = {"nonce-0001"}
        self.assertEqual(verify_handoff(
            message, sign(message, KEYS["planner"]), KEYS, 100, used,
            PAYLOAD)[1], "REPLAY")

    def test_revoked_message(self):
        self.assertEqual(self.check(self.msg(), revoked={"message-0001"})[1],
                         "REVOKED")

    def test_revoked_capability(self):
        cap = self.msg()["capabilities"][0]
        self.assertEqual(self.check(self.msg(), revoked={cap})[1], "REVOKED")

    def test_duplicate_capability(self):
        cap = self.msg()["capabilities"][0]
        self.assertEqual(self.check(self.msg(capabilities=[cap, cap]))[1],
                         "CAPABILITY_DENIED")

    def test_depth(self):
        self.assertEqual(self.check(self.msg(delegation_depth=4))[1],
                         "DELEGATION_DEPTH_DENIED")

    def child(self, parent, **changes):
        resource = parent["resource"]
        cap = capability("patch.propose", "patch-worker", resource)
        value = self.msg(
            message_id="message-0002", parent_id=parent["message_id"],
            sender="policy", receiver="patch-worker", operation="patch.propose",
            capabilities=[cap], delegation_depth=1, nonce="nonce-0002",
            expires_at=190)
        value.update(changes)
        return value

    def parent_for_child(self):
        parent = self.msg()
        parent["capabilities"].append(
            capability("patch.propose", "patch-worker", parent["resource"]))
        return parent

    def check_child(self, child, parent, **changes):
        kwargs = {
            "parent": parent,
            "parent_signature": sign(parent, KEYS[parent["sender"]])
        }
        kwargs.update(changes)
        return self.check(child, **kwargs)

    def test_parent_must_be_authenticated(self):
        parent = self.parent_for_child()
        self.assertEqual(self.check(self.child(parent), parent=parent)[1],
                         "PARENT_AUTHENTICATION_DENIED")

    def test_privilege_laundering(self):
        parent = self.parent_for_child()
        child = self.child(parent, sender="retriever")
        self.assertEqual(self.check_child(child, parent)[1],
                         "PRIVILEGE_LAUNDERING_DENIED")

    def test_scope_expansion(self):
        parent = self.parent_for_child()
        self.assertEqual(self.check_child(
            self.child(parent, tenant="other"), parent)[1],
            "SCOPE_EXPANSION_DENIED")

    def test_privilege_amplification(self):
        parent = self.msg()
        child = self.child(parent)
        self.assertEqual(self.check_child(child, parent)[1],
                         "PRIVILEGE_AMPLIFICATION_DENIED")

    def test_parent_binding(self):
        parent = self.parent_for_child()
        self.assertEqual(self.check_child(
            self.child(parent, parent_id="wrong"), parent)[1],
            "PARENT_BINDING_DENIED")

    def test_child_expiry(self):
        parent = self.parent_for_child()
        self.assertEqual(self.check_child(
            self.child(parent, expires_at=201), parent)[1],
            "DELEGATION_CHAIN_DENIED")

    def test_nonce_consumed(self):
        message = self.msg()
        used = set()
        self.assertTrue(verify_handoff(
            message, sign(message, KEYS["planner"]), KEYS, 100, used,
            PAYLOAD)[0])
        self.assertIn("nonce-0001", used)

    def test_graph_safe(self):
        self.assertEqual(graph_safe(
            [("planner", "policy"), ("policy", "patch-worker")]), (True, "SAFE"))

    def test_cycle(self):
        self.assertEqual(graph_safe([("a", "b"), ("b", "a")])[1],
                         "CYCLE_OR_DEPTH")

    def test_fanout(self):
        self.assertEqual(graph_safe([("a", str(i)) for i in range(5)])[1],
                         "FANOUT_LIMIT")

    def test_handoff_limit(self):
        self.assertEqual(graph_safe(
            [(str(i), str(i + 1)) for i in range(13)])[1], "HANDOFF_LIMIT")

    def test_depth_limit_exact(self):
        self.assertEqual(graph_safe(
            [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")])[1],
            "CYCLE_OR_DEPTH")

    def test_sanitize_nested(self):
        result = sanitize_context(
            {"scope": "ok", "inner": {"token": "x", "reason": "DENY"}})
        self.assertNotIn("token", result["inner"])
        self.assertIn("inner.token", result["redacted_fields"])

    def test_context_must_be_object(self):
        with self.assertRaises(ValueError):
            sanitize_context(["unsafe"])

    def test_canonical_stable(self):
        self.assertEqual(canonical({"a": 1, "b": 2}),
                         canonical({"b": 2, "a": 1}))
