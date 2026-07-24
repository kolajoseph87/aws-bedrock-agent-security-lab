import unittest
from python.incident_response import *

KEY = b"chapter-11-offline-test-key"

class BehaviorTests(unittest.TestCase):
    def command(self, **changes):
        value = {"incident_id":"INC-11","nonce":"nonce-00000001",
                 "issued_at":100,"expires_at":200,
                 "requested_by":"detector","approved_by":"commander",
                 "approvers":["commander","security-lead"],"action":"ACTIVATE",
                 "scope":"tenant:synthetic"}
        value.update(changes)
        return value

    def test_valid_command(self):
        c=self.command(); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,set()),(True,"AUTHORIZED"))
    def test_bad_signature(self):
        c=self.command(); self.assertEqual(verify_command(c,"bad",KEY,100,set())[1],"BAD_SIGNATURE")
    def test_expired(self):
        c=self.command(); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,200,set())[1],"EXPIRED_OR_NOT_YET_VALID")
    def test_replay(self):
        c=self.command(); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,{"nonce-00000001"})[1],"REPLAY")
    def test_self_approval(self):
        c=self.command(approved_by="detector"); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,set())[1],"SELF_APPROVAL")
    def test_two_person_rule(self):
        c=self.command(approvers=["commander"]); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,set())[1],"TWO_PERSON_RULE")
    def test_duplicate_approvers_denied(self):
        c=self.command(approvers=["commander","commander"]); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,set())[1],"TWO_PERSON_RULE")
    def test_requester_cannot_approve(self):
        c=self.command(approvers=["commander","detector"]); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,set())[1],"TWO_PERSON_RULE")
    def test_ttl_too_long(self):
        c=self.command(expires_at=1001); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,set())[1],"TTL_TOO_LONG")
    def test_unknown_command_denied(self):
        c=self.command(action="DELETE_EVIDENCE"); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,set())[1],"UNKNOWN_COMMAND")
    def test_unknown_command_field_denied(self):
        c=self.command(extra=True); self.assertEqual(verify_command(c,sign_command(c,KEY),KEY,100,set())[1],"COMMAND_SCHEMA_DENIED")
    def test_nonce_consumed_after_success(self):
        c=self.command(); used=set()
        self.assertTrue(verify_command(c,sign_command(c,KEY),KEY,100,used)[0])
        self.assertIn("nonce-00000001",used)
    def test_digest_stable(self):
        self.assertEqual(canonical_digest({"a":1,"b":2}),canonical_digest({"b":2,"a":1}))
    def test_fail_closed_state(self):
        self.assertEqual(authorize_action("model.invoke",False,False)[1],"INCIDENT_STATE_UNAVAILABLE")
    def test_kill_model(self):
        self.assertFalse(authorize_action("model.invoke",True)[0])
    def test_kill_rag(self):
        self.assertFalse(authorize_action("rag.retrieve",True)[0])
    def test_kill_tool(self):
        self.assertFalse(authorize_action("tool.request",True)[0])
    def test_kill_worker(self):
        self.assertFalse(authorize_action("worker.start",True)[0])
    def test_kill_repo(self):
        self.assertFalse(authorize_action("repository.write",True)[0])
    def test_kill_release(self):
        self.assertFalse(authorize_action("release.promote",True)[0])
    def test_kill_deploy(self):
        self.assertFalse(authorize_action("deployment.start",True)[0])
    def test_read_only_during_incident(self):
        self.assertTrue(authorize_action("evidence.read",True)[0])
    def test_unknown_action_denied(self):
        self.assertEqual(authorize_action("shell.execute",False)[1],"UNKNOWN_ACTION_DENIED")
    def test_malformed_incident_state_denied(self):
        self.assertEqual(authorize_action("model.invoke","false")[1],"INCIDENT_STATE_UNAVAILABLE")
    def test_recovery_ready(self):
        keys=["known_good_digest_verified","credentials_rotated","rag_negative_test_passed",
              "security_regression_passed","independent_approval","canary_ready",
              "rollback_ready","new_authorization"]
        self.assertEqual(recovery_ready({k:True for k in keys}),(True,"READY"))
    def test_recovery_missing(self):
        self.assertFalse(recovery_ready({})[0])
    def test_sanitize(self):
        clean=sanitize_evidence({"reason":"DENY","prompt":"secret","token":"x"})
        self.assertNotIn("prompt",clean); self.assertNotIn("token",clean)
    def test_nested_sensitive_evidence_removed(self):
        clean=sanitize_evidence({"context":{"token":"x","reason":"DENY"}})
        self.assertNotIn("token",clean["context"])
        self.assertIn("context.token",clean["redacted_fields"])
    def test_recovery_unknown_field_denied(self):
        self.assertEqual(recovery_ready({"extra":True})[1],"RECOVERY_SCHEMA_DENIED")
    def test_sanitize_digest(self):
        self.assertEqual(len(sanitize_evidence({"reason":"DENY"})["event_digest"]),64)
