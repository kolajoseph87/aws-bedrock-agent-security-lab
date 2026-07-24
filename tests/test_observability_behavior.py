import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"python"))
from observability import deliver_event, detect, event_hash, keyed_hash, sanitize_event
KEY=b"k"*32
H=keyed_hash("synthetic",KEY); ZERO="0"*64
def event(**kw):
 x={"event_id":"evt-1","schema_version":"1","timestamp":"2026-07-23T00:00:00Z","sequence_number":1,"previous_event_hash":ZERO,"event_hash":ZERO,"correlation_id":"corr-1","principal_id":"runtime-role","session_id_hash":H,"tenant_id_hash":H,"repository_id_hash":H,"model_id":"approved-model","policy_version":"policy-v9","stage":"PRE_TOOL","action":"analyze","decision":"ALLOW","reason_code":"AUTHORIZED","latency_ms":10,"input_tokens":20,"output_tokens":30}
 x.update(kw); x["event_hash"]=event_hash(x,KEY); return x
class BehaviorTests(unittest.TestCase):
 def clean_event(self,**kw): return event(**kw)
 def sanitize(self,x=None,**kw): return sanitize_event(x or event(),"runtime-role",H,H,KEY,**kw)
 def test_hash_is_deterministic(self): self.assertEqual(keyed_hash("x",KEY),keyed_hash("x",KEY))
 def test_hash_is_not_plaintext(self): self.assertNotEqual("x",keyed_hash("x",KEY))
 def test_short_hash_key_fails(self):
  with self.assertRaises(ValueError): keyed_hash("x",b"short")
 def test_event_ok(self): self.assertTrue(self.sanitize()["allow"])
 def test_unknown_field(self):
  x=event(); x["debug"]="raw"; self.assertEqual("SCHEMA_DENIED",self.sanitize(x)["reason"])
 def test_missing_field(self):
  x=event(); del x["model_id"]; self.assertEqual("SCHEMA_DENIED",self.sanitize(x)["reason"])
 def test_empty_field(self): self.assertEqual("REQUIRED_FIELD_MISSING",self.sanitize(event(model_id=""))["reason"])
 def test_forged_principal(self): self.assertEqual("PRINCIPAL_MISMATCH",self.sanitize(event(principal_id="agent"))["reason"])
 def test_forged_scope(self): self.assertEqual("SCOPE_MISMATCH",self.sanitize(event(tenant_id_hash="a"*64))["reason"])
 def test_invalid_decision(self): self.assertEqual("DECISION_DENIED",self.sanitize(event(decision="SKIP"))["reason"])
 def test_invalid_stage(self): self.assertEqual("EVENT_ENUM_DENIED",self.sanitize(event(stage="UNKNOWN"))["reason"])
 def test_invalid_timestamp(self): self.assertEqual("TIMESTAMP_INVALID",self.sanitize(event(timestamp="yesterday"))["reason"])
 def test_invalid_sequence(self): self.assertEqual("SEQUENCE_INVALID",self.sanitize(event(sequence_number=0))["reason"])
 def test_negative_metric(self): self.assertEqual("METRIC_INVALID",self.sanitize(event(input_tokens=-1))["reason"])
 def test_email_denied(self): self.assertEqual("SENSITIVE_VALUE_DENIED",self.sanitize(event(reason_code="a@b.com"))["reason"])
 def test_bearer_denied(self): self.assertEqual("SENSITIVE_VALUE_DENIED",self.sanitize(event(reason_code="Bearer abc.def"))["reason"])
 def test_bad_hash(self):
  x=event(); x["session_id_hash"]="bad"; x["event_hash"]=event_hash(x,KEY)
  self.assertEqual("HASH_INVALID",self.sanitize(x)["reason"])
 def test_tampered_event(self):
  x=event(); x["action"]="changed"
  self.assertEqual("EVENT_INTEGRITY_INVALID",self.sanitize(x)["reason"])
 def clean(self): return self.sanitize()
 def test_delivery_ok(self): self.assertTrue(deliver_event(self.clean())["allow"])
 def test_unsanitized_denied(self): self.assertEqual("UNSANITIZED_EVENT",deliver_event({"allow":False})["reason"])
 def test_disable_denied(self): self.assertEqual("TELEMETRY_DISABLE_DENIED",deliver_event(self.clean(),agent_disable_requested=True)["reason"])
 def test_gap_blocks_action(self): self.assertEqual("AUDIT_BUFFERED_ACTION_BLOCKED",deliver_event(self.clean(),False)["reason"])
 def test_full_buffer_denied(self): self.assertEqual("AUDIT_DELIVERY_FAILED",deliver_event(self.clean(),False,buffer_size=100)["reason"])
 def test_no_alert(self): self.assertEqual([],detect([event()]))
 def test_duplicate(self): self.assertIn("DUPLICATE_EVENT_REPLAY",detect([event(),event()]))
 def test_cross_tenant(self): self.assertIn("CROSS_TENANT",detect([event(reason_code="CROSS_TENANT",decision="DENY")]))
 def test_cross_repository(self): self.assertIn("CROSS_REPOSITORY",detect([event(reason_code="CROSS_REPOSITORY",decision="DENY")]))
 def test_prompt_injection(self): self.assertIn("PROMPT_INJECTION",detect([event(reason_code="PROMPT_INJECTION",decision="DENY")]))
 def test_tool_authorization(self): self.assertIn("TOOL_AUTHORIZATION_FAILED",detect([event(reason_code="TOOL_AUTHORIZATION_FAILED",decision="DENY")]))
 def test_unexpected_tool(self): self.assertIn("UNEXPECTED_TOOL_OR_RESOURCE",detect([event(reason_code="UNEXPECTED_TOOL",decision="DENY")]))
 def test_work_order_replay(self): self.assertIn("WORK_ORDER_REPLAY",detect([event(reason_code="WORK_ORDER_REPLAY",decision="DENY")]))
 def test_credential_hit(self): self.assertIn("CREDENTIAL_DETECTED",detect([event(reason_code="CREDENTIAL_DETECTED",decision="DENY")]))
 def test_phi_hit(self): self.assertIn("PHI_DETECTED",detect([event(reason_code="PHI_DETECTED",decision="DENY")]))
 def test_policy_drift(self): self.assertIn("POLICY_VERSION_DRIFT",detect([event(policy_version="old")]))
 def test_model_drift(self): self.assertIn("MODEL_VERSION_DRIFT",detect([event(model_id="other")]))
 def test_cost_latency_anomaly(self): self.assertIn("TOKEN_COST_OR_LATENCY_ANOMALY",detect([event(input_tokens=10001)]))
 def test_deployment_bypass(self): self.assertIn("DEPLOYMENT_BYPASS",detect([event(reason_code="DEPLOYMENT_BYPASS",decision="DENY")]))
 def test_sequence_gap(self): self.assertIn("TELEMETRY_SEQUENCE_GAP",detect([event(sequence_number=2)]))
 def test_out_of_order_delivery(self):
  first=event(event_id="e1",sequence_number=1)
  second=event(event_id="e2",sequence_number=2,previous_event_hash=first["event_hash"])
  self.assertIn("TELEMETRY_SEQUENCE_GAP",detect([second,first]))
 def test_chain_tamper(self): self.assertIn("TELEMETRY_GAP_OR_TAMPER",detect([event(previous_event_hash="f"*64)]))
 def test_denial_spike(self): self.assertIn("RUNTIME_DENIAL_SPIKE",detect([event(event_id=f"e{i}",decision="DENY") for i in range(3)]))
if __name__=="__main__": unittest.main()
