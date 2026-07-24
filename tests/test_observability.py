import copy, importlib.util, json, unittest
from datetime import date
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("v",ROOT/"scripts"/"validate_observability.py"); v=importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
BASE=json.loads((ROOT/"observability"/"observability.aws.json").read_text())
class ManifestTests(unittest.TestCase):
 def fails(self,d,t=date(2026,7,23)): return {x["name"] for x in v.validate(d,t) if x["status"]=="FAIL"}
 def m(self,path,value):
  d=copy.deepcopy(BASE); c=d
  for k in path[:-1]: c=c[k]
  c[path[-1]]=value; return d
 def test_reference(self): self.assertEqual(set(),self.fails(BASE))
 def test_production(self): self.assertIn("synthetic non-production scope",self.fails(self.m(["environment"],"production")))
 def test_wrong_order(self): self.assertIn("complete monitoring order",self.fails(self.m(["event_flow"],list(reversed(BASE["event_flow"])))))
 def test_prompt_body(self): self.assertIn("minimum necessary telemetry",self.fails(self.m(["telemetry_policy","raw_prompt_logging_allowed"],True)))
 def test_tool_arguments(self): self.assertIn("minimum necessary telemetry",self.fails(self.m(["telemetry_policy","tool_argument_body_logging_allowed"],True)))
 def test_prompt_identity(self): self.assertIn("structured attributable telemetry",self.fails(self.m(["telemetry_policy","server_generated_identity_required"],False)))
 def test_fail_open_delivery(self): self.assertIn("fail-closed audit delivery",self.fails(self.m(["delivery_policy","fail_closed_for_security_audit_events"],False)))
 def test_agent_disable(self): self.assertIn("fail-closed audit delivery",self.fails(self.m(["delivery_policy","agent_can_disable_telemetry"],True)))
 def test_agent_log_read(self): self.assertIn("isolated immutable storage",self.fails(self.m(["storage_policy","agent_log_read_access_allowed"],True)))
 def test_short_retention(self): self.assertIn("isolated immutable storage",self.fails(self.m(["storage_policy","retention_days"],30)))
 def test_missing_replay_detection(self): self.assertIn("complete detection coverage",self.fails(self.m(["detection_policy","work_order_replay"],False)))
 def test_destructive_response(self): self.assertIn("complete detection coverage",self.fails(self.m(["detection_policy","automated_destructive_response_allowed"],True)))
 def test_invocation_bodies(self): self.assertIn("AWS telemetry safeguards",self.fails(self.m(["aws_controls","bedrock_invocation_logging_body_capture"],True)))
 def test_no_cloudtrail_validation(self): self.assertIn("AWS telemetry safeguards",self.fails(self.m(["aws_controls","cloudtrail_log_file_validation_required"],False)))
 def test_unknown_fields_allowed(self): self.assertIn("sanitized event schema",self.fails(self.m(["audit_event","unknown_fields_rejected"],False)))
 def test_sensitive_alert(self): self.assertIn("actionable safe alerting",self.fails(self.m(["alerting","alert_contains_sensitive_bodies"],True)))
 def test_slow_ack(self): self.assertIn("actionable safe alerting",self.fails(self.m(["alerting","high_severity_ack_minutes"],60)))
 def test_attack_side_effect(self): self.assertIn("safe attack contracts",self.fails(self.m(["safe_attacks",0,"prohibited_side_effects"],1)))
 def test_expired_review(self): self.assertIn("current independent review",self.fails(BASE,date(2026,9,16)))
 def test_wrong_chapter(self): self.assertIn("exact chapter contract",self.fails(self.m(["chapter"],8)))
if __name__=="__main__": unittest.main()
