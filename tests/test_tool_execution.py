import copy, importlib.util, json, unittest
from datetime import date
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("v",ROOT/"scripts"/"validate_tool_execution.py"); v=importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
BASE=json.loads((ROOT/"tool-execution"/"tool-execution.aws.json").read_text())
class ManifestTests(unittest.TestCase):
 def fails(self,d,t=date(2026,7,23)): return {x["name"] for x in v.validate(d,t) if x["status"]=="FAIL"}
 def mutate(self,path,value):
  d=copy.deepcopy(BASE); cur=d
  for k in path[:-1]: cur=cur[k]
  cur[path[-1]]=value; return d
 def test_reference(self): self.assertEqual(set(),self.fails(BASE))
 def test_production(self): self.assertIn("synthetic non-production scope",self.fails(self.mutate(["environment"],"production")))
 def test_real_phi(self): self.assertIn("synthetic non-production scope",self.fails(self.mutate(["healthcare_controls","real_phi_allowed"],True)))
 def test_wrong_order(self): self.assertIn("complete execution order",self.fails(self.mutate(["execution_order"],list(reversed(BASE["execution_order"])))))
 def test_agent_shell(self): self.assertIn("agent has no direct execution authority",self.fails(self.mutate(["authority","agent_has_shell"],True)))
 def test_no_return_control(self): self.assertIn("agent has no direct execution authority",self.fails(self.mutate(["authority","return_control_required"],False)))
 def test_confirmation_only(self): self.assertIn("authorization independent and fail closed",self.fails(self.mutate(["authority","user_confirmation_is_sufficient_authorization"],True)))
 def test_fail_open(self): self.assertIn("authorization independent and fail closed",self.fails(self.mutate(["authority","fail_mode"],"open")))
 def test_long_order(self): self.assertIn("immutable replay-resistant work order",self.fails(self.mutate(["work_order","maximum_ttl_seconds"],3600)))
 def test_prompt_scope(self): self.assertIn("immutable replay-resistant work order",self.fails(self.mutate(["work_order","prompt_supplied_identity_or_scope_trusted"],True)))
 def test_privileged(self): self.assertIn("non-privileged credential-free worker",self.fails(self.mutate(["worker_isolation","privileged_mode"],True)))
 def test_open_egress(self): self.assertIn("disposable private worker",self.fails(self.mutate(["worker_isolation","default_network_egress"],"allow")))
 def test_secret_access(self): self.assertIn("non-privileged credential-free worker",self.fails(self.mutate(["worker_isolation","secrets_access_allowed"],True)))
 def test_free_shell(self): self.assertIn("deterministic command and path policy",self.fails(self.mutate(["command_policy","free_form_shell_allowed"],True)))
 def test_package_install(self): self.assertIn("safe operation catalog",self.fails(self.mutate(["command_policy","package_install_allowed"],True)))
 def test_bad_limit(self): self.assertIn("bounded worker resources",self.fails(self.mutate(["resource_limits","max_concurrent_jobs_per_repository"],5)))
 def test_self_approval(self): self.assertIn("validated human-reviewed artifact",self.fails(self.mutate(["artifact_policy","worker_can_approve_itself"],True)))
 def test_log_streaming(self): self.assertIn("validated human-reviewed artifact",self.fails(self.mutate(["artifact_policy","streaming_worker_logs_allowed"],True)))
 def test_debug(self): self.assertIn("AWS least-privilege execution controls",self.fails(self.mutate(["aws_controls","codebuild_session_manager_debug_allowed"],True)))
 def test_sensitive_audit(self):
  d=copy.deepcopy(BASE); d["audit"]["forbidden_fields"].remove("patch_body"); self.assertIn("sanitized execution audit",self.fails(d))
 def test_attack_effect(self): self.assertIn("safe attack contracts",self.fails(self.mutate(["safe_attacks",0,"prohibited_side_effects"],1)))
 def test_expired_review(self): self.assertIn("current independent review",self.fails(BASE,date(2026,9,16)))
if __name__=="__main__": unittest.main()
