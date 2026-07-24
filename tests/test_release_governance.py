import copy, importlib.util, json, unittest
from datetime import date
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("v",ROOT/"scripts"/"validate_release_governance.py"); v=importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
BASE=json.loads((ROOT/"release-governance"/"release-governance.aws.json").read_text())
class ManifestTests(unittest.TestCase):
 def fails(self,d,t=date(2026,7,23)): return {x["name"] for x in v.validate(d,t) if x["status"]=="FAIL"}
 def m(self,path,value):
  d=copy.deepcopy(BASE); c=d
  for k in path[:-1]: c=c[k]
  c[path[-1]]=value; return d
 def test_reference(self): self.assertEqual(set(),self.fails(BASE))
 def test_production(self): self.assertIn("synthetic non-production scope",self.fails(self.m(["environment"],"production")))
 def test_wrong_order(self): self.assertIn("complete release order",self.fails(self.m(["pipeline_order"],list(reversed(BASE["pipeline_order"])))))
 def test_agent_merge(self): self.assertIn("protected independently reviewed source",self.fails(self.m(["source_policy","agent_can_merge"],True)))
 def test_one_reviewer(self): self.assertIn("protected independently reviewed source",self.fails(self.m(["source_policy","required_reviewers"],1)))
 def test_fork_creds(self): self.assertIn("verifiable build provenance",self.fails(self.m(["provenance","untrusted_fork_credentials_allowed"],True)))
 def test_fail_open(self): self.assertIn("mandatory fail-closed security gates",self.fails(self.m(["security_gates","fail_mode"],"open")))
 def test_high_findings(self): self.assertIn("mandatory fail-closed security gates",self.fails(self.m(["security_gates","high_findings_allowed"],1)))
 def test_permanent_waiver(self): self.assertIn("governed risk waivers",self.fails(self.m(["security_gates","waivers_expire"],False)))
 def test_mutable_tag(self): self.assertIn("hardened dependencies",self.fails(self.m(["dependency_policy","mutable_tags_allowed"],True)))
 def test_install_script(self): self.assertIn("hardened dependencies",self.fails(self.m(["dependency_policy","install_scripts_allowed"],True)))
 def test_unsigned(self): self.assertIn("signed immutable artifacts",self.fails(self.m(["artifact_policy","cosign_signature_required"],False)))
 def test_rebuild(self): self.assertIn("same artifact promoted",self.fails(self.m(["artifact_policy","rebuild_between_environments"],True)))
 def test_agent_deploy(self): self.assertIn("separated deployment authority",self.fails(self.m(["deployment_policy","agent_can_deploy"],True)))
 def test_long_lived_creds(self): self.assertIn("separated deployment authority",self.fails(self.m(["deployment_policy","long_lived_cloud_credentials_allowed"],True)))
 def test_no_rollback(self): self.assertIn("safe production rollout",self.fails(self.m(["deployment_policy","automatic_rollback_required"],False)))
 def test_sensitive_evidence(self): self.assertIn("healthcare-safe evidence",self.fails(self.m(["healthcare_controls","sensitive_bodies_in_evidence_allowed"],True)))
 def test_privileged_build(self): self.assertIn("AWS pipeline safeguards",self.fails(self.m(["aws_controls","codebuild_privileged_mode"],True)))
 def test_attack_side_effect(self): self.assertIn("safe attack contracts",self.fails(self.m(["safe_attacks",0,"prohibited_side_effects"],1)))
 def test_expired_review(self): self.assertIn("current independent review",self.fails(BASE,date(2026,9,16)))
if __name__=="__main__": unittest.main()
