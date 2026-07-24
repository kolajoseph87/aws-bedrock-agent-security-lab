import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"python"))
from release_governance import authorize_deployment,verify_artifact,verify_security_gates,verify_source
S="a"*40; T="b"*40; H="a"*64; B="b"*64
PASS={k:True for k in ["sast","sca","secret_scan","iac_scan","malware_scan","unit_tests","policy_tests"]}
def approval(target="test",digest=H,ticket="CHG-1",approver="human",expires_at=20):
 return {"target":target,"artifact_digest":digest,"change_ticket":ticket,"approver":approver,"expires_at":expires_at}
class BehaviorTests(unittest.TestCase):
 def test_source_ok(self): self.assertTrue(verify_source(S,S,B,B)["allow"])
 def test_unprotected(self): self.assertEqual("SOURCE_APPROVAL_DENIED",verify_source(S,S,B,B,False)["reason"])
 def test_agent_approval(self): self.assertEqual("SOURCE_APPROVAL_DENIED",verify_source(S,S,B,B,agent_approved=True)["reason"])
 def test_duplicate_reviewer(self): self.assertEqual("SOURCE_APPROVAL_DENIED",verify_source(S,S,B,B,reviewers=["one","one"])["reason"])
 def test_author_self_review(self): self.assertEqual("SOURCE_APPROVAL_DENIED",verify_source(S,S,B,B,reviewers=["patch-author","two"])["reason"])
 def test_sha_swap(self): self.assertEqual("SOURCE_SHA_MISMATCH",verify_source(S,T,B,B)["reason"])
 def test_patch_swap(self): self.assertEqual("PATCH_PROVENANCE_MISMATCH",verify_source(S,S,H,B)["reason"])
 def test_gates_ok(self): self.assertTrue(verify_security_gates(PASS)["allow"])
 def test_missing_gate(self):
  x=dict(PASS); x.pop("sca"); self.assertEqual("MISSING_SECURITY_GATE",verify_security_gates(x)["reason"])
 def test_failed_gate(self):
  x=dict(PASS,sca=False); self.assertEqual("SECURITY_GATE_FAILED",verify_security_gates(x)["reason"])
 def test_expired_waiver(self):
  x=dict(PASS,sca=False); w={"expires_at":10,"independent_risk_owner":True,"approved_by":"risk-owner","ticket":"RISK-1","reason":"temporary","gates":["sca"]}
  self.assertEqual("WAIVER_DENIED",verify_security_gates(x,w,10)["reason"])
 def test_wrong_waiver_scope(self):
  x=dict(PASS,sca=False); w={"expires_at":11,"independent_risk_owner":True,"approved_by":"risk-owner","ticket":"RISK-1","reason":"temporary","gates":["sast"]}
  self.assertEqual("WAIVER_DENIED",verify_security_gates(x,w,10)["reason"])
 def test_valid_waiver(self):
  x=dict(PASS,sca=False); w={"expires_at":11,"independent_risk_owner":True,"approved_by":"risk-owner","ticket":"RISK-1","reason":"temporary","gates":["sca"]}
  self.assertTrue(verify_security_gates(x,w,10)["allow"])
 def test_waiver_too_long(self):
  x=dict(PASS,sca=False); w={"expires_at":604811,"independent_risk_owner":True,"approved_by":"risk-owner","ticket":"RISK-1","reason":"temporary","gates":["sca"]}
  self.assertEqual("WAIVER_DENIED",verify_security_gates(x,w,10)["reason"])
 def test_artifact_ok(self): self.assertTrue(verify_artifact(S,S,B,B,H,H)["allow"])
 def test_bad_provenance(self): self.assertEqual("PROVENANCE_MISMATCH",verify_artifact(S,T,B,B,H,H)["reason"])
 def test_bad_signature(self): self.assertEqual("SIGNATURE_INVALID",verify_artifact(S,S,B,B,H,H,False)["reason"])
 def test_unapproved_signer(self): self.assertEqual("SIGNATURE_INVALID",verify_artifact(S,S,B,B,H,H,True,"unknown")["reason"])
 def test_artifact_swap(self): self.assertEqual("SIGNATURE_INVALID",verify_artifact(S,S,B,H,H,H)["reason"])
 def test_sbom_swap(self): self.assertEqual("SBOM_MISMATCH",verify_artifact(S,S,B,B,H,B)["reason"])
 def deploy(self,actor="release-pipeline",approver="human",target="test",digest=H,approved=H,ticket="CHG-1",temporary=True,**kw):
  return authorize_deployment(actor,approver,target,digest,approved,ticket,temporary,approval=kw.pop("approval",approval(target,digest,ticket,approver)),now=10,**kw)
 def test_deploy_ok(self): self.assertTrue(self.deploy()["allow"])
 def test_agent_deploy(self): self.assertEqual("SEPARATION_OF_DUTIES",self.deploy(actor="agent")["reason"])
 def test_self_approval(self): self.assertEqual("SEPARATION_OF_DUTIES",self.deploy(approver="release-pipeline")["reason"])
 def test_wrong_pipeline_identity(self): self.assertEqual("DEPLOYMENT_IDENTITY_DENIED",self.deploy(actor="other")["reason"])
 def test_digest_swap(self): self.assertEqual("ARTIFACT_SUBSTITUTION",self.deploy(approved=B)["reason"])
 def test_no_ticket(self): self.assertEqual("DEPLOYMENT_AUTHORIZATION_MISSING",self.deploy(ticket="")["reason"])
 def test_long_lived_identity(self): self.assertEqual("DEPLOYMENT_AUTHORIZATION_MISSING",self.deploy(temporary=False)["reason"])
 def test_approval_wrong_target(self): self.assertEqual("APPROVAL_BINDING_MISMATCH",self.deploy(approval=approval("production"))["reason"])
 def test_approval_expired(self): self.assertEqual("APPROVAL_BINDING_MISMATCH",self.deploy(approval=approval(expires_at=10))["reason"])
 def test_promotion_digest_mismatch(self): self.assertEqual("PROMOTION_DIGEST_MISMATCH",self.deploy(promoted_digests=[H,B])["reason"])
if __name__=="__main__": unittest.main()
