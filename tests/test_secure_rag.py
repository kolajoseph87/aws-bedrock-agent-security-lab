import copy, importlib.util, json, unittest
from datetime import date
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("v",ROOT/"scripts"/"validate_secure_rag.py"); v=importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
BASE=json.loads((ROOT/"secure-rag"/"secure-rag.aws.json").read_text())
class ManifestTests(unittest.TestCase):
 def fails(self,d,t=date(2026,7,23)): return {x["name"] for x in v.validate(d,t) if x["status"]=="FAIL"}
 def mutate(self,path,value):
  d=copy.deepcopy(BASE); cur=d
  for k in path[:-1]: cur=cur[k]
  cur[path[-1]]=value; return d
 def test_reference(self): self.assertEqual(set(),self.fails(BASE))
 def test_production(self): self.assertIn("synthetic non-production scope",self.fails(self.mutate(["environment"],"production")))
 def test_real_phi(self): self.assertIn("synthetic non-production scope",self.fails(self.mutate(["healthcare_controls","real_phi_allowed"],True)))
 def test_guardrail_reference_claim(self): self.assertIn("deterministic healthcare filtering",self.fails(self.mutate(["healthcare_controls","guardrail_applies_to_retrieved_references"],True)))
 def test_auto_pr_ingestion(self): self.assertIn("approved provenance-controlled ingestion",self.fails(self.mutate(["source_governance","automatic_ingestion_from_pull_requests"],True)))
 def test_no_quarantine(self): self.assertIn("approved provenance-controlled ingestion",self.fails(self.mutate(["source_governance","quarantine_on_failure"],False)))
 def test_prompt_scope(self): self.assertIn("repository and tenant isolation",self.fails(self.mutate(["isolation","prompt_supplied_scope_trusted"],True)))
 def test_cross_repo(self): self.assertIn("repository and tenant isolation",self.fails(self.mutate(["isolation","cross_repository_retrieval_allowed"],True)))
 def test_wrong_order(self): self.assertIn("safe retrieval order",self.fails(self.mutate(["retrieval_policy","execution_order"],list(reversed(BASE["retrieval_policy"]["execution_order"])))))
 def test_fail_open(self): self.assertIn("fail-closed bounded retrieval",self.fails(self.mutate(["retrieval_policy","fail_mode"],"open")))
 def test_too_many_chunks(self): self.assertIn("fail-closed bounded retrieval",self.fails(self.mutate(["retrieval_policy","max_chunks"],100)))
 def test_follow_chunk_instruction(self): self.assertIn("untrusted chunk handling",self.fails(self.mutate(["retrieval_policy","instructions_in_retrieved_text_followed"],True)))
 def test_streaming(self): self.assertIn("grounded validated output",self.fails(self.mutate(["retrieval_policy","streaming_before_validation_allowed"],True)))
 def test_retain(self): self.assertIn("complete deletion lifecycle",self.fails(self.mutate(["lifecycle","deletion_policy"],"RETAIN")))
 def test_no_post_delete_test(self): self.assertIn("complete deletion lifecycle",self.fails(self.mutate(["lifecycle","post_delete_retrieval_test_required"],False)))
 def test_wildcard_kb(self): self.assertIn("repository and tenant isolation",self.fails(self.mutate(["isolation","wildcard_knowledge_base_access_allowed"],True)))
 def test_cross_region(self): self.assertIn("AWS least-privilege defense in depth",self.fails(self.mutate(["aws_controls","cross_region_inference_allowed"],True)))
 def test_sensitive_audit(self):
  d=copy.deepcopy(BASE); d["audit"]["forbidden_fields"].remove("retrieved_text"); self.assertIn("sanitized retrieval audit",self.fails(d))
 def test_attack_effect(self): self.assertIn("safe attack contracts",self.fails(self.mutate(["safe_attacks",0,"prohibited_side_effects"],1)))
 def test_expired(self): self.assertIn("current independent review",self.fails(BASE,date(2026,9,16)))
 def test_sensitive_key(self):
  d=copy.deepcopy(BASE); d["example"]={"patient_name":"Synthetic"}; self.assertIn("no sensitive values",self.fails(d))
if __name__=="__main__": unittest.main()
