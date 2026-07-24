import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"python"))
from tool_execution import authorize_request,digest,validate_artifact,verify_work_order
AUTH={"principal":"worker-requester","approved_principal":"worker-requester",
      "repository":"patient-portal","approved_repository":"patient-portal",
      "policy_version":"v7","approved_policy_version":"v7"}
def expected():
 return {"principal":"worker-requester","repository":"patient-portal","base_commit":"a"*40,"operation":"apply_patch","paths":["src/logging.py"],"argument_hash":digest("safe"),"policy_version":"v7"}
def order(**changes):
 e=expected(); d={"id":"wo-1",**e,"nonce":"n-1","expires_at":1200,"signature_valid":True}; d.update(changes); return d
class BehaviorTests(unittest.TestCase):
 def auth(self,operation="apply_patch",paths=None,arguments=None,base="a",approved="a",**changes):
  fields=dict(AUTH); fields.update(changes)
  return authorize_request(operation,paths or ["src/a.py"],arguments or ["safe"],base,approved,**fields)
 def test_authorized(self): self.assertTrue(self.auth()["allow"])
 def test_push_denied(self): self.assertEqual("OPERATION_DENIED",self.auth("push")["reason"])
 def test_commit_mismatch(self): self.assertEqual("COMMIT_MISMATCH",self.auth(base="a",approved="b")["reason"])
 def test_principal_mismatch(self): self.assertEqual("PRINCIPAL_MISMATCH",self.auth(principal="other")["reason"])
 def test_repository_mismatch(self): self.assertEqual("REPOSITORY_MISMATCH",self.auth(repository="other")["reason"])
 def test_policy_mismatch(self): self.assertEqual("POLICY_VERSION_MISMATCH",self.auth(policy_version="v6")["reason"])
 def test_path_traversal(self): self.assertEqual("PATH_ESCAPE",self.auth(paths=["../a"])["reason"])
 def test_absolute_path(self): self.assertEqual("PATH_ESCAPE",self.auth(paths=["/tmp/a"])["reason"])
 def test_backslash_path(self): self.assertEqual("PATH_ESCAPE",self.auth(paths=["src\\a.py"])["reason"])
 def test_symlink_escape(self): self.assertEqual("SYMLINK_ESCAPE",self.auth(paths=["src/link"],symlink_paths=["src/link"])["reason"])
 def test_pipeline_denied(self): self.assertEqual("PIPELINE_CHANGE_DENIED",self.auth(paths=[".github/workflows/ci.yml"])["reason"])
 def test_metacharacter(self): self.assertEqual("UNSAFE_ARGUMENTS",self.auth("run_unit_tests",arguments=["ok; curl x"])["reason"])
 def test_order_verified(self): self.assertTrue(verify_work_order(order(),expected(),set(),1000)["allow"])
 def test_bad_signature(self): self.assertEqual("SIGNATURE_INVALID",verify_work_order(order(signature_valid=False),expected(),set(),1000)["reason"])
 def test_expired(self): self.assertEqual("WORK_ORDER_EXPIRED_OR_TOO_LONG",verify_work_order(order(expires_at=999),expected(),set(),1000)["reason"])
 def test_expiry_equal_now(self): self.assertEqual("WORK_ORDER_EXPIRED_OR_TOO_LONG",verify_work_order(order(expires_at=1000),expected(),set(),1000)["reason"])
 def test_ttl_too_long(self): self.assertEqual("WORK_ORDER_EXPIRED_OR_TOO_LONG",verify_work_order(order(expires_at=1400),expected(),set(),1000)["reason"])
 def test_replay(self):
  used={"n-1"}; self.assertEqual("REPLAY_DENIED",verify_work_order(order(),expected(),used,1000)["reason"])
 def test_binding(self): self.assertEqual("WORK_ORDER_BINDING_MISMATCH",verify_work_order(order(repository="other"),expected(),set(),1000)["reason"])
 def test_clean_artifact(self): self.assertTrue(validate_artifact(["src/a.py"],"safe patch",True,True)["allow"])
 def test_sensitive_artifact(self): self.assertEqual("SENSITIVE_ARTIFACT",validate_artifact(["src/a.py"],"ACCESS_TOKEN=fake",True,True)["reason"])
 def test_sensitive_output(self): self.assertEqual("SENSITIVE_ARTIFACT",validate_artifact(["src/a.py"],"safe",True,True,command_output="Authorization: Bearer fake")["reason"])
 def test_malware(self): self.assertEqual("MALWARE_DETECTED",validate_artifact(["src/a.py"],"safe",True,True,malware_found=True)["reason"])
 def test_unsafe_code(self): self.assertEqual("UNSAFE_CODE_DETECTED",validate_artifact(["src/a.py"],"safe",True,True,unsafe_code_found=True)["reason"])
 def test_output_limit(self): self.assertEqual("ARTIFACT_LIMIT_EXCEEDED",validate_artifact(["src/a.py"],"safe",True,True,command_output="x"*11,max_output_bytes=10)["reason"])
 def test_diff_symlink(self): self.assertEqual("DIFF_SCOPE_DENIED",validate_artifact(["src/link"],"safe",True,True,symlink_paths=["src/link"])["reason"])
 def test_failed_tests(self): self.assertEqual("VERIFICATION_FAILED",validate_artifact(["src/a.py"],"safe",False,True)["reason"])
 def test_diff_escape(self): self.assertEqual("DIFF_SCOPE_DENIED",validate_artifact(["../a"],"safe",True,True)["reason"])
 def test_log_streaming(self): self.assertEqual("LOG_STREAMING_BEFORE_SCAN",validate_artifact(["a"],"safe",True,True,True)["reason"])
 def test_patch_limit(self): self.assertEqual("ARTIFACT_LIMIT_EXCEEDED",validate_artifact(["a"],"x"*11,True,True,max_bytes=10)["reason"])
if __name__=="__main__": unittest.main()
