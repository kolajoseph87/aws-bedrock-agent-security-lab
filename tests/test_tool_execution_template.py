import unittest
from pathlib import Path
TEXT=(Path(__file__).resolve().parents[1]/"infra"/"chapter-7-tool-execution.yaml").read_text()
class TemplateTests(unittest.TestCase):
 def test_default_false(self): self.assertIn("Default: 'false'",TEXT)
 def test_condition(self): self.assertIn("DeployChapter7ToolExecutionCondition",TEXT)
 def test_non_privileged(self): self.assertIn("PrivilegedMode: false",TEXT)
 def test_no_source(self): self.assertIn("Type: NO_SOURCE",TEXT)
 def test_concurrency(self): self.assertIn("ConcurrentBuildLimit: 1",TEXT)
 def test_vpc_id_present(self): self.assertIn("VpcId: !Ref ApprovedVpcId",TEXT)
 def test_disabled_defaults_need_no_network_ids(self):
  self.assertIn("ApprovedVpcId:\n    Type: String\n    Default: ''",TEXT)
  self.assertEqual(2,TEXT.count("Type: CommaDelimitedList"))
 def test_deny_bedrock(self): self.assertIn("bedrock:InvokeModel",TEXT)
 def test_no_allow_wildcard(self): self.assertNotIn("Effect: Allow\n                Action: '*'",TEXT)
if __name__=="__main__": unittest.main()
