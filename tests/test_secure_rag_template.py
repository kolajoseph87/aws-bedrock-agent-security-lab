import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; TEXT=(ROOT/"infra"/"chapter-6-secure-rag.yaml").read_text()
class TemplateTests(unittest.TestCase):
 def test_default_false(self): self.assertIn("Default: 'false'",TEXT)
 def test_condition(self): self.assertIn("DeployChapter6SecureRagCondition",TEXT)
 def test_public_block(self): self.assertIn("BlockPublicAcls: true",TEXT)
 def test_versioning(self): self.assertIn("Status: Enabled",TEXT)
 def test_delete_policy(self): self.assertIn("DataDeletionPolicy: DELETE",TEXT)
 def test_no_wildcard_action(self): self.assertNotIn("Action: '*'",TEXT)
if __name__=="__main__": unittest.main()
