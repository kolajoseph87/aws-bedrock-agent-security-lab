import unittest
from pathlib import Path
TEXT=(Path(__file__).resolve().parents[1]/"infra"/"chapter-8-release-governance.yaml").read_text()
class TemplateTests(unittest.TestCase):
 def test_default_false(self): self.assertIn("Default: 'false'",TEXT)
 def test_condition(self): self.assertIn("DeployChapter8ReleaseGovernanceCondition",TEXT)
 def test_separate_roles(self): self.assertIn("ReleasePipelineRole:",TEXT); self.assertIn("BuildRole:",TEXT)
 def test_production_role_is_separate(self): self.assertIn("ProductionDeploymentRole:",TEXT)
 def test_oidc_is_exactly_bound(self):
  self.assertIn("sts:AssumeRoleWithWebIdentity",TEXT)
  self.assertIn("token.actions.githubusercontent.com:aud:",TEXT)
  self.assertIn("token.actions.githubusercontent.com:sub:",TEXT)
 def test_non_privileged(self): self.assertIn("PrivilegedMode: false",TEXT)
 def test_build_image_is_digest_parameter(self):
  self.assertIn("Image: !Ref ApprovedBuildImage",TEXT)
  self.assertIn("REPLACE_WITH_APPROVED_ECR_IMAGE_AT_SHA256_DIGEST",TEXT)
  self.assertNotIn("aws/codebuild/amazonlinux-x86_64-standard:5.0",TEXT)
 def test_encrypted_artifacts(self): self.assertIn("EncryptionKey: !Ref ArtifactKmsKeyArn",TEXT)
 def test_production_deny(self): self.assertIn("PolicyName: ExplicitProductionDeny",TEXT)
 def test_no_allow_star(self): self.assertNotIn("Effect: Allow\n                Action: '*'",TEXT)
 def test_timeout(self): self.assertIn("TimeoutInMinutes: 30",TEXT)
if __name__=="__main__": unittest.main()
