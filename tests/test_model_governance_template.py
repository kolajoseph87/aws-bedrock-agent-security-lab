import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "infra" / "chapter-3-model-governance.yaml").read_text()


class ModelGovernanceTemplateTests(unittest.TestCase):
    def test_deployment_guard_defaults_false(self):
        self.assertIn("DeployChapter3ModelGovernance:", TEXT)
        self.assertIn("Default: 'false'", TEXT)
        self.assertIn("CreateChapter3Controls:", TEXT)

    def test_iam_is_scoped_to_converse_and_model(self):
        self.assertIn("- bedrock:Converse", TEXT)
        self.assertNotIn("- bedrock:*", TEXT)
        self.assertIn("foundation-model/", TEXT)

    def test_region_and_principal_conditions_exist(self):
        self.assertIn("aws:RequestedRegion", TEXT)
        self.assertIn("aws:PrincipalTag/NorthstarUseCase", TEXT)
        self.assertIn("bedrock:GuardrailIdentifier", TEXT)

    def test_template_creates_no_logging_destination(self):
        self.assertNotIn("AWS::Logs::LogGroup", TEXT)
        self.assertNotIn("AWS::S3::Bucket", TEXT)


if __name__ == "__main__":
    unittest.main()
