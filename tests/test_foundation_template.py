import unittest
from pathlib import Path


TEMPLATE = (Path(__file__).resolve().parents[1] / "infra" / "chapter-0-foundation.yaml").read_text(encoding="utf-8")


class FoundationTemplateTests(unittest.TestCase):
    def test_deployment_defaults_to_false(self):
        block = TEMPLATE.split("DeployLabFoundation:", 1)[1].split("Owner:", 1)[0]
        self.assertIn("Default: 'false'", block)

    def test_every_resource_is_conditionally_guarded(self):
        resources = TEMPLATE.split("Resources:", 1)[1].split("Outputs:", 1)[0]
        self.assertIn("Condition: DeployFoundation", resources)
        self.assertEqual(resources.count("Type: AWS::"), resources.count("Condition: DeployFoundation"))

    def test_no_bedrock_or_compute_resource_is_deployed(self):
        resources = TEMPLATE.split("Resources:", 1)[1].split("Outputs:", 1)[0]
        for prohibited in ("AWS::Bedrock::", "AWS::Lambda::", "AWS::CodeBuild::", "AWS::S3::"):
            self.assertNotIn(prohibited, resources)

    def test_budget_email_is_not_a_real_address(self):
        self.assertIn("example.invalid", TEMPLATE)
        self.assertIn("NoEcho: true", TEMPLATE)


if __name__ == "__main__":
    unittest.main()
