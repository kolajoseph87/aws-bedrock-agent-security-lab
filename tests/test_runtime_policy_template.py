import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "infra" / "chapter-5-runtime-policy.yaml").read_text()


class RuntimePolicyTemplateTests(unittest.TestCase):
    def test_deployment_guard_defaults_false(self):
        self.assertIn("DeployChapter5RuntimePolicy", TEXT)
        self.assertIn("Default: 'false'", TEXT)

    def test_every_resource_is_guarded(self):
        resources = TEXT.split("Resources:", 1)[1].split("Outputs:", 1)[0]
        self.assertEqual(resources.count("    Type:"), resources.count("    Condition: DeployRuntimePolicy"))

    def test_lambda_is_bounded_and_signed(self):
        self.assertIn("ReservedConcurrentExecutions: 5", TEXT)
        self.assertIn("CodeSigningConfigArn:", TEXT)
        self.assertIn("Timeout: 3", TEXT)

    def test_lambda_is_private(self):
        self.assertIn("VpcConfig:", TEXT)
        self.assertIn("SecurityGroupIds:", TEXT)
        self.assertIn("SubnetIds:", TEXT)

    def test_logs_are_encrypted_retained_and_body_logging_disabled(self):
        self.assertIn("KmsKeyId:", TEXT)
        self.assertIn("RetentionInDays: 30", TEXT)
        self.assertIn("DeletionPolicy: Retain", TEXT)
        self.assertIn("LOG_CONTENT_BODIES: 'false'", TEXT)


if __name__ == "__main__":
    unittest.main()
