import unittest
from pathlib import Path

TEMPLATE = (Path(__file__).resolve().parents[1] / "infra" / "chapter-10-security-evaluations.yaml").read_text()


class SecurityEvaluationTemplateTests(unittest.TestCase):
    def test_disabled_by_default(self):
        self.assertIn("Default: 'false'", TEMPLATE)

    def test_guard_condition(self):
        self.assertIn("DeployChapter10SecurityEvaluationsCondition", TEMPLATE)

    def test_non_privileged_worker(self):
        self.assertIn("PrivilegedMode: false", TEMPLATE)

    def test_no_broad_iam_action(self):
        self.assertNotIn("Action: '*'", TEMPLATE)

    def test_encrypted_result_location(self):
        self.assertIn("EvaluationResultKmsKeyArn", TEMPLATE)

    def test_result_archive_is_immutable(self):
        self.assertIn("ObjectLockEnabled: true", TEMPLATE)
        self.assertIn("Mode: COMPLIANCE", TEMPLATE)
        self.assertIn("Days: 400", TEMPLATE)

    def test_no_inbound_network_rule(self):
        self.assertNotIn("SecurityGroupIngress", TEMPLATE)

    def test_private_vpc_required(self):
        self.assertIn("VpcConfig:", TEMPLATE)
        self.assertIn("EvaluatorSubnetIds", TEMPLATE)
        self.assertIn("EvaluatorSecurityGroupIds", TEMPLATE)

    def test_evaluator_image_must_be_digest_pinned(self):
        self.assertIn("@sha256:", TEMPLATE)
        self.assertIn("AllowedPattern:", TEMPLATE)

    def test_concurrency_is_bounded(self):
        self.assertIn("ConcurrentBuildLimit: 1", TEMPLATE)

    def test_confused_deputy_protection(self):
        self.assertIn("aws:SourceArn", TEMPLATE)
        self.assertIn("aws:SourceAccount", TEMPLATE)

    def test_dangerous_capabilities_explicitly_denied(self):
        for action in ["bedrock:InvokeModel", "secretsmanager:GetSecretValue",
                       "iam:PassRole", "sts:AssumeRole", "s3:DeleteObject"]:
            self.assertIn(action, TEMPLATE)

    def test_cloudwatch_logging_enabled(self):
        self.assertIn("CloudWatchLogs:", TEMPLATE)
        self.assertIn("Status: ENABLED", TEMPLATE)


if __name__ == "__main__":
    unittest.main()
