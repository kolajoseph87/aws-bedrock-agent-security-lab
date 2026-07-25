import unittest
from pathlib import Path
T=(Path(__file__).resolve().parents[1]/"infra/chapter-12-multi-agent-security.yaml").read_text()
class TemplateTests(unittest.TestCase):
    def test_default_false(self): self.assertIn("Default: 'false'",T)
    def test_all_resources_guarded(self): self.assertEqual(T.count("    Condition: Deploy"),10)
    def test_fifo(self): self.assertGreaterEqual(T.count("FifoQueue: true"),2)
    def test_encrypted(self): self.assertIn("KmsMasterKeyId: alias/aws/sqs",T)
    def test_dlq(self): self.assertIn("deadLetterTargetArn",T)
    def test_short_retention(self): self.assertIn("MessageRetentionPeriod: 900",T)
    def test_distinct_roles(self):
        for x in ["PlannerRole","RetrieverRole","PolicyRole","PatchWorkerRole",
                  "ReviewerRole","ReleaseControllerRole","OrchestratorRole"]:
            self.assertIn(x,T)
    def test_no_wildcard_allow(self): self.assertNotIn("Effect: Allow\n                Action: '*'",T)
    def test_no_bedrock_invoke(self): self.assertNotIn("bedrock:InvokeModel",T)
    def test_no_direct_agent_trust(self): self.assertIn("No direct agent-to-agent IAM trust",T)
    def test_live_limit(self): self.assertIn("does not implement message signing",T)
    def test_only_orchestrator_receives(self):
        self.assertEqual(T.count("sqs:ReceiveMessage"),1)
        self.assertIn("OrchestratorReceiveOnly",T)
    def test_fifo_dlq_matches_source(self):
        self.assertGreaterEqual(T.count("FifoQueue: true"),2)
    def test_confused_deputy_source_account(self):
        self.assertGreaterEqual(T.count("aws:SourceAccount"),7)
    def test_transport_security_required(self):
        self.assertIn("aws:SecureTransport",T)
        self.assertIn("DenyInsecureTransport",T)
    def test_release_controller_cannot_deploy(self):
        self.assertIn("codepipeline:StartPipelineExecution",T)
        self.assertIn("Effect: Deny",T)
