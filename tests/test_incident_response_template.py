import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TEXT=(ROOT/"infra/chapter-11-incident-response.yaml").read_text()

class TemplateTests(unittest.TestCase):
    def test_default_false(self): self.assertIn("Default: 'false'",TEXT)
    def test_all_resources_guarded(self): self.assertEqual(TEXT.count("    Condition: Deploy"),5)
    def test_retained_state(self): self.assertRegex(TEXT,r"IncidentStateTable:[\s\S]*?DeletionPolicy: Retain")
    def test_retained_revocations(self): self.assertRegex(TEXT,r"RevocationTable:[\s\S]*?DeletionPolicy: Retain")
    def test_pitr(self): self.assertIn("PointInTimeRecoveryEnabled: true",TEXT)
    def test_encryption(self): self.assertIn("SSEEnabled: true",TEXT)
    def test_mfa(self): self.assertIn("aws:MultiFactorAuthPresent",TEXT)
    def test_short_session(self): self.assertIn("MaxSessionDuration: 900",TEXT)
    def test_no_allow_wildcard(self): self.assertNotIn("Effect: Allow\n                Action: '*'",TEXT)
    def test_explicit_model_deny(self): self.assertIn("bedrock:InvokeModel",TEXT)
    def test_external_evidence_archive_required(self):
        self.assertIn("EvidenceArchiveArn",TEXT)
        self.assertIn("separately managed security-account bucket",TEXT)
    def test_evidence_deletion_denied(self):
        self.assertIn("s3:DeleteObject",TEXT)
        self.assertIn("cloudtrail:StopLogging",TEXT)
    def test_evidence_retention_actions(self):
        self.assertIn("s3:PutObjectRetention",TEXT)
        self.assertIn("s3:PutObjectLegalHold",TEXT)
    def test_live_enforcement_limitation_is_explicit(self):
        self.assertIn("does not retrofit enforcement",TEXT)
