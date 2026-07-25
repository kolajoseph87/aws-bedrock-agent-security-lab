import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TEXT=(ROOT/"infra/chapter-13-compliance-assurance.yaml").read_text()
class TemplateTests(unittest.TestCase):
    def test_guarded(self): self.assertIn("Default: 'false'",TEXT)
    def test_every_resource_guarded(self): self.assertEqual(TEXT.count("Condition: DeployChapter13"),3)
    def test_object_lock(self): self.assertIn("ObjectLockEnabled: true",TEXT)
    def test_compliance_mode_default_retention(self):
        self.assertIn("Mode: COMPLIANCE",TEXT)
        self.assertIn("Days: 400",TEXT)
    def test_encrypted(self): self.assertIn("SSEAlgorithm: aws:kms",TEXT)
    def test_retained(self): self.assertEqual(TEXT.count("DeletionPolicy: Retain"),2)
    def test_public_blocked(self): self.assertIn("RestrictPublicBuckets: true",TEXT)
    def test_tls(self): self.assertIn("aws:SecureTransport",TEXT)
    def test_rotation(self): self.assertIn("EnableKeyRotation: true",TEXT)
