import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TEXT=(ROOT/"infra/chapter-14-capstone.yaml").read_text()

class TemplateTests(unittest.TestCase):
    def test_disabled(self): self.assertIn("Default: 'false'",TEXT)
    def test_every_resource_guarded(self): self.assertEqual(TEXT.count("Condition: DeployChapter14"),3)
    def test_object_lock(self): self.assertIn("ObjectLockEnabled: true",TEXT)
    def test_compliance_retention(self):
        self.assertIn("Mode: COMPLIANCE",TEXT); self.assertIn("Days: 400",TEXT)
    def test_kms_encryption(self): self.assertIn("SSEAlgorithm: aws:kms",TEXT)
    def test_key_rotation(self): self.assertIn("EnableKeyRotation: true",TEXT)
    def test_resources_retained(self): self.assertEqual(TEXT.count("DeletionPolicy: Retain"),2)
    def test_replacements_retained(self): self.assertEqual(TEXT.count("UpdateReplacePolicy: Retain"),2)
    def test_public_access_blocked(self): self.assertIn("RestrictPublicBuckets: true",TEXT)
    def test_tls_required(self): self.assertIn("aws:SecureTransport",TEXT)
    def test_unencrypted_writes_denied(self): self.assertIn("DenyUnencryptedWrites",TEXT)
    def test_wrong_kms_key_denied(self): self.assertIn("DenyWrongKmsKey",TEXT)
