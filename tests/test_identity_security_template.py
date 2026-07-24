import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "infra" / "chapter-4-identity-kms-secrets.yaml").read_text()


class IdentitySecurityTemplateTests(unittest.TestCase):
    def test_deployment_guard_defaults_false(self):
        self.assertIn("Default: 'false'", TEXT)
        self.assertIn("DeployChapter4IdentitySecurity", TEXT)

    def test_every_resource_is_guarded(self):
        resources = TEXT.split("Resources:", 1)[1]
        self.assertEqual(resources.count("    Type:"), resources.count("    Condition: DeployIdentitySecurity"))

    def test_roles_have_permissions_boundaries(self):
        self.assertEqual(3, TEXT.count("PermissionsBoundary: !Ref PermissionsBoundaryArn"))

    def test_no_secret_or_kms_key_is_created(self):
        self.assertNotIn("AWS::SecretsManager::Secret", TEXT)
        self.assertNotIn("AWS::KMS::Key", TEXT)


if __name__ == "__main__":
    unittest.main()
