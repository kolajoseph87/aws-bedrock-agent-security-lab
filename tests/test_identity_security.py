import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("identity_validator", ROOT / "scripts" / "validate_identity_security.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BASE = json.loads((ROOT / "identity-security" / "identity-kms-secrets.aws.json").read_text())


class IdentitySecurityTests(unittest.TestCase):
    def failures(self, data):
        return {c["name"] for c in MODULE.validate(data) if c["status"] == "FAIL"}

    def test_reference_manifest_passes(self):
        self.assertEqual(set(), self.failures(BASE))

    def test_production_scope_fails(self):
        data = copy.deepcopy(BASE)
        data["environment"] = "production"
        self.assertIn("non-production synthetic scope", self.failures(data))

    def test_real_phi_permission_fails(self):
        data = copy.deepcopy(BASE)
        data["healthcare_data_controls"]["real_phi_allowed"] = True
        self.assertIn("non-production synthetic scope", self.failures(data))

    def test_duplicate_role_fails(self):
        data = copy.deepcopy(BASE)
        data["roles"].append(copy.deepcopy(data["roles"][0]))
        self.assertIn("separate complete workload roles", self.failures(data))

    def test_long_lived_key_fails(self):
        data = copy.deepcopy(BASE)
        data["identity_model"]["long_lived_access_keys_allowed"] = True
        self.assertIn("temporary identity only", self.failures(data))

    def test_bedrock_api_key_fails(self):
        data = copy.deepcopy(BASE)
        data["identity_model"]["bedrock_api_keys_allowed"] = True
        self.assertIn("temporary identity only", self.failures(data))

    def test_missing_source_identity_fails(self):
        data = copy.deepcopy(BASE)
        data["identity_model"]["source_identity_required"] = False
        self.assertIn("session attribution", self.failures(data))

    def test_wildcard_principal_fails(self):
        data = copy.deepcopy(BASE)
        data["trust_policy_controls"]["wildcard_principals_allowed"] = True
        self.assertIn("restricted trust policies", self.failures(data))

    def test_confused_deputy_protection_removed_fails(self):
        data = copy.deepcopy(BASE)
        data["trust_policy_controls"]["source_account_condition_required"] = False
        self.assertIn("restricted trust policies", self.failures(data))

    def test_agent_secret_access_fails(self):
        data = copy.deepcopy(BASE)
        data["roles"][0]["may_read_secrets"] = True
        self.assertIn("least-authority role boundaries", self.failures(data))

    def test_agent_self_approval_fails(self):
        data = copy.deepcopy(BASE)
        data["roles"][0]["may_approve_pull_request"] = True
        self.assertIn("least-authority role boundaries", self.failures(data))

    def test_full_access_policy_fails(self):
        data = copy.deepcopy(BASE)
        data["iam_policy_controls"]["aws_managed_full_access_policies_allowed"] = True
        self.assertIn("least-privilege policy governance", self.failures(data))

    def test_direct_agent_decrypt_fails(self):
        data = copy.deepcopy(BASE)
        data["kms_controls"]["agent_role_direct_decrypt_allowed"] = True
        self.assertIn("safe KMS governance", self.failures(data))

    def test_sensitive_encryption_context_fails(self):
        data = copy.deepcopy(BASE)
        data["kms_controls"]["phi_pii_or_secrets_in_encryption_context_allowed"] = True
        self.assertIn("safe KMS governance", self.failures(data))

    def test_secret_in_prompt_fails(self):
        data = copy.deepcopy(BASE)
        data["secrets_controls"]["secrets_in_prompts_allowed"] = True
        self.assertIn("safe secrets lifecycle", self.failures(data))

    def test_blanket_secret_access_fails(self):
        data = copy.deepcopy(BASE)
        data["secrets_controls"]["agent_blanket_secret_access_allowed"] = True
        self.assertIn("safe secrets lifecycle", self.failures(data))

    def test_model_output_as_authority_fails(self):
        data = copy.deepcopy(BASE)
        data["authorization_boundaries"]["model_output_is_authority"] = True
        self.assertIn("authorization remains separate", self.failures(data))

    def test_expired_review_fails(self):
        data = copy.deepcopy(BASE)
        data["review_and_evidence"]["review_expires"] = "2026-01-01"
        self.assertIn("current review and live verification plan", self.failures(data))

    def test_attack_with_aws_call_fails(self):
        data = copy.deepcopy(BASE)
        data["safe_attacks"][0]["aws_calls"] = 1
        self.assertIn("safe identity attack contracts", self.failures(data))

    def test_sensitive_key_fails(self):
        data = copy.deepcopy(BASE)
        data["example"] = {"secret_value": "SYNTHETIC"}
        self.assertIn("no sensitive fields", self.failures(data))


if __name__ == "__main__":
    unittest.main()
