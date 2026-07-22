import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from preflight import Check, load_config, redacted_evidence, validate_config  # noqa: E402


VALID = {
    "organization": "Northstar Health Systems",
    "environment": "dev",
    "awsRegion": "us-east-1",
    "awsAccountId": "123456789012",
    "owner": "application-security-team",
    "monthlyBudgetUsd": 100,
    "allowedData": ["synthetic-source-code", "synthetic-security-findings", "synthetic-patient-examples"],
    "forbiddenData": ["real-phi", "real-pii", "production-secrets", "production-source-code", "live-patient-records"],
    "requiredServices": ["bedrock", "iam", "kms", "secretsmanager", "cloudformation", "cloudtrail", "cloudwatch", "budgets"],
    "tags": {
        "Application": "northstar-secure-coding-agent",
        "Environment": "dev",
        "Owner": "application-security-team",
        "CostCenter": "ai-security-training",
        "DataClassification": "synthetic-training-only",
        "ManagedBy": "cloudformation",
    },
}


class PreflightTests(unittest.TestCase):
    def checks(self, config):
        return {item.name: item for item in validate_config(config)}

    def test_valid_configuration_passes(self):
        self.assertTrue(all(x.status == "PASS" for x in validate_config(VALID)))

    def test_production_environment_fails(self):
        value = copy.deepcopy(VALID); value["environment"] = "prod"
        self.assertEqual("FAIL", self.checks(value)["non-production-environment"].status)

    def test_owner_placeholder_fails(self):
        value = copy.deepcopy(VALID); value["owner"] = "replace-with-team-owner"; value["tags"]["Owner"] = "replace-with-team-owner"
        self.assertEqual("FAIL", self.checks(value)["named-owner"].status)

    def test_invalid_account_fails(self):
        value = copy.deepcopy(VALID); value["awsAccountId"] = "1234"
        self.assertEqual("FAIL", self.checks(value)["aws-account-format"].status)

    def test_placeholder_account_fails(self):
        value = copy.deepcopy(VALID); value["awsAccountId"] = "000000000000"
        self.assertEqual("FAIL", self.checks(value)["aws-account-format"].status)

    def test_invalid_region_fails(self):
        value = copy.deepcopy(VALID); value["awsRegion"] = "everywhere"
        self.assertEqual("FAIL", self.checks(value)["aws-region-format"].status)

    def test_boolean_budget_fails(self):
        value = copy.deepcopy(VALID); value["monthlyBudgetUsd"] = True
        self.assertEqual("FAIL", self.checks(value)["monthly-budget"].status)

    def test_missing_bedrock_service_fails(self):
        value = copy.deepcopy(VALID); value["requiredServices"].remove("bedrock")
        self.assertEqual("FAIL", self.checks(value)["service-manifest"].status)

    def test_missing_phi_denial_fails(self):
        value = copy.deepcopy(VALID); value["forbiddenData"].remove("real-phi")
        self.assertEqual("FAIL", self.checks(value)["healthcare-data-boundary"].status)

    def test_real_phi_cannot_be_added_to_allowlist(self):
        value = copy.deepcopy(VALID); value["allowedData"].append("real-phi")
        self.assertEqual("FAIL", self.checks(value)["synthetic-only-allowlist"].status)

    def test_sensitive_tag_value_fails(self):
        value = copy.deepcopy(VALID); value["tags"]["CostCenter"] = "patient-records"
        self.assertEqual("FAIL", self.checks(value)["safe-required-tags"].status)

    def test_sensitive_extra_tag_key_fails(self):
        value = copy.deepcopy(VALID); value["tags"]["PatientName"] = "training-alpha"
        self.assertEqual("FAIL", self.checks(value)["safe-required-tags"].status)

    def test_email_tag_value_fails(self):
        value = copy.deepcopy(VALID); value["tags"]["Owner"] = value["owner"] = "owner@example.org"
        self.assertEqual("FAIL", self.checks(value)["safe-required-tags"].status)

    def test_wrong_tag_owner_fails(self):
        value = copy.deepcopy(VALID); value["tags"]["Owner"] = "another-team"
        self.assertEqual("FAIL", self.checks(value)["safe-required-tags"].status)

    def test_wrong_data_classification_fails(self):
        value = copy.deepcopy(VALID); value["tags"]["DataClassification"] = "phi"
        self.assertEqual("FAIL", self.checks(value)["safe-required-tags"].status)

    def test_evidence_redacts_full_account(self):
        evidence = redacted_evidence(VALID, validate_config(VALID))
        serialized = json.dumps(evidence)
        self.assertNotIn(VALID["awsAccountId"], serialized)
        self.assertEqual("ending-9012", evidence["accountFingerprint"])
        self.assertFalse(evidence["containsPhiOrPii"])

    def test_online_check_details_cannot_leak_account_ids(self):
        checks = [Check("approved-aws-account", "FAIL", "expected=123456789012; actual=999999999999")]
        evidence = redacted_evidence(VALID, checks)
        serialized = json.dumps(evidence)
        self.assertNotIn("123456789012", serialized)
        self.assertNotIn("999999999999", serialized)
        self.assertEqual([{"name": "approved-aws-account", "status": "FAIL"}], evidence["checks"])

    def test_load_config_rejects_array(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"; path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError): load_config(path)


if __name__ == "__main__":
    unittest.main()
