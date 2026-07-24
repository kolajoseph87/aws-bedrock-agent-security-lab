import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validator", ROOT / "scripts" / "validate_model_governance.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BASE = json.loads((ROOT / "model-governance" / "model-governance.aws.json").read_text())


class ModelGovernanceTests(unittest.TestCase):
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
        data["data_controls"]["real_phi_allowed"] = True
        self.assertIn("non-production synthetic scope", self.failures(data))

    def test_empty_model_inventory_fails(self):
        data = copy.deepcopy(BASE)
        data["model_catalog"]["approved_models"] = []
        self.assertIn("complete approved model inventory", self.failures(data))

    def test_duplicate_model_fails(self):
        data = copy.deepcopy(BASE)
        data["model_catalog"]["approved_models"].append(copy.deepcopy(data["model_catalog"]["approved_models"][0]))
        self.assertIn("complete approved model inventory", self.failures(data))

    def test_wrong_region_fails(self):
        data = copy.deepcopy(BASE)
        data["model_catalog"]["approved_models"][0]["region"] = "eu-west-1"
        self.assertIn("approved region binding", self.failures(data))

    def test_cross_region_inference_fails(self):
        data = copy.deepcopy(BASE)
        data["model_catalog"]["cross_region_inference_allowed"] = True
        self.assertIn("approved region binding", self.failures(data))

    def test_unversioned_model_fails(self):
        data = copy.deepcopy(BASE)
        data["model_catalog"]["approved_models"][0]["model_id"] = "provider.model-latest"
        self.assertIn("versioned model identifiers", self.failures(data))

    def test_expired_review_fails(self):
        data = copy.deepcopy(BASE)
        data["model_catalog"]["approved_models"][0]["review_expires"] = "2026-01-01"
        self.assertIn("current model approvals", self.failures(data))

    def test_fail_open_policy_fails(self):
        data = copy.deepcopy(BASE)
        data["invocation_policy"]["fail_closed_on_policy_error"] = False
        self.assertIn("fail-closed invocation gate", self.failures(data))

    def test_streaming_expands_surface_and_fails(self):
        data = copy.deepcopy(BASE)
        data["invocation_policy"]["streaming_allowed"] = True
        self.assertIn("minimal inference surface", self.failures(data))

    def test_excessive_output_limit_fails(self):
        data = copy.deepcopy(BASE)
        data["inference_limits"]["output_tokens_max"] = 100000
        self.assertIn("bounded inference settings", self.failures(data))

    def test_prompt_body_logging_fails(self):
        data = copy.deepcopy(BASE)
        data["data_controls"]["prompt_logging_allowed"] = True
        self.assertIn("layered privacy controls", self.failures(data))

    def test_guardrails_only_fails(self):
        data = copy.deepcopy(BASE)
        data["data_controls"]["deterministic_input_scan"] = False
        data["data_controls"]["deterministic_output_scan"] = False
        self.assertIn("layered privacy controls", self.failures(data))

    def test_wildcard_iam_fails(self):
        data = copy.deepcopy(BASE)
        data["iam_contract"]["wildcard_resource_allowed"] = True
        self.assertIn("least-privilege IAM contract", self.failures(data))

    def test_missing_independent_approval_fails(self):
        data = copy.deepcopy(BASE)
        data["change_control"]["independent_approval_required"] = False
        self.assertIn("controlled model changes", self.failures(data))

    def test_attack_with_model_call_fails(self):
        data = copy.deepcopy(BASE)
        data["safe_attacks"][0]["model_calls"] = 1
        self.assertIn("safe pre-invocation attacks", self.failures(data))

    def test_sensitive_key_fails(self):
        data = copy.deepcopy(BASE)
        data["example"] = {"patient_name": "SYNTHETIC"}
        self.assertIn("no sensitive fields", self.failures(data))


if __name__ == "__main__":
    unittest.main()
