import copy
import importlib.util
import json
import unittest
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runtime_validator", ROOT / "scripts" / "validate_runtime_policy.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BASE = json.loads((ROOT / "runtime-policy" / "runtime-policy.aws.json").read_text())


class RuntimePolicyManifestTests(unittest.TestCase):
    def failures(self, data, today=date(2026, 7, 23)):
        return {c["name"] for c in MODULE.validate(data, today=today) if c["status"] == "FAIL"}

    def test_reference_manifest_passes(self):
        self.assertEqual(set(), self.failures(BASE))

    def test_production_scope_fails(self):
        data = copy.deepcopy(BASE)
        data["environment"] = "production"
        self.assertIn("non-production synthetic scope", self.failures(data))

    def test_real_phi_permission_fails(self):
        data = copy.deepcopy(BASE)
        data["healthcare_controls"]["real_phi_allowed"] = True
        self.assertIn("non-production synthetic scope", self.failures(data))

    def test_mutable_policy_fails(self):
        data = copy.deepcopy(BASE)
        data["policy_source"]["mutable_latest_alias_allowed"] = True
        self.assertIn("trusted versioned policy", self.failures(data))

    def test_wrong_order_fails(self):
        data = copy.deepcopy(BASE)
        data["execution_order"][0:2] = ["BEDROCK_MODEL", "PRE_INPUT"]
        self.assertIn("safe execution order", self.failures(data))

    def test_missing_boundary_fails(self):
        data = copy.deepcopy(BASE)
        data["boundaries"].pop()
        self.assertIn("three complete boundaries", self.failures(data))

    def test_fail_open_fails(self):
        data = copy.deepcopy(BASE)
        data["boundaries"][2]["fail_mode"] = "open"
        self.assertIn("fail closed with zero side effects", self.failures(data))

    def test_denial_side_effect_fails(self):
        data = copy.deepcopy(BASE)
        data["boundaries"][1]["on_deny"]["prohibited_side_effects"] = 1
        self.assertIn("fail closed with zero side effects", self.failures(data))

    def test_guardrail_only_fails(self):
        data = copy.deepcopy(BASE)
        data["healthcare_controls"]["guardrail_is_only_control"] = True
        self.assertIn("layered healthcare data protection", self.failures(data))

    def test_unbuffered_streaming_fails(self):
        data = copy.deepcopy(BASE)
        data["healthcare_controls"]["streaming_buffered_until_validation"] = False
        self.assertIn("layered healthcare data protection", self.failures(data))

    def test_prompt_identity_trust_fails(self):
        data = copy.deepcopy(BASE)
        data["identity_contract"]["prompt_supplied_identity_trusted"] = True
        self.assertIn("trusted AWS identity context", self.failures(data))

    def test_bedrock_api_key_fails(self):
        data = copy.deepcopy(BASE)
        data["identity_contract"]["bedrock_api_keys_allowed"] = True
        self.assertIn("trusted AWS identity context", self.failures(data))

    def test_wildcard_resource_fails(self):
        data = copy.deepcopy(BASE)
        data["tool_policies"][0]["resources"] = ["*"]
        self.assertIn("least-privileged current tool policies", self.failures(data))

    def test_expired_tool_policy_fails(self):
        self.assertIn("least-privileged current tool policies", self.failures(BASE, today=date(2026, 9, 16)))

    def test_write_without_approval_contract_fails(self):
        data = copy.deepcopy(BASE)
        data["tool_policies"][2]["human_approval_required"] = False
        self.assertIn("independent approval for writes", self.failures(data))

    def test_direct_model_sdk_access_fails(self):
        data = copy.deepcopy(BASE)
        data["worker_enforcement"]["model_can_call_privileged_sdk_directly"] = True
        self.assertIn("non-bypassable worker enforcement", self.failures(data))

    def test_long_decision_ttl_fails(self):
        data = copy.deepcopy(BASE)
        data["worker_enforcement"]["decision_ttl_seconds_max"] = 3600
        self.assertIn("non-bypassable worker enforcement", self.failures(data))

    def test_full_prompt_audit_fails(self):
        data = copy.deepcopy(BASE)
        data["audit_contract"]["forbidden_fields"].remove("full_prompt")
        self.assertIn("sanitized correlated audit", self.failures(data))

    def test_missing_guardrail_iam_condition_fails(self):
        data = copy.deepcopy(BASE)
        data["aws_runtime_controls"]["bedrock_guardrail_identifier_iam_condition_required"] = False
        self.assertIn("AWS runtime defense in depth", self.failures(data))

    def test_denied_attack_with_tool_call_fails(self):
        data = copy.deepcopy(BASE)
        data["safe_attacks"][2]["tool_calls"] = 1
        self.assertIn("safe runtime attack contracts", self.failures(data))

    def test_expired_review_fails(self):
        data = copy.deepcopy(BASE)
        data["review_and_evidence"]["review_expires"] = "2026-01-01"
        self.assertIn("current review and live verification plan", self.failures(data))

    def test_sensitive_value_key_fails(self):
        data = copy.deepcopy(BASE)
        data["example"] = {"secret_value": "SYNTHETIC"}
        self.assertIn("no sensitive value fields", self.failures(data))


if __name__ == "__main__":
    unittest.main()
