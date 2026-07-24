import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "security-evaluations" / "security-evaluations.aws.json"
SPEC = importlib.util.spec_from_file_location("validator", ROOT / "scripts" / "validate_security_evaluations.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class SecurityEvaluationManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(MANIFEST.read_text())

    def result(self, data=None):
        return validator.validate(data or self.data)

    def test_manifest_passes(self):
        checks = self.result()
        self.assertTrue(all(c["status"] == "PASS" for c in checks))

    def test_validator_has_seventeen_checks(self):
        self.assertEqual(17, len(self.result()))

    def test_chapter_is_ten(self):
        self.assertEqual(10, self.data["chapter"])

    def test_flow_is_exact(self):
        self.assertEqual(validator.ORDER, self.data["evaluation_flow"])

    def test_twelve_attack_classes(self):
        self.assertEqual(12, len(self.data["attack_corpus"]["required_attack_classes"]))

    def test_twelve_safe_attacks(self):
        self.assertEqual(12, len(self.data["safe_attacks"]))

    def test_unique_attack_ids(self):
        ids = [x["id"] for x in self.data["safe_attacks"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_no_aws_calls(self):
        self.assertTrue(all(x["aws_calls"] == 0 for x in self.data["safe_attacks"]))

    def test_no_side_effects(self):
        self.assertTrue(all(x["prohibited_side_effects"] == 0 for x in self.data["safe_attacks"]))

    def test_all_attacks_expect_denial(self):
        self.assertTrue(all(x["expected_decision"] == "DENY" for x in self.data["safe_attacks"]))

    def test_production_scope_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["scope"]["production_endpoints_allowed"] = True
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_real_phi_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["scope"]["real_phi_or_pii_allowed"] = True
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_incomplete_coverage_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["attack_corpus"]["required_attack_classes"] = []
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_model_judge_only_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["evaluation_harness"]["model_judge_is_sole_authority"] = True
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_critical_override_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["scoring_and_gates"]["aggregate_score_cannot_override_critical_failure"] = False
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_unsigned_results_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["scoring_and_gates"]["signed_result_bundle_required"] = False
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_evaluator_tamper_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["integrity"]["pinned_evaluator_image_required"] = False
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_sensitive_evidence_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["integrity"]["raw_prompts_or_completions_in_evidence"] = True
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_invocation_body_logging_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["aws_controls"]["bedrock_invocation_body_logging_allowed"] = True
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])

    def test_duplicate_attack_ids_mutation_fails(self):
        data = copy.deepcopy(self.data)
        data["safe_attacks"][1]["id"] = data["safe_attacks"][0]["id"]
        self.assertIn("FAIL", [x["status"] for x in self.result(data)])


if __name__ == "__main__":
    unittest.main()
