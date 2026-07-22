import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_threat_model import Check, evidence, validate  # noqa: E402

BASE = json.loads((ROOT / "threat-model/threat-model.json").read_text())

def failed(model):
    return {x.name for x in validate(model) if x.status == "FAIL"}

class ThreatModelTests(unittest.TestCase):
    def test_reviewed_manifest_passes(self):
        self.assertEqual(set(), failed(BASE))

    def test_production_fails(self):
        m = copy.deepcopy(BASE); m["environment"] = "production"
        self.assertIn("identity", failed(m))

    def test_missing_phi_boundary_fails(self):
        m = copy.deepcopy(BASE); m["dataPolicy"]["forbidden"].remove("real-phi")
        self.assertIn("data-boundary", failed(m))

    def test_guardrails_only_fails(self):
        m = copy.deepcopy(BASE); m["dataPolicy"]["bedrockGuardrailsAreOnlyControl"] = True
        self.assertIn("layered-protection", failed(m))

    def test_unowned_asset_fails(self):
        m = copy.deepcopy(BASE); m["assets"][0]["owner"] = ""
        self.assertIn("owned-assets", failed(m))

    def test_duplicate_component_fails(self):
        m = copy.deepcopy(BASE); m["components"][1]["id"] = m["components"][0]["id"]
        self.assertIn("components", failed(m))

    def test_untrusted_actor_without_trust_level_fails(self):
        m = copy.deepcopy(BASE); m["actors"][0]["trust"] = ""
        self.assertIn("actors", failed(m))

    def test_malformed_data_policy_fails_closed(self):
        m = copy.deepcopy(BASE); m["dataPolicy"] = []
        names = failed(m)
        self.assertIn("data-boundary", names)
        self.assertIn("layered-protection", names)

    def test_unknown_boundary_endpoint_fails(self):
        m = copy.deepcopy(BASE); m["trustBoundaries"][0]["to"] = "UNKNOWN"
        self.assertIn("trust-boundaries", failed(m))

    def test_boundary_without_checks_fails(self):
        m = copy.deepcopy(BASE); m["trustBoundaries"][0]["requiredChecks"] = []
        self.assertIn("trust-boundaries", failed(m))

    def test_unsafe_test_contract_fails(self):
        m = copy.deepcopy(BASE); m["abuseTests"][0]["prohibitedSideEffects"] = []
        self.assertIn("safe-abuse-tests", failed(m))

    def test_unknown_threat_asset_fails(self):
        m = copy.deepcopy(BASE); m["threats"][0]["assetIds"] = ["UNKNOWN"]
        self.assertIn("threat-references", failed(m))

    def test_missing_stride_category_fails(self):
        m = copy.deepcopy(BASE); m["threats"] = [x for x in m["threats"] if x["stride"] != "Spoofing"]
        self.assertIn("stride-coverage", failed(m))

    def test_threat_without_owner_fails(self):
        m = copy.deepcopy(BASE); m["threats"][0]["owner"] = ""
        self.assertIn("actionable-threats", failed(m))

    def test_unlinked_test_fails(self):
        m = copy.deepcopy(BASE); m["abuseTests"].append({"id": "AT9", "name": "extra", "payloadClass": "synthetic", "expected": "deny", "prohibitedSideEffects": ["change"]})
        self.assertIn("test-coverage", failed(m))

    def test_missing_objective_fails(self):
        m = copy.deepcopy(BASE); m["securityObjectives"].remove("no-self-approval")
        self.assertIn("security-objectives", failed(m))

    def test_real_looking_ssn_fails(self):
        m = copy.deepcopy(BASE); m["threats"][0]["scenario"] += " 123-45-6789"
        self.assertIn("no-sensitive-values", failed(m))

    def test_residual_risk_without_treatment_fails(self):
        m = copy.deepcopy(BASE); m["residualRisks"][0]["treatment"] = ""
        self.assertIn("residual-risk", failed(m))

    def test_evidence_excludes_check_details(self):
        records = evidence(BASE, [Check("data-boundary", "FAIL", "patient name: Example Person")])
        serialized = json.dumps(records)
        self.assertNotIn("Example Person", serialized)
        self.assertEqual([{"name": "data-boundary", "status": "FAIL"}], records["checks"])

if __name__ == "__main__":
    unittest.main()
