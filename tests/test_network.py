import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_network", ROOT / "scripts" / "validate_network.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BASE = json.loads((ROOT / "network" / "landing-zone.aws.json").read_text())


class NetworkTests(unittest.TestCase):
    def failures(self, data):
        return {c["name"] for c in MODULE.validate(data) if c["status"] == "FAIL"}

    def test_baseline_passes(self): self.assertEqual(self.failures(BASE), set())
    def test_production_fails(self):
        d = copy.deepcopy(BASE); d["environment"] = "production"
        self.assertIn("non-production synthetic scope", self.failures(d))
    def test_real_phi_fails(self):
        d = copy.deepcopy(BASE); d["healthcare_data"]["real_phi_allowed"] = True
        self.assertIn("non-production synthetic scope", self.failures(d))
    def test_overlapping_subnet_fails(self):
        d = copy.deepcopy(BASE); d["network"]["subnets"][1]["cidr"] = d["network"]["subnets"][0]["cidr"]
        self.assertIn("valid non-overlapping address plan", self.failures(d))
    def test_duplicate_subnet_name_fails(self):
        d = copy.deepcopy(BASE); d["network"]["subnets"][1]["name"] = d["network"]["subnets"][0]["name"]
        self.assertIn("valid non-overlapping address plan", self.failures(d))
    def test_single_az_design_fails(self):
        d = copy.deepcopy(BASE)
        for subnet in d["network"]["subnets"]: subnet["az_index"] = 0
        self.assertIn("separated private trust zones", self.failures(d))
    def test_public_ip_fails(self):
        d = copy.deepcopy(BASE); d["network"]["subnets"][0]["public_ip_on_launch"] = True
        self.assertIn("separated private trust zones", self.failures(d))
    def test_internet_gateway_fails(self):
        d = copy.deepcopy(BASE); d["network"]["internet_gateway_attached"] = True
        self.assertIn("no default internet path", self.failures(d))
    def test_worker_egress_fails(self):
        d = copy.deepcopy(BASE); d["egress"]["direct_worker_internet"] = "allow"
        self.assertIn("no default internet path", self.failures(d))
    def test_missing_bedrock_runtime_endpoint_fails(self):
        d = copy.deepcopy(BASE); d["private_endpoints"] = [e for e in d["private_endpoints"] if e["service"] != "bedrock-runtime"]
        self.assertIn("required private service paths", self.failures(d))
    def test_duplicate_endpoint_service_fails(self):
        d = copy.deepcopy(BASE); d["private_endpoints"].append(copy.deepcopy(d["private_endpoints"][0]))
        self.assertIn("required private service paths", self.failures(d))
    def test_private_dns_disabled_fails(self):
        d = copy.deepcopy(BASE); d["private_endpoints"][0]["private_dns"] = False
        self.assertIn("required private service paths", self.failures(d))
    def test_full_access_endpoint_policy_fails(self):
        d = copy.deepcopy(BASE); d["private_endpoints"][0]["endpoint_policy"] = "full-access"
        self.assertIn("restricted endpoint policies", self.failures(d))
    def test_world_open_security_group_fails(self):
        d = copy.deepcopy(BASE); d["security_groups"]["agent"]["outbound"][0]["destination"] = "0.0.0.0/0"
        self.assertIn("least-privilege security groups", self.failures(d))
    def test_private_network_treated_as_trust_fails(self):
        d = copy.deepcopy(BASE); d["authorization"]["private_network_is_trust"] = True
        self.assertIn("network is not authorization", self.failures(d))
    def test_runtime_check_removed_fails(self):
        d = copy.deepcopy(BASE); d["authorization"]["runtime_exact_action_check_required"] = False
        self.assertIn("network is not authorization", self.failures(d))
    def test_missing_logging_fails(self):
        d = copy.deepcopy(BASE); d["observability"]["dns_query_logging_required_for_live_environment"] = False
        self.assertIn("privacy-safe network evidence", self.failures(d))
    def test_side_effecting_attack_fails(self):
        d = copy.deepcopy(BASE); d["safe_attacks"][0]["prohibited_side_effects"] = 1
        self.assertIn("safe negative tests", self.failures(d))
    def test_duplicate_attack_identifier_fails(self):
        d = copy.deepcopy(BASE); d["safe_attacks"][1]["id"] = d["safe_attacks"][0]["id"]
        self.assertIn("safe negative tests", self.failures(d))
    def test_misleading_denial_text_fails(self):
        d = copy.deepcopy(BASE); d["safe_attacks"][0]["expected"] = "not_denied"
        self.assertIn("safe negative tests", self.failures(d))
    def test_sensitive_key_fails(self):
        d = copy.deepcopy(BASE); d["access_key"] = "example"
        self.assertIn("no sensitive fields", self.failures(d))
    def test_nested_sensitive_key_fails(self):
        d = copy.deepcopy(BASE); d["network"]["patient_name"] = "synthetic"
        self.assertIn("no sensitive fields", self.failures(d))
    def test_malformed_network_fails_closed(self):
        d = copy.deepcopy(BASE); d["network"] = []
        failures = self.failures(d)
        self.assertIn("valid non-overlapping address plan", failures)
        self.assertIn("separated private trust zones", failures)
    def test_evidence_excludes_check_details(self):
        checks = [{"name": "test", "status": "FAIL", "detail": "patient name: Example Person"}]
        evidence = MODULE.sanitized_evidence(checks)
        self.assertNotIn("Example Person", json.dumps(evidence))


if __name__ == "__main__": unittest.main()
