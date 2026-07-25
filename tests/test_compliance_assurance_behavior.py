import copy
import datetime as dt
import unittest

from python.compliance_assurance import evidence_fresh, production_decision


TODAY = dt.date(2026, 7, 25)
VERSION = "00ccafc"
DIGEST = "sha256:" + "a" * 64
GOOD = [
    {
        "control_id": "AC-1",
        "owner": "control-owner",
        "independent_approver": "technical-reviewer",
        "test": "python3 -m unittest tests.test_access",
        "test_result": "PASS",
        "evidence_digest": DIGEST,
        "collected_on": "2026-07-24",
        "source_commit": VERSION,
        "model_version": "model-v1",
        "policy_version": "policy-v1",
        "status": "PASS",
    }
]
APPROVALS = [
    {
        "person": "security-person",
        "role": "security-reviewer",
        "decision": "APPROVE",
        "independent": True,
        "assessed_version": VERSION,
        "approved_on": "2026-07-24",
    },
    {
        "person": "privacy-person",
        "role": "privacy-reviewer",
        "decision": "APPROVE",
        "independent": True,
        "assessed_version": VERSION,
        "approved_on": "2026-07-24",
    },
]
EXECUTIVE = {
    "person": "executive-person",
    "role": "accountable-executive",
    "decision": "ACCEPT",
    "assessed_version": VERSION,
    "accepted_on": "2026-07-24",
}


def decide(records=None, approvals=None, executive=None, version=VERSION):
    return production_decision(
        GOOD if records is None else records,
        APPROVALS if approvals is None else approvals,
        EXECUTIVE if executive is None else executive,
        version,
        today=TODAY,
    )


class BehaviorTests(unittest.TestCase):
    def test_fresh(self):
        self.assertTrue(evidence_fresh("2026-07-01", TODAY))

    def test_stale(self):
        self.assertFalse(evidence_fresh("2025-01-01", TODAY))

    def test_future(self):
        self.assertFalse(evidence_fresh("2026-08-01", TODAY))

    def test_invalid_date(self):
        self.assertFalse(evidence_fresh("yesterday", TODAY))

    def test_boolean_freshness_window(self):
        self.assertFalse(evidence_fresh("2026-07-24", TODAY, True))

    def test_excessive_freshness_window(self):
        self.assertFalse(evidence_fresh("2026-07-24", TODAY, 365))

    def test_ready(self):
        self.assertEqual(decide(), "READY_FOR_CONTROLLED_NONPRODUCTION_PILOT")

    def test_no_records(self):
        self.assertEqual(decide(records=[]), "BLOCK")

    def test_records_must_be_list(self):
        self.assertEqual(decide(records={}), "BLOCK")

    def test_missing_record_field(self):
        bad = copy.deepcopy(GOOD)
        del bad[0]["model_version"]
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_extra_record_field(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["unexpected"] = True
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_failed_status(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["status"] = "FAIL"
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_unknown_status(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["status"] = "UNKNOWN"
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_failed_test_result(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["test_result"] = "FAIL"
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_forged_digest(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["evidence_digest"] = "sha256:x"
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_uppercase_digest_rejected(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["evidence_digest"] = "sha256:" + "A" * 64
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_stale_record(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["collected_on"] = "2025-01-01"
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_future_record(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["collected_on"] = "2026-08-01"
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_wrong_source_commit(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["source_commit"] = "older"
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_duplicate_control_id(self):
        bad = copy.deepcopy(GOOD) + copy.deepcopy(GOOD)
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_control_self_approval(self):
        bad = copy.deepcopy(GOOD)
        bad[0]["independent_approver"] = bad[0]["owner"]
        self.assertEqual(decide(records=bad), "BLOCK")

    def test_no_approvals(self):
        self.assertEqual(decide(approvals=[]), "BLOCK")

    def test_approvals_must_be_list(self):
        self.assertEqual(decide(approvals={}), "BLOCK")

    def test_one_approval(self):
        self.assertEqual(decide(approvals=APPROVALS[:1]), "BLOCK")

    def test_duplicate_approver(self):
        self.assertEqual(decide(approvals=[APPROVALS[0], APPROVALS[0]]), "BLOCK")

    def test_non_independent_approval(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["independent"] = False
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_unapproved_decision(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["decision"] = "REJECT"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_unknown_approval_role(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["role"] = "agent"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_approval_wrong_version(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["assessed_version"] = "older"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_stale_approval(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["approved_on"] = "2025-01-01"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_control_owner_cannot_be_gate_approver(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["person"] = GOOD[0]["owner"]
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_boolean_executive_acceptance_rejected(self):
        self.assertEqual(decide(executive=True), "BLOCK")

    def test_wrong_executive_role(self):
        bad = copy.deepcopy(EXECUTIVE)
        bad["role"] = "agent"
        self.assertEqual(decide(executive=bad), "BLOCK")

    def test_wrong_executive_decision(self):
        bad = copy.deepcopy(EXECUTIVE)
        bad["decision"] = "APPROVE"
        self.assertEqual(decide(executive=bad), "BLOCK")

    def test_executive_wrong_version(self):
        bad = copy.deepcopy(EXECUTIVE)
        bad["assessed_version"] = "older"
        self.assertEqual(decide(executive=bad), "BLOCK")

    def test_stale_executive_acceptance(self):
        bad = copy.deepcopy(EXECUTIVE)
        bad["accepted_on"] = "2025-01-01"
        self.assertEqual(decide(executive=bad), "BLOCK")

    def test_gate_approver_cannot_accept_executive_risk(self):
        bad = copy.deepcopy(EXECUTIVE)
        bad["person"] = APPROVALS[0]["person"]
        self.assertEqual(decide(executive=bad), "BLOCK")

    def test_control_owner_cannot_accept_executive_risk(self):
        bad = copy.deepcopy(EXECUTIVE)
        bad["person"] = GOOD[0]["owner"]
        self.assertEqual(decide(executive=bad), "BLOCK")

    def test_missing_assessed_version(self):
        self.assertEqual(decide(version=""), "BLOCK")
