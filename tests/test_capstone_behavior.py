import copy
import datetime as dt
import unittest

from python.capstone import ATTACK_CLASSES, PHASES, execution_decision


TODAY = dt.date(2026, 7, 25)
VERSION = "ce849d8"


def digest(number):
    return "sha256:" + f"{number:064x}"


AUTHORIZATION = {
    "account_id": "111122223333",
    "region": "us-east-1",
    "artifact_digest": digest(900),
    "change_ticket": "CHG-SYNTHETIC-14",
    "session_ttl_minutes": 60,
    "production_account": False,
    "synthetic_data_only": True,
}
PHASE_RESULTS = [
    {
        "name": name,
        "status": "PASS",
        "source_commit": VERSION,
        "evidence_digest": digest(index + 1),
        "collected_on": "2026-07-24",
    }
    for index, name in enumerate(PHASES)
]
ATTACKS = [
    {
        "id": f"attack-{index}",
        "class": attack_class,
        "expected": "BLOCK",
        "actual": "BLOCK",
        "critical": True,
        "side_effects": 0,
        "source_commit": VERSION,
        "evidence_digest": digest(index + 100),
        "collected_on": "2026-07-24",
    }
    for index, attack_class in enumerate(sorted(ATTACK_CLASSES))
]
APPROVALS = [
    {
        "person": "security-person",
        "role": "security-assessor",
        "decision": "APPROVE",
        "independent": True,
        "source_commit": VERSION,
        "account_id": AUTHORIZATION["account_id"],
        "region": AUTHORIZATION["region"],
        "artifact_digest": AUTHORIZATION["artifact_digest"],
        "change_ticket": AUTHORIZATION["change_ticket"],
        "approved_on": "2026-07-24",
    },
    {
        "person": "privacy-person",
        "role": "privacy-reviewer",
        "decision": "APPROVE",
        "independent": True,
        "source_commit": VERSION,
        "account_id": AUTHORIZATION["account_id"],
        "region": AUTHORIZATION["region"],
        "artifact_digest": AUTHORIZATION["artifact_digest"],
        "change_ticket": AUTHORIZATION["change_ticket"],
        "approved_on": "2026-07-24",
    },
    {
        "person": "business-person",
        "role": "business-owner",
        "decision": "APPROVE",
        "independent": True,
        "source_commit": VERSION,
        "account_id": AUTHORIZATION["account_id"],
        "region": AUTHORIZATION["region"],
        "artifact_digest": AUTHORIZATION["artifact_digest"],
        "change_ticket": AUTHORIZATION["change_ticket"],
        "approved_on": "2026-07-24",
    },
]


def decide(phases=None, attacks=None, approvals=None, authorization=None, version=VERSION):
    return execution_decision(
        PHASE_RESULTS if phases is None else phases,
        ATTACKS if attacks is None else attacks,
        APPROVALS if approvals is None else approvals,
        AUTHORIZATION if authorization is None else authorization,
        version,
        today=TODAY,
    )


class BehaviorTests(unittest.TestCase):
    def test_validated(self):
        self.assertEqual(decide(), "CONTROLLED_NONPRODUCTION_CAPSTONE_VALIDATED")

    def test_empty_version(self):
        self.assertEqual(decide(version=""), "BLOCK")

    def test_authorization_must_be_object(self):
        self.assertEqual(decide(authorization=True), "BLOCK")

    def test_authorization_extra_field(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["unexpected"] = True
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_invalid_account(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["account_id"] = "123"
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_invalid_region(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["region"] = "anywhere"
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_invalid_artifact_digest(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["artifact_digest"] = "sha256:x"
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_missing_change_ticket(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["change_ticket"] = ""
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_long_session(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["session_ttl_minutes"] = 61
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_boolean_session_ttl(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["session_ttl_minutes"] = True
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_production_account(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["production_account"] = True
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_non_synthetic_data(self):
        bad = copy.deepcopy(AUTHORIZATION)
        bad["synthetic_data_only"] = False
        self.assertEqual(decide(authorization=bad), "BLOCK")

    def test_missing_phase(self):
        self.assertEqual(decide(phases=PHASE_RESULTS[:-1]), "BLOCK")

    def test_reordered_phase(self):
        bad = copy.deepcopy(PHASE_RESULTS)
        bad[0], bad[1] = bad[1], bad[0]
        self.assertEqual(decide(phases=bad), "BLOCK")

    def test_failed_phase(self):
        bad = copy.deepcopy(PHASE_RESULTS)
        bad[3]["status"] = "FAIL"
        self.assertEqual(decide(phases=bad), "BLOCK")

    def test_unknown_phase_status(self):
        bad = copy.deepcopy(PHASE_RESULTS)
        bad[3]["status"] = "UNKNOWN"
        self.assertEqual(decide(phases=bad), "BLOCK")

    def test_wrong_phase_commit(self):
        bad = copy.deepcopy(PHASE_RESULTS)
        bad[0]["source_commit"] = "older"
        self.assertEqual(decide(phases=bad), "BLOCK")

    def test_bad_phase_digest(self):
        bad = copy.deepcopy(PHASE_RESULTS)
        bad[0]["evidence_digest"] = "sha256:x"
        self.assertEqual(decide(phases=bad), "BLOCK")

    def test_duplicate_phase_digest(self):
        bad = copy.deepcopy(PHASE_RESULTS)
        bad[1]["evidence_digest"] = bad[0]["evidence_digest"]
        self.assertEqual(decide(phases=bad), "BLOCK")

    def test_stale_phase_evidence(self):
        bad = copy.deepcopy(PHASE_RESULTS)
        bad[0]["collected_on"] = "2025-01-01"
        self.assertEqual(decide(phases=bad), "BLOCK")

    def test_future_phase_evidence(self):
        bad = copy.deepcopy(PHASE_RESULTS)
        bad[0]["collected_on"] = "2026-08-01"
        self.assertEqual(decide(phases=bad), "BLOCK")

    def test_too_few_attacks(self):
        self.assertEqual(decide(attacks=ATTACKS[:-1]), "BLOCK")

    def test_too_many_attacks(self):
        self.assertEqual(decide(attacks=ATTACKS + [copy.deepcopy(ATTACKS[0])]), "BLOCK")

    def test_duplicate_attack(self):
        bad = copy.deepcopy(ATTACKS)
        bad[-1]["id"] = bad[0]["id"]
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_duplicate_attack_class(self):
        bad = copy.deepcopy(ATTACKS)
        bad[-1]["class"] = bad[0]["class"]
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_unknown_attack_class(self):
        bad = copy.deepcopy(ATTACKS)
        bad[0]["class"] = "unknown"
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_attack_mismatch(self):
        bad = copy.deepcopy(ATTACKS)
        bad[0]["actual"] = "ALLOW"
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_attack_expected_allow(self):
        bad = copy.deepcopy(ATTACKS)
        bad[0]["expected"] = bad[0]["actual"] = "ALLOW"
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_attack_not_critical(self):
        bad = copy.deepcopy(ATTACKS)
        bad[0]["critical"] = False
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_attack_side_effect(self):
        bad = copy.deepcopy(ATTACKS)
        bad[0]["side_effects"] = 1
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_attack_wrong_commit(self):
        bad = copy.deepcopy(ATTACKS)
        bad[0]["source_commit"] = "older"
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_duplicate_attack_digest(self):
        bad = copy.deepcopy(ATTACKS)
        bad[1]["evidence_digest"] = bad[0]["evidence_digest"]
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_stale_attack_evidence(self):
        bad = copy.deepcopy(ATTACKS)
        bad[0]["collected_on"] = "2025-01-01"
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_attack_extra_field(self):
        bad = copy.deepcopy(ATTACKS)
        bad[0]["unexpected"] = True
        self.assertEqual(decide(attacks=bad), "BLOCK")

    def test_too_few_approvals(self):
        self.assertEqual(decide(approvals=APPROVALS[:2]), "BLOCK")

    def test_duplicate_approver(self):
        bad = copy.deepcopy(APPROVALS)
        bad[1]["person"] = bad[0]["person"]
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_missing_role(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["role"] = "agent"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_rejected(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["decision"] = "REJECT"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_not_independent(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["independent"] = False
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_approval_wrong_commit(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["source_commit"] = "older"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_approval_wrong_account(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["account_id"] = "999900001111"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_approval_wrong_region(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["region"] = "us-west-2"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_approval_wrong_artifact(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["artifact_digest"] = digest(901)
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_approval_wrong_ticket(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["change_ticket"] = "CHG-OTHER"
        self.assertEqual(decide(approvals=bad), "BLOCK")

    def test_stale_approval(self):
        bad = copy.deepcopy(APPROVALS)
        bad[0]["approved_on"] = "2025-01-01"
        self.assertEqual(decide(approvals=bad), "BLOCK")
