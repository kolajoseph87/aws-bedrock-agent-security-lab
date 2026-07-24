import copy
import json
import unittest
from pathlib import Path
from scripts.validate_incident_response import validate

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads((ROOT / "incident-response/incident-response.aws.json").read_text())

class ManifestTests(unittest.TestCase):
    def test_reference(self):
        self.assertTrue(all(x["status"] == "PASS" for x in validate(BASE)))

def mutation(path, value):
    def test(self):
        data = copy.deepcopy(BASE)
        cursor = data
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = value
        self.assertTrue(any(x["status"] == "FAIL" for x in validate(data)))
    return test

CASES = {
 "wrong_order":(("response_flow",),[]),
 "agent_clears":(("authority","agent_can_restore_service"),True),
 "one_person":(("authority","break_glass_requires_two_people"),False),
 "long_breakglass":(("authority","maximum_break_glass_ttl_seconds"),3600),
 "fail_open":(("kill_switch","fail_closed_if_state_unavailable"),False),
 "no_model_block":(("kill_switch","deny_new_model_invocations"),False),
 "slow_propagation":(("kill_switch","bounded_propagation_seconds"),600),
 "prompt_override":(("kill_switch","cannot_be_overridden_by_prompt"),False),
 "orders_not_revoked":(("revocation","work_orders_revoked_required"),False),
 "tokens_not_revoked":(("revocation","repository_tokens_revoked_required"),False),
 "no_rag_quarantine":(("containment","knowledge_base_source_quarantine_required"),False),
 "destroy_evidence":(("containment","containment_must_not_destroy_evidence"),False),
 "mutable_evidence":(("evidence","immutable_preservation_required"),False),
 "short_retention":(("evidence","minimum_retention_days"),30),
 "raw_prompts":(("evidence","raw_prompts_completions_code_or_chunks_allowed"),True),
 "no_regression":(("recovery","full_security_regression_required"),False),
 "no_new_auth":(("recovery","kill_switch_clear_requires_new_authorization"),False),
 "missing_playbooks":(("playbooks","required"),[]),
 "unsafe_exercise":(("safe_exercises",0,"aws_calls"),1),
 "wrong_chapter":(("chapter",),10)
}

def nested_mutation(path, value):
    def test(self):
        data = copy.deepcopy(BASE)
        cursor = data
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = value
        self.assertTrue(any(x["status"] == "FAIL" for x in validate(data)))
    return test

for name,(path,value) in CASES.items():
    setattr(ManifestTests, "test_"+name, nested_mutation(path,value))
