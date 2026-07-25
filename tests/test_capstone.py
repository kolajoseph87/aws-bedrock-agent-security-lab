import copy
import json
import unittest
from pathlib import Path
from scripts.validate_capstone import validate

ROOT=Path(__file__).resolve().parents[1]
BASE=json.loads((ROOT/"capstone/capstone.aws.json").read_text())

class ManifestTests(unittest.TestCase):
    def test_reference(self):
        self.assertTrue(all(x["status"]=="PASS" for x in validate(BASE)))

def case(path,value):
    def test(self):
        d=copy.deepcopy(BASE); p=d
        for key in path[:-1]: p=p[key]
        p[path[-1]]=value
        self.assertTrue(any(x["status"]=="FAIL" for x in validate(d)))
    return test

CASES={
"wrong_commit":(("baseline","source_commit"),"older"),
"wrong_test_baseline":(("baseline","published_test_count"),642),
"empty_account_allowlist":(("scope","approved_account_ids"),[]),
"invalid_region_allowlist":(("scope","approved_regions"),["anywhere"]),
"binding_wrong_account":(("authorization","example_binding","account_id"),"999900001111"),
"binding_wrong_region":(("authorization","example_binding","region"),"us-west-2"),
"binding_wrong_artifact":(("authorization","example_binding","artifact_digest"),"sha256:x"),
"binding_long_session":(("authorization","example_binding","session_ttl_minutes"),61),
"unbound_approvals":(("authorization","approvals_bound_to_example"),False),
"stale_approval_window":(("authorization","approval_freshness_max_days"),30),
    "missing_chapter":(("baseline","chapters_required"),list(range(13))),
    "dirty_source":(("baseline","no_unreviewed_local_changes"),False),
    "production_allowed":(("scope","production_accounts_prohibited"),False),
    "real_data":(("scope","synthetic_data_only"),False),
    "public_access":(("scope","public_access_prohibited"),False),
    "enabled_by_default":(("authorization","deployment_disabled_by_default"),False),
    "agent_deploys":(("authorization","agent_cannot_deploy_approve_waive_or_accept_risk"),False),
    "missing_ticket":(("authorization","change_ticket_required"),False),
    "wrong_phase_order":(("execution","ordered_phases"),["deploy","preflight"]),
    "fail_open":(("execution","stop_on_first_critical_failure"),False),
    "kill_switch_late":(("execution","kill_switch_tested_before_attacks"),False),
    "unbounded_cost":(("execution","budgets_quotas_timeouts_and_concurrency_limits_required"),False),
    "live_attack":(("attack_exercises","production_targets_prohibited"),False),
    "missing_attack":(("attack_exercises","classes_required"),BASE["attack_exercises"]["classes_required"][:-1]),
    "no_oracle":(("attack_exercises","expected_result_bound_before_execution"),False),
    "weak_custody":(("evidence","chain_of_custody_required"),False),
    "sensitive_evidence":(("evidence","raw_prompts_code_phi_pii_secrets_tokens_and_tool_bodies_prohibited"),False),
    "short_retention":(("evidence","minimum_retention_days"),30),
    "boolean_retention":(("evidence","minimum_retention_days"),True),
    "no_executive_report":(("assessment","executive_summary_required"),False),
    "critical_allowed":(("assessment","open_critical_findings_allowed"),True),
    "production_claim":(("assessment","production_authorization_claimed"),True),
    "teardown_optional":(("teardown","teardown_failure_blocks_completion"),False),
    "orphan_check_missing":(("teardown","orphan_resource_and_cost_checks_required"),False),
    "unsafe_failure":(("safe_failures",0,"aws_calls"),1),
    "production_environment":(("environment",),"production"),
    "wrong_chapter":(("chapter",),13),
}
for name,(path,value) in CASES.items():
    setattr(ManifestTests,"test_"+name,case(path,value))
