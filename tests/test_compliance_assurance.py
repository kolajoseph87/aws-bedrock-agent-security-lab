import copy,json,unittest
from pathlib import Path
from scripts.validate_compliance_assurance import validate
ROOT=Path(__file__).resolve().parents[1]
BASE=json.loads((ROOT/"compliance-assurance/compliance-assurance.aws.json").read_text())

class ManifestTests(unittest.TestCase):
    def test_reference(self): self.assertTrue(all(x["status"]=="PASS" for x in validate(BASE)))

def case(path,value):
    def test(self):
        d=copy.deepcopy(BASE); p=d
        for k in path[:-1]: p=p[k]
        p[path[-1]]=value
        self.assertTrue(any(x["status"]=="FAIL" for x in validate(d)))
    return test

CASES={
"owasp_unpinned":(("frameworks","owasp_agentic_ai","version_pinned"),False),
"nist_incomplete":(("frameworks","nist_ai_rmf","govern_map_measure_manage_covered"),False),
"atlas_unmapped":(("frameworks","mitre_atlas","threat_mapping_required"),False),
"hipaa_no_risk_analysis":(("frameworks","hipaa_security_rule","risk_analysis_required"),False),
"aws_no_ai_lens":(("frameworks","aws_well_architected","ai_lens_review_required"),False),
"missing_framework_version":(("frameworks","owasp_agentic_ai","version"),""),
"no_owner":(("control_records","owner_and_approver_required"),False),
"no_digest":(("control_records","evidence_locator_and_digest_required"),False),
"duplicate_control_record":(("control_records","records",1,"control_id"),"NS-00"),
"wrong_record_commit":(("control_records","records",1,"source_commit"),"older"),
"forged_record_digest":(("control_records","records",1,"evidence_sha256"),"sha256:x"),
"control_owner_self_approval":(("control_records","records",1,"independent_approver"),"Application Security"),
"permanent_exception":(("control_records","exceptions_have_owner_expiry_and_compensating_controls"),False),
"screenshot_only":(("evidence","screenshots_alone_sufficient"),True),
"self_attestation":(("evidence","self_attestation_alone_sufficient"),True),
"sensitive_evidence":(("evidence","raw_prompts_code_phi_pii_secrets_or_tokens_prohibited"),False),
"no_live_test":(("assurance","live_nonproduction_validation_required"),False),
"no_red_team":(("assurance","adversarial_testing_required"),False),
"critical_allowed":(("assurance","open_critical_findings_allowed"),True),
"no_legal":(("production_gate","privacy_and_legal_review_required"),False),
"agent_accepts_risk":(("production_gate","agent_cannot_approve_waive_or_accept_risk"),False),
"fail_open":(("production_gate","fail_closed_on_missing_stale_or_conflicting_evidence"),False),
"stale_window":(("continuous_compliance","evidence_freshness_max_days"),365),
"no_drift":(("continuous_compliance","control_drift_detection_required"),False),
"unsafe_failure":(("safe_failures",0,"aws_calls"),1),
"production":(("environment",),"production"),
"wrong_chapter":(("chapter",),12)}
for n,(p,v) in CASES.items(): setattr(ManifestTests,"test_"+n,case(p,v))
