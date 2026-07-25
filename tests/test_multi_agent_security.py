import copy,json,unittest
from pathlib import Path
from scripts.validate_multi_agent_security import validate
ROOT=Path(__file__).resolve().parents[1]
BASE=json.loads((ROOT/"multi-agent-security/multi-agent-security.aws.json").read_text())

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
"shared_identity":(("architecture","shared_agent_credentials_allowed"),True),
"peer_bypass":(("architecture","peer_to_peer_bypass_allowed"),True),
"no_signature":(("messages","signature_required"),False),
"long_ttl":(("messages","maximum_ttl_seconds"),900),
"trust_prompt_identity":(("messages","prompt_claimed_identity_trusted"),True),
"no_nonce":(("messages","single_use_nonce_required"),False),
"amplify":(("delegation","cannot_delegate_more_authority_than_held"),False),
"deep_chain":(("delegation","maximum_depth"),9),
"no_cycle_check":(("delegation","cycle_detection_required"),False),
"scope_expand":(("delegation","scope_cannot_expand"),False),
"no_hop_auth":(("authorization","authorize_every_hop"),False),
"fail_open":(("authorization","fail_closed_if_policy_or_identity_unavailable"),False),
"self_approval":(("authorization","self_approval_prohibited"),False),
"cross_scope":(("authorization","cross_tenant_or_repository_access_prohibited"),False),
"raw_context":(("context","raw_prompts_code_chunks_or_tool_arguments_forwarded"),True),
"sensitive_context":(("context","phi_pii_credentials_secrets_or_tokens_forwarded"),True),
"trust_retrieval":(("context","retrieved_content_is_untrusted_data"),False),
"no_quarantine":(("containment","compromised_agent_quarantine_required"),False),
"broad_fallback":(("containment","partial_failure_cannot_fall_back_to_broader_agent"),False),
"body_logging":(("observability","message_body_logging_prohibited"),False),
"unsafe_attack":(("safe_attacks",0,"aws_calls"),1),
"wrong_chapter":(("chapter",),11),
"production":(("environment",),"production")}
for n,(p,v) in CASES.items(): setattr(ManifestTests,"test_"+n,case(p,v))
