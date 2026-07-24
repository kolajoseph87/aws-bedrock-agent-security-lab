"""Deterministic, side-effect-free Chapter 8 teaching gates."""
import re
SOURCE_SHA=re.compile(r"^[0-9a-f]{40}$")
DIGEST=re.compile(r"^[0-9a-f]{64}$")
def deny(reason): return {"allow":False,"reason":reason,"side_effects":0}
def verify_source(source_sha,approved_sha,patch_hash,approved_patch_hash,branch_protected=True,
                  reviewers=None,author="patch-author",agent_identity="secure-coding-agent",
                  agent_approved=False):
 reviewers=reviewers if reviewers is not None else ["appsec-reviewer","platform-reviewer"]
 independent=(len(reviewers)>=2 and len(set(reviewers))==len(reviewers)
              and author not in reviewers and agent_identity not in reviewers)
 if not branch_protected or not independent or agent_approved: return deny("SOURCE_APPROVAL_DENIED")
 if not SOURCE_SHA.fullmatch(source_sha or "") or source_sha!=approved_sha: return deny("SOURCE_SHA_MISMATCH")
 if not DIGEST.fullmatch(patch_hash or "") or patch_hash!=approved_patch_hash: return deny("PATCH_PROVENANCE_MISMATCH")
 return {"allow":True,"reason":"SOURCE_VERIFIED","side_effects":0}
def verify_security_gates(results,waiver=None,now=0,max_waiver_seconds=604800):
 required={"sast","sca","secret_scan","iac_scan","malware_scan","unit_tests","policy_tests"}
 if set(results)!=required: return deny("MISSING_SECURITY_GATE")
 failed={k for k,v in results.items() if v is not True}
 if not failed: return {"allow":True,"reason":"GATES_PASSED","side_effects":0}
 if not waiver: return deny("SECURITY_GATE_FAILED")
 ttl=waiver.get("expires_at",0)-now
 if (ttl<=0 or ttl>max_waiver_seconds or not waiver.get("independent_risk_owner")
     or not waiver.get("approved_by") or not waiver.get("ticket")
     or not waiver.get("reason") or set(waiver.get("gates",[]))!=failed):
  return deny("WAIVER_DENIED")
 return {"allow":True,"reason":"TIME_BOUND_WAIVER","side_effects":0}
def verify_artifact(source_sha,provenance_sha,artifact_digest,signed_digest,sbom_digest,
                    expected_sbom_digest,signature_valid=True,signature_identity="release-signer",
                    approved_signers=None):
 approved_signers=approved_signers if approved_signers is not None else {"release-signer"}
 if not SOURCE_SHA.fullmatch(source_sha or "") or not SOURCE_SHA.fullmatch(provenance_sha or ""):
  return deny("INVALID_DIGEST")
 values=[artifact_digest,signed_digest,sbom_digest,expected_sbom_digest]
 if not all(DIGEST.fullmatch(x or "") for x in values): return deny("INVALID_DIGEST")
 if source_sha!=provenance_sha: return deny("PROVENANCE_MISMATCH")
 if artifact_digest!=signed_digest or not signature_valid or signature_identity not in approved_signers:
  return deny("SIGNATURE_INVALID")
 if sbom_digest!=expected_sbom_digest: return deny("SBOM_MISMATCH")
 return {"allow":True,"reason":"ARTIFACT_VERIFIED","side_effects":0}
def authorize_deployment(actor,approver,target,artifact_digest,approved_digest,change_ticket,
                         temporary_identity=True,approved_actor="release-pipeline",
                         approval=None,now=0,promoted_digests=None):
 if actor=="agent" or actor==approver: return deny("SEPARATION_OF_DUTIES")
 if actor!=approved_actor: return deny("DEPLOYMENT_IDENTITY_DENIED")
 if target not in {"development","test","production"}: return deny("TARGET_DENIED")
 if artifact_digest!=approved_digest: return deny("ARTIFACT_SUBSTITUTION")
 if not change_ticket or not temporary_identity: return deny("DEPLOYMENT_AUTHORIZATION_MISSING")
 approval=approval or {}
 if (approval.get("approver")!=approver or approval.get("target")!=target
     or approval.get("artifact_digest")!=artifact_digest
     or approval.get("change_ticket")!=change_ticket
     or approval.get("expires_at",0)<=now):
  return deny("APPROVAL_BINDING_MISMATCH")
 if promoted_digests is not None and any(x!=artifact_digest for x in promoted_digests):
  return deny("PROMOTION_DIGEST_MISMATCH")
 return {"allow":True,"reason":"DEPLOYMENT_AUTHORIZED","side_effects":0}
