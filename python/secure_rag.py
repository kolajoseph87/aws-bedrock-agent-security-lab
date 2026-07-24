"""Deterministic offline teaching model. Makes no AWS calls."""
import hashlib
import re


BAD = (
    r"ignore (all|previous) instructions",
    r"system prompt",
    r"access[_ -]?token",
    r"synthetic[- ]?mrn",
    r"patient diagnosis",
)
SENSITIVE_OUTPUT = (r"access[_ -]?token", r"synthetic[- ]?mrn", r"patient diagnosis")


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def authorize_query(principal_tenant, principal_repo, requested_tenant, requested_repo):
    if principal_tenant != requested_tenant:
        return {"allow": False, "reason": "CROSS_TENANT_DENIED"}
    if principal_repo != requested_repo:
        return {"allow": False, "reason": "CROSS_REPOSITORY_DENIED"}
    return {"allow": True, "reason": "SCOPE_OK"}


def inspect_chunks(
    chunks,
    expected_tenant,
    expected_repo,
    minimum_score=.72,
    max_chunks=5,
    max_characters=4000,
):
    if len(chunks) > max_chunks:
        return {"allow": False, "reason": "TOO_MANY_CHUNKS", "chunks": []}

    accepted = []
    for chunk in chunks:
        text = chunk.get("text", "")
        if chunk.get("tenant_id") != expected_tenant:
            return {"allow": False, "reason": "CHUNK_TENANT_MISMATCH", "chunks": []}
        if chunk.get("repository_id") != expected_repo:
            return {"allow": False, "reason": "CHUNK_REPOSITORY_MISMATCH", "chunks": []}
        if len(text) > max_characters:
            return {"allow": False, "reason": "CHUNK_TOO_LARGE", "chunks": []}
        if not chunk.get("id") or not chunk.get("citation"):
            return {"allow": False, "reason": "CHUNK_METADATA_INCOMPLETE", "chunks": []}
        if chunk.get("deleted") is True:
            return {"allow": False, "reason": "STALE_DELETED_DOCUMENT", "chunks": []}
        if chunk.get("sha256") != digest(text):
            return {"allow": False, "reason": "SOURCE_HASH_MISMATCH", "chunks": []}
        if chunk.get("score", 0) < minimum_score:
            return {"allow": False, "reason": "LOW_RELEVANCE", "chunks": []}
        if any(re.search(pattern, text, re.I) for pattern in BAD):
            return {"allow": False, "reason": "UNTRUSTED_CHUNK_CONTENT", "chunks": []}
        accepted.append(
            {
                "id": chunk["id"],
                "citation": chunk["citation"],
                "sha256": chunk["sha256"],
            }
        )

    return {
        "allow": bool(accepted),
        "reason": "CHUNKS_APPROVED" if accepted else "NO_GROUNDED_RESULTS",
        "chunks": accepted,
    }


def validate_output(output, approved_chunks, cited_chunk_ids, streaming_started=False):
    if streaming_started:
        return {"allow": False, "reason": "STREAMING_BEFORE_VALIDATION"}
    if not approved_chunks:
        return {"allow": False, "reason": "NO_GROUNDED_RESULTS"}
    if any(re.search(pattern, output, re.I) for pattern in SENSITIVE_OUTPUT):
        return {"allow": False, "reason": "OUTPUT_SENSITIVE"}

    approved_ids = {chunk["id"] for chunk in approved_chunks}
    cited_ids = set(cited_chunk_ids)
    if not cited_ids or not cited_ids.issubset(approved_ids):
        return {"allow": False, "reason": "CITATION_INVALID"}
    return {"allow": True, "reason": "OUTPUT_APPROVED"}
